use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use pecr_contracts::{Budget, PolicySnapshot, TerminalMode};
use pecr_ledger::CreateSessionRecord;
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use ulid::Ulid;

use super::auth::{extract_principal, extract_request_id, extract_trace_id, sanitize_as_of_time};
use super::runtime::sha256_hex;
use super::session::unix_epoch_ms_now;
use super::{AppState, ErrorResponse, json_error};
use crate::opa::OpaCacheKey;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateSessionRequest {
    pub(super) budget: Budget,
    #[serde(default)]
    pub(super) as_of_time: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct CreateSessionResponse {
    pub(super) session_id: String,
    pub(super) trace_id: String,
    pub(super) policy_snapshot_id: String,
    pub(super) budget: Budget,
}

pub(super) async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Result<(HeaderMap, Json<CreateSessionResponse>), (StatusCode, Json<ErrorResponse>)> {
    let principal = extract_principal(&state, &headers).await?;
    let principal_id = principal.principal_id.clone();

    if !state.rate_limiter.allow(
        format!("sessions:{}", principal_id).as_str(),
        state.config.rate_limit_sessions_per_window,
    ) {
        return Err(json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "ERR_RATE_LIMITED",
            "rate limit exceeded for session creation".to_string(),
            TerminalMode::InsufficientPermission,
            true,
        ));
    }

    let request_id = extract_request_id(&headers);
    let trace_id = extract_trace_id(&headers);

    let Json(req) = req.map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "invalid JSON body".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    req.budget.validate().map_err(|reason| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            format!("invalid budget: {}", reason),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let as_of_time = match req
        .as_of_time
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => state.config.as_of_time_default.clone(),
        Some(raw) => sanitize_as_of_time(raw).ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "as_of_time must be RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ)".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?,
    };

    let session_id = Ulid::new().to_string();
    let policy_snapshot_id = Ulid::new().to_string();

    let span = tracing::info_span!(
        "session.create",
        trace_id = %trace_id,
        request_id = %request_id,
        session_id = %session_id,
        principal_id = %principal_id,
        policy_snapshot_id = %policy_snapshot_id,
        policy_snapshot_hash = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let started = Instant::now();

    let result = async move {
        let mut policy_snapshot = PolicySnapshot {
            policy_snapshot_hash: String::new(),
            principal_id: principal_id.clone(),
            tenant_id: principal.tenant_id.clone(),
            principal_roles: principal.principal_roles.clone(),
            principal_attrs_hash: principal.principal_attrs_hash.clone(),
            policy_bundle_hash: state.config.policy_bundle_hash.clone(),
            as_of_time: as_of_time.clone(),
            evaluated_at: as_of_time.clone(),
        };
        policy_snapshot.policy_snapshot_hash = policy_snapshot.compute_hash();
        tracing::Span::current().record(
            "policy_snapshot_hash",
            policy_snapshot.policy_snapshot_hash.as_str(),
        );

        let budget_hash =
            sha256_hex(&serde_json::to_vec(&req.budget).unwrap_or_else(|_| Vec::new()));

        let policy_span = tracing::info_span!(
            "policy.evaluate",
            trace_id = %trace_id,
            request_id = %request_id,
            session_id = %session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %policy_snapshot_id,
            policy_snapshot_hash = %policy_snapshot.policy_snapshot_hash,
            action = "create_session",
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        let decision = async {
            let started = Instant::now();
            let decision = state
                .opa
                .decide(
                    serde_json::json!({
                        "action": "create_session",
                        "principal_id": principal_id.as_str(),
                        "policy_snapshot_hash": policy_snapshot.policy_snapshot_hash.as_str(),
                        "policy_bundle_hash": state.config.policy_bundle_hash.as_str(),
                        "as_of_time": as_of_time.as_str(),
                        "budget_hash": budget_hash,
                        "request_id": request_id.as_str(),
                    }),
                    Some(OpaCacheKey::create_session(
                        &policy_snapshot.policy_snapshot_hash,
                    )),
                )
                .await;

            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);

            match decision {
                Ok(decision) => {
                    let outcome = if decision.allow { "allow" } else { "deny" };
                    tracing::Span::current().record("outcome", outcome);
                    Ok(decision)
                }
                Err(err) => {
                    tracing::Span::current().record("outcome", "error");
                    Err(err)
                }
            }
        }
        .instrument(policy_span)
        .await
        .map_err(|err| super::opa_error_response(&err))?;

        if !decision.allow {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "ERR_POLICY_DENIED",
                "policy denied".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let session_token = Ulid::new().to_string();
        let session_token_hash = sha256_hex(session_token.as_bytes());
        let session_token_expires_at_epoch_ms = unix_epoch_ms_now()
            + i64::try_from(state.config.session_token_ttl_secs.saturating_mul(1000))
                .unwrap_or(i64::MAX);

        tracing::info!(
            trace_id = %trace_id,
            request_id = %request_id,
            session_id = %session_id,
            principal_id = %principal_id,
            "gateway.create_session"
        );

        let ledger_span = tracing::info_span!(
            "ledger.append",
            trace_id = %trace_id,
            request_id = %request_id,
            session_id = %session_id,
            event_type = "SESSION_CREATED",
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        async {
            let started = Instant::now();
            state
                .ledger
                .create_session(CreateSessionRecord {
                    session_id: &session_id,
                    trace_id: &trace_id,
                    principal_id: &principal_id,
                    budget: &req.budget,
                    policy_snapshot_id: &policy_snapshot_id,
                    policy_snapshot: &policy_snapshot,
                    tenant_id: &policy_snapshot.tenant_id,
                    session_token_hash: &session_token_hash,
                    session_token_expires_at_epoch_ms,
                })
                .await
                .map_err(|_| {
                    json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "ERR_LEDGER_UNAVAILABLE",
                        "ledger unavailable".to_string(),
                        TerminalMode::SourceUnavailable,
                        true,
                    )
                })?;

            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("outcome", "ok");
            Ok::<_, (StatusCode, Json<ErrorResponse>)>(())
        }
        .instrument(ledger_span)
        .await?;

        let mut resp_headers = HeaderMap::new();
        let token_value = axum::http::HeaderValue::from_str(&session_token).map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_INTERNAL",
                "failed to issue session token".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;
        resp_headers.insert("x-pecr-session-token", token_value);

        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::Span::current().record("latency_ms", latency_ms);
        tracing::Span::current().record("outcome", "ok");

        Ok((
            resp_headers,
            Json(CreateSessionResponse {
                session_id,
                trace_id,
                policy_snapshot_id,
                budget: req.budget,
            }),
        ))
    }
    .instrument(span)
    .await;

    let status = match &result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/sessions",
        "POST",
        status.as_u16(),
        started.elapsed(),
    );
    result
}
