use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use hex::ToHex;
use pecr_auth::{OidcAuthenticator, Principal};
use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, EvidenceContentType, EvidenceUnit, EvidenceUnitRef, PolicySnapshot, TerminalMode,
    TransformStep,
};
use pecr_ledger::{CreateSessionRecord, FinalizeResultRecord, LedgerWriter};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use similar::TextDiff;
use sqlx::{PgPool, Row};
use tokio::sync::RwLock;
use tracing::Instrument;
use ulid::Ulid;

use crate::config::{AuthMode, GatewayConfig, StartupError};
use crate::opa::{OpaCacheKey, OpaClient, OpaClientConfig};
use crate::operator_cache::{OperatorCache, OperatorCacheKey};
use crate::rate_limit::RateLimiter;

mod finalize;
mod operator;
mod policy;
mod session;

use self::finalize::{FinalizeRequest, FinalizeResponse, finalize_gate};
use self::operator::is_allowlisted_operator;
use self::policy::{
    apply_field_redaction, apply_field_redaction_to_evidence_unit, compute_content_hash,
    compute_evidence_unit_id, parse_field_redaction, redact_span_or_row_spec_fields,
};
use self::session::{
    acquire_session_lock, load_session_runtime, persist_session_runtime, unix_epoch_ms_now,
};

#[cfg(test)]
use self::session::Session;
#[cfg(test)]
use pecr_contracts::{ClaimMap, ClaimStatus};
#[cfg(test)]
use pecr_policy::FieldRedaction;

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    oidc: Option<OidcAuthenticator>,
    ledger: LedgerWriter,
    opa: OpaClient,
    operator_cache: OperatorCache,
    rate_limiter: RateLimiter,
    pg_pool: PgPool,
    fs_versions: Arc<RwLock<FsVersionCache>>,
    pg_versions: Arc<RwLock<FsVersionCache>>,
}

type ApiError = (StatusCode, Json<ErrorResponse>);
type FilterEq = (String, String);

pub async fn router(config: GatewayConfig) -> Result<Router, StartupError> {
    let oidc = if config.auth_mode == AuthMode::Oidc {
        let oidc_config = config.oidc.clone().ok_or_else(|| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "oidc auth mode requires oidc config".to_string(),
        })?;

        Some(
            OidcAuthenticator::new(oidc_config)
                .await
                .map_err(|err| StartupError {
                    code: err.code,
                    message: err.message,
                })?,
        )
    } else {
        None
    };

    let ledger = LedgerWriter::connect_and_migrate(
        &config.db_url,
        Duration::from_millis(config.ledger_write_timeout_ms),
    )
    .await
    .map_err(|err| StartupError {
        code: "ERR_LEDGER_UNAVAILABLE",
        message: format!("failed to initialize ledger: {}", err),
    })?;

    let opa = OpaClient::new(OpaClientConfig {
        base_url: config.opa_url.clone(),
        timeout: Duration::from_millis(config.opa_timeout_ms),
        cache_max_entries: config.cache_max_entries,
        cache_ttl: Duration::from_millis(config.cache_ttl_ms),
        retry_max_attempts: config.opa_retry_max_attempts,
        retry_base_backoff: Duration::from_millis(config.opa_retry_base_backoff_ms),
        circuit_breaker_failure_threshold: config.opa_circuit_breaker_failure_threshold,
        circuit_breaker_open_for: Duration::from_millis(config.opa_circuit_breaker_open_ms),
    })
    .map_err(|_| StartupError {
        code: "ERR_OPA_UNAVAILABLE",
        message: "failed to initialize policy client".to_string(),
    })?;

    let pg_pool = PgPool::connect(&config.db_url)
        .await
        .map_err(|_| StartupError {
            code: "ERR_DB_UNAVAILABLE",
            message: "failed to initialize safe-view database pool".to_string(),
        })?;
    validate_safeview_schema(&pg_pool).await?;

    let operator_cache = OperatorCache::new(
        config.cache_max_entries,
        Duration::from_millis(config.cache_ttl_ms),
    );
    let rate_limiter = RateLimiter::new(
        Duration::from_secs(config.rate_limit_window_secs.max(1)),
        16_384,
    );

    let fs_versions = Arc::new(RwLock::new(FsVersionCache::new(
        config.fs_version_cache_max_bytes,
        config.fs_version_cache_max_versions_per_object,
    )));

    let pg_versions = Arc::new(RwLock::new(FsVersionCache::new(
        config.fs_version_cache_max_bytes,
        config.fs_version_cache_max_versions_per_object,
    )));

    let state = AppState {
        config,
        oidc,
        ledger,
        opa,
        operator_cache,
        rate_limiter,
        pg_pool,
        fs_versions,
        pg_versions,
    };

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/sessions", post(create_session))
        .route("/v1/operators/{op_name}", post(call_operator))
        .route("/v1/finalize", post(finalize))
        .with_state(state))
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
struct ReadyzResponse {
    status: &'static str,
    checks: BTreeMap<&'static str, bool>,
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let mut checks = BTreeMap::new();

    let ledger_ready = state.ledger.ping().await.is_ok();
    checks.insert("ledger", ledger_ready);

    let postgres_ready = tokio::time::timeout(
        Duration::from_millis(state.config.pg_safeview_query_timeout_ms.max(50)),
        sqlx::query("SELECT 1").execute(&state.pg_pool),
    )
    .await
    .is_ok_and(|res| res.is_ok());
    checks.insert("postgres", postgres_ready);

    let opa_ready = state.opa.ready().await.is_ok();
    checks.insert("opa", opa_ready);

    let all_ready = checks.values().all(|ok| *ok);
    let status = if all_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadyzResponse {
            status: if all_ready { "ready" } else { "not_ready" },
            checks,
        }),
    )
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if state.config.metrics_require_auth
        && let Err(err) = extract_principal(&state, &headers).await
    {
        return err.into_response();
    }

    match crate::metrics::render() {
        Ok((body, content_type)) => {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(content_type.as_str()) {
                headers.insert(header::CONTENT_TYPE, value);
            }
            (headers, body).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    budget: Budget,
    #[serde(default)]
    as_of_time: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateSessionResponse {
    session_id: String,
    trace_id: String,
    policy_snapshot_id: String,
    budget: Budget,
}

async fn create_session(
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
        .map(|s| s.trim())
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
        .map_err(|err| opa_error_response(&err))?;

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorCallRequest {
    session_id: String,
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OperatorCallResponse {
    terminal_mode: TerminalMode,
    result: serde_json::Value,
}

async fn call_operator(
    State(state): State<AppState>,
    Path(op_name): Path<String>,
    headers: HeaderMap,
    req: Result<Json<OperatorCallRequest>, JsonRejection>,
) -> Result<Json<OperatorCallResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_started = Instant::now();
    let op_name_for_metrics = op_name.clone();

    let handler_result = (async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id.clone();

        if !state
            .rate_limiter
            .allow(
                format!("operators:{}", principal_id).as_str(),
                state.config.rate_limit_operators_per_window,
            )
        {
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_RATE_LIMITED",
                "rate limit exceeded for operator calls".to_string(),
                TerminalMode::InsufficientPermission,
                true,
            ));
        }

        let request_id = extract_request_id(&headers);
        let session_token = extract_session_token(&headers)?;

        let Json(req) = req.map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "invalid JSON body".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;
        let _session_lock = acquire_session_lock(&state, &req.session_id).await?;

        let params_bytes = serde_json::to_vec(&req.params)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let params_hash =
            sha256_hex(&serde_json::to_vec(&req.params).unwrap_or_else(|_| Vec::new()));

        let mut session = load_session_runtime(&state, &req.session_id)
            .await?
            .ok_or_else(|| {
                json_error(
                    StatusCode::NOT_FOUND,
                    "ERR_INVALID_PARAMS",
                    "unknown session_id".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?;

        if session.session_id != req.session_id {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "ERR_INVALID_PARAMS",
                "unknown session_id".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if session.finalized {
            return Err(json_error(
                StatusCode::CONFLICT,
                "ERR_INVALID_PARAMS",
                "session already finalized".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if session.principal_id != principal_id {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "POLICY_DECISION",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "decision": "deny",
                        "reason": "principal_mismatch",
                        "op_name": op_name.as_str(),
                        "request_id": request_id.as_str(),
                    }),
                )
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

            tracing::warn!(
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                "gateway.principal_mismatch"
            );
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "invalid session credentials".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let session_token_hash = sha256_hex(session_token.as_bytes());
        if unix_epoch_ms_now() > session.session_token_expires_at_epoch_ms
            || session.session_token_hash != session_token_hash
        {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "POLICY_DECISION",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "decision": "deny",
                        "reason": "invalid_session_token",
                        "op_name": op_name.as_str(),
                        "request_id": request_id.as_str(),
                    }),
                )
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

            tracing::warn!(
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                "gateway.session_token_invalid"
            );
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "invalid session credentials".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        if session.operator_calls_used >= session.budget.max_operator_calls {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "BUDGET_VIOLATION",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "op_name": op_name.as_str(),
                        "request_id": request_id.as_str(),
                        "operator_calls_used": session.operator_calls_used,
                        "max_operator_calls": session.budget.max_operator_calls,
                    }),
                )
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

            crate::metrics::inc_budget_violation();
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_BUDGET_EXCEEDED",
                "budget exceeded".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if session.budget.max_bytes > 0
            && session
                .bytes_used
                .saturating_add(params_bytes)
                .gt(&session.budget.max_bytes)
        {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "BUDGET_VIOLATION",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "op_name": op_name.as_str(),
                        "request_id": request_id.as_str(),
                        "bytes_used": session.bytes_used,
                        "params_bytes": params_bytes,
                        "max_bytes": session.budget.max_bytes,
                    }),
                )
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

            crate::metrics::inc_budget_violation();
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_BUDGET_EXCEEDED",
                "budget exceeded".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        let budget_hash =
            sha256_hex(&serde_json::to_vec(&session.budget).unwrap_or_else(|_| Vec::new()));
        tracing::info!(
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %session.policy_snapshot_id,
            op_name = %op_name,
            params_hash = %params_hash,
            budget_hash = %budget_hash,
            "gateway.call_operator"
        );

        if !is_allowlisted_operator(&op_name) {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "POLICY_DECISION",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "decision": "deny",
                        "reason": "operator_not_allowlisted",
                        "op_name": op_name.as_str(),
                        "request_id": request_id.as_str(),
                    }),
                )
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

            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "OPERATOR_CALL",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "op_name": op_name.as_str(),
                        "params_hash": params_hash.as_str(),
                        "params_bytes": params_bytes,
                        "outcome": "denied",
                        "request_id": request_id.as_str(),
                    }),
                )
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

            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "operator not allowlisted".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        let object_id = req.params.get("object_id").and_then(|v| v.as_str());
        let view_id = req
            .params
            .get("view_id")
            .and_then(|v| v.as_str())
            .map(|v| v.trim())
            .filter(|v| !v.is_empty());

        let fields_hash = req
            .params
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let mut fields = arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
                    .map(|v| serde_json::Value::String(v.to_string()))
                    .collect::<Vec<_>>();
                fields.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
                canonical::hash_canonical_json(&serde_json::Value::Array(fields))
            });

        let filter_fingerprint = req
            .params
            .get("filter_spec")
            .map(canonical::hash_canonical_json);

        let opa_input = serde_json::json!({
            "action": "operator_call",
            "principal_id": principal_id.as_str(),
            "trace_id": session.trace_id.as_str(),
            "session_id": session.session_id.as_str(),
            "policy_snapshot_id": session.policy_snapshot_id.as_str(),
            "policy_snapshot_hash": session.policy_snapshot_hash.as_str(),
            "policy_bundle_hash": state.config.policy_bundle_hash.as_str(),
            "as_of_time": session.as_of_time.as_str(),
            "op_name": op_name.as_str(),
            "params_hash": params_hash.as_str(),
            "params_bytes": params_bytes,
            "object_id": object_id,
            "view_id": view_id,
            "fields_hash": fields_hash,
            "filter_fingerprint": filter_fingerprint,
            "request_id": request_id.as_str(),
        });

        let cache_key = OpaCacheKey::operator_call(
            &session.policy_snapshot_hash,
            op_name.as_str(),
            &params_hash,
        );
        let policy_span = tracing::info_span!(
            "policy.evaluate",
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %session.policy_snapshot_id,
            policy_snapshot_hash = %session.policy_snapshot_hash,
            operator_name = %op_name,
            action = "operator_call",
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        let decision = match async {
            let started = Instant::now();
            let res = state.opa.decide(opa_input, Some(cache_key)).await;
            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);

            match &res {
                Ok(decision) => {
                    let outcome = if decision.allow { "allow" } else { "deny" };
                    tracing::Span::current().record("outcome", outcome);
                }
                Err(_) => {
                    tracing::Span::current().record("outcome", "error");
                }
            }

            res
        }
        .instrument(policy_span)
        .await
        {
            Ok(decision) => decision,
            Err(err) => {
                state
                    .ledger
                    .append_event(
                        &session.trace_id,
                        &session.session_id,
                        "POLICY_DECISION",
                        &principal_id,
                        &session.policy_snapshot_id,
                        serde_json::json!({
                            "decision": "deny",
                            "reason": "policy_engine_error",
                            "op_name": op_name.as_str(),
                            "request_id": request_id.as_str(),
                        }),
                    )
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

                return Err(opa_error_response(&err));
            }
        };

        let reason = decision.reason.as_deref().unwrap_or(if decision.allow {
            "policy_allow"
        } else {
            "policy_deny"
        });

        state
            .ledger
            .append_event(
                &session.trace_id,
                &session.session_id,
                "POLICY_DECISION",
                &principal_id,
                &session.policy_snapshot_id,
                serde_json::json!({
                    "decision": if decision.allow { "allow" } else { "deny" },
                    "reason": reason,
                    "op_name": op_name.as_str(),
                    "request_id": request_id.as_str(),
                }),
            )
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

        if !decision.allow {
            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "OPERATOR_CALL",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "op_name": op_name.as_str(),
                        "params_hash": params_hash.as_str(),
                        "params_bytes": params_bytes,
                        "outcome": "denied",
                        "request_id": request_id.as_str(),
                    }),
                )
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

            return Err(json_error(
                StatusCode::FORBIDDEN,
                "ERR_POLICY_DENIED",
                "policy denied".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let field_redaction = parse_field_redaction(decision.redaction.as_ref())?;

        let operator_span = match op_name.as_str() {
            "search" => tracing::info_span!(
                "operator.search",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "search",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "fetch_span" => tracing::info_span!(
                "operator.fetch_span",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "fetch_span",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "fetch_rows" => tracing::info_span!(
                "operator.fetch_rows",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "fetch_rows",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "aggregate" => tracing::info_span!(
                "operator.aggregate",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "aggregate",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "list_versions" => tracing::info_span!(
                "operator.list_versions",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "list_versions",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "diff" => tracing::info_span!(
                "operator.diff",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "diff",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            _ => tracing::info_span!(
                "operator.unknown",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = %op_name,
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
        };

        async {
        let started = Instant::now();

        let mut cache_hit = false;
        let operator_cache_key = OperatorCacheKey::operator_call(
            principal_id.as_str(),
            session.policy_snapshot_hash.as_str(),
            session.as_of_time.as_str(),
            op_name.as_str(),
            params_hash.as_str(),
        );

        let (status, error_code, response, evidence_emitted) = match op_name.as_str() {
            "search" => {
                let adapter_span = tracing::info_span!(
                    "adapter.fs_corpus",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "fs_corpus",
                    operator_name = "search",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );

                let (terminal_mode, result, hit) = async {
                    let started = Instant::now();
                    if let Some((terminal_mode, result)) =
                        state.operator_cache.get(&operator_cache_key).await
                    {
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "cache_hit");
                        return Ok::<_, ApiError>((terminal_mode, result, true));
                    }

                    let fs_corpus_path = state.config.fs_corpus_path.clone();
                    let as_of_time = session.as_of_time.clone();
                    let policy_snapshot_hash = session.policy_snapshot_hash.clone();
                    let params = req.params.clone();
                    let refs = tokio::task::spawn_blocking(move || {
                        search_from_fs(
                            fs_corpus_path.as_str(),
                            as_of_time.as_str(),
                            policy_snapshot_hash.as_str(),
                            &params,
                        )
                    })
                    .await
                    .map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_INTERNAL",
                            "search execution task failed".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })??;
                    let result = serde_json::json!({ "refs": refs });
                    state
                        .operator_cache
                        .put(
                            operator_cache_key.clone(),
                            TerminalMode::Supported,
                            result.clone(),
                        )
                        .await;

                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");

                    Ok::<_, ApiError>((TerminalMode::Supported, result, false))
                }
                .instrument(adapter_span)
                .await?;

                if hit {
                    cache_hit = true;
                    crate::metrics::inc_operator_cache_hit("search");
                }

                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode,
                        result,
                    },
                    Vec::new(),
                )
            }
            "list_versions" => {
                let adapter_span = tracing::info_span!(
                    "adapter.fs_corpus",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "fs_corpus",
                    operator_name = "list_versions",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );
                let versions = async {
                    let started = Instant::now();
                    let versions = list_versions_from_fs(
                        &state.fs_versions,
                        &state.config.fs_corpus_path,
                        session.as_of_time.as_str(),
                        &req.params,
                    )
                    .await?;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");
                    Ok::<_, ApiError>(versions)
                }
                .instrument(adapter_span)
                .await?;

                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result: serde_json::json!({ "versions": versions }),
                    },
                    Vec::new(),
                )
            }
            "diff" => {
                let adapter_span = tracing::info_span!(
                    "adapter.fs_corpus",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "fs_corpus",
                    operator_name = "diff",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );
                let evidence = async {
                    let started = Instant::now();
                    let evidence = diff_from_fs(
                        &state.fs_versions,
                        &state.config.fs_corpus_path,
                        session.as_of_time.as_str(),
                        state.config.fs_diff_max_bytes,
                        &session.policy_snapshot_id,
                        &session.policy_snapshot_hash,
                        &req.params,
                    )
                    .await?;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");
                    Ok::<_, ApiError>(evidence)
                }
                .instrument(adapter_span)
                .await?;

                let result =
                    serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result,
                    },
                    evidence,
                )
            }
            "fetch_span" => {
                let adapter_span = tracing::info_span!(
                    "adapter.fs_corpus",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "fs_corpus",
                    operator_name = "fetch_span",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );

                let evidence = async {
                    let started = Instant::now();
                    let evidence = fetch_span_from_fs(
                        &state.fs_versions,
                        &state.config.fs_corpus_path,
                        session.as_of_time.as_str(),
                        &session.policy_snapshot_id,
                        &session.policy_snapshot_hash,
                        &req.params,
                    )
                    .await?;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");
                    Ok::<_, ApiError>(evidence)
                }
                .instrument(adapter_span)
                .await?;

                let result =
                    serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result,
                    },
                    vec![evidence],
                )
            }
            "fetch_rows" => {
                let tenant_id = session.tenant_id.clone();
                let policy_snapshot_id = session.policy_snapshot_id.clone();
                let policy_snapshot_hash = session.policy_snapshot_hash.clone();
                let as_of_time = session.as_of_time.clone();

                let adapter_span = tracing::info_span!(
                    "adapter.pg_safeview",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "pg_safeview",
                    operator_name = "fetch_rows",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );

                let evidence = async {
                    let started = Instant::now();
                    let ctx = PgSafeviewContext {
                        pool: &state.pg_pool,
                        config: &state.config,
                        versions: &state.pg_versions,
                        tenant_id: tenant_id.as_str(),
                        policy_snapshot_id: policy_snapshot_id.as_str(),
                        policy_snapshot_hash: policy_snapshot_hash.as_str(),
                        as_of_time: as_of_time.as_str(),
                    };
                    let evidence = fetch_rows_from_pg_safeview(ctx, &req.params).await?;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");
                    Ok::<_, ApiError>(evidence)
                }
                .instrument(adapter_span)
                .await?;

                let evidence = if let Some(redaction) = field_redaction.as_ref() {
                    evidence
                        .into_iter()
                        .map(|unit| apply_field_redaction_to_evidence_unit(unit, redaction))
                        .collect::<Result<Vec<_>, ApiError>>()?
                } else {
                    evidence
                };

                let result =
                    serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result,
                    },
                    evidence,
                )
            }
            "aggregate" => {
                let tenant_id = session.tenant_id.clone();
                let policy_snapshot_id = session.policy_snapshot_id.clone();
                let policy_snapshot_hash = session.policy_snapshot_hash.clone();
                let as_of_time = session.as_of_time.clone();

                let adapter_span = tracing::info_span!(
                    "adapter.pg_safeview",
                    trace_id = %session.trace_id,
                    request_id = %request_id,
                    session_id = %session.session_id,
                    source_system = "pg_safeview",
                    operator_name = "aggregate",
                    latency_ms = tracing::field::Empty,
                    outcome = tracing::field::Empty,
                );

                let evidence = async {
                    let started = Instant::now();
                    let evidence = aggregate_from_pg_safeview(
                        &state.pg_pool,
                        &state.config,
                        &tenant_id,
                        &policy_snapshot_id,
                        &policy_snapshot_hash,
                        as_of_time.as_str(),
                        &req.params,
                    )
                    .await?;
                    let latency_ms = started.elapsed().as_millis() as u64;
                    tracing::Span::current().record("latency_ms", latency_ms);
                    tracing::Span::current().record("outcome", "ok");
                    Ok::<_, ApiError>(evidence)
                }
                .instrument(adapter_span)
                .await?;

                let evidence = if let Some(redaction) = field_redaction.as_ref() {
                    apply_field_redaction_to_evidence_unit(evidence, redaction)?
                } else {
                    evidence
                };

                let result =
                    serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result,
                    },
                    vec![evidence],
                )
            }
            "redact" => {
                let evidence_units = req
                    .params
                    .get("evidence_units")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| {
                        json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "params.evidence_units must be an array".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        )
                    })?;

                if evidence_units.len() > 200 {
                    return Err(json_error(
                        StatusCode::BAD_REQUEST,
                        "ERR_INVALID_PARAMS",
                        "evidence_units too large".to_string(),
                        TerminalMode::InsufficientEvidence,
                        false,
                    ));
                }

                let mut out_units = Vec::with_capacity(evidence_units.len());
                let mut evidence_emitted = Vec::new();

                for raw in evidence_units {
                    let unit: EvidenceUnit = serde_json::from_value(raw.clone()).map_err(|_| {
                        json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "invalid EvidenceUnit".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        )
                    })?;

                    if !canonical::is_sha256_hex(&unit.evidence_unit_id) {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "EvidenceUnit.evidence_unit_id must be sha256 hex".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    if !session.evidence_unit_ids.contains(&unit.evidence_unit_id) {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "evidence_unit_id not emitted in this session".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    if unit.policy_snapshot_hash != session.policy_snapshot_hash
                        || unit.as_of_time != session.as_of_time
                    {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "evidence_unit must match current session policy_snapshot_hash and as_of_time".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    let content = unit.content.as_ref().ok_or_else(|| {
                        json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "EvidenceUnit.content is required".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        )
                    })?;
                    let expected_content_hash = compute_content_hash(unit.content_type, content)?;
                    if unit.content_hash != expected_content_hash {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "EvidenceUnit.content_hash mismatch".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    let expected_id = compute_evidence_unit_id(&unit);
                    if unit.evidence_unit_id != expected_id {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "EvidenceUnit.evidence_unit_id mismatch".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    let Some(redaction) = field_redaction.as_ref() else {
                        out_units.push(unit);
                        continue;
                    };

                    if unit.content_type != EvidenceContentType::ApplicationJson {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "redact supports application/json evidence only".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    let redacted_content = apply_field_redaction(content, redaction);
                    if redacted_content == *content {
                        out_units.push(unit);
                        continue;
                    }

                    let mut redacted = unit.clone();
                    redacted.content = Some(redacted_content);
                    redacted.content_hash = compute_content_hash(
                        EvidenceContentType::ApplicationJson,
                        redacted.content.as_ref().unwrap(),
                    )?;
                    redacted.span_or_row_spec =
                        redact_span_or_row_spec_fields(&redacted.span_or_row_spec, redaction);
                    redacted.policy_snapshot_id = session.policy_snapshot_id.clone();
                    redacted.policy_snapshot_hash = session.policy_snapshot_hash.clone();

                    let step_params = redaction.params_value();
                    let step_hash = canonical::hash_canonical_json(&step_params);
                    redacted.transform_chain.push(TransformStep {
                        transform_type: "redaction".to_string(),
                        transform_hash: step_hash,
                        params: Some(step_params),
                    });
                    redacted.evidence_unit_id = compute_evidence_unit_id(&redacted);

                    evidence_emitted.push(redacted.clone());
                    out_units.push(redacted);
                }

                let result =
                    serde_json::to_value(&out_units).unwrap_or_else(|_| serde_json::json!([]));
                (
                    StatusCode::OK,
                    None,
                    OperatorCallResponse {
                        terminal_mode: TerminalMode::Supported,
                        result,
                    },
                    evidence_emitted,
                )
            }
            _ => (
                StatusCode::NOT_IMPLEMENTED,
                Some("ERR_INTERNAL"),
                OperatorCallResponse {
                    terminal_mode: TerminalMode::SourceUnavailable,
                    result: serde_json::json!({"message":"operator execution not implemented yet"}),
                },
                Vec::new(),
            ),
        };

        let result_bytes = serde_json::to_vec(&response.result)
            .map(|v| v.len() as u64)
            .unwrap_or(0);

        let ledger_span = tracing::info_span!(
            "ledger.append",
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            event_type = "OPERATOR_CALL",
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        async {
            let started = Instant::now();
            let store_payload = matches!(
                state.config.evidence_payload_store_mode,
                crate::config::EvidencePayloadStoreMode::PayloadEnabled
            );
            for evidence in &evidence_emitted {
                state
                    .ledger
                    .insert_evidence_unit(
                        &session.trace_id,
                        &session.session_id,
                        evidence,
                        store_payload,
                    )
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

                state
                    .ledger
                    .append_event(
                        &session.trace_id,
                        &session.session_id,
                        "EVIDENCE_EMITTED",
                        &principal_id,
                        &session.policy_snapshot_id,
                        serde_json::json!({
                            "evidence_unit_id": evidence.evidence_unit_id.as_str(),
                            "content_hash": evidence.content_hash.as_str(),
                            "source_system": evidence.source_system.as_str(),
                            "object_id": evidence.object_id.as_str(),
                            "version_id": evidence.version_id.as_str(),
                            "op_name": op_name.as_str(),
                            "request_id": request_id,
                        }),
                    )
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
            }

            for evidence in &evidence_emitted {
                session
                    .evidence_unit_ids
                    .insert(evidence.evidence_unit_id.clone());
            }

            let next_operator_calls_used = session.operator_calls_used.saturating_add(1);
            let next_bytes_used = session
                .bytes_used
                .saturating_add(params_bytes + result_bytes);

            state
                .ledger
                .append_event(
                    &session.trace_id,
                    &session.session_id,
                    "OPERATOR_CALL",
                    &principal_id,
                    &session.policy_snapshot_id,
                    serde_json::json!({
                        "op_name": op_name.as_str(),
                        "params_hash": params_hash,
                        "cache_hit": cache_hit,
                        "params_bytes": params_bytes,
                        "result_bytes": result_bytes,
                        "terminal_mode": response.terminal_mode.as_str(),
                        "outcome": if error_code.is_none() { "success" } else { "error" },
                        "error_code": error_code,
                        "operator_calls_used": next_operator_calls_used,
                        "bytes_used": next_bytes_used,
                        "request_id": request_id,
                    }),
                )
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

            session.operator_calls_used = next_operator_calls_used;
            session.bytes_used = next_bytes_used;
            persist_session_runtime(&state, &session)
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

            tracing::Span::current().record("latency_ms", started.elapsed().as_millis() as u64);
            tracing::Span::current().record("outcome", "ok");

            Ok::<_, ApiError>(())
        }
        .instrument(ledger_span)
        .await?;

        let latency_ms = started.elapsed().as_millis() as u64;
        let terminal_mode = response.terminal_mode.as_str();
        let operator_calls_used = session.operator_calls_used;
        let bytes_used = session.bytes_used;
        let outcome = if status == StatusCode::OK {
            "ok"
        } else {
            "error"
        };

        tracing::Span::current().record("latency_ms", latency_ms);
        tracing::Span::current().record("result_bytes", result_bytes);
        tracing::Span::current().record("terminal_mode", terminal_mode);
        tracing::Span::current().record("operator_calls_used", operator_calls_used);
        tracing::Span::current().record("bytes_used", bytes_used);
        tracing::Span::current().record("outcome", outcome);

        if status == StatusCode::OK {
            Ok(Json(response))
        } else {
            Err(json_error(
                status,
                error_code.unwrap_or("ERR_INTERNAL"),
                "operator execution not implemented yet".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            ))
        }
    }
    .instrument(operator_span)
    .await
    })
    .await;

    let status = match &handler_result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/operators",
        "POST",
        status.as_u16(),
        request_started.elapsed(),
    );

    let outcome = if handler_result.is_ok() {
        "success"
    } else {
        "error"
    };
    crate::metrics::observe_operator_call(op_name_for_metrics.as_str(), outcome);
    match &handler_result {
        Ok(Json(body)) => {
            crate::metrics::observe_terminal_mode("/v1/operators", body.terminal_mode.as_str());
        }
        Err((_, Json(err))) => {
            crate::metrics::observe_terminal_mode("/v1/operators", err.terminal_mode_hint.as_str())
        }
    }

    handler_result
}

#[derive(Debug, Serialize)]
struct VersionInfo {
    version_id: String,
    as_of_time: String,
    metadata_hash: String,
}

#[derive(Debug)]
struct FsVersionCache {
    max_total_bytes: usize,
    max_versions_per_object: usize,
    total_bytes: usize,
    fifo: VecDeque<(String, String, usize)>,
    entries: HashMap<String, HashMap<String, Vec<u8>>>,
    observed_versions: HashMap<String, BTreeMap<String, String>>,
}

impl FsVersionCache {
    fn new(max_total_bytes: usize, max_versions_per_object: usize) -> Self {
        Self {
            max_total_bytes,
            max_versions_per_object: max_versions_per_object.max(1),
            total_bytes: 0,
            fifo: VecDeque::new(),
            entries: HashMap::new(),
            observed_versions: HashMap::new(),
        }
    }

    fn observe_version(&mut self, object_id: &str, as_of_time: &str, version_id: &str) {
        self.observed_versions
            .entry(object_id.to_string())
            .or_default()
            .insert(as_of_time.to_string(), version_id.to_string());
    }

    fn select_version_at(&self, object_id: &str, as_of_time: &str) -> Option<String> {
        let observed = self.observed_versions.get(object_id)?;
        let object_entry = self.entries.get(object_id)?;

        if let Some((latest_as_of_time, _)) = observed.last_key_value()
            && as_of_time > latest_as_of_time.as_str()
        {
            return None;
        }

        observed
            .range(..=as_of_time.to_string())
            .rev()
            .find_map(|(_, version_id)| {
                object_entry
                    .contains_key(version_id)
                    .then(|| version_id.clone())
            })
    }

    fn insert(&mut self, object_id: &str, version_id: &str, bytes: Vec<u8>) {
        if self.max_total_bytes == 0 {
            return;
        }

        let size = bytes.len();
        if size == 0 || size > self.max_total_bytes {
            return;
        }

        let object_entry = self.entries.entry(object_id.to_string()).or_default();

        if object_entry.contains_key(version_id) {
            return;
        }

        object_entry.insert(version_id.to_string(), bytes);
        self.total_bytes = self.total_bytes.saturating_add(size);
        self.fifo
            .push_back((object_id.to_string(), version_id.to_string(), size));

        self.enforce_object_limit(object_id, version_id);
        while self.total_bytes > self.max_total_bytes {
            self.evict_one();
        }
    }

    fn get(&self, object_id: &str, version_id: &str) -> Option<&[u8]> {
        self.entries
            .get(object_id)
            .and_then(|m| m.get(version_id))
            .map(|v| v.as_slice())
    }

    fn list_version_ids(&self, object_id: &str) -> Vec<String> {
        self.entries
            .get(object_id)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn enforce_object_limit(&mut self, object_id: &str, keep_version_id: &str) {
        while self.entries.get(object_id).map(|m| m.len()).unwrap_or(0)
            > self.max_versions_per_object
        {
            let Some(object_entry) = self.entries.get(object_id) else {
                return;
            };

            let mut candidates = object_entry.keys().cloned().collect::<Vec<_>>();
            candidates.sort();

            let version_to_evict = candidates
                .into_iter()
                .find(|v| v != keep_version_id)
                .unwrap_or_else(|| keep_version_id.to_string());

            self.remove_entry(object_id, &version_to_evict);
        }
    }

    fn remove_entry(&mut self, object_id: &str, version_id: &str) {
        let Some(object_entry) = self.entries.get_mut(object_id) else {
            return;
        };

        let Some(bytes) = object_entry.remove(version_id) else {
            return;
        };

        self.total_bytes = self.total_bytes.saturating_sub(bytes.len());
        if object_entry.is_empty() {
            self.entries.remove(object_id);
        }

        let mut idx = 0;
        while idx < self.fifo.len() {
            if let Some((obj, ver, _)) = self.fifo.get(idx)
                && obj == object_id
                && ver == version_id
            {
                let _ = self.fifo.remove(idx);
                break;
            }
            idx += 1;
        }
    }

    fn evict_one(&mut self) {
        while let Some((object_id, version_id, size)) = self.fifo.pop_front() {
            let Some(object_entry) = self.entries.get_mut(&object_id) else {
                continue;
            };

            if object_entry.remove(&version_id).is_none() {
                continue;
            }

            self.total_bytes = self.total_bytes.saturating_sub(size);
            if object_entry.is_empty() {
                self.entries.remove(&object_id);
            }
            return;
        }
    }
}

async fn read_object_bytes_from_fs(
    fs_corpus_path: &str,
    object_id: &str,
) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    let object_rel = std::path::Path::new(object_id);
    if object_rel.is_absolute() || !is_safe_rel_path(object_rel) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "object_id must be a relative path without parent components".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let base = std::path::Path::new(fs_corpus_path);
    let base_canon = tokio::fs::canonicalize(base).await.map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let full_path = base.join(object_rel);
    let full_canon = tokio::fs::canonicalize(full_path).await.map_err(|_| {
        json_error(
            StatusCode::NOT_FOUND,
            "ERR_SOURCE_UNAVAILABLE",
            "object not found".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    if !full_canon.starts_with(&base_canon) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "object_id escapes corpus root".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    tokio::fs::read(&full_canon).await.map_err(|_| {
        json_error(
            StatusCode::NOT_FOUND,
            "ERR_SOURCE_UNAVAILABLE",
            "object not found".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })
}

async fn list_versions_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time_default: &str,
    params: &serde_json::Value,
) -> Result<Vec<VersionInfo>, ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;

    let version_id = sha256_hex(&bytes);
    let metadata_hash = sha256_hex(object_id.as_bytes());

    let mut cache = fs_versions.write().await;
    cache.insert(object_id, &version_id, bytes);
    cache.observe_version(object_id, as_of_time_default, &version_id);
    let mut version_ids = cache.list_version_ids(object_id);
    if !version_ids.contains(&version_id) {
        version_ids.push(version_id.clone());
    }
    version_ids.sort();

    Ok(version_ids
        .into_iter()
        .map(|version_id| VersionInfo {
            version_id,
            as_of_time: as_of_time_default.to_string(),
            metadata_hash: metadata_hash.clone(),
        })
        .collect())
}

async fn diff_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time_default: &str,
    max_diff_bytes: usize,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<Vec<pecr_contracts::EvidenceUnit>, ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let v1 = params
        .get("v1")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.v1 is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let v2 = params
        .get("v2")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.v2 is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    if !canonical::is_sha256_hex(v1) || !canonical::is_sha256_hex(v2) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "v1 and v2 must be sha256 hex version ids".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    async fn version_bytes(
        fs_versions: &Arc<RwLock<FsVersionCache>>,
        fs_corpus_path: &str,
        object_id: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ApiError> {
        if let Some(bytes) = fs_versions
            .read()
            .await
            .get(object_id, version_id)
            .map(|v| v.to_vec())
        {
            return Ok(bytes);
        }

        let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
        let current_version = sha256_hex(&bytes);
        if current_version != version_id {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "ERR_SOURCE_UNAVAILABLE",
                "requested version not found".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            ));
        }

        let mut cache = fs_versions.write().await;
        cache.insert(object_id, &current_version, bytes.clone());
        Ok(bytes)
    }

    let bytes_v1 = version_bytes(fs_versions, fs_corpus_path, object_id, v1).await?;
    let bytes_v2 = version_bytes(fs_versions, fs_corpus_path, object_id, v2).await?;

    let text_v1 = std::str::from_utf8(&bytes_v1).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "version v1 is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let text_v2 = std::str::from_utf8(&bytes_v2).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "version v2 is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let text_v1 = canonical::canonicalize_text_plain(text_v1);
    let text_v2 = canonical::canonicalize_text_plain(text_v2);

    let header_before = format!("a/{}@{}", object_id, v1);
    let header_after = format!("b/{}@{}", object_id, v2);
    let patch = TextDiff::from_lines(&text_v1, &text_v2)
        .unified_diff()
        .context_radius(3)
        .header(&header_before, &header_after)
        .to_string();

    let patch = canonical::canonicalize_text_plain(&patch);
    let patch_len = patch.len();

    if max_diff_bytes != 0 && patch_len > max_diff_bytes {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "diff exceeds size cap".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let content_hash = canonical::sha256_hex(patch.as_bytes());

    let newline_count = patch.as_bytes().iter().filter(|b| **b == b'\n').count() as u64;
    let span_or_row_spec = serde_json::json!({
        "type": "text_span",
        "start_byte": 0,
        "end_byte": patch_len as u64,
        "line_start": 1,
        "line_end": 1 + newline_count,
    });

    let diff_params = serde_json::json!({
        "object_id": object_id,
        "v1": v1,
        "v2": v2,
    });
    let transform_chain = vec![pecr_contracts::TransformStep {
        transform_type: "diff_unified_v1".to_string(),
        transform_hash: canonical::hash_canonical_json(&diff_params),
        params: Some(diff_params),
    }];

    let identity = serde_json::json!({
        "source_system": "fs_corpus",
        "object_id": object_id,
        "version_id": v2,
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time_default,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(vec![pecr_contracts::EvidenceUnit {
        source_system: "fs_corpus".to_string(),
        object_id: object_id.to_string(),
        version_id: v2.to_string(),
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::TextPlain,
        content: Some(serde_json::Value::String(patch)),
        content_hash,
        retrieved_at: as_of_time_default.to_string(),
        as_of_time: as_of_time_default.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain,
        evidence_unit_id,
    }])
}

async fn fetch_span_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, (StatusCode, Json<ErrorResponse>)> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let selected_version_id = fs_versions
        .read()
        .await
        .select_version_at(object_id, as_of_time);

    let (bytes, version_id) = if let Some(version_id) = selected_version_id {
        if let Some(bytes) = fs_versions.read().await.get(object_id, &version_id) {
            (bytes.to_vec(), version_id)
        } else {
            let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
            let version_id = sha256_hex(&bytes);

            let mut cache = fs_versions.write().await;
            cache.insert(object_id, &version_id, bytes.clone());
            cache.observe_version(object_id, as_of_time, &version_id);

            (bytes, version_id)
        }
    } else {
        let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
        let version_id = sha256_hex(&bytes);

        let mut cache = fs_versions.write().await;
        cache.insert(object_id, &version_id, bytes.clone());
        cache.observe_version(object_id, as_of_time, &version_id);

        (bytes, version_id)
    };

    let start_byte = params
        .get("start_byte")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let end_byte = params
        .get("end_byte")
        .and_then(|v| v.as_u64())
        .unwrap_or(bytes.len() as u64);

    if end_byte > bytes.len() as u64 || start_byte > end_byte {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "invalid span range".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let start = start_byte as usize;
    let end = end_byte as usize;

    let span_bytes = &bytes[start..end];
    let content = std::str::from_utf8(span_bytes).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "span is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let line_start = 1 + bytes[..start].iter().filter(|b| **b == b'\n').count() as u64;
    let line_end = line_start + span_bytes.iter().filter(|b| **b == b'\n').count() as u64;

    let span_or_row_spec = serde_json::json!({
        "type": "text_span",
        "start_byte": start_byte,
        "end_byte": end_byte,
        "line_start": line_start,
        "line_end": line_end,
    });

    let canonical_content = canonical::canonicalize_text_plain(content);
    let content_hash = canonical::sha256_hex(canonical_content.as_bytes());

    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "fs_corpus",
        "object_id": object_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(pecr_contracts::EvidenceUnit {
        source_system: "fs_corpus".to_string(),
        object_id: object_id.to_string(),
        version_id,
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::TextPlain,
        content: Some(serde_json::Value::String(content.to_string())),
        content_hash,
        retrieved_at: as_of_time.to_string(),
        as_of_time: as_of_time.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

fn search_from_fs(
    fs_corpus_path: &str,
    as_of_time_default: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<Vec<EvidenceUnitRef>, (StatusCode, Json<ErrorResponse>)> {
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.query is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(50) as usize;

    let base = std::path::Path::new(fs_corpus_path);
    let base_canon = base.canonicalize().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    fn collect_files(
        dir: &std::path::Path,
        out: &mut Vec<std::path::PathBuf>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = entry.metadata()?;
            if meta.is_dir() {
                collect_files(&path, out)?;
            } else if meta.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect_files(&base_canon, &mut files).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "failed to enumerate filesystem corpus".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    let mut refs = Vec::new();

    for path in files {
        if limit != 0 && refs.len() >= limit {
            break;
        }

        let rel = match path.strip_prefix(&base_canon) {
            Ok(rel) => rel,
            Err(_) => continue,
        };

        let object_id = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");

        let bytes = std::fs::read(&path).map_err(|_| {
            json_error(
                StatusCode::NOT_FOUND,
                "ERR_SOURCE_UNAVAILABLE",
                "object not found".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => continue,
        };

        if !text.contains(query) {
            continue;
        }

        let version_id = sha256_hex(&bytes);
        let canonical_content = canonical::canonicalize_text_plain(text);
        let content_hash = canonical::sha256_hex(canonical_content.as_bytes());

        let newline_count = bytes.iter().filter(|b| **b == b'\n').count() as u64;
        let span_or_row_spec = serde_json::json!({
            "type": "text_span",
            "start_byte": 0,
            "end_byte": bytes.len() as u64,
            "line_start": 1,
            "line_end": 1 + newline_count,
        });

        let identity = serde_json::json!({
            "source_system": "fs_corpus",
            "object_id": object_id.clone(),
            "version_id": version_id.clone(),
            "span_or_row_spec": span_or_row_spec,
            "content_hash": content_hash,
            "as_of_time": as_of_time_default,
            "policy_snapshot_hash": policy_snapshot_hash,
            "transform_chain": [],
        });
        let evidence_unit_id = canonical::hash_canonical_json(&identity);

        refs.push(EvidenceUnitRef {
            evidence_unit_id,
            source_system: "fs_corpus".to_string(),
            object_id,
            version_id,
        });
    }

    Ok(refs)
}

fn is_safe_rel_path(path: &std::path::Path) -> bool {
    use std::path::Component;
    path.components().all(|c| match c {
        Component::Normal(_) => true,
        Component::CurDir => false,
        Component::ParentDir => false,
        Component::RootDir => false,
        Component::Prefix(_) => false,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().encode_hex::<String>()
}

#[derive(Debug, Clone, Copy)]
struct SafeViewSpec {
    view_id: &'static str,
    primary_key_fields: &'static [&'static str],
    version_field: &'static str,
    allowlisted_fields: &'static [&'static str],
    allowlisted_filter_fields: &'static [&'static str],
    allowlisted_group_by_fields: &'static [&'static str],
    allowlisted_metrics: &'static [SafeMetricAllowlist],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SafeMetricAllowlist {
    name: &'static str,
    field: &'static str,
}

fn safeview_spec(view_id: &str) -> Option<SafeViewSpec> {
    const PK: &[&str] = &["tenant_id", "customer_id"];
    const METRICS: &[SafeMetricAllowlist] = &[SafeMetricAllowlist {
        name: "count",
        field: "customer_id",
    }];

    match view_id {
        "safe_customer_view_public" => Some(SafeViewSpec {
            view_id: "safe_customer_view_public",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_public_slow" => Some(SafeViewSpec {
            view_id: "safe_customer_view_public_slow",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_admin" => Some(SafeViewSpec {
            view_id: "safe_customer_view_admin",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "admin_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_support" => Some(SafeViewSpec {
            view_id: "safe_customer_view_support",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "support_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_injection" => Some(SafeViewSpec {
            view_id: "safe_customer_view_injection",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "injection_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        _ => None,
    }
}

const ALLOWLISTED_SAFEVIEW_IDS: &[&str] = &[
    "safe_customer_view_public",
    "safe_customer_view_public_slow",
    "safe_customer_view_admin",
    "safe_customer_view_support",
    "safe_customer_view_injection",
];

async fn validate_safeview_schema(pool: &PgPool) -> Result<(), StartupError> {
    for view_id in ALLOWLISTED_SAFEVIEW_IDS {
        let spec = safeview_spec(view_id).ok_or_else(|| StartupError {
            code: "ERR_INTERNAL",
            message: format!("internal safe-view allowlist mismatch for `{}`", view_id),
        })?;

        let rows = sqlx::query(
            "SELECT column_name \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1",
        )
        .bind(spec.view_id)
        .fetch_all(pool)
        .await
        .map_err(|_| StartupError {
            code: "ERR_DB_UNAVAILABLE",
            message: format!(
                "failed to introspect safe-view schema for `{}`",
                spec.view_id
            ),
        })?;

        if rows.is_empty() {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "safe-view schema mismatch: required view `{}` does not exist in current schema",
                    spec.view_id
                ),
            });
        }

        let available_columns = rows
            .into_iter()
            .filter_map(|row| row.try_get::<String, _>("column_name").ok())
            .map(|c| c.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();

        let missing = missing_safeview_columns(spec, &available_columns);
        if !missing.is_empty() {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "safe-view schema mismatch for `{}`: missing columns [{}]",
                    spec.view_id,
                    missing.join(", ")
                ),
            });
        }
    }

    Ok(())
}

fn missing_safeview_columns(
    spec: SafeViewSpec,
    available_columns: &BTreeSet<String>,
) -> Vec<String> {
    let mut required_columns = BTreeSet::<&str>::new();
    required_columns.extend(spec.primary_key_fields.iter().copied());
    required_columns.extend(spec.allowlisted_fields.iter().copied());
    required_columns.extend(spec.allowlisted_filter_fields.iter().copied());
    required_columns.extend(spec.allowlisted_group_by_fields.iter().copied());
    required_columns.insert(spec.version_field);
    for metric in spec.allowlisted_metrics {
        required_columns.insert(metric.field);
    }

    required_columns
        .into_iter()
        .filter(|field| !available_columns.contains(*field))
        .map(str::to_string)
        .collect()
}

fn parse_safeview_string(
    value: Option<&serde_json::Value>,
    key: &'static str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    value
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("params.{} is required", key),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })
}

fn parse_safeview_fields(
    params: &serde_json::Value,
    spec: SafeViewSpec,
    max_fields: usize,
) -> Result<Vec<String>, (StatusCode, Json<ErrorResponse>)> {
    let mut fields = params
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.fields must be an array of strings".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?
        .iter()
        .filter_map(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect::<Vec<_>>();

    fields.sort();
    fields.dedup();

    if fields.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.fields must be a non-empty array".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    if fields.len() > max_fields {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.fields exceeds max field count".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    for field in &fields {
        if !spec.allowlisted_fields.contains(&field.as_str()) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
    }

    Ok(fields)
}

fn parse_safeview_filter_spec(
    params: &serde_json::Value,
    spec: SafeViewSpec,
) -> Result<Vec<FilterEq>, ApiError> {
    let Some(filter) = params.get("filter_spec") else {
        return Ok(Vec::new());
    };

    let Some(map) = filter.as_object() else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.filter_spec must be an object".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    };

    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let field = k.trim();
        if field.is_empty() {
            continue;
        }

        if !spec.allowlisted_filter_fields.contains(&field) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("filter field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        let value = v
            .as_str()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    format!("filter_spec.{} must be a non-empty string", field),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?;

        out.push((field.to_string(), value.to_string()));
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

struct PgSafeviewContext<'a> {
    pool: &'a PgPool,
    config: &'a GatewayConfig,
    versions: &'a Arc<RwLock<FsVersionCache>>,
    tenant_id: &'a str,
    policy_snapshot_id: &'a str,
    policy_snapshot_hash: &'a str,
    as_of_time: &'a str,
}

async fn fetch_rows_from_pg_safeview(
    ctx: PgSafeviewContext<'_>,
    params: &serde_json::Value,
) -> Result<Vec<pecr_contracts::EvidenceUnit>, (StatusCode, Json<ErrorResponse>)> {
    let PgSafeviewContext {
        pool,
        config,
        versions: pg_versions,
        tenant_id,
        policy_snapshot_id,
        policy_snapshot_hash,
        as_of_time,
    } = ctx;
    let view_id = parse_safeview_string(params.get("view_id"), "view_id")?;
    let spec = safeview_spec(&view_id).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "view_id not allowlisted".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let fields = parse_safeview_fields(params, spec, config.pg_safeview_max_fields)?;
    let filters = parse_safeview_filter_spec(params, spec)?;

    if let Some(customer_id) = filters
        .iter()
        .find(|(field, _)| field == "customer_id")
        .map(|(_, value)| value.as_str())
    {
        let cache_object_id = format!("{}:{}:{}", spec.view_id, tenant_id, customer_id);
        let cache = pg_versions.read().await;
        if let Some(version_id) = cache.select_version_at(cache_object_id.as_str(), as_of_time)
            && let Some(snapshot_bytes) = cache.get(cache_object_id.as_str(), version_id.as_str())
            && let Ok(snapshot_value) = serde_json::from_slice::<serde_json::Value>(snapshot_bytes)
            && let Some(snapshot_obj) = snapshot_value.as_object()
            && filters.iter().all(|(field, expected)| {
                snapshot_obj
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(|actual| actual == expected)
                    .unwrap_or(false)
            })
        {
            let mut primary_key = serde_json::Map::new();
            let mut pk_values = Vec::with_capacity(spec.primary_key_fields.len());
            for pk in spec.primary_key_fields {
                let value = snapshot_obj
                    .get(*pk)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_INTERNAL",
                            "safe view snapshot missing primary key field".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                pk_values.push(value.to_string());
                primary_key.insert(pk.to_string(), serde_json::Value::String(value.to_string()));
            }

            let mut content = serde_json::Map::new();
            for field in &fields {
                content.insert(
                    field.clone(),
                    snapshot_obj
                        .get(field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
            }
            let content = serde_json::Value::Object(content);
            let content_hash = canonical::hash_canonical_json(&content);

            let span_or_row_spec = serde_json::json!({
                "type": "db_row",
                "view_id": spec.view_id,
                "primary_key": primary_key,
                "fields": &fields,
            });

            let object_id = format!("{}:{}", spec.view_id, pk_values.join(":"));
            let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
            let identity = serde_json::json!({
                "source_system": "pg_safeview",
                "object_id": object_id.as_str(),
                "version_id": version_id.clone(),
                "span_or_row_spec": span_or_row_spec.clone(),
                "content_hash": content_hash.clone(),
                "as_of_time": as_of_time,
                "policy_snapshot_hash": policy_snapshot_hash,
                "transform_chain": transform_chain,
            });
            let evidence_unit_id = canonical::hash_canonical_json(&identity);

            return Ok(vec![pecr_contracts::EvidenceUnit {
                source_system: "pg_safeview".to_string(),
                object_id,
                version_id,
                span_or_row_spec,
                content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
                content: Some(content),
                content_hash,
                retrieved_at: as_of_time.to_string(),
                as_of_time: as_of_time.to_string(),
                policy_snapshot_id: policy_snapshot_id.to_string(),
                policy_snapshot_hash: policy_snapshot_hash.to_string(),
                transform_chain: Vec::new(),
                evidence_unit_id,
            }]);
        }
    }

    let select_fields = spec
        .allowlisted_fields
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let select_sql = select_fields
        .iter()
        .map(|f| {
            if f == spec.version_field {
                format!(
                    "to_char({} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as {}",
                    f, f
                )
            } else {
                format!("{}::text as {}", f, f)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    let mut sql = format!("SELECT {} FROM {}", select_sql, spec.view_id);
    if !filters.is_empty() {
        sql.push_str(" WHERE ");
        for (idx, (field, _)) in filters.iter().enumerate() {
            if idx != 0 {
                sql.push_str(" AND ");
            }
            sql.push_str(field);
            sql.push_str(" = $");
            sql.push_str(&(idx + 1).to_string());
        }
    }

    sql.push_str(" ORDER BY ");
    sql.push_str(&spec.primary_key_fields.join(", "));
    sql.push_str(" LIMIT ");
    sql.push_str(&config.pg_safeview_max_rows.to_string());

    let timeout_str = format!("{}ms", config.pg_safeview_query_timeout_ms);
    let mut tx = pool.begin().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    sqlx::query("SELECT set_config('pecr.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let mut query = sqlx::query(&sql);
    for (_, value) in &filters {
        query = query.bind(value.as_str());
    }

    let rows = query.fetch_all(&mut *tx).await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database query failed".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    tx.commit().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    let schema_error = || {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "safe view schema mismatch".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    };

    let mut out = Vec::with_capacity(rows.len());
    let mut cache = pg_versions.write().await;
    for row in rows {
        let mut snapshot = serde_json::Map::new();
        for field in spec.allowlisted_fields {
            let value: Option<String> = row.try_get(field).map_err(|_| schema_error())?;
            snapshot.insert(
                field.to_string(),
                value
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }

        let mut primary_key = serde_json::Map::new();
        let mut pk_values = Vec::with_capacity(spec.primary_key_fields.len());
        for pk in spec.primary_key_fields {
            let value = snapshot
                .get(*pk)
                .and_then(|v| v.as_str())
                .ok_or_else(&schema_error)?;
            pk_values.push(value.to_string());
            primary_key.insert(pk.to_string(), serde_json::Value::String(value.to_string()));
        }

        let updated_at = snapshot
            .get(spec.version_field)
            .and_then(|v| v.as_str())
            .ok_or_else(&schema_error)?;
        let version_id = sha256_hex(updated_at.as_bytes());

        let mut content = serde_json::Map::new();
        for field in &fields {
            content.insert(
                field.clone(),
                snapshot
                    .get(field)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        let content = serde_json::Value::Object(content);
        let content_hash = canonical::hash_canonical_json(&content);

        let span_or_row_spec = serde_json::json!({
            "type": "db_row",
            "view_id": spec.view_id,
            "primary_key": primary_key,
            "fields": &fields,
        });

        let object_id = format!("{}:{}", spec.view_id, pk_values.join(":"));
        let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
        let identity = serde_json::json!({
            "source_system": "pg_safeview",
            "object_id": object_id.as_str(),
            "version_id": version_id.clone(),
            "span_or_row_spec": span_or_row_spec.clone(),
            "content_hash": content_hash.clone(),
            "as_of_time": as_of_time,
            "policy_snapshot_hash": policy_snapshot_hash,
            "transform_chain": transform_chain,
        });
        let evidence_unit_id = canonical::hash_canonical_json(&identity);

        let snapshot_bytes =
            serde_json::to_vec(&serde_json::Value::Object(snapshot)).unwrap_or_else(|_| Vec::new());
        cache.insert(object_id.as_str(), version_id.as_str(), snapshot_bytes);
        cache.observe_version(object_id.as_str(), as_of_time, version_id.as_str());

        out.push(pecr_contracts::EvidenceUnit {
            source_system: "pg_safeview".to_string(),
            object_id,
            version_id,
            span_or_row_spec,
            content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
            content: Some(content),
            content_hash,
            retrieved_at: as_of_time.to_string(),
            as_of_time: as_of_time.to_string(),
            policy_snapshot_id: policy_snapshot_id.to_string(),
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id,
        });
    }
    drop(cache);

    Ok(out)
}

async fn aggregate_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    as_of_time: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, (StatusCode, Json<ErrorResponse>)> {
    let view_id = parse_safeview_string(params.get("view_id"), "view_id")?;
    let spec = safeview_spec(&view_id).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "view_id not allowlisted".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let mut group_by = params
        .get("group_by")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    group_by.sort();
    group_by.dedup();

    for field in &group_by {
        if !spec.allowlisted_group_by_fields.contains(&field.as_str()) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("group_by field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetricParam {
        name: String,
        field: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct MetricSpec {
        name: String,
        field: String,
    }

    let metrics_raw = params
        .get("metrics")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.metrics must be an array".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?
        .to_vec();

    let mut metrics = Vec::with_capacity(metrics_raw.len());
    for raw in metrics_raw {
        let metric: MetricParam = serde_json::from_value(raw).map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "invalid metric object".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;
        let name = metric.name.trim();
        let field = metric.field.trim();
        if name.is_empty() || field.is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "metric name and field are required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if !spec
            .allowlisted_metrics
            .iter()
            .any(|m| m.name == name && m.field == field)
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("metric not allowlisted: {}({})", name, field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        metrics.push(MetricSpec {
            name: name.to_string(),
            field: field.to_string(),
        });
    }

    metrics.sort();
    metrics.dedup();

    if metrics.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.metrics must be a non-empty array".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let filters = parse_safeview_filter_spec(params, spec)?;
    let default_filter = serde_json::json!({});
    let filter_value = params.get("filter_spec").unwrap_or(&default_filter);
    let filter_fingerprint = canonical::hash_canonical_json(filter_value);

    let mut select_parts = Vec::new();
    for field in &group_by {
        select_parts.push(format!("{}::text as {}", field, field));
    }
    for metric in &metrics {
        if metric.name.as_str() == "count" {
            select_parts.push(format!(
                "COUNT({})::bigint as {}_{}",
                metric.field.as_str(),
                metric.name.as_str(),
                metric.field.as_str()
            ));
        }
    }

    let mut sql = format!("SELECT {} FROM {}", select_parts.join(", "), spec.view_id);
    if !filters.is_empty() {
        sql.push_str(" WHERE ");
        for (idx, (field, _)) in filters.iter().enumerate() {
            if idx != 0 {
                sql.push_str(" AND ");
            }
            sql.push_str(field);
            sql.push_str(" = $");
            sql.push_str(&(idx + 1).to_string());
        }
    }

    if !group_by.is_empty() {
        sql.push_str(" GROUP BY ");
        sql.push_str(&group_by.join(", "));
        sql.push_str(" ORDER BY ");
        sql.push_str(&group_by.join(", "));
        sql.push_str(" LIMIT ");
        sql.push_str(&config.pg_safeview_max_groups.to_string());
    } else {
        sql.push_str(" LIMIT 1");
    }

    let timeout_str = format!("{}ms", config.pg_safeview_query_timeout_ms);
    let mut tx = pool.begin().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    sqlx::query("SELECT set_config('pecr.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let mut query = sqlx::query(&sql);
    for (_, value) in &filters {
        query = query.bind(value.as_str());
    }

    let rows = query.fetch_all(&mut *tx).await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database query failed".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    tx.commit().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    let schema_error = || {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "safe view schema mismatch".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    };

    let mut result_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let mut group = serde_json::Map::new();
        for field in &group_by {
            let value: Option<String> = row.try_get(field.as_str()).map_err(|_| schema_error())?;
            group.insert(
                field.clone(),
                value
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }

        let mut metric_values = Vec::with_capacity(metrics.len());
        for metric in &metrics {
            let col = format!("{}_{}", metric.name.as_str(), metric.field.as_str());
            let value: i64 = row.try_get(col.as_str()).map_err(|_| schema_error())?;
            metric_values.push(serde_json::json!({
                "name": metric.name.as_str(),
                "field": metric.field.as_str(),
                "value": value,
            }));
        }

        result_rows.push(serde_json::json!({
            "group": group,
            "metrics": metric_values,
        }));
    }

    let content = serde_json::json!({
        "rows": result_rows,
    });
    let content_hash = canonical::hash_canonical_json(&content);

    let span_or_row_spec = serde_json::json!({
        "type": "db_aggregate",
        "view_id": spec.view_id,
        "filter_fingerprint": filter_fingerprint,
        "group_by": group_by,
        "metrics": metrics
            .iter()
            .map(|m| serde_json::json!({"name": m.name.as_str(), "field": m.field.as_str()}))
            .collect::<Vec<_>>(),
    });

    let version_id = content_hash.clone();
    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "pg_safeview",
        "object_id": spec.view_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(pecr_contracts::EvidenceUnit {
        source_system: "pg_safeview".to_string(),
        object_id: spec.view_id.to_string(),
        version_id,
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
        content: Some(content),
        content_hash,
        retrieved_at: as_of_time.to_string(),
        as_of_time: as_of_time.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

async fn finalize(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<FinalizeRequest>, JsonRejection>,
) -> Result<Json<FinalizeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_started = Instant::now();

    let handler_result = (async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id.clone();

        if !state.rate_limiter.allow(
            format!("finalize:{}", principal_id).as_str(),
            state.config.rate_limit_finalize_per_window,
        ) {
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_RATE_LIMITED",
                "rate limit exceeded for finalize calls".to_string(),
                TerminalMode::InsufficientPermission,
                true,
            ));
        }

        let request_id = extract_request_id(&headers);
        let session_token = extract_session_token(&headers)?;

        let Json(req) = req.map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "invalid JSON body".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;
        let _session_lock = acquire_session_lock(&state, &req.session_id).await?;

        let mut session = load_session_runtime(&state, &req.session_id)
            .await?
            .ok_or_else(|| {
                json_error(
                    StatusCode::NOT_FOUND,
                    "ERR_INVALID_PARAMS",
                    "unknown session_id".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?;

        if session.finalized {
            return Err(json_error(
                StatusCode::CONFLICT,
                "ERR_INVALID_PARAMS",
                "session already finalized".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if session.principal_id != principal_id {
            tracing::warn!(
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                "gateway.principal_mismatch"
            );
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "invalid session credentials".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let session_token_hash = sha256_hex(session_token.as_bytes());
        if unix_epoch_ms_now() > session.session_token_expires_at_epoch_ms
            || session.session_token_hash != session_token_hash
        {
            tracing::warn!(
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                "gateway.session_token_invalid"
            );
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "invalid session credentials".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let opa_input = serde_json::json!({
            "action": "finalize",
            "principal_id": principal_id.as_str(),
            "trace_id": session.trace_id.as_str(),
            "session_id": session.session_id.as_str(),
            "policy_snapshot_id": session.policy_snapshot_id.as_str(),
            "policy_snapshot_hash": session.policy_snapshot_hash.as_str(),
            "policy_bundle_hash": state.config.policy_bundle_hash.as_str(),
            "as_of_time": session.as_of_time.as_str(),
            "request_id": request_id.as_str(),
        });
        let cache_key = OpaCacheKey::finalize(&session.policy_snapshot_hash);
        let policy_span = tracing::info_span!(
            "policy.evaluate",
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %session.policy_snapshot_id,
            policy_snapshot_hash = %session.policy_snapshot_hash,
            operator_name = "finalize",
            action = "finalize",
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        let decision = match async {
            let started = Instant::now();
            let res = state.opa.decide(opa_input, Some(cache_key)).await;
            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);

            match &res {
                Ok(decision) => {
                    let outcome = if decision.allow { "allow" } else { "deny" };
                    tracing::Span::current().record("outcome", outcome);
                }
                Err(_) => {
                    tracing::Span::current().record("outcome", "error");
                }
            }

            res
        }
        .instrument(policy_span)
        .await
        {
            Ok(decision) => decision,
            Err(err) => {
                state
                    .ledger
                    .append_event(
                        &session.trace_id,
                        &session.session_id,
                        "POLICY_DECISION",
                        &principal_id,
                        &session.policy_snapshot_id,
                        serde_json::json!({
                            "decision": "deny",
                            "reason": "policy_engine_error",
                            "op_name": "finalize",
                            "request_id": request_id.as_str(),
                        }),
                    )
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

                return Err(opa_error_response(&err));
            }
        };

        let reason = decision.reason.as_deref().unwrap_or(if decision.allow {
            "policy_allow"
        } else {
            "policy_deny"
        });

        state
            .ledger
            .append_event(
                &session.trace_id,
                &session.session_id,
                "POLICY_DECISION",
                &principal_id,
                &session.policy_snapshot_id,
                serde_json::json!({
                    "decision": if decision.allow { "allow" } else { "deny" },
                    "reason": reason,
                    "op_name": "finalize",
                    "request_id": request_id.as_str(),
                }),
            )
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

        if !decision.allow {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "ERR_POLICY_DENIED",
                "policy denied".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            ));
        }

        let finalize_span = tracing::info_span!(
            "finalize.compile",
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %session.policy_snapshot_id,
            policy_snapshot_hash = %session.policy_snapshot_hash,
            terminal_mode = tracing::field::Empty,
            coverage_observed = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        let state_for_finalize = state.clone();
        async move {
            let started = Instant::now();

            let FinalizeRequest {
                claim_map,
                response_text,
                session_id: _,
            } = req;
            let claim_map = finalize_gate(
                &session,
                claim_map,
                state_for_finalize.config.coverage_threshold,
            )?;

            let terminal_mode = claim_map.terminal_mode.as_str();
            tracing::Span::current().record("terminal_mode", terminal_mode);
            tracing::Span::current().record("coverage_observed", claim_map.coverage_observed);

            tracing::info!(
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                "gateway.finalize"
            );

            let budget_counters = serde_json::json!({
                "operator_calls_used": session.operator_calls_used,
                "bytes_used": session.bytes_used,
                "max_operator_calls": session.budget.max_operator_calls,
                "max_bytes": session.budget.max_bytes,
            });

            let ledger_span = tracing::info_span!(
                "ledger.append",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                event_type = "FINALIZE_RESULT",
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            );

            async {
                let started = Instant::now();
                state_for_finalize
                    .ledger
                    .record_finalize_result(FinalizeResultRecord {
                        trace_id: &session.trace_id,
                        session_id: &session.session_id,
                        principal_id: &principal_id,
                        policy_snapshot_id: &session.policy_snapshot_id,
                        claim_map: &claim_map,
                        budget_counters: &budget_counters,
                        request_id: &request_id,
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
                Ok::<_, ApiError>(())
            }
            .instrument(ledger_span)
            .await?;

            session.finalized = true;
            persist_session_runtime(&state_for_finalize, &session)
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

            Ok(Json(FinalizeResponse {
                terminal_mode: claim_map.terminal_mode,
                trace_id: session.trace_id.clone(),
                claim_map,
                response_text,
            }))
        }
        .instrument(finalize_span)
        .await
    })
    .await;

    let status = match &handler_result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/finalize",
        "POST",
        status.as_u16(),
        request_started.elapsed(),
    );

    match &handler_result {
        Ok(Json(body)) => {
            crate::metrics::observe_terminal_mode("/v1/finalize", body.terminal_mode.as_str())
        }
        Err((_, Json(err))) => {
            crate::metrics::observe_terminal_mode("/v1/finalize", err.terminal_mode_hint.as_str())
        }
    }

    handler_result
}

async fn extract_principal(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiError> {
    match state.config.auth_mode {
        AuthMode::Local => {
            validate_local_auth_shared_secret(
                headers,
                state.config.local_auth_shared_secret.as_deref(),
            )?;
            let principal_id = extract_principal_id(headers)?;
            Ok(Principal {
                principal_id,
                tenant_id: "local".to_string(),
                principal_roles: Vec::new(),
                principal_attrs_hash: canonical::hash_canonical_json(&serde_json::json!({})),
            })
        }
        AuthMode::Oidc => {
            let Some(auth) = state.oidc.as_ref() else {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "oidc authenticator is not initialized".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                ));
            };

            auth.authenticate(headers)
                .await
                .map_err(|err| match err.code {
                    "ERR_AUTH_UNAVAILABLE" => json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        err.code,
                        err.message,
                        TerminalMode::SourceUnavailable,
                        true,
                    ),
                    "ERR_AUTH_REQUIRED" | "ERR_AUTH_INVALID" => json_error(
                        StatusCode::UNAUTHORIZED,
                        err.code,
                        err.message,
                        TerminalMode::InsufficientPermission,
                        false,
                    ),
                    _ => json_error(
                        StatusCode::UNAUTHORIZED,
                        err.code,
                        err.message,
                        TerminalMode::InsufficientPermission,
                        false,
                    ),
                })
        }
    }
}

fn validate_local_auth_shared_secret(
    headers: &HeaderMap,
    expected_secret: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_secret) = expected_secret else {
        return Ok(());
    };

    let provided_secret = headers
        .get("x-pecr-local-auth-secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_AUTH_REQUIRED",
                "missing local auth secret".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    if provided_secret != expected_secret {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "ERR_AUTH_INVALID",
            "invalid local auth secret".to_string(),
            TerminalMode::InsufficientPermission,
            false,
        ));
    }

    Ok(())
}

fn extract_principal_id(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let principal_id = headers
        .get("x-pecr-principal-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "missing x-pecr-principal-id header".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    Ok(principal_id)
}

fn extract_session_token(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("x-pecr-session-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "missing or invalid session token".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    Ok(token.to_string())
}

fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-pecr-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(sanitize_request_id)
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("x-pecr-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<Ulid>().ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn sanitize_request_id(raw: &str) -> Option<String> {
    const MAX_LEN: usize = 64;
    let mut out = String::with_capacity(raw.len().min(MAX_LEN));

    for ch in raw.chars() {
        if out.len() >= MAX_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        }
    }

    (!out.is_empty()).then_some(out)
}

fn sanitize_as_of_time(raw: &str) -> Option<String> {
    const LEN: usize = 20;
    let raw = raw.trim();
    if raw.len() != LEN {
        return None;
    }

    let bytes = raw.as_bytes();
    let digit = |idx: usize| bytes.get(idx).is_some_and(|b| b.is_ascii_digit());

    if !digit(0)
        || !digit(1)
        || !digit(2)
        || !digit(3)
        || bytes.get(4) != Some(&b'-')
        || !digit(5)
        || !digit(6)
        || bytes.get(7) != Some(&b'-')
        || !digit(8)
        || !digit(9)
        || bytes.get(10) != Some(&b'T')
        || !digit(11)
        || !digit(12)
        || bytes.get(13) != Some(&b':')
        || !digit(14)
        || !digit(15)
        || bytes.get(16) != Some(&b':')
        || !digit(17)
        || !digit(18)
        || bytes.get(19) != Some(&b'Z')
    {
        return None;
    }

    Some(raw.to_string())
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: String,
    message: String,
    terminal_mode_hint: TerminalMode,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

fn json_error(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    terminal_mode_hint: TerminalMode,
    retryable: bool,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            code: code.into(),
            message: message.into(),
            terminal_mode_hint,
            retryable,
            detail: None,
        }),
    )
}

fn opa_error_response(err: &crate::opa::OpaError) -> (StatusCode, Json<ErrorResponse>) {
    match err {
        crate::opa::OpaError::Timeout => json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "ERR_SOURCE_TIMEOUT",
            "policy engine timeout".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        ),
        crate::opa::OpaError::CircuitOpen => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "policy engine circuit breaker is open".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        ),
        _ => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "policy engine unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::collections::HashSet;

    fn make_session(
        evidence_unit_ids: &[&str],
        operator_calls_used: u32,
        bytes_used: u64,
        budget: Budget,
    ) -> Session {
        let mut set = HashSet::new();
        for id in evidence_unit_ids {
            set.insert(id.to_string());
        }

        Session {
            session_id: "sess".to_string(),
            trace_id: "trace".to_string(),
            principal_id: "principal".to_string(),
            tenant_id: "tenant".to_string(),
            policy_snapshot_id: "policy".to_string(),
            policy_snapshot_hash: "hash".to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            budget,
            session_token_hash: sha256_hex("token".as_bytes()),
            session_token_expires_at_epoch_ms: unix_epoch_ms_now() + 60_000,
            operator_calls_used,
            bytes_used,
            evidence_unit_ids: set,
            finalized: false,
        }
    }

    fn make_claim_map(claims: Vec<pecr_contracts::Claim>, terminal_mode: TerminalMode) -> ClaimMap {
        ClaimMap {
            claim_map_id: "claim_map".to_string(),
            terminal_mode,
            claims,
            coverage_threshold: 0.95,
            coverage_observed: 0.0,
            notes: None,
        }
    }

    #[test]
    fn finalize_gate_rejects_unknown_evidence_unit_ids() {
        let emitted =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let missing =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

        let session = make_session(
            &[emitted.as_str()],
            0,
            0,
            Budget {
                max_operator_calls: 10,
                max_bytes: 1024,
                max_wallclock_ms: 1000,
                max_recursion_depth: 1,
                max_parallelism: None,
            },
        );

        let claim_map = make_claim_map(
            vec![pecr_contracts::Claim {
                claim_id: "not_a_hash".to_string(),
                claim_text: "supported claim".to_string(),
                status: ClaimStatus::Supported,
                evidence_unit_ids: vec![missing],
            }],
            TerminalMode::Supported,
        );

        let err = finalize_gate(&session, claim_map, 0.95).unwrap_err();
        let (status, Json(body)) = err;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.code, "ERR_INVALID_PARAMS");
    }

    #[test]
    fn finalize_gate_downgrades_supported_claims_without_evidence() {
        let session = make_session(
            &[],
            0,
            0,
            Budget {
                max_operator_calls: 10,
                max_bytes: 1024,
                max_wallclock_ms: 1000,
                max_recursion_depth: 1,
                max_parallelism: None,
            },
        );

        let claim_map = make_claim_map(
            vec![pecr_contracts::Claim {
                claim_id: "not_a_hash".to_string(),
                claim_text: "supported claim".to_string(),
                status: ClaimStatus::Supported,
                evidence_unit_ids: Vec::new(),
            }],
            TerminalMode::Supported,
        );

        let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
        assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
        assert_eq!(out.coverage_observed, 0.0);
        assert_eq!(out.claims.len(), 1);

        let claim = &out.claims[0];
        assert_eq!(claim.status, ClaimStatus::Unknown);
        assert!(claim.evidence_unit_ids.is_empty());
        assert!(canonical::is_sha256_hex(&claim.claim_id));
    }

    #[test]
    fn finalize_gate_allows_supported_claims_with_emitted_evidence() {
        let emitted =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let session = make_session(
            &[emitted.as_str()],
            0,
            0,
            Budget {
                max_operator_calls: 10,
                max_bytes: 1024,
                max_wallclock_ms: 1000,
                max_recursion_depth: 1,
                max_parallelism: None,
            },
        );

        let claim_map = make_claim_map(
            vec![pecr_contracts::Claim {
                claim_id: "not_a_hash".to_string(),
                claim_text: "supported claim".to_string(),
                status: ClaimStatus::Supported,
                evidence_unit_ids: vec![emitted],
            }],
            TerminalMode::Supported,
        );

        let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
        assert_eq!(out.terminal_mode, TerminalMode::Supported);
        assert_eq!(out.coverage_observed, 1.0);
        assert_eq!(out.claims.len(), 1);
        assert_eq!(out.claims[0].status, ClaimStatus::Supported);
        assert!(canonical::is_sha256_hex(&out.claims[0].claim_id));
    }

    #[test]
    fn finalize_gate_budget_violation_forces_insufficient_evidence() {
        let emitted =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let session = make_session(
            &[emitted.as_str()],
            0,
            5,
            Budget {
                max_operator_calls: 10,
                max_bytes: 0,
                max_wallclock_ms: 1000,
                max_recursion_depth: 1,
                max_parallelism: None,
            },
        );

        let claim_map = make_claim_map(
            vec![pecr_contracts::Claim {
                claim_id: "not_a_hash".to_string(),
                claim_text: "supported claim".to_string(),
                status: ClaimStatus::Supported,
                evidence_unit_ids: vec![emitted],
            }],
            TerminalMode::Supported,
        );

        let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
        assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
    }

    #[test]
    fn field_redaction_parse_allows_and_denies() {
        let allow = parse_field_redaction(Some(&serde_json::json!({
            "allow_fields": ["b", "a", "a"]
        })))
        .expect("allow parse should succeed")
        .expect("allow spec should exist");

        assert!(matches!(
            allow,
            FieldRedaction::Allow(fields) if fields == vec!["a".to_string(), "b".to_string()]
        ));

        let deny = parse_field_redaction(Some(&serde_json::json!({
            "deny_fields": ["secret"]
        })))
        .expect("deny parse should succeed")
        .expect("deny spec should exist");

        assert!(matches!(
            deny,
            FieldRedaction::Deny(fields) if fields == vec!["secret".to_string()]
        ));
    }

    #[test]
    fn field_redaction_applies_recursively() {
        let redaction = FieldRedaction::Deny(vec!["secret".to_string()]);
        let input = serde_json::json!({
            "ok": 1,
            "secret": "top",
            "nested": {
                "secret": "hidden",
                "keep": true
            },
            "arr": [
                {"secret": "x", "keep": 1},
                {"keep": 2}
            ]
        });

        let out = apply_field_redaction(&input, &redaction);
        assert_eq!(
            out,
            serde_json::json!({
                "ok": 1,
                "nested": { "keep": true },
                "arr": [
                    {"keep": 1},
                    {"keep": 2}
                ]
            })
        );
    }

    #[test]
    fn evidence_unit_redaction_updates_hashes_and_ids() {
        let content = serde_json::json!({
            "ok": "1",
            "secret": "x",
        });

        let mut evidence = EvidenceUnit {
            source_system: "pg_safeview".to_string(),
            object_id: "obj".to_string(),
            version_id: "v1".to_string(),
            span_or_row_spec: serde_json::json!({
                "type": "db_row",
                "fields": ["ok", "secret"],
            }),
            content_type: EvidenceContentType::ApplicationJson,
            content: Some(content),
            content_hash: canonical::hash_canonical_json(&serde_json::json!({
                "ok": "1",
                "secret": "x",
            })),
            retrieved_at: "t".to_string(),
            as_of_time: "t".to_string(),
            policy_snapshot_id: "p".to_string(),
            policy_snapshot_hash: "h".to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id: String::new(),
        };
        evidence.evidence_unit_id = compute_evidence_unit_id(&evidence);
        let original_id = evidence.evidence_unit_id.clone();

        let redaction = FieldRedaction::Deny(vec!["secret".to_string()]);
        let redacted =
            apply_field_redaction_to_evidence_unit(evidence, &redaction).expect("redaction ok");

        let out_content = redacted.content.as_ref().expect("content preserved");
        assert_eq!(out_content, &serde_json::json!({ "ok": "1" }));
        assert_eq!(
            redacted.content_hash,
            canonical::hash_canonical_json(out_content)
        );
        assert_ne!(redacted.evidence_unit_id, original_id);
        assert_eq!(redacted.transform_chain.len(), 1);

        let fields = redacted
            .span_or_row_spec
            .get("fields")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(fields, vec![serde_json::Value::String("ok".to_string())]);
    }

    #[test]
    fn safeview_schema_missing_columns_are_detected() {
        let spec = safeview_spec("safe_customer_view_public").expect("spec must exist");
        let available = BTreeSet::from([
            "tenant_id".to_string(),
            "customer_id".to_string(),
            "status".to_string(),
            "plan_tier".to_string(),
        ]);

        let missing = missing_safeview_columns(spec, &available);
        assert!(missing.contains(&"updated_at".to_string()));
    }

    #[test]
    fn safeview_schema_complete_columns_pass() {
        let spec = safeview_spec("safe_customer_view_public").expect("spec must exist");
        let available = BTreeSet::from([
            "tenant_id".to_string(),
            "customer_id".to_string(),
            "status".to_string(),
            "plan_tier".to_string(),
            "updated_at".to_string(),
        ]);

        let missing = missing_safeview_columns(spec, &available);
        assert!(missing.is_empty());
    }
}
