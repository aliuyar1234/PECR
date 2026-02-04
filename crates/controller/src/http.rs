use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use pecr_auth::{OidcAuthenticator, Principal};
use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, Claim, ClaimMap, ClaimStatus, EvidenceUnit, EvidenceUnitRef, TerminalMode,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::Instrument;
use ulid::Ulid;

use crate::config::{AuthMode, ControllerConfig, ControllerEngine, StartupError};

#[cfg(feature = "rlm")]
use std::path::PathBuf;
#[cfg(feature = "rlm")]
use std::process::Stdio;
#[cfg(feature = "rlm")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct AppState {
    config: ControllerConfig,
    http: reqwest::Client,
    oidc: Option<OidcAuthenticator>,
}

type ApiError = (StatusCode, Json<ErrorResponse>);

pub async fn router(config: ControllerConfig) -> Result<Router, StartupError> {
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

    let state = AppState {
        config,
        http: reqwest::Client::new(),
        oidc,
    };

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/run", post(run))
        .with_state(state))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics() -> impl IntoResponse {
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
struct RunRequest {
    query: String,
    #[serde(default)]
    budget: Option<Budget>,
}

#[derive(Debug, Serialize)]
struct RunResponse {
    terminal_mode: TerminalMode,
    trace_id: String,
    claim_map: ClaimMap,
    response_text: String,
}

async fn run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_started = Instant::now();
    let principal = extract_principal(&state, &headers).await?;
    let principal_id = principal.principal_id.clone();
    let request_id = extract_request_id(&headers);
    let trace_id = extract_trace_id(&headers);
    let authz_header = (state.config.auth_mode == AuthMode::Oidc)
        .then(|| extract_authorization_header(&headers))
        .flatten();
    let budget = req
        .budget
        .unwrap_or_else(|| state.config.budget_defaults.clone());
    let query = req.query;

    budget.validate().map_err(|reason| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            format!("invalid budget: {}", reason),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let span = tracing::info_span!(
        "controller.run",
        trace_id = %trace_id,
        request_id = %request_id,
        principal_id = %principal_id
    );
    let handler_result = async move {
        let session = create_session(
            &state,
            &principal_id,
            &request_id,
            &trace_id,
            authz_header.as_deref(),
            &budget,
        )
        .await?;

        let ctx = GatewayCallContext {
            principal_id: &principal_id,
            authz_header: authz_header.as_deref(),
            request_id: &request_id,
            trace_id: &trace_id,
            session_token: &session.session_token,
            session_id: &session.session.session_id,
        };

        let loop_result = match state.config.controller_engine {
            ControllerEngine::Baseline => run_context_loop(&state, ctx, &query, &budget).await?,
            ControllerEngine::Rlm => run_context_loop_rlm(&state, ctx, &query, &budget).await?,
        };

        let finalize_span = tracing::info_span!(
            "finalize.compile",
            trace_id = %trace_id,
            request_id = %request_id,
            session_id = %session.session.session_id,
            terminal_mode = %loop_result.terminal_mode.as_str(),
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );

        let finalized = async {
            let finalize_started = Instant::now();

            let response_text = loop_result
                .response_text
                .unwrap_or_else(|| response_text_for_terminal_mode(loop_result.terminal_mode));
            let claim_map = build_claim_map(&response_text, loop_result.terminal_mode);

            let finalized = finalize_session(&state, ctx, response_text, claim_map).await?;

            let latency_ms = finalize_started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("outcome", "ok");

            Ok::<_, (StatusCode, Json<ErrorResponse>)>(finalized)
        }
        .instrument(finalize_span)
        .await?;

        Ok(Json(RunResponse {
            terminal_mode: finalized.terminal_mode,
            trace_id: finalized.trace_id,
            claim_map: finalized.claim_map,
            response_text: finalized.response_text,
        }))
    }
    .instrument(span)
    .await;

    let status = match &handler_result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/run",
        "POST",
        status.as_u16(),
        request_started.elapsed(),
    );
    match &handler_result {
        Ok(Json(body)) => {
            crate::metrics::observe_terminal_mode("/v1/run", body.terminal_mode.as_str())
        }
        Err((_, Json(err))) => {
            crate::metrics::observe_terminal_mode("/v1/run", err.terminal_mode_hint.as_str())
        }
    }

    handler_result
}

fn response_text_for_terminal_mode(terminal_mode: TerminalMode) -> String {
    match terminal_mode {
        TerminalMode::InsufficientEvidence => {
            "UNKNOWN: insufficient evidence to answer the query.".to_string()
        }
        TerminalMode::InsufficientPermission => {
            "UNKNOWN: insufficient permission to access required evidence.".to_string()
        }
        TerminalMode::SourceUnavailable => {
            "UNKNOWN: required sources were unavailable within budget.".to_string()
        }
        TerminalMode::Supported => "UNKNOWN: supported mode not implemented yet.".to_string(),
    }
}

fn build_claim_map(response_text: &str, terminal_mode: TerminalMode) -> ClaimMap {
    let claims = extract_atomic_claims(response_text)
        .into_iter()
        .map(|(status, claim_text)| {
            let claim_id = claim_id_for(&claim_text, status, &[]);
            Claim {
                claim_id,
                claim_text,
                status,
                evidence_unit_ids: Vec::new(),
            }
        })
        .collect::<Vec<_>>();

    let supported_claims = claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported)
        .count();
    let covered_claims = claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported && !c.evidence_unit_ids.is_empty())
        .count();

    let coverage_observed = if supported_claims == 0 {
        1.0
    } else {
        covered_claims as f64 / supported_claims as f64
    };

    ClaimMap {
        claim_map_id: Ulid::new().to_string(),
        terminal_mode,
        claims,
        coverage_threshold: 0.95,
        coverage_observed,
        notes: None,
    }
}

fn extract_atomic_claims(response_text: &str) -> Vec<(ClaimStatus, String)> {
    response_text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            if let Some(rest) = line.strip_prefix("ASSUMPTION:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Assumption, claim.to_string()));
            }

            if let Some(rest) = line.strip_prefix("UNKNOWN:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Unknown, claim.to_string()));
            }

            Some((ClaimStatus::Unknown, line.to_string()))
        })
        .collect()
}

fn claim_id_for(claim_text: &str, status: ClaimStatus, evidence_unit_ids: &[String]) -> String {
    let status_str = match status {
        ClaimStatus::Supported => "SUPPORTED",
        ClaimStatus::Assumption => "ASSUMPTION",
        ClaimStatus::Unknown => "UNKNOWN",
    };

    canonical::hash_canonical_json(&serde_json::json!({
        "claim_text": claim_text,
        "status": status_str,
        "evidence_unit_ids": evidence_unit_ids,
    }))
}

#[derive(Debug, Serialize)]
struct CreateSessionRequest {
    budget: Budget,
}

#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    session_id: String,
    trace_id: String,
    policy_snapshot_id: String,
    budget: Budget,
}

struct CreatedSession {
    session: CreateSessionResponse,
    session_token: String,
}

async fn create_session(
    state: &AppState,
    principal_id: &str,
    request_id: &str,
    trace_id: &str,
    authz_header: Option<&str>,
    budget: &Budget,
) -> Result<CreatedSession, (StatusCode, Json<ErrorResponse>)> {
    let span = tracing::info_span!(
        "session.create",
        trace_id = %trace_id,
        request_id = %request_id,
        principal_id = %principal_id,
        session_id = tracing::field::Empty,
        policy_snapshot_id = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let started = Instant::now();
    async move {
        let url = format!(
            "{}/v1/sessions",
            state.config.gateway_url.trim_end_matches('/')
        );
        let builder = state
            .http
            .post(url)
            .header("x-pecr-request-id", request_id)
            .header("x-pecr-trace-id", trace_id);

        let response = apply_gateway_auth(builder, principal_id, authz_header)
            .json(&CreateSessionRequest {
                budget: budget.clone(),
            })
            .send()
            .await
            .map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_SOURCE_UNAVAILABLE",
                    "gateway request failed".to_string(),
                    TerminalMode::SourceUnavailable,
                    true,
                )
            })?;

        if !response.status().is_success() {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                "ERR_SOURCE_UNAVAILABLE",
                "gateway returned non-success status".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            ));
        }

        let session_token = response
            .headers()
            .get("x-pecr-session-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
            .ok_or_else(|| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_INTERNAL",
                    "gateway did not return a session token".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;

        let created = response
            .json::<CreateSessionResponse>()
            .await
            .map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_INTERNAL",
                    "failed to parse gateway response".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;

        tracing::info!(
            request_id = %request_id,
            trace_id = %created.trace_id,
            policy_snapshot_id = %created.policy_snapshot_id,
            principal_id = %principal_id,
            "controller.gateway_session_created"
        );

        tracing::Span::current().record("session_id", created.session_id.as_str());
        tracing::Span::current().record("policy_snapshot_id", created.policy_snapshot_id.as_str());
        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::Span::current().record("latency_ms", latency_ms);
        tracing::Span::current().record("outcome", "ok");

        if created.trace_id != trace_id {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                "ERR_INTERNAL",
                "gateway returned mismatched trace_id".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            ));
        }

        if created.budget != *budget {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                "ERR_INTERNAL",
                "gateway returned mismatched budget".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            ));
        }

        Ok(CreatedSession {
            session: created,
            session_token,
        })
    }
    .instrument(span)
    .await
}

#[derive(Debug, Serialize)]
struct FinalizeRequest {
    session_id: String,
    response_text: String,
    claim_map: ClaimMap,
}

#[derive(Debug, Deserialize)]
struct FinalizeResponse {
    terminal_mode: TerminalMode,
    trace_id: String,
    claim_map: ClaimMap,
    response_text: String,
}

async fn finalize_session(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    response_text: String,
    claim_map: ClaimMap,
) -> Result<FinalizeResponse, (StatusCode, Json<ErrorResponse>)> {
    let url = format!(
        "{}/v1/finalize",
        state.config.gateway_url.trim_end_matches('/')
    );
    let builder = state
        .http
        .post(url)
        .header("x-pecr-request-id", ctx.request_id)
        .header("x-pecr-trace-id", ctx.trace_id)
        .header("x-pecr-session-token", ctx.session_token);

    let response = apply_gateway_auth(builder, ctx.principal_id, ctx.authz_header)
        .json(&FinalizeRequest {
            session_id: ctx.session_id.to_string(),
            response_text,
            claim_map,
        })
        .send()
        .await
        .map_err(|_| {
            json_error(
                StatusCode::BAD_GATEWAY,
                "ERR_SOURCE_UNAVAILABLE",
                "gateway request failed".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    if !response.status().is_success() {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            "ERR_SOURCE_UNAVAILABLE",
            "gateway returned non-success status".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        ));
    }

    let finalized = response.json::<FinalizeResponse>().await.map_err(|_| {
        json_error(
            StatusCode::BAD_GATEWAY,
            "ERR_INTERNAL",
            "failed to parse gateway response".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    if finalized.trace_id != ctx.trace_id {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            "ERR_INTERNAL",
            "gateway returned mismatched trace_id".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        ));
    }

    Ok(finalized)
}

#[derive(Debug, Serialize)]
struct OperatorCallRequest {
    session_id: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OperatorCallResponse {
    terminal_mode: TerminalMode,
    result: serde_json::Value,
}

#[derive(Debug)]
struct ContextLoopResult {
    terminal_mode: TerminalMode,
    #[allow(dead_code)]
    response_text: Option<String>,
    #[allow(dead_code)]
    evidence_refs: Vec<EvidenceUnitRef>,
    #[allow(dead_code)]
    evidence_units: Vec<EvidenceUnit>,
    #[allow(dead_code)]
    operator_calls_used: u32,
    #[allow(dead_code)]
    bytes_used: u64,
    #[allow(dead_code)]
    depth_used: u32,
}

#[derive(Debug, Deserialize)]
struct GatewayErrorResponse {
    terminal_mode_hint: TerminalMode,
}

#[derive(Debug)]
struct OperatorCallOutcome {
    terminal_mode_hint: TerminalMode,
    body: Option<OperatorCallResponse>,
    bytes_len: usize,
}

fn remaining_wallclock(budget: &Budget, started_at: Instant) -> Option<Duration> {
    if budget.max_wallclock_ms == 0 {
        return None;
    }

    let elapsed_ms = started_at.elapsed().as_millis() as u64;
    if elapsed_ms >= budget.max_wallclock_ms {
        return None;
    }

    Some(Duration::from_millis(
        budget.max_wallclock_ms.saturating_sub(elapsed_ms),
    ))
}

#[derive(Clone, Copy)]
struct GatewayCallContext<'a> {
    principal_id: &'a str,
    authz_header: Option<&'a str>,
    request_id: &'a str,
    trace_id: &'a str,
    session_token: &'a str,
    session_id: &'a str,
}

async fn call_operator(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    op_name: &str,
    params: serde_json::Value,
    timeout: Duration,
) -> Result<OperatorCallOutcome, (StatusCode, Json<ErrorResponse>)> {
    let params_bytes = serde_json::to_vec(&params)
        .map(|v| v.len() as u64)
        .unwrap_or(0);

    let span = match op_name {
        "search" => tracing::info_span!(
            "operator.search",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "search",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "fetch_span" => tracing::info_span!(
            "operator.fetch_span",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "fetch_span",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "fetch_rows" => tracing::info_span!(
            "operator.fetch_rows",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "fetch_rows",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "aggregate" => tracing::info_span!(
            "operator.aggregate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "aggregate",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "list_versions" => tracing::info_span!(
            "operator.list_versions",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "list_versions",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "diff" => tracing::info_span!(
            "operator.diff",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "diff",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "redact" => tracing::info_span!(
            "operator.redact",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "redact",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        _ => tracing::info_span!(
            "operator.unknown",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = %op_name,
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
    };
    let started = Instant::now();
    async move {
        let url = format!(
            "{}/v1/operators/{}",
            state.config.gateway_url.trim_end_matches('/'),
            op_name
        );

        let send_fut = async {
            let builder = state
                .http
                .post(url)
                .header("x-pecr-request-id", ctx.request_id)
                .header("x-pecr-trace-id", ctx.trace_id)
                .header("x-pecr-session-token", ctx.session_token);

            let response = apply_gateway_auth(builder, ctx.principal_id, ctx.authz_header)
                .json(&OperatorCallRequest {
                    session_id: ctx.session_id.to_string(),
                    params,
                })
                .send()
                .await
                .map_err(|_| {
                    json_error(
                        StatusCode::BAD_GATEWAY,
                        "ERR_SOURCE_UNAVAILABLE",
                        "gateway request failed".to_string(),
                        TerminalMode::SourceUnavailable,
                        true,
                    )
                })?;

            let status = response.status();
            let bytes = response.bytes().await.map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_SOURCE_UNAVAILABLE",
                    "gateway response read failed".to_string(),
                    TerminalMode::SourceUnavailable,
                    true,
                )
            })?;

            Ok::<_, (StatusCode, Json<ErrorResponse>)>((status, bytes))
        };

        let timed = tokio::time::timeout(timeout, send_fut).await;
        let (status, bytes) = match timed {
            Ok(res) => res?,
            Err(_) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                tracing::Span::current().record("latency_ms", latency_ms);
                tracing::Span::current().record("outcome", "timeout");
                return Ok(OperatorCallOutcome {
                    terminal_mode_hint: TerminalMode::SourceUnavailable,
                    body: None,
                    bytes_len: 0,
                });
            }
        };

        let bytes_len = bytes.len();
        let status_code = status.as_u16();
        let result_bytes = bytes_len as u64;
        tracing::Span::current().record("status_code", status_code);
        tracing::Span::current().record("result_bytes", result_bytes);

        if status.is_success() {
            let body = serde_json::from_slice::<OperatorCallResponse>(&bytes).map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_INTERNAL",
                    "failed to parse gateway response".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;

            let terminal_mode = body.terminal_mode.as_str();
            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("terminal_mode", terminal_mode);
            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("outcome", "ok");

            return Ok(OperatorCallOutcome {
                terminal_mode_hint: body.terminal_mode,
                body: Some(body),
                bytes_len,
            });
        }

        let terminal_mode_hint = serde_json::from_slice::<GatewayErrorResponse>(&bytes)
            .map_or(TerminalMode::SourceUnavailable, |e| e.terminal_mode_hint);
        let terminal_mode = terminal_mode_hint.as_str();
        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::Span::current().record("terminal_mode", terminal_mode);
        tracing::Span::current().record("latency_ms", latency_ms);
        tracing::Span::current().record("outcome", "error");

        Ok(OperatorCallOutcome {
            terminal_mode_hint,
            body: None,
            bytes_len,
        })
    }
    .instrument(span)
    .await
}

async fn run_context_loop(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, (StatusCode, Json<ErrorResponse>)> {
    let loop_start = Instant::now();

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let mut stop_reason: &'static str = "unknown";
    let mut budget_violation = false;

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();
    let mut search_refs = Vec::<EvidenceUnitRef>::new();

    'context_loop: for depth in 0..budget.max_recursion_depth {
        crate::metrics::inc_loop_iteration();
        if operator_calls_used >= budget.max_operator_calls {
            stop_reason = "budget_max_operator_calls";
            budget_violation = true;
            break;
        }

        let Some(timeout) = remaining_wallclock(budget, loop_start) else {
            stop_reason = "budget_max_wallclock_ms";
            budget_violation = true;
            break;
        };

        depth_used = depth_used.saturating_add(1);

        match depth {
            0 => {
                let outcome = call_operator(
                    state,
                    ctx,
                    "list_versions",
                    serde_json::json!({ "object_id": "public/public_1.txt" }),
                    timeout,
                )
                .await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                if outcome.body.is_none() {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = "operator_error";
                    break;
                }
            }
            1 => {
                let outcome = call_operator(
                    state,
                    ctx,
                    "fetch_rows",
                    serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "filter_spec": { "customer_id": "cust_public_1" },
                        "fields": ["status", "plan_tier"]
                    }),
                    timeout,
                )
                .await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                let Some(body) = outcome.body else {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = "operator_error";
                    break;
                };

                if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(body.result.clone())
                {
                    evidence_units.extend(units);
                }
            }
            2 => {
                let query = query.trim();
                if query.is_empty() {
                    continue;
                }

                let outcome = call_operator(
                    state,
                    ctx,
                    "search",
                    serde_json::json!({ "query": query, "limit": 5 }),
                    timeout,
                )
                .await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                let Some(body) = outcome.body else {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = "operator_error";
                    break;
                };

                if let Some(refs_value) = body.result.get("refs").cloned()
                    && let Ok(refs) = serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
                {
                    search_refs = refs;
                    evidence_refs = search_refs.clone();
                }
            }
            3 => {
                for r in search_refs.iter().take(2) {
                    if operator_calls_used >= budget.max_operator_calls {
                        stop_reason = "budget_max_operator_calls";
                        budget_violation = true;
                        break 'context_loop;
                    }
                    let Some(timeout) = remaining_wallclock(budget, loop_start) else {
                        stop_reason = "budget_max_wallclock_ms";
                        budget_violation = true;
                        break 'context_loop;
                    };

                    let outcome = call_operator(
                        state,
                        ctx,
                        "fetch_span",
                        serde_json::json!({ "object_id": r.object_id }),
                        timeout,
                    )
                    .await?;
                    operator_calls_used = operator_calls_used.saturating_add(1);
                    bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                    let Some(body) = outcome.body else {
                        terminal_mode = outcome.terminal_mode_hint;
                        stop_reason = "operator_error";
                        break 'context_loop;
                    };

                    if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                        evidence_units.push(unit);
                    }
                }
            }
            _ => {
                stop_reason = "plan_complete";
                break;
            }
        }

        if bytes_used > budget.max_bytes {
            terminal_mode = TerminalMode::InsufficientEvidence;
            stop_reason = "budget_max_bytes";
            budget_violation = true;
            break;
        }
    }

    if stop_reason == "unknown" {
        stop_reason = "budget_max_recursion_depth";
        budget_violation = true;
    }
    if budget_violation {
        crate::metrics::inc_budget_violation();
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    Ok(ContextLoopResult {
        terminal_mode,
        response_text: None,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

#[cfg(feature = "rlm")]
async fn run_context_loop_rlm(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, (StatusCode, Json<ErrorResponse>)> {
    let loop_start = Instant::now();

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let stop_reason: Option<&'static str>;
    let mut budget_violation = false;

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();

    let python = std::env::var("PECR_RLM_PYTHON")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "python".to_string()
            } else {
                "python3".to_string()
            }
        });

    let script_path = std::env::var("PECR_RLM_SCRIPT_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            let candidates = [
                PathBuf::from("/usr/local/share/pecr/pecr_rlm_bridge.py"),
                PathBuf::from("scripts/rlm/pecr_rlm_bridge.py"),
            ];
            candidates.into_iter().find(|p| p.exists())
        })
        .ok_or_else(|| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_SCRIPT_NOT_FOUND",
                "rlm bridge script not found; set PECR_RLM_SCRIPT_PATH or ensure scripts/rlm/pecr_rlm_bridge.py is present"
                    .to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut child = tokio::process::Command::new(&python)
        .arg(&script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_SPAWN_FAILED",
                format!(
                    "failed to spawn rlm bridge (python={}, script={})",
                    python,
                    script_path.display()
                ),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stdin".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    let child_stdout = child.stdout.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stdout".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    let child_stderr = child.stderr.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stderr".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let trace_id = ctx.trace_id.to_string();
    let request_id = ctx.request_id.to_string();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(child_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!(
                trace_id = %trace_id,
                request_id = %request_id,
                line = %line,
                "rlm.bridge.stderr"
            );
        }
    });

    let start_msg = serde_json::json!({
        "type": "start",
        "query": query,
        "budget": budget,
    });
    let start_line = serde_json::to_string(&start_msg).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to serialize rlm bridge start message".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    child_stdin
        .write_all(format!("{}\n", start_line).as_bytes())
        .await
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_PROTOCOL",
                "failed to write rlm bridge start message".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut stdout_lines = tokio::io::BufReader::new(child_stdout).lines();
    let mut response_text: Option<String> = None;

    loop {
        let Some(timeout) = remaining_wallclock(budget, loop_start) else {
            stop_reason = Some("budget_max_wallclock_ms");
            budget_violation = true;
            break;
        };

        let next_line = tokio::time::timeout(timeout, stdout_lines.next_line()).await;
        let line = match next_line {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                stop_reason = Some("bridge_eof");
                budget_violation = false;
                break;
            }
            Ok(Err(_)) => {
                stop_reason = Some("bridge_read_error");
                budget_violation = false;
                break;
            }
            Err(_) => {
                stop_reason = Some("budget_max_wallclock_ms");
                budget_violation = true;
                break;
            }
        };

        let msg = serde_json::from_str::<serde_json::Value>(&line).map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_PROTOCOL",
                "rlm bridge emitted invalid json".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or_default();

        match msg_type {
            "call_operator" => {
                let id = msg
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let op_name = msg
                    .get("op_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

                if id.is_empty() {
                    stop_reason = Some("bridge_invalid_message");
                    break;
                }
                if depth >= budget.max_recursion_depth {
                    stop_reason = Some("budget_max_recursion_depth");
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                if operator_calls_used >= budget.max_operator_calls {
                    stop_reason = Some("budget_max_operator_calls");
                    budget_violation = true;
                    break;
                }

                let allowed = matches!(
                    op_name.as_str(),
                    "search"
                        | "fetch_span"
                        | "fetch_rows"
                        | "aggregate"
                        | "list_versions"
                        | "diff"
                        | "redact"
                );
                if !allowed {
                    stop_reason = Some("bridge_operator_not_allowlisted");
                    break;
                }

                let outcome = call_operator(state, ctx, op_name.as_str(), params, timeout).await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                if let Some(body) = outcome.body {
                    let terminal_mode_for_resp = body.terminal_mode;
                    let result = body.result;
                    if op_name == "search" {
                        if let Some(refs_value) = result.get("refs").cloned()
                            && let Ok(refs) =
                                serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
                        {
                            evidence_refs = refs;
                        }
                    }

                    if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(result.clone()) {
                        evidence_units.extend(units);
                    } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(result.clone())
                    {
                        evidence_units.push(unit);
                    }

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": true,
                        "terminal_mode": terminal_mode_for_resp.as_str(),
                        "result": result,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    child_stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await
                        .map_err(|_| {
                            json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ERR_RLM_BRIDGE_PROTOCOL",
                                "failed to write rlm bridge response".to_string(),
                                TerminalMode::SourceUnavailable,
                                false,
                            )
                        })?;
                } else {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = Some("operator_error");

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": false,
                        "terminal_mode": outcome.terminal_mode_hint.as_str(),
                        "result": serde_json::Value::Null,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    let _ = child_stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await;
                    break;
                }

                if bytes_used > budget.max_bytes {
                    stop_reason = Some("budget_max_bytes");
                    budget_violation = true;
                    break;
                }
            }
            "done" => {
                response_text = msg
                    .get("final_answer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                stop_reason = Some("rlm_done");
                break;
            }
            _ => {
                stop_reason = Some("bridge_unknown_message");
                break;
            }
        }
    }

    if budget_violation {
        crate::metrics::inc_budget_violation();
    }

    let stop_reason = stop_reason.unwrap_or("unknown");
    let stop_is_bridge_failure = matches!(
        stop_reason,
        "bridge_eof"
            | "bridge_read_error"
            | "bridge_invalid_message"
            | "bridge_operator_not_allowlisted"
            | "bridge_unknown_message"
    );

    let status = if stop_reason == "rlm_done" {
        tokio::time::timeout(Duration::from_millis(250), child.wait())
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        let _ = child.kill();
        let _ = tokio::time::timeout(Duration::from_millis(250), child.wait()).await;
        None
    };

    if stop_is_bridge_failure || status.is_some_and(|s| !s.success()) {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_FAILED",
            format!("rlm bridge failed (reason={})", stop_reason),
            TerminalMode::SourceUnavailable,
            false,
        ));
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    Ok(ContextLoopResult {
        terminal_mode,
        response_text,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

#[cfg(not(feature = "rlm"))]
async fn run_context_loop_rlm(
    _state: &AppState,
    _ctx: GatewayCallContext<'_>,
    _query: &str,
    _budget: &Budget,
) -> Result<ContextLoopResult, (StatusCode, Json<ErrorResponse>)> {
    Err(json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "ERR_RLM_FEATURE_DISABLED",
        "rlm controller engine is not enabled in this build".to_string(),
        TerminalMode::InsufficientEvidence,
        false,
    ))
}

fn extract_authorization_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

async fn extract_principal(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiError> {
    match state.config.auth_mode {
        AuthMode::Local => {
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

fn apply_gateway_auth(
    builder: reqwest::RequestBuilder,
    principal_id: &str,
    authz_header: Option<&str>,
) -> reqwest::RequestBuilder {
    match authz_header {
        Some(authz_header) => builder.header(reqwest::header::AUTHORIZATION, authz_header),
        None => builder.header("x-pecr-principal-id", principal_id),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn spawn_mock_gateway(
        counter: Arc<AtomicUsize>,
    ) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        async fn list_versions(
            State(counter): State<Arc<AtomicUsize>>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            counter.fetch_add(1, Ordering::Relaxed);
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": { "versions": [] }
            }))
        }

        async fn fetch_rows(
            State(counter): State<Arc<AtomicUsize>>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            counter.fetch_add(1, Ordering::Relaxed);
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": []
            }))
        }

        async fn search(
            State(counter): State<Arc<AtomicUsize>>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            counter.fetch_add(1, Ordering::Relaxed);
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": { "refs": [] }
            }))
        }

        async fn fetch_span(
            State(counter): State<Arc<AtomicUsize>>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            counter.fetch_add(1, Ordering::Relaxed);
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": {
                    "source_system": "fs_corpus",
                    "object_id": "public/public_1.txt",
                    "version_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "span_or_row_spec": { "type": "text_span", "start_byte": 0, "end_byte": 0, "line_start": 1, "line_end": 1 },
                    "content_type": "text/plain",
                    "content": "unit-test",
                    "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "retrieved_at": "1970-01-01T00:00:00Z",
                    "as_of_time": "1970-01-01T00:00:00Z",
                    "policy_snapshot_id": "policy",
                    "policy_snapshot_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "transform_chain": [],
                    "evidence_unit_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            }))
        }

        let app = Router::new()
            .route("/v1/operators/list_versions", post(list_versions))
            .route("/v1/operators/fetch_rows", post(fetch_rows))
            .route("/v1/operators/search", post(search))
            .route("/v1/operators/fetch_span", post(fetch_span))
            .with_state(counter);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind should succeed");
        let addr = listener.local_addr().expect("local_addr should succeed");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (addr, shutdown_tx, handle)
    }

    fn controller_state(gateway_addr: SocketAddr, budget: Budget) -> AppState {
        AppState {
            config: ControllerConfig {
                bind_addr: "127.0.0.1:0".parse().expect("bind addr must parse"),
                gateway_url: format!("http://{}", gateway_addr),
                controller_engine: crate::config::ControllerEngine::Baseline,
                model_provider: crate::config::ModelProvider::Mock,
                budget_defaults: budget,
                auth_mode: crate::config::AuthMode::Local,
                oidc: None,
            },
            http: reqwest::Client::new(),
            oidc: None,
        }
    }

    #[tokio::test]
    async fn context_loop_respects_max_operator_calls() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 1,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: None,
        };

        let state = controller_state(gateway_addr, budget.clone());
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            request_id: "req_test_calls",
            trace_id: "trace_test_calls",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, "query", &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(result.operator_calls_used, 1);
    }

    #[tokio::test]
    async fn context_loop_respects_max_recursion_depth() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 1,
            max_parallelism: None,
        };

        let state = controller_state(gateway_addr, budget.clone());
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            request_id: "req_test_depth",
            trace_id: "trace_test_depth",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, "query", &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(result.operator_calls_used, 1);
        assert_eq!(result.depth_used, 1);
    }

    #[tokio::test]
    async fn context_loop_respects_max_wallclock_ms() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 0,
            max_recursion_depth: 10,
            max_parallelism: None,
        };

        let state = controller_state(gateway_addr, budget.clone());
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            request_id: "req_test_wallclock",
            trace_id: "trace_test_wallclock",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, "query", &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(result.operator_calls_used, 0);
        assert_eq!(result.depth_used, 0);
    }

    #[tokio::test]
    async fn context_loop_executes_planned_steps_when_budget_allows() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 4,
            max_parallelism: None,
        };

        let state = controller_state(gateway_addr, budget.clone());
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            request_id: "req_test_plan",
            trace_id: "trace_test_plan",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, "query", &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert_eq!(result.operator_calls_used, 3);
        assert_eq!(result.depth_used, 4);
    }

    #[test]
    fn extract_atomic_claims_respects_unknown_and_assumption_labels() {
        let input = "\nUNKNOWN: first claim\nASSUMPTION: second claim\nraw third claim\n";
        let claims = extract_atomic_claims(input);

        assert_eq!(claims.len(), 3);
        assert_eq!(claims[0].0, ClaimStatus::Unknown);
        assert_eq!(claims[0].1, "first claim");
        assert_eq!(claims[1].0, ClaimStatus::Assumption);
        assert_eq!(claims[1].1, "second claim");
        assert_eq!(claims[2].0, ClaimStatus::Unknown);
        assert_eq!(claims[2].1, "raw third claim");
    }

    #[test]
    fn build_claim_map_generates_sha256_claim_ids() {
        let response_text = "UNKNOWN: insufficient evidence.\n";
        let claim_map = build_claim_map(response_text, TerminalMode::InsufficientEvidence);

        assert_eq!(claim_map.terminal_mode, TerminalMode::InsufficientEvidence);
        assert_eq!(claim_map.coverage_observed, 1.0);
        assert_eq!(claim_map.claims.len(), 1);

        let claim = &claim_map.claims[0];
        assert!(pecr_contracts::canonical::is_sha256_hex(&claim.claim_id));
        assert_eq!(claim.status, ClaimStatus::Unknown);
        assert_eq!(claim.claim_text, "insufficient evidence.");
        assert!(claim.evidence_unit_ids.is_empty());
    }
}
