use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, Claim, ClaimMap, ClaimStatus, EvidenceUnit, EvidenceUnitRef, TerminalMode,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::Instrument;
use ulid::Ulid;

use crate::config::{ControllerConfig, ControllerEngine};

#[derive(Clone)]
pub struct AppState {
    config: ControllerConfig,
    http: reqwest::Client,
}

pub fn router(config: ControllerConfig) -> Router {
    let state = AppState {
        config,
        http: reqwest::Client::new(),
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/run", post(run))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
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
    let principal_id = extract_principal_id(&headers)?;
    let request_id = extract_request_id(&headers);
    let trace_id = extract_trace_id(&headers);
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
    async move {
        let session =
            create_session(&state, &principal_id, &request_id, &trace_id, &budget).await?;

        let ctx = GatewayCallContext {
            principal_id: &principal_id,
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

            let response_text = response_text_for_terminal_mode(loop_result.terminal_mode);
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
    .await
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
        let response = state
            .http
            .post(url)
            .header("x-pecr-principal-id", principal_id)
            .header("x-pecr-request-id", request_id)
            .header("x-pecr-trace-id", trace_id)
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
    let response = state
        .http
        .post(url)
        .header("x-pecr-principal-id", ctx.principal_id)
        .header("x-pecr-request-id", ctx.request_id)
        .header("x-pecr-trace-id", ctx.trace_id)
        .header("x-pecr-session-token", ctx.session_token)
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
            let response = state
                .http
                .post(url)
                .header("x-pecr-principal-id", ctx.principal_id)
                .header("x-pecr-request-id", ctx.request_id)
                .header("x-pecr-trace-id", ctx.trace_id)
                .header("x-pecr-session-token", ctx.session_token)
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

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();
    let mut search_refs = Vec::<EvidenceUnitRef>::new();

    for depth in 0..budget.max_recursion_depth {
        if operator_calls_used >= budget.max_operator_calls {
            break;
        }

        let Some(timeout) = remaining_wallclock(budget, loop_start) else {
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
                        break;
                    }
                    let Some(timeout) = remaining_wallclock(budget, loop_start) else {
                        break;
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
                        break;
                    };

                    if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                        evidence_units.push(unit);
                    }
                }
            }
            _ => break,
        }

        if bytes_used > budget.max_bytes {
            terminal_mode = TerminalMode::InsufficientEvidence;
            break;
        }
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    Ok(ContextLoopResult {
        terminal_mode,
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
    tracing::warn!(
        "rlm engine selected; integration is vendored but not wired yet (delegating to baseline loop)"
    );
    run_context_loop(state, ctx, query, budget).await
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
            },
            http: reqwest::Client::new(),
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
