use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use pecr_auth::OidcAuthenticator;
use pecr_contracts::{Budget, ClaimMap, ClientResponseKind, SafeAskCatalog, TerminalMode};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::Instrument;

use crate::config::{AuthMode, ControllerConfig, ControllerEngine, StartupError};
use crate::rate_limit::RateLimiter;
use crate::replay::{PersistedRun, ReplayStore};

mod auth;
mod budget;
mod diagnostics;
mod finalize;
mod orchestration;
mod replay_api;

use self::auth::{
    apply_gateway_auth, extract_authorization_header, extract_principal, extract_request_id,
    extract_trace_id,
};
use self::diagnostics::{healthz, metrics, readyz};
#[cfg(test)]
use self::finalize::build_claim_map;
use self::finalize::build_finalize_output;
use self::orchestration::{GatewayCallContext, run_context_loop, run_context_loop_rlm};
use self::replay_api::{
    get_evaluation, get_replay, get_scorecards, list_replays, submit_evaluation,
};

#[cfg(test)]
use self::finalize::extract_atomic_claims;

#[derive(Clone)]
pub struct AppState {
    config: ControllerConfig,
    http: reqwest::Client,
    oidc: Option<OidcAuthenticator>,
    rate_limiter: RateLimiter,
    replay_store: ReplayStore,
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

    let rate_limiter = RateLimiter::new(
        Duration::from_secs(config.rate_limit_window_secs.max(1)),
        16_384,
    );
    let replay_store = ReplayStore::new(
        PathBuf::from(config.replay_store_dir.clone()),
        config.replay_retention_days,
    )
    .map_err(|err| StartupError {
        code: "ERR_REPLAY_STORE_INIT",
        message: format!("failed to initialize replay store: {}", err),
    })?;
    let state = AppState {
        config,
        http: reqwest::Client::new(),
        oidc,
        rate_limiter,
        replay_store,
    };

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/run", post(run))
        .route("/v1/replays", get(list_replays))
        .route("/v1/replays/{run_id}", get(get_replay))
        .route("/v1/evaluations", post(submit_evaluation))
        .route("/v1/evaluations/scorecards", get(get_scorecards))
        .route("/v1/evaluations/{evaluation_id}", get(get_evaluation))
        .with_state(state))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    response_kind: Option<ClientResponseKind>,
}

async fn capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SafeAskCatalog>, (StatusCode, Json<ErrorResponse>)> {
    let started = Instant::now();
    let result = async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id.clone();
        let request_id = extract_request_id(&headers);
        let trace_id = extract_trace_id(&headers);
        let authz_header = (state.config.auth_mode == AuthMode::Oidc)
            .then(|| extract_authorization_header(&headers))
            .flatten();
        let url = format!(
            "{}/v1/policies/capabilities",
            state.config.gateway_url.trim_end_matches('/')
        );
        let builder = state
            .http
            .get(url)
            .header("x-pecr-request-id", request_id)
            .header("x-pecr-trace-id", trace_id);
        let response = apply_gateway_auth(
            builder,
            principal_id.as_str(),
            authz_header.as_deref(),
            state.config.local_auth_shared_secret.as_deref(),
        )
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
            return Err(gateway_non_success_response(response).await);
        }

        let catalog = response.json::<SafeAskCatalog>().await.map_err(|_| {
            json_error(
                StatusCode::BAD_GATEWAY,
                "ERR_INTERNAL",
                "failed to parse gateway response".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

        Ok(Json(catalog))
    }
    .await;

    let status = match &result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/capabilities",
        "GET",
        status.as_u16(),
        started.elapsed(),
    );
    result
}

async fn run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_started = Instant::now();
    let principal = extract_principal(&state, &headers).await?;
    let principal_id = principal.principal_id.clone();

    if !state.rate_limiter.allow(
        format!("run:{}", principal_id).as_str(),
        state.config.rate_limit_run_per_window,
    ) {
        return Err(json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "ERR_RATE_LIMITED",
            "rate limit exceeded for run requests".to_string(),
            TerminalMode::InsufficientPermission,
            true,
        ));
    }

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
            local_auth_shared_secret: state.config.local_auth_shared_secret.as_deref(),
            request_id: &request_id,
            trace_id: &trace_id,
            session_token: &session.session_token,
            session_id: &session.session.session_id,
        };

        let loop_result = match state.config.controller_engine {
            ControllerEngine::Baseline => run_context_loop(&state, ctx, &query, &budget).await?,
            ControllerEngine::BeamPlanner => run_context_loop(&state, ctx, &query, &budget).await?,
            ControllerEngine::Rlm => run_context_loop_rlm(&state, ctx, &query, &budget).await?,
        };
        let loop_terminal_mode = loop_result.terminal_mode;
        let loop_response_text = loop_result.response_text.clone();
        let planner_traces = loop_result.planner_traces.clone();
        let operator_calls_used = loop_result.operator_calls_used;
        let bytes_used = loop_result.bytes_used;
        let depth_used = loop_result.depth_used;
        let evidence_ref_count = loop_result.evidence_refs.len() as u32;
        let mut evidence_unit_ids = loop_result
            .evidence_units
            .iter()
            .map(|unit| unit.evidence_unit_id.clone())
            .collect::<Vec<_>>();
        evidence_unit_ids.sort();
        evidence_unit_ids.dedup();

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

            let finalized_output = build_finalize_output(
                &query,
                loop_terminal_mode,
                loop_result.response_text.clone(),
                &loop_result.evidence_units,
            );

            let finalized = finalize_session(
                &state,
                ctx,
                finalized_output.response_text,
                finalized_output.claim_map,
            )
            .await?;

            let latency_ms = finalize_started.elapsed().as_millis() as u64;
            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("outcome", "ok");

            Ok::<_, (StatusCode, Json<ErrorResponse>)>(finalized)
        }
        .instrument(finalize_span)
        .await?;

        let run_response = RunResponse {
            terminal_mode: finalized.terminal_mode,
            trace_id: finalized.trace_id.clone(),
            claim_map: finalized.claim_map.clone(),
            response_text: finalized.response_text.clone(),
            response_kind: classify_run_response_kind(
                finalized.terminal_mode,
                finalized.response_text.as_str(),
                &finalized.claim_map,
            ),
        };

        let persisted_run = PersistedRun {
            trace_id: finalized.trace_id,
            request_id: request_id.clone(),
            principal_id: principal_id.clone(),
            engine_mode: state.config.controller_engine,
            query: query.clone(),
            budget: budget.clone(),
            session_id: session.session.session_id.clone(),
            policy_snapshot_id: session.session.policy_snapshot_id.clone(),
            loop_terminal_mode,
            loop_response_text,
            terminal_mode: run_response.terminal_mode,
            response_text: run_response.response_text.clone(),
            claim_map: run_response.claim_map.clone(),
            operator_calls_used,
            bytes_used,
            depth_used,
            evidence_ref_count,
            evidence_unit_ids,
            planner_traces,
        };
        let replay_state = state.clone();
        let replay_request_id = request_id.clone();
        let replay_trace_id = run_response.trace_id.clone();
        let replay_principal_id = principal_id.clone();
        tokio::spawn(async move {
            if let Err(err) = run_replay_store_io(&replay_state, move |replay_store| {
                replay_store.persist_run(persisted_run)
            })
            .await
            {
                tracing::warn!(
                    request_id = %replay_request_id,
                    trace_id = %replay_trace_id,
                    principal_id = %replay_principal_id,
                    error = %err,
                    "controller.replay_persist_failed"
                );
            }
        });

        Ok(Json(run_response))
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

        let response = apply_gateway_auth(
            builder,
            principal_id,
            authz_header,
            state.config.local_auth_shared_secret.as_deref(),
        )
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
            return Err(gateway_non_success_response(response).await);
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

    let response = apply_gateway_auth(
        builder,
        ctx.principal_id,
        ctx.authz_header,
        state.config.local_auth_shared_secret.as_deref(),
    )
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
        return Err(gateway_non_success_response(response).await);
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

async fn gateway_non_success_response(response: reqwest::Response) -> ApiError {
    let raw_status = response.status();
    let status = StatusCode::from_u16(raw_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match response.json::<ErrorResponse>().await {
        Ok(err) => (status, Json(with_actionable_guidance(err))),
        Err(_) => json_error(
            status,
            "ERR_SOURCE_UNAVAILABLE",
            "gateway returned non-success status".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        ),
    }
}

async fn run_replay_store_io<T, F>(state: &AppState, operation: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce(ReplayStore) -> std::io::Result<T> + Send + 'static,
{
    let replay_store = state.replay_store.clone();
    tokio::task::spawn_blocking(move || operation(replay_store))
        .await
        .map_err(map_replay_store_join_error)?
}

fn map_replay_store_join_error(err: tokio::task::JoinError) -> std::io::Error {
    std::io::Error::other(format!("replay store task failed: {}", err))
}

fn map_replay_store_error(err: std::io::Error) -> ApiError {
    match err.kind() {
        std::io::ErrorKind::InvalidInput => json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            err.to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ),
        _ => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_REPLAY_STORE",
            format!("replay store operation failed: {}", err),
            TerminalMode::SourceUnavailable,
            true,
        ),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
    terminal_mode_hint: TerminalMode,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_kind: Option<ClientResponseKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    what_failed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_alternative: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

#[derive(Clone, Copy)]
struct ErrorGuidance {
    what_failed: &'static str,
    safe_alternative: &'static str,
}

fn classify_run_response_kind(
    terminal_mode: TerminalMode,
    response_text: &str,
    claim_map: &ClaimMap,
) -> Option<ClientResponseKind> {
    if claim_map
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("Partial answer:"))
    {
        return Some(ClientResponseKind::PartialAnswer);
    }

    if claim_map.clarification_prompt.is_some() {
        return Some(ClientResponseKind::Ambiguous);
    }

    if terminal_mode == TerminalMode::InsufficientEvidence {
        let response_text = response_text.to_ascii_lowercase();
        if response_text.contains("underspecified")
            || response_text.contains("too broad")
            || response_text.contains("specify which document or policy")
            || response_text.contains("safe scopes for the current principal")
        {
            return Some(ClientResponseKind::Ambiguous);
        }
    }

    None
}

fn classify_error_response_kind(terminal_mode_hint: TerminalMode) -> Option<ClientResponseKind> {
    match terminal_mode_hint {
        TerminalMode::InsufficientPermission => Some(ClientResponseKind::Blocked),
        TerminalMode::SourceUnavailable => Some(ClientResponseKind::SourceDown),
        _ => None,
    }
}

fn default_error_guidance(
    code: &str,
    terminal_mode_hint: TerminalMode,
    retryable: bool,
) -> Option<ErrorGuidance> {
    match (code, terminal_mode_hint) {
        ("ERR_RATE_LIMITED", TerminalMode::InsufficientPermission) => Some(ErrorGuidance {
            what_failed: "The controller blocked the request because the caller exceeded the current run rate limit.",
            safe_alternative: "Retry after the rate-limit window resets, or reduce request frequency for this principal.",
        }),
        ("ERR_POLICY_DENIED", TerminalMode::InsufficientPermission) => Some(ErrorGuidance {
            what_failed: "The current principal is not allowed to access the required session or evidence for this request.",
            safe_alternative: "Retry with a principal that can access this data, or narrow the request to data the current principal may read.",
        }),
        (_, TerminalMode::InsufficientPermission) => Some(ErrorGuidance {
            what_failed: "The current principal could not complete this request with its available permissions.",
            safe_alternative: "Retry with a principal that has the required access, or narrow the request to data the current principal may read.",
        }),
        ("ERR_REPLAY_STORE", TerminalMode::SourceUnavailable) => Some(ErrorGuidance {
            what_failed: "The replay store could not complete the requested audit or evaluation operation.",
            safe_alternative: "Retry the replay or evaluation request after the replay store recovers. If you only need the answer path, prefer `/v1/run` once controller readiness is healthy again.",
        }),
        ("ERR_SOURCE_UNAVAILABLE", TerminalMode::SourceUnavailable) => Some(ErrorGuidance {
            what_failed: "A required upstream dependency such as the gateway, policy engine, or source system was unavailable or timed out.",
            safe_alternative: if retryable {
                "Retry the same request after the dependency recovers, or ask a narrower question that can succeed with fewer sources."
            } else {
                "Check dependency health and retry once the required source path is available again."
            },
        }),
        (_, TerminalMode::SourceUnavailable) => Some(ErrorGuidance {
            what_failed: "A required dependency or source-backed operation was unavailable for this request.",
            safe_alternative: if retryable {
                "Retry the request after the dependency recovers, or narrow the request to a smaller safe path."
            } else {
                "Check dependency health and retry once the unavailable source path is restored."
            },
        }),
        _ => None,
    }
}

fn with_actionable_guidance(mut err: ErrorResponse) -> ErrorResponse {
    if err.response_kind.is_none() {
        err.response_kind = classify_error_response_kind(err.terminal_mode_hint);
    }
    if let Some(guidance) =
        default_error_guidance(err.code.as_str(), err.terminal_mode_hint, err.retryable)
    {
        if err.what_failed.is_none() {
            err.what_failed = Some(guidance.what_failed.to_string());
        }
        if err.safe_alternative.is_none() {
            err.safe_alternative = Some(guidance.safe_alternative.to_string());
        }
    }
    err
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
        Json(with_actionable_guidance(ErrorResponse {
            code: code.into(),
            message: message.into(),
            terminal_mode_hint,
            retryable,
            response_kind: None,
            what_failed: None,
            safe_alternative: None,
            detail: None,
        })),
    )
}

#[cfg(test)]
mod tests;
