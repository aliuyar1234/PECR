use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use pecr_auth::{OidcAuthenticator, Principal};
use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, ClaimMap, EngineMode, ReplayBundle, ReplayBundleMetadata, ReplayEvaluationResult,
    ReplayEvaluationSubmission, RunQualityScorecard, TerminalMode,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::Instrument;
use ulid::Ulid;

use crate::config::{AuthMode, ControllerConfig, ControllerEngine, StartupError};
use crate::rate_limit::RateLimiter;
use crate::replay::{PersistedRun, ReplayStore, hash_principal_id};

mod budget;
mod finalize;
mod orchestration;

use self::finalize::{build_claim_map, response_text_for_terminal_mode};
use self::orchestration::{GatewayCallContext, run_context_loop, run_context_loop_rlm};

#[cfg(test)]
use self::finalize::extract_atomic_claims;
#[cfg(test)]
use pecr_contracts::ClaimStatus;

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
        .route("/v1/run", post(run))
        .route("/v1/replays", get(list_replays))
        .route("/v1/replays/{run_id}", get(get_replay))
        .route("/v1/evaluations", post(submit_evaluation))
        .route("/v1/evaluations/scorecards", get(get_scorecards))
        .route("/v1/evaluations/{evaluation_id}", get(get_evaluation))
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
    let gateway_ready = {
        let url = format!("{}/readyz", state.config.gateway_url.trim_end_matches('/'));
        tokio::time::timeout(Duration::from_secs(2), state.http.get(url).send())
            .await
            .is_ok_and(|resp| resp.map(|r| r.status().is_success()).unwrap_or(false))
    };

    let auth_ready = match state.config.auth_mode {
        AuthMode::Local => true,
        AuthMode::Oidc => state.oidc.is_some(),
    };

    let mut checks = BTreeMap::new();
    checks.insert("gateway", gateway_ready);
    checks.insert("auth", auth_ready);

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
            ControllerEngine::Rlm => run_context_loop_rlm(&state, ctx, &query, &budget).await?,
        };
        let loop_terminal_mode = loop_result.terminal_mode;
        let loop_response_text = loop_result.response_text.clone();
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

            let response_text = loop_result
                .response_text
                .unwrap_or_else(|| response_text_for_terminal_mode(loop_terminal_mode));
            let claim_map = build_claim_map(&response_text, loop_terminal_mode);

            let finalized = finalize_session(&state, ctx, response_text, claim_map).await?;

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
        };
        if let Err(err) = run_replay_store_io(&state, move |replay_store| {
            replay_store.persist_run(persisted_run)
        })
        .await
        {
            tracing::warn!(
                request_id = %request_id,
                trace_id = %run_response.trace_id,
                principal_id = %principal_id,
                error = %err,
                "controller.replay_persist_failed"
            );
        }

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

#[derive(Debug, Deserialize)]
struct ReplayListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    engine_mode: Option<EngineMode>,
}

#[derive(Debug, Serialize)]
struct ReplayListResponse {
    replays: Vec<ReplayBundleMetadata>,
}

#[derive(Debug, Serialize)]
struct ReplayScorecardsResponse {
    scorecards: Vec<RunQualityScorecard>,
}

async fn list_replays(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReplayListQuery>,
) -> Result<Json<ReplayListResponse>, ApiError> {
    let principal = extract_principal(&state, &headers).await?;
    let principal_id_hash = hash_principal_id(&principal.principal_id);
    let limit = query
        .limit
        .unwrap_or(state.config.replay_list_limit)
        .max(1)
        .min(state.config.replay_list_limit);
    let engine_mode = query.engine_mode;
    let replays = run_replay_store_io(&state, move |replay_store| {
        replay_store.list_replay_metadata(&principal_id_hash, limit, engine_mode)
    })
    .await
    .map_err(map_replay_store_error)?;

    Ok(Json(ReplayListResponse { replays }))
}

async fn get_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<ReplayBundle>, ApiError> {
    let principal = extract_principal(&state, &headers).await?;
    let principal_id_hash = hash_principal_id(&principal.principal_id);
    let Some(bundle) = run_replay_store_io(&state, move |replay_store| {
        replay_store.load_replay(&principal_id_hash, run_id.as_str())
    })
    .await
    .map_err(map_replay_store_error)?
    else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "ERR_REPLAY_NOT_FOUND",
            "replay run was not found".to_string(),
            TerminalMode::InsufficientPermission,
            false,
        ));
    };

    Ok(Json(bundle))
}

async fn submit_evaluation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReplayEvaluationSubmission>,
) -> Result<Json<ReplayEvaluationResult>, ApiError> {
    if let Some(min_quality_score) = req.min_quality_score
        && !(0.0..=100.0).contains(&min_quality_score)
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "min_quality_score must be in [0, 100]".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    if let Some(max_source_unavailable_rate) = req.max_source_unavailable_rate
        && !(0.0..=1.0).contains(&max_source_unavailable_rate)
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "max_source_unavailable_rate must be in [0, 1]".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let principal = extract_principal(&state, &headers).await?;
    let principal_id_hash = hash_principal_id(&principal.principal_id);
    let max_runs = state.config.replay_list_limit;
    let result = run_replay_store_io(&state, move |replay_store| {
        replay_store.submit_evaluation(&principal_id_hash, req, max_runs)
    })
    .await
    .map_err(map_replay_store_error)?;

    Ok(Json(result))
}

async fn get_evaluation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(evaluation_id): Path<String>,
) -> Result<Json<ReplayEvaluationResult>, ApiError> {
    let principal = extract_principal(&state, &headers).await?;
    let principal_id_hash = hash_principal_id(&principal.principal_id);
    let Some(result) = run_replay_store_io(&state, move |replay_store| {
        replay_store.load_evaluation(&principal_id_hash, evaluation_id.as_str())
    })
    .await
    .map_err(map_replay_store_error)?
    else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "ERR_EVALUATION_NOT_FOUND",
            "evaluation result was not found".to_string(),
            TerminalMode::InsufficientPermission,
            false,
        ));
    };

    Ok(Json(result))
}

async fn get_scorecards(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ReplayListQuery>,
) -> Result<Json<ReplayScorecardsResponse>, ApiError> {
    let principal = extract_principal(&state, &headers).await?;
    let principal_id_hash = hash_principal_id(&principal.principal_id);
    let limit = query
        .limit
        .unwrap_or(state.config.replay_list_limit)
        .max(1)
        .min(state.config.replay_list_limit);
    let engine_mode = query.engine_mode;
    let scorecards = run_replay_store_io(&state, move |replay_store| {
        replay_store.scorecards_for_principal(&principal_id_hash, limit, engine_mode)
    })
    .await
    .map_err(map_replay_store_error)?;

    Ok(Json(ReplayScorecardsResponse { scorecards }))
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
        Ok(err) => (status, Json(err)),
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
    std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("replay store task failed: {}", err),
    )
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
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_REPLAY_STORE",
            format!("replay store operation failed: {}", err),
            TerminalMode::SourceUnavailable,
            true,
        ),
    }
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

fn apply_gateway_auth(
    builder: reqwest::RequestBuilder,
    principal_id: &str,
    authz_header: Option<&str>,
    local_auth_shared_secret: Option<&str>,
) -> reqwest::RequestBuilder {
    match authz_header {
        Some(authz_header) => builder.header(reqwest::header::AUTHORIZATION, authz_header),
        None => {
            let builder = builder.header("x-pecr-principal-id", principal_id);
            if let Some(secret) = local_auth_shared_secret {
                builder.header("x-pecr-local-auth-secret", secret)
            } else {
                builder
            }
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

#[derive(Debug, Serialize, Deserialize)]
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
    #[cfg(feature = "rlm")]
    use std::collections::HashMap;
    #[cfg(feature = "rlm")]
    use std::fs;
    use std::net::SocketAddr;
    #[cfg(feature = "rlm")]
    use std::path::PathBuf;
    use std::sync::Arc;
    #[cfg(feature = "rlm")]
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "rlm")]
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[cfg(feature = "rlm")]
    static RLM_SCRIPT_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(feature = "rlm")]
    #[derive(Clone, Default)]
    struct BatchGatewayMetrics {
        start_order: Arc<Mutex<Vec<String>>>,
        in_flight_by_operator: Arc<Mutex<HashMap<String, usize>>>,
        max_in_flight_by_operator: Arc<Mutex<HashMap<String, usize>>>,
    }

    #[cfg(feature = "rlm")]
    impl BatchGatewayMetrics {
        fn record_start(&self, op_name: &str) {
            self.start_order
                .lock()
                .expect("start order lock should not be poisoned")
                .push(op_name.to_string());

            let mut in_flight = self
                .in_flight_by_operator
                .lock()
                .expect("in flight lock should not be poisoned");
            let current = in_flight.entry(op_name.to_string()).or_insert(0);
            *current += 1;

            let mut max = self
                .max_in_flight_by_operator
                .lock()
                .expect("max in flight lock should not be poisoned");
            let max_seen = max.entry(op_name.to_string()).or_insert(0);
            if *max_seen < *current {
                *max_seen = *current;
            }
        }

        fn record_end(&self, op_name: &str) {
            if let Some(current) = self
                .in_flight_by_operator
                .lock()
                .expect("in flight lock should not be poisoned")
                .get_mut(op_name)
            {
                *current = current.saturating_sub(1);
            }
        }

        fn start_order_snapshot(&self) -> Vec<String> {
            self.start_order
                .lock()
                .expect("start order lock should not be poisoned")
                .clone()
        }

        fn max_in_flight_for(&self, op_name: &str) -> usize {
            *self
                .max_in_flight_by_operator
                .lock()
                .expect("max in flight lock should not be poisoned")
                .get(op_name)
                .unwrap_or(&0)
        }
    }

    #[cfg(feature = "rlm")]
    #[derive(Clone)]
    struct BatchGatewayState {
        metrics: BatchGatewayMetrics,
        delay_ms: u64,
    }

    #[cfg(feature = "rlm")]
    async fn spawn_batch_gateway(
        state: BatchGatewayState,
    ) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        async fn search(
            State(state): State<BatchGatewayState>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            state.metrics.record_start("search");
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
            state.metrics.record_end("search");
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": { "refs": [] }
            }))
        }

        async fn fetch_span(
            State(state): State<BatchGatewayState>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            state.metrics.record_start("fetch_span");
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
            state.metrics.record_end("fetch_span");
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
            .route("/v1/operators/search", post(search))
            .route("/v1/operators/fetch_span", post(fetch_span))
            .with_state(state);

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

    async fn spawn_parallel_fetch_gateway(
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
    ) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        async fn list_versions(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": { "versions": [] }
            }))
        }

        async fn fetch_rows(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": []
            }))
        }

        async fn search(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": {
                    "refs": [
                        {
                            "evidence_unit_id": "ev1",
                            "source_system": "fs_corpus",
                            "object_id": "public/public_1.txt",
                            "version_id": "v1"
                        },
                        {
                            "evidence_unit_id": "ev2",
                            "source_system": "fs_corpus",
                            "object_id": "public/public_2.txt",
                            "version_id": "v2"
                        }
                    ]
                }
            }))
        }

        async fn fetch_span(
            State((in_flight, max_in_flight)): State<(Arc<AtomicUsize>, Arc<AtomicUsize>)>,
            Json(_): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            loop {
                let seen = max_in_flight.load(Ordering::SeqCst);
                if seen >= current {
                    break;
                }
                if max_in_flight
                    .compare_exchange(seen, current, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break;
                }
            }

            tokio::time::sleep(Duration::from_millis(75)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);

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
            .with_state((in_flight, max_in_flight));

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

    fn controller_state(
        gateway_addr: SocketAddr,
        budget: Budget,
        baseline_plan: Vec<crate::config::BaselinePlanStep>,
    ) -> AppState {
        let replay_store_dir =
            std::env::temp_dir().join(format!("pecr-controller-http-tests-{}", Ulid::new()));
        AppState {
            config: ControllerConfig {
                bind_addr: "127.0.0.1:0".parse().expect("bind addr must parse"),
                gateway_url: format!("http://{}", gateway_addr),
                controller_engine: crate::config::ControllerEngine::Baseline,
                model_provider: crate::config::ModelProvider::Mock,
                budget_defaults: budget,
                baseline_plan,
                adaptive_parallelism_enabled: true,
                batch_mode_enabled: true,
                operator_concurrency_policies: std::collections::HashMap::new(),
                auth_mode: crate::config::AuthMode::Local,
                local_auth_shared_secret: None,
                oidc: None,
                metrics_require_auth: false,
                rate_limit_window_secs: 60,
                rate_limit_run_per_window: 1_000,
                replay_store_dir: replay_store_dir.display().to_string(),
                replay_retention_days: 30,
                replay_list_limit: 200,
            },
            http: reqwest::Client::new(),
            oidc: None,
            rate_limiter: RateLimiter::new(Duration::from_secs(60), 1024),
            replay_store: ReplayStore::new(replay_store_dir, 30)
                .expect("replay store should initialize"),
        }
    }

    #[cfg(feature = "rlm")]
    fn write_temp_bridge_script(contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pecr-rlm-bridge-test-{}.py", nanos));
        fs::write(&path, contents).expect("temp bridge script must be writable");
        path
    }

    #[tokio::test]
    async fn replay_and_evaluation_handlers_return_principal_scoped_data() {
        let gateway_addr: SocketAddr = "127.0.0.1:1".parse().expect("socket address should parse");
        let budget = Budget {
            max_operator_calls: 10,
            max_bytes: 2048,
            max_wallclock_ms: 1_000,
            max_recursion_depth: 4,
            max_parallelism: Some(1),
        };
        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );

        let claim_map = build_claim_map(
            "UNKNOWN: insufficient evidence to answer",
            TerminalMode::InsufficientEvidence,
        );
        let replay_meta = state
            .replay_store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-test-replay-api".to_string(),
                principal_id: "dev".to_string(),
                engine_mode: ControllerEngine::Baseline,
                query: "q".to_string(),
                budget,
                session_id: "session".to_string(),
                policy_snapshot_id: "policy".to_string(),
                loop_terminal_mode: TerminalMode::InsufficientEvidence,
                loop_response_text: Some("UNKNOWN: insufficient evidence".to_string()),
                terminal_mode: TerminalMode::InsufficientEvidence,
                response_text: "UNKNOWN: insufficient evidence".to_string(),
                claim_map,
                operator_calls_used: 2,
                bytes_used: 100,
                depth_used: 2,
                evidence_ref_count: 0,
                evidence_unit_ids: Vec::new(),
            })
            .expect("persist run should succeed");

        let mut headers = HeaderMap::new();
        headers.insert("x-pecr-principal-id", HeaderValue::from_static("dev"));

        let list = list_replays(
            State(state.clone()),
            headers.clone(),
            Query(ReplayListQuery {
                limit: Some(10),
                engine_mode: None,
            }),
        )
        .await
        .expect("list_replays should succeed");
        assert_eq!(list.0.replays.len(), 1);

        let replay = get_replay(
            State(state.clone()),
            headers.clone(),
            Path(replay_meta.run_id.clone()),
        )
        .await
        .expect("get_replay should succeed");
        assert_eq!(replay.0.metadata.run_id, replay_meta.run_id);

        let evaluation = submit_evaluation(
            State(state.clone()),
            headers.clone(),
            Json(ReplayEvaluationSubmission {
                evaluation_name: "smoke-eval".to_string(),
                replay_ids: vec![replay.0.metadata.run_id.clone()],
                engine_mode: None,
                min_quality_score: Some(0.0),
                max_source_unavailable_rate: Some(1.0),
            }),
        )
        .await
        .expect("submit_evaluation should succeed");
        assert_eq!(evaluation.0.replay_ids.len(), 1);

        let fetched_evaluation = get_evaluation(
            State(state.clone()),
            headers.clone(),
            Path(evaluation.0.evaluation_id.clone()),
        )
        .await
        .expect("get_evaluation should succeed");
        assert_eq!(
            fetched_evaluation.0.evaluation_id,
            evaluation.0.evaluation_id
        );

        let scorecards = get_scorecards(
            State(state),
            headers,
            Query(ReplayListQuery {
                limit: Some(10),
                engine_mode: None,
            }),
        )
        .await
        .expect("get_scorecards should succeed");
        assert_eq!(scorecards.0.scorecards.len(), 1);
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

        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
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

        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
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
    async fn context_loop_treats_zero_wallclock_as_unbounded() {
        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 0,
            max_recursion_depth: 10,
            max_parallelism: None,
        };

        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
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

        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert_eq!(result.operator_calls_used, 3);
        assert_eq!(result.depth_used, 4);
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

        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
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

    #[tokio::test]
    async fn context_loop_applies_max_parallelism_to_fetch_span_fan_out() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) =
            spawn_parallel_fetch_gateway(in_flight, max_in_flight.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(2),
        };
        let plan = vec![
            crate::config::BaselinePlanStep::Operator {
                op_name: "search".to_string(),
                params: serde_json::json!({ "query": "$query", "limit": 2 }),
            },
            crate::config::BaselinePlanStep::SearchRefFetchSpan { max_refs: 2 },
        ];

        let state = controller_state(gateway_addr, budget.clone(), plan);
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_parallelism",
            trace_id: "trace_test_parallelism",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, "query", &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(result.operator_calls_used, 3);
        assert_eq!(max_in_flight.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_executes_batch_calls_with_parallelism_budget() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("rlm")
            .join("pecr_rlm_bridge.py");
        assert!(script_path.exists(), "rlm bridge script must exist");
        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) =
            spawn_parallel_fetch_gateway(in_flight, max_in_flight.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(2),
        };
        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_parallelism",
            trace_id: "trace_test_rlm_parallelism",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }

        let result = result.expect("rlm context loop should succeed");

        assert_eq!(result.operator_calls_used, 5);
        assert_eq!(max_in_flight.load(Ordering::SeqCst), 2);
        assert_eq!(result.evidence_refs.len(), 2);
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_batch_mode_flag_off_falls_back_to_sequential() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("rlm")
            .join("pecr_rlm_bridge.py");
        assert!(script_path.exists(), "rlm bridge script must exist");

        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) =
            spawn_parallel_fetch_gateway(in_flight, max_in_flight.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(4),
        };
        let mut state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        state.config.batch_mode_enabled = false;
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_batch_off",
            trace_id: "trace_test_rlm_batch_off",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }

        let result = result.expect("rlm context loop should succeed");
        assert_eq!(result.operator_calls_used, 5);
        assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_batch_scheduler_applies_weighted_fairness() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = write_temp_bridge_script(
            r#"#!/usr/bin/env python3
import json
import sys

line = sys.stdin.readline()
json.loads(line)
sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 1}) + "\n")
sys.stdout.flush()

batch_id = "batch_fairness"
calls = [
    {"op_name": "search", "params": {"query": "q1"}},
    {"op_name": "search", "params": {"query": "q2"}},
    {"op_name": "search", "params": {"query": "q3"}},
    {"op_name": "fetch_span", "params": {"object_id": "o1"}},
    {"op_name": "fetch_span", "params": {"object_id": "o2"}},
]
sys.stdout.write(json.dumps({"type": "call_operator_batch", "id": batch_id, "depth": 0, "calls": calls}) + "\n")
sys.stdout.flush()

resp = json.loads(sys.stdin.readline())
if resp.get("type") != "operator_batch_result" or resp.get("id") != batch_id:
    raise SystemExit("unexpected batch response")

sys.stdout.write(json.dumps({"type": "done", "final_answer": "UNKNOWN: fairness"}) + "\n")
sys.stdout.flush()
"#,
        );

        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let metrics = BatchGatewayMetrics::default();
        let (gateway_addr, shutdown, task) = spawn_batch_gateway(BatchGatewayState {
            metrics: metrics.clone(),
            delay_ms: 5,
        })
        .await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(1),
        };
        let mut state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        state.config.operator_concurrency_policies.insert(
            "fetch_span".to_string(),
            crate::config::OperatorConcurrencyPolicy {
                max_in_flight: None,
                fairness_weight: Some(2),
            },
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_fairness",
            trace_id: "trace_test_rlm_fairness",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }
        let _ = fs::remove_file(&script_path);

        let result = result.expect("rlm context loop should succeed");
        assert_eq!(result.operator_calls_used, 5);
        assert_eq!(
            metrics.start_order_snapshot(),
            vec![
                "search".to_string(),
                "fetch_span".to_string(),
                "fetch_span".to_string(),
                "search".to_string(),
                "search".to_string(),
            ]
        );
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_batch_scheduler_enforces_per_operator_in_flight_caps() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = write_temp_bridge_script(
            r#"#!/usr/bin/env python3
import json
import sys

line = sys.stdin.readline()
json.loads(line)
sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 1}) + "\n")
sys.stdout.flush()

batch_id = "batch_caps"
calls = [
    {"op_name": "search", "params": {"query": "q1"}},
    {"op_name": "search", "params": {"query": "q2"}},
    {"op_name": "search", "params": {"query": "q3"}},
    {"op_name": "fetch_span", "params": {"object_id": "o1"}},
    {"op_name": "fetch_span", "params": {"object_id": "o2"}},
    {"op_name": "fetch_span", "params": {"object_id": "o3"}},
]
sys.stdout.write(json.dumps({"type": "call_operator_batch", "id": batch_id, "depth": 0, "calls": calls}) + "\n")
sys.stdout.flush()

resp = json.loads(sys.stdin.readline())
if resp.get("type") != "operator_batch_result" or resp.get("id") != batch_id:
    raise SystemExit("unexpected batch response")

sys.stdout.write(json.dumps({"type": "done", "final_answer": "UNKNOWN: caps"}) + "\n")
sys.stdout.flush()
"#,
        );

        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let metrics = BatchGatewayMetrics::default();
        let (gateway_addr, shutdown, task) = spawn_batch_gateway(BatchGatewayState {
            metrics: metrics.clone(),
            delay_ms: 60,
        })
        .await;

        let budget = Budget {
            max_operator_calls: 100,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(4),
        };
        let mut state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        state.config.operator_concurrency_policies.insert(
            "search".to_string(),
            crate::config::OperatorConcurrencyPolicy {
                max_in_flight: Some(1),
                fairness_weight: None,
            },
        );
        state.config.operator_concurrency_policies.insert(
            "fetch_span".to_string(),
            crate::config::OperatorConcurrencyPolicy {
                max_in_flight: Some(1),
                fairness_weight: None,
            },
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_caps",
            trace_id: "trace_test_rlm_caps",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }
        let _ = fs::remove_file(&script_path);

        let result = result.expect("rlm context loop should succeed");
        assert_eq!(result.operator_calls_used, 6);
        assert_eq!(metrics.max_in_flight_for("search"), 1);
        assert_eq!(metrics.max_in_flight_for("fetch_span"), 1);
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_supports_legacy_bridge_without_start_ack() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = write_temp_bridge_script(
            r#"#!/usr/bin/env python3
import json
import sys

line = sys.stdin.readline()
json.loads(line)
sys.stdout.write(json.dumps({"type": "done", "final_answer": "UNKNOWN: legacy bridge"}) + "\n")
sys.stdout.flush()
"#,
        );

        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

        let budget = Budget {
            max_operator_calls: 10,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(2),
        };
        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_legacy",
            trace_id: "trace_test_rlm_legacy",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }
        let _ = fs::remove_file(&script_path);

        let result = result.expect("legacy bridge without start_ack should still work");
        assert_eq!(
            result.response_text.as_deref(),
            Some("UNKNOWN: legacy bridge")
        );
        assert_eq!(result.operator_calls_used, 0);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "rlm")]
    #[tokio::test]
    async fn rlm_loop_rejects_unsupported_bridge_protocol_version() {
        let _env_lock = RLM_SCRIPT_ENV_LOCK
            .lock()
            .expect("rlm script env lock should not be poisoned");
        let script_path = write_temp_bridge_script(
            r#"#!/usr/bin/env python3
import json
import sys

line = sys.stdin.readline()
json.loads(line)
sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 99}) + "\n")
sys.stdout.flush()
"#,
        );

        let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
        // Safety: this test scopes env var mutation to setup/teardown in the same thread.
        unsafe {
            std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter).await;

        let budget = Budget {
            max_operator_calls: 10,
            max_bytes: 1024 * 1024,
            max_wallclock_ms: 10_000,
            max_recursion_depth: 10,
            max_parallelism: Some(2),
        };
        let state = controller_state(
            gateway_addr,
            budget.clone(),
            crate::config::default_baseline_plan(),
        );
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: "req_test_rlm_bad_protocol",
            trace_id: "trace_test_rlm_bad_protocol",
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, "query", &budget).await;

        shutdown.send(()).ok();
        let _ = task.await;
        if let Some(previous) = previous_script_path {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::set_var("PECR_RLM_SCRIPT_PATH", previous);
            }
        } else {
            // Safety: restoring the test-local env var mutation.
            unsafe {
                std::env::remove_var("PECR_RLM_SCRIPT_PATH");
            }
        }
        let _ = fs::remove_file(&script_path);

        let err = result.expect_err("unsupported bridge protocol must fail");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.1.0.code, "ERR_RLM_BRIDGE_PROTOCOL");
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
