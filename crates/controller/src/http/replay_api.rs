use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use pecr_contracts::{
    EngineMode, ReplayBundle, ReplayBundleMetadata, ReplayEvaluationResult,
    ReplayEvaluationSubmission, RunQualityScorecard, TerminalMode,
};
use serde::{Deserialize, Serialize};

use super::{
    ApiError, AppState, extract_principal, json_error, map_replay_store_error, run_replay_store_io,
};
use crate::replay::hash_principal_id;

#[derive(Debug, Deserialize)]
pub(super) struct ReplayListQuery {
    #[serde(default)]
    pub(super) limit: Option<usize>,
    #[serde(default)]
    pub(super) engine_mode: Option<EngineMode>,
}

#[derive(Debug, Serialize)]
pub(super) struct ReplayListResponse {
    pub(super) replays: Vec<ReplayBundleMetadata>,
}

#[derive(Debug, Serialize)]
pub(super) struct ReplayScorecardsResponse {
    pub(super) scorecards: Vec<RunQualityScorecard>,
}

pub(super) async fn list_replays(
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

pub(super) async fn get_replay(
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

pub(super) async fn submit_evaluation(
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

pub(super) async fn get_evaluation(
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

pub(super) async fn get_scorecards(
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
