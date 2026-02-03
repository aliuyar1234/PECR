use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use hex::ToHex;
use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, ClaimMap, ClaimStatus, EvidenceUnitRef, PolicySnapshot, TerminalMode,
};
use pecr_ledger::{FinalizeResultRecord, LedgerWriter};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use similar::TextDiff;
use sqlx::{PgPool, Row};
use tokio::sync::RwLock;
use ulid::Ulid;

use crate::config::{GatewayConfig, StartupError};
use crate::opa::{OpaCacheKey, OpaClient};

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    ledger: LedgerWriter,
    opa: OpaClient,
    pg_pool: PgPool,
    fs_versions: Arc<RwLock<FsVersionCache>>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

type ApiError = (StatusCode, Json<ErrorResponse>);
type FilterEq = (String, String);

#[derive(Debug, Clone)]
struct Session {
    session_id: String,
    trace_id: String,
    principal_id: String,
    tenant_id: String,
    policy_snapshot_id: String,
    policy_snapshot_hash: String,
    budget: Budget,
    session_token: String,
    session_token_expires_at: Instant,
    operator_calls_used: u32,
    bytes_used: u64,
    evidence_unit_ids: HashSet<String>,
    finalized: bool,
}

pub async fn router(config: GatewayConfig) -> Result<Router, StartupError> {
    let ledger = LedgerWriter::connect_and_migrate(
        &config.db_url,
        Duration::from_millis(config.ledger_write_timeout_ms),
    )
    .await
    .map_err(|_| StartupError {
        code: "ERR_LEDGER_UNAVAILABLE",
        message: "failed to initialize ledger".to_string(),
    })?;

    let opa = OpaClient::new(
        config.opa_url.clone(),
        Duration::from_millis(config.opa_timeout_ms),
        config.cache_max_entries,
        Duration::from_millis(config.cache_ttl_ms),
    )
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

    let fs_versions = Arc::new(RwLock::new(FsVersionCache::new(
        config.fs_version_cache_max_bytes,
        config.fs_version_cache_max_versions_per_object,
    )));

    let state = AppState {
        config,
        ledger,
        opa,
        pg_pool,
        fs_versions,
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/sessions", post(create_session))
        .route("/v1/operators/{op_name}", post(call_operator))
        .route("/v1/finalize", post(finalize))
        .with_state(state))
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSessionRequest {
    budget: Budget,
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
    let principal_id = extract_principal_id(&headers)?;
    let request_id = extract_request_id(&headers);

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

    let session_id = Ulid::new().to_string();
    let trace_id = Ulid::new().to_string();
    let policy_snapshot_id = Ulid::new().to_string();

    let mut policy_snapshot = PolicySnapshot {
        policy_snapshot_hash: String::new(),
        principal_id: principal_id.clone(),
        tenant_id: "local".to_string(),
        principal_roles: Vec::new(),
        principal_attrs_hash: canonical::hash_canonical_json(&serde_json::json!({})),
        policy_bundle_hash: state.config.policy_bundle_hash.clone(),
        as_of_time: state.config.as_of_time_default.clone(),
        evaluated_at: state.config.as_of_time_default.clone(),
    };
    policy_snapshot.policy_snapshot_hash = policy_snapshot.compute_hash();

    let budget_hash = sha256_hex(&serde_json::to_vec(&req.budget).unwrap_or_else(|_| Vec::new()));
    let decision = state
        .opa
        .decide(
            serde_json::json!({
                "action": "create_session",
                "principal_id": principal_id.as_str(),
                "policy_snapshot_hash": policy_snapshot.policy_snapshot_hash.as_str(),
                "policy_bundle_hash": state.config.policy_bundle_hash.as_str(),
                "as_of_time": state.config.as_of_time_default.as_str(),
                "budget_hash": budget_hash,
                "request_id": request_id.as_str(),
            }),
            Some(OpaCacheKey::create_session(
                &policy_snapshot.policy_snapshot_hash,
            )),
        )
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
    let session_token_expires_at =
        Instant::now() + Duration::from_secs(state.config.session_token_ttl_secs);

    tracing::info!(
        trace_id = %trace_id,
        request_id = %request_id,
        session_id = %session_id,
        principal_id = %principal_id,
        "gateway.create_session"
    );

    state
        .ledger
        .create_session(
            &session_id,
            &trace_id,
            &principal_id,
            &req.budget,
            &policy_snapshot_id,
            &policy_snapshot,
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

    let session = Session {
        session_id: session_id.clone(),
        trace_id: trace_id.clone(),
        principal_id: principal_id.clone(),
        tenant_id: policy_snapshot.tenant_id.clone(),
        policy_snapshot_id: policy_snapshot_id.clone(),
        policy_snapshot_hash: policy_snapshot.policy_snapshot_hash.clone(),
        budget: req.budget.clone(),
        session_token: session_token.clone(),
        session_token_expires_at,
        operator_calls_used: 0,
        bytes_used: 0,
        evidence_unit_ids: HashSet::new(),
        finalized: false,
    };

    state
        .sessions
        .write()
        .await
        .insert(session_id.clone(), session);

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
    let principal_id = extract_principal_id(&headers)?;
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

    let params_bytes = serde_json::to_vec(&req.params)
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    let params_hash = sha256_hex(&serde_json::to_vec(&req.params).unwrap_or_else(|_| Vec::new()));

    let mut sessions = state.sessions.write().await;
    let Some(session) = sessions.get_mut(&req.session_id) else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "ERR_INVALID_PARAMS",
            "unknown session_id".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    };

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

    if Instant::now() > session.session_token_expires_at || session.session_token != session_token {
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
        "as_of_time": state.config.as_of_time_default.as_str(),
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
    let decision = match state.opa.decide(opa_input, Some(cache_key)).await {
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

    let (status, error_code, response, evidence_emitted) = match op_name.as_str() {
        "search" => {
            let refs = search_from_fs(
                &state.config.fs_corpus_path,
                &state.config.as_of_time_default,
                &session.policy_snapshot_hash,
                &req.params,
            )?;
            (
                StatusCode::OK,
                None,
                OperatorCallResponse {
                    terminal_mode: TerminalMode::Supported,
                    result: serde_json::json!({ "refs": refs }),
                },
                Vec::new(),
            )
        }
        "list_versions" => {
            let versions = list_versions_from_fs(
                &state.fs_versions,
                &state.config.fs_corpus_path,
                &state.config.as_of_time_default,
                &req.params,
            )
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
            let evidence = diff_from_fs(
                &state.fs_versions,
                &state.config.fs_corpus_path,
                &state.config.as_of_time_default,
                state.config.fs_diff_max_bytes,
                &session.policy_snapshot_id,
                &session.policy_snapshot_hash,
                &req.params,
            )
            .await?;
            let result = serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
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
            let evidence = fetch_span_from_fs(
                &state.config.fs_corpus_path,
                &state.config.as_of_time_default,
                &session.policy_snapshot_id,
                &session.policy_snapshot_hash,
                &req.params,
            )?;
            let result = serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
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

            let evidence = fetch_rows_from_pg_safeview(
                &state.pg_pool,
                &state.config,
                &tenant_id,
                &policy_snapshot_id,
                &policy_snapshot_hash,
                &req.params,
            )
            .await?;

            let result = serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
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

            let evidence = aggregate_from_pg_safeview(
                &state.pg_pool,
                &state.config,
                &tenant_id,
                &policy_snapshot_id,
                &policy_snapshot_hash,
                &req.params,
            )
            .await?;

            let result = serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
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

    let result_bytes = serde_json::to_vec(&response.result)
        .map(|v| v.len() as u64)
        .unwrap_or(0);
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
}

impl FsVersionCache {
    fn new(max_total_bytes: usize, max_versions_per_object: usize) -> Self {
        Self {
            max_total_bytes,
            max_versions_per_object: max_versions_per_object.max(1),
            total_bytes: 0,
            fifo: VecDeque::new(),
            entries: HashMap::new(),
        }
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

fn read_object_bytes_from_fs(
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
    let base_canon = base.canonicalize().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let full_path = base.join(object_rel);
    let full_canon = full_path.canonicalize().map_err(|_| {
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

    std::fs::read(&full_canon).map_err(|_| {
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

    let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id)?;

    let version_id = sha256_hex(&bytes);
    let metadata_hash = sha256_hex(object_id.as_bytes());

    let mut cache = fs_versions.write().await;
    cache.insert(object_id, &version_id, bytes);
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

        let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id)?;
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

fn fetch_span_from_fs(
    fs_corpus_path: &str,
    as_of_time_default: &str,
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
    let base_canon = base.canonicalize().map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let full_path = base.join(object_rel);
    let full_canon = full_path.canonicalize().map_err(|_| {
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

    let bytes = std::fs::read(&full_canon).map_err(|_| {
        json_error(
            StatusCode::NOT_FOUND,
            "ERR_SOURCE_UNAVAILABLE",
            "object not found".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let version_id = sha256_hex(&bytes);

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
        "as_of_time": as_of_time_default,
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
        retrieved_at: as_of_time_default.to_string(),
        as_of_time: as_of_time_default.to_string(),
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

async fn fetch_rows_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<Vec<pecr_contracts::EvidenceUnit>, (StatusCode, Json<ErrorResponse>)> {
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

    let mut select_fields = spec
        .primary_key_fields
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    select_fields.push(spec.version_field.to_string());
    for f in &fields {
        if !select_fields.iter().any(|existing| existing == f) {
            select_fields.push(f.clone());
        }
    }

    let select_sql = select_fields
        .iter()
        .map(|f| format!("{}::text as {}", f, f))
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

    let as_of_time_default = config.as_of_time_default.as_str();

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
    for row in rows {
        let mut primary_key = serde_json::Map::new();
        let mut pk_values = Vec::with_capacity(spec.primary_key_fields.len());
        for pk in spec.primary_key_fields {
            let value: Option<String> = row.try_get(pk).map_err(|_| schema_error())?;
            let value = value.ok_or_else(&schema_error)?;
            pk_values.push(value.clone());
            primary_key.insert(pk.to_string(), serde_json::Value::String(value));
        }

        let updated_at: Option<String> = row
            .try_get(spec.version_field)
            .map_err(|_| schema_error())?;
        let updated_at = updated_at.ok_or_else(&schema_error)?;
        let version_id = sha256_hex(updated_at.as_bytes());

        let mut content = serde_json::Map::new();
        for field in &fields {
            let value: Option<String> = row.try_get(field.as_str()).map_err(|_| schema_error())?;
            content.insert(
                field.clone(),
                value
                    .map(serde_json::Value::String)
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
            "as_of_time": as_of_time_default,
            "policy_snapshot_hash": policy_snapshot_hash,
            "transform_chain": transform_chain,
        });
        let evidence_unit_id = canonical::hash_canonical_json(&identity);

        out.push(pecr_contracts::EvidenceUnit {
            source_system: "pg_safeview".to_string(),
            object_id,
            version_id,
            span_or_row_spec,
            content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
            content: Some(content),
            content_hash,
            retrieved_at: as_of_time_default.to_string(),
            as_of_time: as_of_time_default.to_string(),
            policy_snapshot_id: policy_snapshot_id.to_string(),
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id,
        });
    }

    Ok(out)
}

async fn aggregate_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
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

    let as_of_time_default = config.as_of_time_default.as_str();
    let version_id = content_hash.clone();
    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "pg_safeview",
        "object_id": spec.view_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time_default,
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
        retrieved_at: as_of_time_default.to_string(),
        as_of_time: as_of_time_default.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeRequest {
    session_id: String,
    response_text: String,
    claim_map: ClaimMap,
}

#[derive(Debug, Serialize)]
struct FinalizeResponse {
    terminal_mode: TerminalMode,
    trace_id: String,
    claim_map: ClaimMap,
    response_text: String,
}

fn claim_status_str(status: ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Supported => "SUPPORTED",
        ClaimStatus::Assumption => "ASSUMPTION",
        ClaimStatus::Unknown => "UNKNOWN",
    }
}

fn claim_id_for(claim_text: &str, status: ClaimStatus, evidence_unit_ids: &[String]) -> String {
    canonical::hash_canonical_json(&serde_json::json!({
        "claim_text": claim_text,
        "status": claim_status_str(status),
        "evidence_unit_ids": evidence_unit_ids,
    }))
}

fn finalize_gate(session: &Session, mut claim_map: ClaimMap) -> Result<ClaimMap, ApiError> {
    if !claim_map.coverage_threshold.is_finite()
        || !(0.0..=1.0).contains(&claim_map.coverage_threshold)
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "claim_map.coverage_threshold must be between 0 and 1".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let mut supported_claims: u64 = 0;
    let mut covered_supported_claims: u64 = 0;

    for claim in &mut claim_map.claims {
        let trimmed = claim.claim_text.trim();
        if trimmed.is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "claim.claim_text must be non-empty".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
        claim.claim_text = trimmed.to_string();

        claim.evidence_unit_ids.sort();
        claim.evidence_unit_ids.dedup();

        for evidence_unit_id in &claim.evidence_unit_ids {
            if !canonical::is_sha256_hex(evidence_unit_id) {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    "claim.evidence_unit_ids must be sha256 hex".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                ));
            }

            if !session.evidence_unit_ids.contains(evidence_unit_id) {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    "claim references evidence not emitted in this trace".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                ));
            }
        }

        if claim.status == ClaimStatus::Supported {
            if claim.evidence_unit_ids.is_empty() {
                claim.status = ClaimStatus::Unknown;
            } else {
                supported_claims = supported_claims.saturating_add(1);
                covered_supported_claims = covered_supported_claims.saturating_add(1);
            }
        }

        claim.claim_id = claim_id_for(&claim.claim_text, claim.status, &claim.evidence_unit_ids);
    }

    claim_map.coverage_observed = if supported_claims == 0 {
        1.0
    } else {
        covered_supported_claims as f64 / supported_claims as f64
    };

    let budget_violation = session.operator_calls_used > session.budget.max_operator_calls
        || session.bytes_used > session.budget.max_bytes;

    claim_map.terminal_mode = if !budget_violation
        && supported_claims > 0
        && claim_map.coverage_observed >= claim_map.coverage_threshold
    {
        TerminalMode::Supported
    } else {
        TerminalMode::InsufficientEvidence
    };

    Ok(claim_map)
}

async fn finalize(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<FinalizeRequest>, JsonRejection>,
) -> Result<Json<FinalizeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let principal_id = extract_principal_id(&headers)?;
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

    let mut sessions = state.sessions.write().await;
    let Some(session) = sessions.get_mut(&req.session_id) else {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "ERR_INVALID_PARAMS",
            "unknown session_id".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    };

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

    if Instant::now() > session.session_token_expires_at || session.session_token != session_token {
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
        "as_of_time": state.config.as_of_time_default.as_str(),
        "request_id": request_id.as_str(),
    });
    let cache_key = OpaCacheKey::finalize(&session.policy_snapshot_hash);
    let decision = match state.opa.decide(opa_input, Some(cache_key)).await {
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

    let FinalizeRequest {
        claim_map,
        response_text,
        session_id: _,
    } = req;
    let claim_map = finalize_gate(session, claim_map)?;

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

    state
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

    session.finalized = true;

    Ok(Json(FinalizeResponse {
        terminal_mode: claim_map.terminal_mode,
        trace_id: session.trace_id.clone(),
        claim_map,
        response_text,
    }))
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

fn is_allowlisted_operator(op_name: &str) -> bool {
    matches!(
        op_name,
        "search" | "fetch_span" | "fetch_rows" | "aggregate" | "list_versions" | "diff" | "redact"
    )
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
            budget,
            session_token: "token".to_string(),
            session_token_expires_at: Instant::now() + Duration::from_secs(60),
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

        let err = finalize_gate(&session, claim_map).unwrap_err();
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

        let out = finalize_gate(&session, claim_map).expect("gate should succeed");
        assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
        assert_eq!(out.coverage_observed, 1.0);
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

        let out = finalize_gate(&session, claim_map).expect("gate should succeed");
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

        let out = finalize_gate(&session, claim_map).expect("gate should succeed");
        assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
    }
}
