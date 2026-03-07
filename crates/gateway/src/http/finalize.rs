use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use pecr_contracts::canonical;
use pecr_contracts::{ClaimMap, ClaimStatus, TerminalMode};
use pecr_ledger::FinalizeResultRecord;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::auth::{extract_principal, extract_request_id, extract_session_token};
use super::session::Session;
use super::session::{acquire_session_lock, load_session_runtime, persist_session_runtime};
use super::{ApiError, AppState, json_error, opa_error_response};
use crate::opa::OpaCacheKey;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinalizeRequest {
    pub(super) session_id: String,
    pub(super) response_text: String,
    pub(super) claim_map: ClaimMap,
}

#[derive(Debug, Serialize)]
pub(super) struct FinalizeResponse {
    pub(super) terminal_mode: TerminalMode,
    pub(super) trace_id: String,
    pub(super) claim_map: ClaimMap,
    pub(super) response_text: String,
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

pub(super) fn finalize_gate(
    session: &Session,
    mut claim_map: ClaimMap,
    coverage_threshold: f64,
) -> Result<ClaimMap, ApiError> {
    claim_map.coverage_threshold = coverage_threshold;

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

    claim_map.coverage_observed =
        covered_supported_claims as f64 / std::cmp::max(1, supported_claims) as f64;

    let budget_violation = session.operator_calls_used > session.budget.max_operator_calls
        || session.bytes_used > session.budget.max_bytes;

    claim_map.terminal_mode = if !budget_violation
        && supported_claims > 0
        && claim_map.coverage_observed >= coverage_threshold
    {
        TerminalMode::Supported
    } else if supported_claims == 0 && claim_map.terminal_mode != TerminalMode::Supported {
        claim_map.terminal_mode
    } else {
        TerminalMode::InsufficientEvidence
    };

    Ok(claim_map)
}

pub(super) async fn finalize(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<FinalizeRequest>, JsonRejection>,
) -> Result<Json<FinalizeResponse>, ApiError> {
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

        let session_token_hash = super::runtime::sha256_hex(session_token.as_bytes());
        if super::session::unix_epoch_ms_now() > session.session_token_expires_at_epoch_ms
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
        Err(err) => err.status_code(),
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
        Err(err) => crate::metrics::observe_terminal_mode(
            "/v1/finalize",
            err.error_response().terminal_mode_hint.as_str(),
        ),
    }

    handler_result
}
