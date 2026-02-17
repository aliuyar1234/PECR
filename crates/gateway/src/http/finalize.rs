use axum::http::StatusCode;
use pecr_contracts::canonical;
use pecr_contracts::{ClaimMap, ClaimStatus, TerminalMode};
use serde::{Deserialize, Serialize};

use super::session::Session;
use super::{ApiError, json_error};

#[derive(Debug, Deserialize)]
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
    } else {
        TerminalMode::InsufficientEvidence
    };

    Ok(claim_map)
}
