use pecr_contracts::canonical;
use pecr_contracts::{Claim, ClaimMap, ClaimStatus, TerminalMode};
use ulid::Ulid;

pub(super) fn response_text_for_terminal_mode(terminal_mode: TerminalMode) -> String {
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

pub(super) fn build_claim_map(response_text: &str, terminal_mode: TerminalMode) -> ClaimMap {
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

pub(super) fn extract_atomic_claims(response_text: &str) -> Vec<(ClaimStatus, String)> {
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
