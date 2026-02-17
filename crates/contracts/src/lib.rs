use serde::{Deserialize, Serialize};

pub mod canonical;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalMode {
    Supported,
    InsufficientEvidence,
    InsufficientPermission,
    SourceUnavailable,
}

impl TerminalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TerminalMode::Supported => "SUPPORTED",
            TerminalMode::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
            TerminalMode::InsufficientPermission => "INSUFFICIENT_PERMISSION",
            TerminalMode::SourceUnavailable => "SOURCE_UNAVAILABLE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceContentType {
    #[serde(rename = "text/plain")]
    TextPlain,
    #[serde(rename = "application/json")]
    ApplicationJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceUnitRef {
    pub evidence_unit_id: String,
    pub source_system: String,
    pub object_id: String,
    pub version_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformStep {
    pub transform_type: String,
    pub transform_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceUnit {
    pub source_system: String,
    pub object_id: String,
    pub version_id: String,
    pub span_or_row_spec: serde_json::Value,
    pub content_type: EvidenceContentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
    pub content_hash: String,
    pub retrieved_at: String,
    pub as_of_time: String,
    pub policy_snapshot_id: String,
    pub policy_snapshot_hash: String,
    pub transform_chain: Vec<TransformStep>,
    pub evidence_unit_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub policy_snapshot_hash: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub principal_roles: Vec<String>,
    pub principal_attrs_hash: String,
    pub policy_bundle_hash: String,
    pub as_of_time: String,
    pub evaluated_at: String,
}

impl PolicySnapshot {
    pub fn compute_hash(&self) -> String {
        let mut roles = self.principal_roles.clone();
        roles.sort();

        canonical::hash_canonical_json(&serde_json::json!(
            {
                "principal_id": self.principal_id.clone(),
                "tenant_id": self.tenant_id.clone(),
                "principal_roles": roles,
                "principal_attrs_hash": self.principal_attrs_hash.clone(),
                "policy_bundle_hash": self.policy_bundle_hash.clone(),
                "as_of_time": self.as_of_time.clone(),
            }
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimStatus {
    Supported,
    Assumption,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub claim_text: String,
    pub status: ClaimStatus,
    pub evidence_unit_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMap {
    pub claim_map_id: String,
    pub terminal_mode: TerminalMode,
    pub claims: Vec<Claim>,
    pub coverage_threshold: f64,
    pub coverage_observed: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub trace_id: String,
    pub event_type: String,
    pub event_time: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub max_operator_calls: u32,
    pub max_bytes: u64,
    pub max_wallclock_ms: u64,
    pub max_recursion_depth: u32,
    #[serde(default)]
    pub max_parallelism: Option<u32>,
}

impl Budget {
    pub const MAX_OPERATOR_CALLS_HARD_LIMIT: u32 = 10_000;
    pub const MAX_BYTES_HARD_LIMIT: u64 = 64 * 1024 * 1024;
    pub const MAX_WALLCLOCK_MS_HARD_LIMIT: u64 = 300_000;
    pub const MAX_RECURSION_DEPTH_HARD_LIMIT: u32 = 20;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_operator_calls > Self::MAX_OPERATOR_CALLS_HARD_LIMIT {
            return Err("max_operator_calls out of range");
        }
        if self.max_bytes > Self::MAX_BYTES_HARD_LIMIT {
            return Err("max_bytes out of range");
        }
        if self.max_wallclock_ms > Self::MAX_WALLCLOCK_MS_HARD_LIMIT {
            return Err("max_wallclock_ms out of range");
        }
        if self.max_recursion_depth > Self::MAX_RECURSION_DEPTH_HARD_LIMIT {
            return Err("max_recursion_depth out of range");
        }
        if let Some(max_parallelism) = self.max_parallelism
            && !(1..=256).contains(&max_parallelism)
        {
            return Err("max_parallelism out of range");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_snapshot_hash_sorts_roles_and_ignores_evaluated_at() {
        let a = PolicySnapshot {
            policy_snapshot_hash: "unused".to_string(),
            principal_id: "principal".to_string(),
            tenant_id: "tenant".to_string(),
            principal_roles: vec!["z".to_string(), "a".to_string()],
            principal_attrs_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            policy_bundle_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            evaluated_at: "2026-02-03T00:00:00Z".to_string(),
        };

        let mut b = a.clone();
        b.principal_roles = vec!["a".to_string(), "z".to_string()];
        b.evaluated_at = "2099-01-01T00:00:00Z".to_string();

        assert_eq!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn budget_validate_rejects_excessive_max_bytes() {
        let budget = Budget {
            max_operator_calls: 10,
            max_bytes: Budget::MAX_BYTES_HARD_LIMIT + 1,
            max_wallclock_ms: 1000,
            max_recursion_depth: 1,
            max_parallelism: Some(4),
        };

        let err = budget.validate().expect_err("budget should be rejected");
        assert_eq!(err, "max_bytes out of range");
    }

    #[test]
    fn budget_validate_rejects_excessive_wallclock() {
        let budget = Budget {
            max_operator_calls: 10,
            max_bytes: 1024,
            max_wallclock_ms: Budget::MAX_WALLCLOCK_MS_HARD_LIMIT + 1,
            max_recursion_depth: 1,
            max_parallelism: Some(4),
        };

        let err = budget.validate().expect_err("budget should be rejected");
        assert_eq!(err, "max_wallclock_ms out of range");
    }

    #[test]
    fn budget_validate_rejects_invalid_parallelism_range() {
        let too_low = Budget {
            max_operator_calls: 10,
            max_bytes: 1024,
            max_wallclock_ms: 1000,
            max_recursion_depth: 1,
            max_parallelism: Some(0),
        };
        let too_high = Budget {
            max_operator_calls: 10,
            max_bytes: 1024,
            max_wallclock_ms: 1000,
            max_recursion_depth: 1,
            max_parallelism: Some(257),
        };

        assert_eq!(
            too_low.validate().expect_err("parallelism=0 must fail"),
            "max_parallelism out of range"
        );
        assert_eq!(
            too_high.validate().expect_err("parallelism=257 must fail"),
            "max_parallelism out of range"
        );
    }

    #[test]
    fn budget_validate_accepts_boundary_values() {
        let budget = Budget {
            max_operator_calls: Budget::MAX_OPERATOR_CALLS_HARD_LIMIT,
            max_bytes: Budget::MAX_BYTES_HARD_LIMIT,
            max_wallclock_ms: 0,
            max_recursion_depth: Budget::MAX_RECURSION_DEPTH_HARD_LIMIT,
            max_parallelism: Some(256),
        };

        budget
            .validate()
            .expect("boundary values should be accepted");
    }

    #[test]
    fn policy_snapshot_hash_changes_when_policy_input_changes() {
        let base = PolicySnapshot {
            policy_snapshot_hash: "unused".to_string(),
            principal_id: "principal".to_string(),
            tenant_id: "tenant".to_string(),
            principal_roles: vec!["viewer".to_string()],
            principal_attrs_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            policy_bundle_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            evaluated_at: "1970-01-01T00:00:01Z".to_string(),
        };

        let mut changed = base.clone();
        changed.policy_bundle_hash =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();

        assert_ne!(base.compute_hash(), changed.compute_hash());
    }
}
