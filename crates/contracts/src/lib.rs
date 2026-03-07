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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    Baseline,
    BeamPlanner,
    Rlm,
}

impl EngineMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EngineMode::Baseline => "baseline",
            EngineMode::BeamPlanner => "beam_planner",
            EngineMode::Rlm => "rlm",
        }
    }
}

pub const PLANNER_CONTRACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePackMode {
    Raw,
    Compact,
    Summary,
    Diff,
    Mixed,
}

impl EvidencePackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidencePackMode::Raw => "raw",
            EvidencePackMode::Compact => "compact",
            EvidencePackMode::Summary => "summary",
            EvidencePackMode::Diff => "diff",
            EvidencePackMode::Mixed => "mixed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerIntent {
    Default,
    StructuredLookup,
    StructuredAggregation,
    EvidenceLookup,
    VersionReview,
    StructuredEvidenceLookup,
    StructuredAggregationEvidence,
    StructuredVersionReview,
}

impl PlannerIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            PlannerIntent::Default => "default",
            PlannerIntent::StructuredLookup => "structured_lookup",
            PlannerIntent::StructuredAggregation => "structured_aggregation",
            PlannerIntent::EvidenceLookup => "evidence_lookup",
            PlannerIntent::VersionReview => "version_review",
            PlannerIntent::StructuredEvidenceLookup => "structured_evidence_lookup",
            PlannerIntent::StructuredAggregationEvidence => "structured_aggregation_evidence",
            PlannerIntent::StructuredVersionReview => "structured_version_review",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientResponseKind {
    Blocked,
    Ambiguous,
    SourceDown,
    PartialAnswer,
}

impl ClientResponseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientResponseKind::Blocked => "blocked",
            ClientResponseKind::Ambiguous => "ambiguous",
            ClientResponseKind::SourceDown => "source_down",
            ClientResponseKind::PartialAnswer => "partial_answer",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_byte: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_byte: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_score: Option<u32>,
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
#[serde(deny_unknown_fields)]
pub struct StructuredMetricDescriptor {
    pub name: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredDimensionValueCount {
    pub value: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredDimensionDescriptor {
    pub field: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_values: Vec<StructuredDimensionValueCount>,
    #[serde(default)]
    pub drilldown_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredDrilldownHint {
    pub dimension: String,
    pub filter_spec: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredDimensionDiscoveryResult {
    pub view_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub available_dimensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<StructuredMetricDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dimensions: Vec<StructuredDimensionDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters_applied: Option<serde_json::Value>,
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
pub struct ClaimEvidenceSnippet {
    pub evidence_unit_id: String,
    pub location: String,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub claim_text: String,
    pub status: ClaimStatus,
    pub evidence_unit_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_snippets: Vec<ClaimEvidenceSnippet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationPrompt {
    pub question: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeAskCapability {
    pub capability_id: String,
    pub intent: PlannerIntent,
    pub title: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub view_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dimension_labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_hints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeAskCatalog {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<SafeAskCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_queries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimMap {
    pub claim_map_id: String,
    pub terminal_mode: TerminalMode,
    pub claims: Vec<Claim>,
    pub coverage_threshold: f64,
    pub coverage_observed: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clarification_prompt: Option<ClarificationPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_planner_step_params() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn default_planner_max_refs() -> usize {
    2
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannerStep {
    Operator {
        op_name: String,
        #[serde(default = "default_planner_step_params")]
        params: serde_json::Value,
    },
    SearchRefFetchSpan {
        #[serde(default = "default_planner_max_refs")]
        max_refs: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerHints {
    pub intent: PlannerIntent,
    #[serde(default)]
    pub recommended_path: Vec<PlannerStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerRecoveryContext {
    pub failed_step: String,
    pub failure_terminal_mode: TerminalMode,
    #[serde(default)]
    pub attempted_path: Vec<PlannerStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step_details: Option<PlannerStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerToolSchema {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_params: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_params: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerObservationOutcome {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerObservation {
    pub step: PlannerStep,
    pub outcome: PlannerObservationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_mode: Option<TerminalMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerFailureFeedback {
    pub failure_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<PlannerStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_mode: Option<TerminalMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    pub schema_version: u32,
    pub query: String,
    pub budget: Budget,
    pub context_budget: ContextBudget,
    pub planner_hints: PlannerHints,
    pub preferred_evidence_pack_mode: EvidencePackMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_context: Option<PlannerRecoveryContext>,
    #[serde(default)]
    pub available_operator_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operator_schemas: Vec<PlannerToolSchema>,
    #[serde(default)]
    pub allow_search_ref_fetch_span: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_observations: Vec<PlannerObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clarification_opportunities: Vec<ClarificationPrompt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_feedback: Vec<PlannerFailureFeedback>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanResponse {
    pub schema_version: u32,
    #[serde(default)]
    pub steps: Vec<PlannerStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPlannerDecisionSummary {
    pub planner_source: String,
    pub stop_reason: String,
    pub selected_for_execution: bool,
    #[serde(default)]
    pub used_fallback_plan: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_from_step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_usefulness_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_usefulness_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPlannerTrace {
    pub plan_request: PlanRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_steps: Vec<PlannerStep>,
    pub decision_summary: ReplayPlannerDecisionSummary,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundleMetadata {
    pub schema_version: u32,
    pub run_id: String,
    pub trace_id: String,
    pub request_id: String,
    pub principal_id_hash: String,
    pub engine_mode: EngineMode,
    pub recorded_at_unix_ms: u64,
    pub terminal_mode: TerminalMode,
    pub quality_score: f64,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundle {
    pub metadata: ReplayBundleMetadata,
    pub query: String,
    pub budget: Budget,
    pub session_id: String,
    pub policy_snapshot_id: String,
    pub loop_terminal_mode: TerminalMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_response_text: Option<String>,
    pub response_text: String,
    pub claim_map: ClaimMap,
    pub operator_calls_used: u32,
    pub bytes_used: u64,
    pub depth_used: u32,
    pub evidence_ref_count: u32,
    pub evidence_unit_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub planner_traces: Vec<ReplayPlannerTrace>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEvaluationSubmission {
    pub evaluation_name: String,
    #[serde(default)]
    pub replay_ids: Vec<String>,
    #[serde(default)]
    pub engine_mode: Option<EngineMode>,
    #[serde(default)]
    pub min_quality_score: Option<f64>,
    #[serde(default)]
    pub max_source_unavailable_rate: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRunScore {
    pub run_id: String,
    pub trace_id: String,
    pub engine_mode: EngineMode,
    pub terminal_mode: TerminalMode,
    pub quality_score: f64,
    pub coverage_observed: f64,
    #[serde(default)]
    pub citation_quality: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<ClientResponseKind>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunQualityScorecard {
    pub engine_mode: EngineMode,
    pub run_count: u64,
    pub average_quality_score: f64,
    pub minimum_quality_score: f64,
    pub maximum_quality_score: f64,
    pub supported_rate: f64,
    pub source_unavailable_rate: f64,
    pub ambiguity_rate: f64,
    pub partial_answer_rate: f64,
    pub refusal_friction_rate: f64,
    pub average_coverage_observed: f64,
    #[serde(default)]
    pub average_citation_quality: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineComparisonSummary {
    pub primary_engine_mode: EngineMode,
    pub secondary_engine_mode: EngineMode,
    pub paired_query_count: u64,
    pub average_quality_score_delta: f64,
    pub supported_rate_delta: f64,
    pub source_unavailable_rate_delta: f64,
    pub average_coverage_observed_delta: f64,
    pub average_citation_quality_delta: f64,
    pub primary_win_rate: f64,
    pub secondary_win_rate: f64,
    pub tie_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub more_helpful_engine_mode: Option<EngineMode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEvaluationResult {
    pub evaluation_id: String,
    pub evaluation_name: String,
    pub principal_id_hash: String,
    pub created_at_unix_ms: u64,
    pub replay_ids: Vec<String>,
    #[serde(default)]
    pub missing_replay_ids: Vec<String>,
    pub run_results: Vec<ReplayRunScore>,
    pub scorecards: Vec<RunQualityScorecard>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_comparisons: Vec<EngineComparisonSummary>,
    pub overall_pass: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBudget {
    pub max_evidence_units: usize,
    pub max_total_chars: usize,
    pub max_structured_rows: usize,
    pub max_inline_citations: usize,
}

impl ContextBudget {
    pub const MAX_EVIDENCE_UNITS_HARD_LIMIT: usize = 128;
    pub const MAX_TOTAL_CHARS_HARD_LIMIT: usize = 256 * 1024;
    pub const MAX_STRUCTURED_ROWS_HARD_LIMIT: usize = 256;
    pub const MAX_INLINE_CITATIONS_HARD_LIMIT: usize = 64;

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_evidence_units == 0
            || self.max_evidence_units > Self::MAX_EVIDENCE_UNITS_HARD_LIMIT
        {
            return Err("max_evidence_units out of range");
        }
        if self.max_total_chars == 0 || self.max_total_chars > Self::MAX_TOTAL_CHARS_HARD_LIMIT {
            return Err("max_total_chars out of range");
        }
        if self.max_structured_rows == 0
            || self.max_structured_rows > Self::MAX_STRUCTURED_ROWS_HARD_LIMIT
        {
            return Err("max_structured_rows out of range");
        }
        if self.max_inline_citations == 0
            || self.max_inline_citations > Self::MAX_INLINE_CITATIONS_HARD_LIMIT
        {
            return Err("max_inline_citations out of range");
        }
        Ok(())
    }
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self {
            max_evidence_units: 6,
            max_total_chars: 2_400,
            max_structured_rows: 6,
            max_inline_citations: 4,
        }
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

    #[test]
    fn engine_mode_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&EngineMode::Baseline).expect("serialize engine mode"),
            "\"baseline\""
        );
        assert_eq!(
            serde_json::to_string(&EngineMode::BeamPlanner).expect("serialize engine mode"),
            "\"beam_planner\""
        );
        assert_eq!(
            serde_json::to_string(&EngineMode::Rlm).expect("serialize engine mode"),
            "\"rlm\""
        );
    }

    #[test]
    fn planner_intent_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&PlannerIntent::StructuredLookup)
                .expect("serialize planner intent"),
            "\"structured_lookup\""
        );
        assert_eq!(
            serde_json::to_string(&PlannerIntent::StructuredVersionReview)
                .expect("serialize planner intent"),
            "\"structured_version_review\""
        );
    }

    #[test]
    fn evidence_pack_mode_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&EvidencePackMode::Mixed).expect("serialize evidence pack mode"),
            "\"mixed\""
        );
        assert_eq!(
            serde_json::to_string(&EvidencePackMode::Diff).expect("serialize evidence pack mode"),
            "\"diff\""
        );
    }

    #[test]
    fn context_budget_defaults_validate() {
        ContextBudget::default()
            .validate()
            .expect("default context budget should be valid");
    }

    #[test]
    fn planner_contract_round_trip_preserves_steps() {
        let request = PlanRequest {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            query: "What is the customer status and plan tier?".to_string(),
            budget: Budget {
                max_operator_calls: 10,
                max_bytes: 2048,
                max_wallclock_ms: 1000,
                max_recursion_depth: 3,
                max_parallelism: Some(2),
            },
            context_budget: ContextBudget {
                max_evidence_units: 8,
                max_total_chars: 4096,
                max_structured_rows: 8,
                max_inline_citations: 6,
            },
            planner_hints: PlannerHints {
                intent: PlannerIntent::StructuredLookup,
                recommended_path: vec![
                    PlannerStep::Operator {
                        op_name: "fetch_rows".to_string(),
                        params: serde_json::json!({
                            "view_id": "safe_customer_view_public",
                            "fields": ["status", "plan_tier"],
                        }),
                    },
                    PlannerStep::SearchRefFetchSpan { max_refs: 2 },
                ],
            },
            preferred_evidence_pack_mode: EvidencePackMode::Mixed,
            recovery_context: Some(PlannerRecoveryContext {
                failed_step: "fetch_rows".to_string(),
                failure_terminal_mode: TerminalMode::SourceUnavailable,
                attempted_path: vec![PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                }],
                failed_step_details: Some(PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                }),
            }),
            available_operator_names: vec![
                "fetch_rows".to_string(),
                "lookup_evidence".to_string(),
                "search".to_string(),
                "fetch_span".to_string(),
            ],
            operator_schemas: vec![PlannerToolSchema {
                name: "fetch_rows".to_string(),
                description: "Fetch rows from an allowlisted safeview.".to_string(),
                required_params: vec!["view_id".to_string(), "fields".to_string()],
                optional_params: vec!["filter_spec".to_string()],
                params_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["view_id", "fields"],
                    "properties": {
                        "view_id": { "type": "string" },
                        "fields": { "type": "array", "items": { "type": "string" } },
                        "filter_spec": { "type": "object" },
                    }
                })),
            }],
            allow_search_ref_fetch_span: true,
            prior_observations: vec![PlannerObservation {
                step: PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                },
                outcome: PlannerObservationOutcome::Failed,
                terminal_mode: Some(TerminalMode::SourceUnavailable),
                summary: Some("fetch_rows failed and triggered recovery planning".to_string()),
            }],
            clarification_opportunities: Vec::new(),
            failure_feedback: vec![PlannerFailureFeedback {
                failure_code: "terminal_mode_source_unavailable".to_string(),
                failed_step: Some(PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                }),
                terminal_mode: Some(TerminalMode::SourceUnavailable),
                message: Some(
                    "The previous fetch_rows attempt ended with source_unavailable.".to_string(),
                ),
            }],
        };
        let response = PlanResponse {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            steps: vec![
                PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                },
                PlannerStep::SearchRefFetchSpan { max_refs: 1 },
            ],
            planner_summary: Some("Prefer direct structured lookup.".to_string()),
        };

        let encoded_request = serde_json::to_vec(&request).expect("encode plan request");
        let decoded_request =
            serde_json::from_slice::<PlanRequest>(&encoded_request).expect("decode plan request");
        let encoded_response = serde_json::to_vec(&response).expect("encode plan response");
        let decoded_response = serde_json::from_slice::<PlanResponse>(&encoded_response)
            .expect("decode plan response");

        assert_eq!(decoded_request, request);
        assert_eq!(decoded_response, response);
    }

    #[test]
    fn structured_dimension_discovery_contract_round_trip_preserves_values() {
        let discovery = StructuredDimensionDiscoveryResult {
            view_id: "safe_customer_view_public".to_string(),
            available_dimensions: vec!["plan_tier".to_string(), "status".to_string()],
            metrics: vec![StructuredMetricDescriptor {
                name: "count".to_string(),
                field: "customer_id".to_string(),
            }],
            dimensions: vec![
                StructuredDimensionDescriptor {
                    field: "plan_tier".to_string(),
                    top_values: vec![
                        StructuredDimensionValueCount {
                            value: "starter".to_string(),
                            count: 9,
                        },
                        StructuredDimensionValueCount {
                            value: "premium".to_string(),
                            count: 4,
                        },
                    ],
                    drilldown_supported: true,
                },
                StructuredDimensionDescriptor {
                    field: "status".to_string(),
                    top_values: vec![StructuredDimensionValueCount {
                        value: "active".to_string(),
                        count: 10,
                    }],
                    drilldown_supported: true,
                },
            ],
            filters_applied: Some(serde_json::json!({ "status": "active" })),
        };
        let drilldown = StructuredDrilldownHint {
            dimension: "status".to_string(),
            filter_spec: serde_json::json!({ "plan_tier": "starter" }),
        };

        let encoded_discovery = serde_json::to_vec(&discovery).expect("encode discovery contract");
        let decoded_discovery =
            serde_json::from_slice::<StructuredDimensionDiscoveryResult>(&encoded_discovery)
                .expect("decode discovery contract");
        let encoded_drilldown = serde_json::to_vec(&drilldown).expect("encode drilldown contract");
        let decoded_drilldown =
            serde_json::from_slice::<StructuredDrilldownHint>(&encoded_drilldown)
                .expect("decode drilldown contract");

        assert_eq!(decoded_discovery, discovery);
        assert_eq!(decoded_drilldown, drilldown);
    }

    #[test]
    fn replay_bundle_round_trip_preserves_metadata() {
        let bundle = ReplayBundle {
            metadata: ReplayBundleMetadata {
                schema_version: 1,
                run_id: "run_01".to_string(),
                trace_id: "01HRAY56GFKGG7M9VG6FXFXAFM".to_string(),
                request_id: "req_01".to_string(),
                principal_id_hash:
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                engine_mode: EngineMode::Baseline,
                recorded_at_unix_ms: 1_700_000_000_000,
                terminal_mode: TerminalMode::InsufficientEvidence,
                quality_score: 61.5,
                bundle_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            },
            query: "status".to_string(),
            budget: Budget {
                max_operator_calls: 10,
                max_bytes: 2048,
                max_wallclock_ms: 1000,
                max_recursion_depth: 3,
                max_parallelism: Some(1),
            },
            session_id: "session_01".to_string(),
            policy_snapshot_id: "policy_01".to_string(),
            loop_terminal_mode: TerminalMode::InsufficientEvidence,
            loop_response_text: Some("UNKNOWN: no evidence".to_string()),
            response_text: "UNKNOWN: no evidence".to_string(),
            claim_map: ClaimMap {
                claim_map_id: "claim_map_01".to_string(),
                terminal_mode: TerminalMode::InsufficientEvidence,
                claims: Vec::new(),
                coverage_threshold: 0.95,
                coverage_observed: 1.0,
                clarification_prompt: None,
                notes: None,
            },
            operator_calls_used: 2,
            bytes_used: 128,
            depth_used: 2,
            evidence_ref_count: 0,
            evidence_unit_ids: Vec::new(),
            planner_traces: vec![ReplayPlannerTrace {
                plan_request: PlanRequest {
                    schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
                    query: "status".to_string(),
                    budget: Budget {
                        max_operator_calls: 10,
                        max_bytes: 2048,
                        max_wallclock_ms: 1000,
                        max_recursion_depth: 3,
                        max_parallelism: Some(1),
                    },
                    context_budget: ContextBudget::default(),
                    planner_hints: PlannerHints {
                        intent: PlannerIntent::StructuredLookup,
                        recommended_path: vec![PlannerStep::Operator {
                            op_name: "fetch_rows".to_string(),
                            params: serde_json::json!({
                                "view_id": "safe_customer_view_public",
                                "fields": ["status", "plan_tier"],
                            }),
                        }],
                    },
                    preferred_evidence_pack_mode: EvidencePackMode::Raw,
                    recovery_context: None,
                    available_operator_names: vec![
                        "fetch_rows".to_string(),
                        "lookup_evidence".to_string(),
                    ],
                    operator_schemas: vec![PlannerToolSchema {
                        name: "fetch_rows".to_string(),
                        description: "Fetch rows from an allowlisted safeview.".to_string(),
                        required_params: vec!["view_id".to_string(), "fields".to_string()],
                        optional_params: vec!["filter_spec".to_string()],
                        params_schema: None,
                    }],
                    allow_search_ref_fetch_span: true,
                    prior_observations: Vec::new(),
                    clarification_opportunities: Vec::new(),
                    failure_feedback: Vec::new(),
                },
                output_steps: vec![PlannerStep::Operator {
                    op_name: "fetch_rows".to_string(),
                    params: serde_json::json!({
                        "view_id": "safe_customer_view_public",
                        "fields": ["status", "plan_tier"],
                    }),
                }],
                decision_summary: ReplayPlannerDecisionSummary {
                    planner_source: "rust_owned".to_string(),
                    stop_reason: "plan_complete".to_string(),
                    selected_for_execution: true,
                    used_fallback_plan: false,
                    fallback_from_step: None,
                    expected_usefulness_score: Some(0.91),
                    expected_usefulness_reasons: vec![
                        "starts with a direct structured lookup for a row-oriented question"
                            .to_string(),
                    ],
                    selection_rationale: Some(
                        "rust_owned was preferred because expected usefulness scored 0.9100; starts with a direct structured lookup for a row-oriented question."
                            .to_string(),
                    ),
                    planner_summary: None,
                },
            }],
        };

        let encoded = serde_json::to_vec(&bundle).expect("encode replay bundle");
        let decoded =
            serde_json::from_slice::<ReplayBundle>(&encoded).expect("decode replay bundle");

        assert_eq!(decoded.metadata.run_id, "run_01");
        assert_eq!(decoded.metadata.engine_mode, EngineMode::Baseline);
        assert_eq!(decoded.response_text, "UNKNOWN: no evidence");
        assert_eq!(decoded.planner_traces.len(), 1);
    }
}
