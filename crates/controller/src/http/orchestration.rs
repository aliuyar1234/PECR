use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use futures_util::stream::{FuturesUnordered, StreamExt};
use pecr_contracts::{
    Budget, ClarificationPrompt, ContextBudget, EvidencePackMode, EvidenceUnit, EvidenceUnitRef,
    PLANNER_CONTRACT_SCHEMA_VERSION, PlanRequest, PlanResponse, PlannerFailureFeedback,
    PlannerHints, PlannerIntent, PlannerObservation, PlannerObservationOutcome,
    PlannerRecoveryContext, PlannerStep, PlannerToolSchema, ReplayPlannerDecisionSummary,
    ReplayPlannerTrace, TerminalMode,
};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::budget::{BudgetScheduler, BudgetStopReason};
use super::{ApiError, AppState, apply_gateway_auth, json_error};
use crate::config::{BaselinePlanStep, ControllerEngine, PlannerClientKind, PlannerMode};

#[cfg(feature = "rlm")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "rlm")]
use std::path::PathBuf;
#[cfg(feature = "rlm")]
use std::process::Stdio;
#[cfg(feature = "rlm")]
use std::sync::Arc;
#[cfg(feature = "rlm")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
#[cfg(feature = "rlm")]
use tokio::process::{Child, ChildStdin, ChildStdout};
#[cfg(feature = "rlm")]
use tokio::sync::Mutex as AsyncMutex;

const PLANNER_AVAILABLE_OPERATOR_NAMES: &[&str] = &[
    "aggregate",
    "compare",
    "discover_dimensions",
    "diff",
    "fetch_rows",
    "fetch_span",
    "list_versions",
    "lookup_evidence",
    "redact",
    "search",
];

#[derive(Debug, Serialize)]
struct OperatorCallRequest {
    session_id: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OperatorCallResponse {
    terminal_mode: TerminalMode,
    result: serde_json::Value,
    #[serde(default)]
    result_summary: Option<String>,
}

#[derive(Debug)]
pub(super) struct ContextLoopResult {
    pub(super) terminal_mode: TerminalMode,
    pub(super) response_text: Option<String>,
    #[allow(dead_code)]
    pub(super) planner_traces: Vec<ReplayPlannerTrace>,
    #[allow(dead_code)]
    pub(super) evidence_refs: Vec<EvidenceUnitRef>,
    #[allow(dead_code)]
    pub(super) evidence_units: Vec<EvidenceUnit>,
    #[allow(dead_code)]
    pub(super) operator_calls_used: u32,
    #[allow(dead_code)]
    pub(super) bytes_used: u64,
    #[allow(dead_code)]
    pub(super) depth_used: u32,
}

#[derive(Debug, Deserialize)]
struct GatewayErrorResponse {
    terminal_mode_hint: TerminalMode,
}

#[derive(Debug, Serialize)]
struct PolicySimulateRequest {
    action: String,
    params: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PolicySimulateResponse {
    allow: bool,
    #[serde(default)]
    narrowing: Option<serde_json::Value>,
}

#[derive(Debug)]
struct OperatorCallOutcome {
    terminal_mode_hint: TerminalMode,
    body: Option<OperatorCallResponse>,
    bytes_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QueryPlanIntent {
    Default,
    StructuredLookup,
    StructuredAggregation,
    EvidenceLookup,
    VersionReview,
    StructuredEvidenceLookup,
    StructuredAggregationEvidence,
    StructuredVersionReview,
}

#[derive(Debug, Clone, Copy)]
struct QueryPlanProfile {
    include_fetch_rows_ops: bool,
    include_aggregate_ops: bool,
    include_version_ops: bool,
    include_search_ops: bool,
}

type PlannerClientFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PlanResponse, PlannerClientError>> + Send + 'a>>;

#[derive(Debug)]
struct PlannerClientError {
    code: &'static str,
    message: String,
}

trait PlannerClient {
    fn plan<'a>(&'a self, request: &'a PlanRequest) -> PlannerClientFuture<'a>;
}

struct BeamPlannerClient<'a> {
    state: &'a AppState,
}

impl PlannerClient for BeamPlannerClient<'_> {
    fn plan<'a>(&'a self, request: &'a PlanRequest) -> PlannerClientFuture<'a> {
        Box::pin(async move { request_beam_plan(self.state, request).await })
    }
}

#[derive(Debug)]
struct SelectedExecutionPlan {
    steps: Vec<PlannedQueryStep>,
    planner_source: &'static str,
    planner_summary: Option<String>,
    planner_traces: Vec<ReplayPlannerTrace>,
}

#[derive(Debug, Clone)]
struct PlannedQueryStep {
    query_context: String,
    step: BaselinePlanStep,
}

#[derive(Debug, Clone)]
struct PlannerUsefulnessAssessment {
    score: f64,
    reasons: Vec<String>,
}

struct InflightOpsGuard;

impl InflightOpsGuard {
    fn new() -> Self {
        crate::metrics::inc_inflight_ops();
        Self
    }
}

impl Drop for InflightOpsGuard {
    fn drop(&mut self) {
        crate::metrics::dec_inflight_ops();
    }
}

#[cfg(feature = "rlm")]
#[derive(Debug, Deserialize)]
struct BatchBridgeCall {
    op_name: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[cfg(feature = "rlm")]
#[derive(Debug)]
struct PendingBatchCall {
    idx: usize,
    params: serde_json::Value,
}

#[cfg(feature = "rlm")]
const RLM_BRIDGE_PROTOCOL_MIN_VERSION: u32 = 1;
#[cfg(feature = "rlm")]
const RLM_BRIDGE_PROTOCOL_MAX_VERSION: u32 = 1;

#[cfg(feature = "rlm")]
pub(super) fn is_rlm_bridge_failure_stop_reason(stop_reason: &str) -> bool {
    matches!(
        stop_reason,
        "bridge_eof"
            | "bridge_read_error"
            | "bridge_invalid_json"
            | "bridge_invalid_message"
            | "bridge_invalid_tool_request"
            | "bridge_unknown_message"
            | "bridge_invalid_request"
            | "bridge_protocol_missing_version"
            | "bridge_protocol_version_unsupported"
            | "bridge_script_not_found"
            | "bridge_spawn_failed"
            | "bridge_internal"
            | "bridge_backend_unavailable"
            | "bridge_backend_runtime_error"
    )
}

#[cfg(feature = "rlm")]
#[derive(Clone, Default)]
pub(super) struct RlmBridgeRuntime {
    cached_process: Arc<AsyncMutex<Option<CachedRlmBridgeProcess>>>,
}

#[cfg(feature = "rlm")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RlmBridgeProcessKey {
    python: String,
    script_path: PathBuf,
}

#[cfg(feature = "rlm")]
struct CachedRlmBridgeProcess {
    key: RlmBridgeProcessKey,
    child: Child,
    stdin: ChildStdin,
    stdout_lines: Lines<BufReader<ChildStdout>>,
}

#[cfg(feature = "rlm")]
struct RlmBridgeSetupError {
    stop_reason: &'static str,
    message: String,
}

#[derive(Clone, Copy)]
pub(super) struct GatewayCallContext<'a> {
    pub(super) principal_id: &'a str,
    pub(super) authz_header: Option<&'a str>,
    pub(super) local_auth_shared_secret: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) trace_id: &'a str,
    pub(super) session_token: &'a str,
    pub(super) session_id: &'a str,
}

#[cfg(feature = "rlm")]
fn allowed_operator(op_name: &str) -> bool {
    matches!(
        op_name,
        "search"
            | "fetch_span"
            | "fetch_rows"
            | "aggregate"
            | "compare"
            | "lookup_evidence"
            | "list_versions"
            | "diff"
            | "redact"
    )
}

#[cfg(feature = "rlm")]
fn record_operator_result(
    op_name: &str,
    result: &serde_json::Value,
    evidence_refs: &mut Vec<EvidenceUnitRef>,
    evidence_units: &mut Vec<EvidenceUnit>,
) {
    if op_name == "search"
        && let Some(refs_value) = result.get("refs").cloned()
        && let Ok(refs) = serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
    {
        *evidence_refs = refs;
    }

    if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(result.clone()) {
        evidence_units.extend(units);
    } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(result.clone()) {
        evidence_units.push(unit);
    }
}

fn remember_operator_summary(summaries: &mut Vec<String>, result_summary: Option<&str>) {
    let Some(summary) = result_summary
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    if !summaries.iter().any(|existing| existing == summary) {
        summaries.push(summary.to_string());
    }
}

fn render_operator_summaries_response_text(summaries: &[String]) -> Option<String> {
    let lines = summaries
        .iter()
        .map(|summary| format!("SUPPORTED: {}", summary))
        .take(3)
        .collect::<Vec<_>>();
    (!lines.is_empty()).then(|| lines.join("\n"))
}

const QUERY_CLAUSE_SEPARATORS: &[&str] = &[
    "; ",
    " as well as ",
    " along with ",
    " plus ",
    " then ",
    " and ",
];
const QUERY_ACTION_TOKENS: &[&str] = &[
    "cite",
    "compare",
    "describe",
    "diff",
    "explain",
    "find",
    "list",
    "quote",
    "review",
    "show",
    "summarize",
    "tell",
];

fn is_generic_clause_token(token: &str) -> bool {
    matches!(
        token,
        "cite"
            | "citation"
            | "citations"
            | "compare"
            | "comparison"
            | "count"
            | "counts"
            | "daily"
            | "diff"
            | "evidence"
            | "latest"
            | "monthly"
            | "newest"
            | "previous"
            | "quote"
            | "quotes"
            | "source"
            | "sources"
            | "summarize"
            | "summary"
            | "text"
            | "time"
            | "total"
            | "totals"
            | "trend"
            | "trends"
            | "version"
            | "versions"
    )
}

fn clause_is_actionable(clause: &str) -> bool {
    let tokens = query_tokens(clause);
    if tokens.is_empty() {
        return false;
    }

    query_has_any_token(&tokens, QUERY_ACTION_TOKENS)
        || (tokens.len() >= 3 && classify_query_plan_intent(clause) != QueryPlanIntent::Default)
}

fn clause_subject_hint(clause: &str) -> Option<String> {
    let hint_tokens = semantic_query_tokens(clause)
        .into_iter()
        .filter(|token| !is_generic_clause_token(token))
        .collect::<Vec<_>>();
    (!hint_tokens.is_empty()).then(|| hint_tokens.join(" "))
}

fn clause_needs_subject_context(clause: &str) -> bool {
    let semantic_tokens = semantic_query_tokens(clause);
    !semantic_tokens.is_empty()
        && semantic_tokens
            .iter()
            .all(|token| is_generic_clause_token(token))
}

fn contextualize_decomposed_clauses(parts: Vec<String>) -> Vec<String> {
    let subject_hints = parts
        .iter()
        .map(|clause| clause_subject_hint(clause))
        .collect::<Vec<_>>();

    parts
        .into_iter()
        .enumerate()
        .map(|(index, clause)| {
            if !clause_needs_subject_context(&clause) {
                return clause;
            }

            let context_hint = (0..subject_hints.len())
                .filter(|candidate_index| *candidate_index != index)
                .find_map(|candidate_index| subject_hints[candidate_index].clone());

            match context_hint {
                Some(hint) => {
                    let clause_lower = clause.to_ascii_lowercase();
                    let hint_lower = hint.trim().to_ascii_lowercase();
                    if clause_lower.contains(hint_lower.as_str()) {
                        clause
                    } else {
                        format!("{} for {}", clause.trim_end_matches(['.', '?', '!']), hint)
                    }
                }
                _ => clause,
            }
        })
        .collect()
}

pub(super) fn decompose_query_clauses(query: &str) -> Vec<String> {
    let normalized = query.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Vec::new();
    }

    for separator in QUERY_CLAUSE_SEPARATORS {
        let parts = normalized
            .split(separator)
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect::<Vec<_>>();

        if parts.len() < 2
            || parts.len() > 3
            || !parts.iter().all(|part| clause_is_actionable(part))
        {
            continue;
        }

        let contextualized = contextualize_decomposed_clauses(parts);
        if contextualized.len() >= 2 {
            return contextualized;
        }
    }

    vec![normalized]
}

fn scheduler_parallelism(
    state: &AppState,
    scheduler: BudgetScheduler<'_>,
    operator_calls_used: u32,
    scheduled_calls: u32,
) -> usize {
    if state.config.adaptive_parallelism_enabled {
        scheduler.adaptive_parallelism(operator_calls_used, scheduled_calls)
    } else {
        scheduler.effective_parallelism()
    }
}

fn query_tokens(query: &str) -> Vec<String> {
    query
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

fn query_has_any_token(tokens: &[String], candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.iter().any(|token| token == candidate))
}

pub(super) fn semantic_query_tokens(query: &str) -> Vec<String> {
    query_tokens(query)
        .into_iter()
        .filter(|token| {
            !matches!(
                token.as_str(),
                "a" | "an"
                    | "and"
                    | "about"
                    | "by"
                    | "for"
                    | "from"
                    | "get"
                    | "give"
                    | "help"
                    | "i"
                    | "in"
                    | "is"
                    | "list"
                    | "me"
                    | "of"
                    | "on"
                    | "please"
                    | "show"
                    | "tell"
                    | "the"
                    | "to"
                    | "what"
                    | "which"
                    | "with"
            )
        })
        .collect()
}

fn is_generic_evidence_token(token: &str) -> bool {
    matches!(
        token,
        "cite"
            | "citation"
            | "citations"
            | "document"
            | "documents"
            | "evidence"
            | "file"
            | "files"
            | "policy"
            | "policies"
            | "quote"
            | "quotes"
            | "source"
            | "sources"
            | "text"
    )
}

fn is_generic_version_token(token: &str) -> bool {
    matches!(
        token,
        "change"
            | "changed"
            | "changes"
            | "diff"
            | "history"
            | "latest"
            | "newest"
            | "previous"
            | "version"
            | "versions"
    )
}

fn query_has_specific_filter_value(tokens: &[String]) -> bool {
    query_has_any_token(
        tokens,
        &[
            "active",
            "inactive",
            "starter",
            "premium",
            "enterprise",
            "free",
            "suspended",
            "annual",
            "billing",
            "refund",
            "support",
        ],
    )
}

fn clarification_prompt(question: &str, options: &[&str]) -> ClarificationPrompt {
    let mut seen = BTreeSet::new();
    let options = options
        .iter()
        .map(|option| option.trim())
        .filter(|option| !option.is_empty())
        .filter(|option| seen.insert((*option).to_string()))
        .map(|option| option.to_string())
        .collect::<Vec<_>>();
    ClarificationPrompt {
        question: question.trim().to_string(),
        options,
    }
}

fn render_clarification_prompt(prompt: &ClarificationPrompt) -> String {
    let mut message = String::from("UNKNOWN: I can help, but I need one detail first. ");
    message.push_str(prompt.question.trim());
    if !prompt.question.trim_end().ends_with('?') {
        message.push('?');
    }
    if !prompt.options.is_empty() {
        message.push_str(" Options: ");
        let rendered_options = prompt
            .options
            .iter()
            .take(3)
            .map(|option| format!("`{option}`"))
            .collect::<Vec<_>>();
        if rendered_options.len() == 1 {
            message.push_str(&rendered_options[0]);
        } else {
            message.push_str(&rendered_options[..rendered_options.len() - 1].join(", "));
            message.push_str(", or ");
            message.push_str(rendered_options.last().expect("last option must exist"));
        }
        message.push('.');
    }
    message
}

pub(super) fn clarification_prompt_for_query(query: &str) -> Option<ClarificationPrompt> {
    let semantic_tokens = semantic_query_tokens(query);
    let intent = classify_query_plan_intent(query);

    if semantic_tokens.is_empty() {
        return Some(clarification_prompt(
            "What kind of answer would be most useful here",
            &[
                "customer status and plan tier",
                "source-backed evidence from a document",
                "what changed between versions",
            ],
        ));
    }

    match intent {
        QueryPlanIntent::Default if semantic_tokens.len() <= 2 => Some(clarification_prompt(
            "What would you like me to do first",
            &[
                "structured customer lookup",
                "quote a policy or document",
                "compare counts or trends",
            ],
        )),
        QueryPlanIntent::StructuredLookup | QueryPlanIntent::StructuredEvidenceLookup => {
            let has_dimension = query_mentions_status_dimension(&semantic_tokens)
                || query_mentions_plan_dimension(&semantic_tokens)
                || query_has_any_token(
                    &semantic_tokens,
                    &["field", "fields", "row", "rows", "tenant", "tenants"],
                );
            if semantic_tokens.len() <= 1
                || (!has_dimension && !query_has_specific_filter_value(&semantic_tokens))
            {
                Some(clarification_prompt(
                    "Which field or filter should I use for the customer lookup",
                    &["customer status", "plan tier", "specific customer_id"],
                ))
            } else {
                None
            }
        }
        QueryPlanIntent::StructuredAggregation | QueryPlanIntent::StructuredAggregationEvidence => {
            let has_dimension = query_mentions_status_dimension(&semantic_tokens)
                || query_mentions_plan_dimension(&semantic_tokens)
                || query_mentions_time_trend(&semantic_tokens);
            if !has_dimension {
                Some(clarification_prompt(
                    "How should I break the comparison down",
                    &["by status", "by plan tier", "monthly trend"],
                ))
            } else {
                None
            }
        }
        QueryPlanIntent::EvidenceLookup => {
            if semantic_tokens
                .iter()
                .all(|token| is_generic_evidence_token(token))
            {
                Some(clarification_prompt(
                    "Which document or policy should I quote or cite",
                    &["support policy", "billing terms", "refund policy"],
                ))
            } else {
                None
            }
        }
        QueryPlanIntent::VersionReview | QueryPlanIntent::StructuredVersionReview => {
            let has_subject = semantic_tokens
                .iter()
                .any(|token| !is_generic_version_token(token) && !is_generic_evidence_token(token));
            if !has_subject {
                Some(clarification_prompt(
                    "Which document or object should I compare versions for",
                    &["support policy", "billing terms", "latest support document"],
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn ambiguity_guidance_for_query(query: &str) -> Option<String> {
    let semantic_tokens = semantic_query_tokens(query);
    let intent = classify_query_plan_intent(query);

    if semantic_tokens.is_empty() {
        return clarification_prompt_for_query(query)
            .map(|prompt| render_clarification_prompt(&prompt));
    }

    match intent {
        QueryPlanIntent::Default => {
            if semantic_tokens.len() <= 2 {
                clarification_prompt_for_query(query)
                    .map(|prompt| render_clarification_prompt(&prompt))
            } else {
                None
            }
        }
        QueryPlanIntent::StructuredLookup | QueryPlanIntent::StructuredEvidenceLookup => {
            let has_dimension = query_mentions_status_dimension(&semantic_tokens)
                || query_mentions_plan_dimension(&semantic_tokens)
                || query_has_any_token(
                    &semantic_tokens,
                    &["field", "fields", "row", "rows", "tenant", "tenants"],
                );
            if semantic_tokens.len() <= 1
                || (!has_dimension && !query_has_specific_filter_value(&semantic_tokens))
            {
                clarification_prompt_for_query(query)
                    .map(|prompt| render_clarification_prompt(&prompt))
            } else {
                None
            }
        }
        QueryPlanIntent::StructuredAggregation | QueryPlanIntent::StructuredAggregationEvidence => {
            let has_dimension = query_mentions_status_dimension(&semantic_tokens)
                || query_mentions_plan_dimension(&semantic_tokens)
                || query_mentions_time_trend(&semantic_tokens);
            if !has_dimension {
                clarification_prompt_for_query(query)
                    .map(|prompt| render_clarification_prompt(&prompt))
            } else {
                None
            }
        }
        QueryPlanIntent::EvidenceLookup => {
            if semantic_tokens
                .iter()
                .all(|token| is_generic_evidence_token(token))
            {
                clarification_prompt_for_query(query)
                    .map(|prompt| render_clarification_prompt(&prompt))
            } else {
                None
            }
        }
        QueryPlanIntent::VersionReview | QueryPlanIntent::StructuredVersionReview => {
            let has_subject = semantic_tokens
                .iter()
                .any(|token| !is_generic_version_token(token) && !is_generic_evidence_token(token));
            if !has_subject {
                clarification_prompt_for_query(query)
                    .map(|prompt| render_clarification_prompt(&prompt))
            } else {
                None
            }
        }
    }
}

fn policy_narrowing_string_list(narrowing: &serde_json::Value, key: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let Some(items) = narrowing.get(key).and_then(|value| value.as_array()) else {
        return out;
    };

    for item in items {
        let Some(value) = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let lowered = value.to_ascii_lowercase();
        if seen.insert(lowered) {
            out.push(value.to_string());
        }
    }

    out
}

fn render_policy_narrowing_code_list(items: &[String], limit: usize) -> String {
    items
        .iter()
        .take(limit)
        .map(|item| format!("`{item}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_policy_narrowing_guidance(
    base_guidance: Option<String>,
    narrowing: &serde_json::Value,
) -> Option<String> {
    let mut message = base_guidance.unwrap_or_else(|| {
        "UNKNOWN: narrow the request to one of the safe scopes allowed for the current principal."
            .to_string()
    });

    let scope_labels = policy_narrowing_string_list(narrowing, "scope_labels");
    if !scope_labels.is_empty() {
        message.push_str(" Safe scopes for the current principal: ");
        message.push_str(&scope_labels.join(", "));
        message.push('.');
    }

    let view_ids = policy_narrowing_string_list(narrowing, "view_ids");
    if !view_ids.is_empty() {
        message.push_str(" Available safe views: ");
        message.push_str(&render_policy_narrowing_code_list(&view_ids, 3));
        message.push('.');
    }

    let field_labels = policy_narrowing_string_list(narrowing, "field_labels");
    if !field_labels.is_empty() {
        message.push_str(" Useful filters or fields: ");
        message.push_str(&render_policy_narrowing_code_list(&field_labels, 4));
        message.push('.');
    }

    let dimension_labels = policy_narrowing_string_list(narrowing, "dimension_labels");
    if !dimension_labels.is_empty() {
        message.push_str(" Useful comparison dimensions: ");
        message.push_str(&render_policy_narrowing_code_list(&dimension_labels, 3));
        message.push('.');
    }

    let source_scopes = policy_narrowing_string_list(narrowing, "source_scopes");
    if !source_scopes.is_empty() {
        message.push_str(" Safe document scopes: ");
        message.push_str(&render_policy_narrowing_code_list(&source_scopes, 3));
        message.push('.');
    }

    let document_hints = policy_narrowing_string_list(narrowing, "document_hints");
    if !document_hints.is_empty() {
        message.push_str(" Relevant document types: ");
        message.push_str(
            &document_hints
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        );
        message.push('.');
    }

    let examples = policy_narrowing_string_list(narrowing, "examples");
    if !examples.is_empty() {
        let rendered = examples
            .iter()
            .take(2)
            .map(|example| format!("'{}'", example))
            .collect::<Vec<_>>()
            .join(" or ");
        message.push_str(" Try: ");
        message.push_str(&rendered);
        message.push('.');
    }

    Some(message)
}

pub(super) fn classify_query_plan_intent(query: &str) -> QueryPlanIntent {
    let tokens = query_tokens(query);
    if tokens.is_empty() {
        return QueryPlanIntent::Default;
    }

    let structured = query_has_any_token(
        &tokens,
        &[
            "status",
            "plan",
            "tier",
            "customer",
            "customers",
            "account",
            "accounts",
            "tenant",
            "row",
            "rows",
            "field",
            "fields",
            "view",
            "table",
        ],
    );
    let aggregate = query_has_any_token(
        &tokens,
        &[
            "count",
            "counts",
            "total",
            "totals",
            "average",
            "avg",
            "sum",
            "summarize",
            "summary",
            "breakdown",
            "distribution",
            "compare",
            "comparison",
            "trend",
            "trends",
            "over",
            "time",
            "daily",
            "monthly",
        ],
    );
    let version = query_has_any_token(
        &tokens,
        &[
            "version", "versions", "change", "changed", "changes", "diff", "history", "latest",
            "previous", "newest",
        ],
    );
    let evidence = query_has_any_token(
        &tokens,
        &[
            "quote",
            "quotes",
            "cite",
            "citation",
            "citations",
            "evidence",
            "source",
            "sources",
            "document",
            "documents",
            "file",
            "files",
            "text",
            "policy",
            "policies",
            "term",
            "terms",
            "why",
            "where",
            "mention",
        ],
    );

    match (structured, aggregate, version, evidence) {
        (true, true, _, true) => QueryPlanIntent::StructuredAggregationEvidence,
        (false, true, false, true) => QueryPlanIntent::EvidenceLookup,
        (true, true, _, false) => QueryPlanIntent::StructuredAggregation,
        (true, false, false, false) => QueryPlanIntent::StructuredLookup,
        (false, false, true, false) => QueryPlanIntent::VersionReview,
        (false, false, false, true) => QueryPlanIntent::EvidenceLookup,
        (true, false, false, true) => QueryPlanIntent::StructuredEvidenceLookup,
        (true, false, true, _) => QueryPlanIntent::StructuredVersionReview,
        (false, _, true, true) => QueryPlanIntent::VersionReview,
        _ => QueryPlanIntent::Default,
    }
}

fn query_plan_profile(intent: QueryPlanIntent) -> Option<QueryPlanProfile> {
    match intent {
        QueryPlanIntent::Default => None,
        QueryPlanIntent::StructuredLookup => Some(QueryPlanProfile {
            include_fetch_rows_ops: true,
            include_aggregate_ops: false,
            include_version_ops: false,
            include_search_ops: false,
        }),
        QueryPlanIntent::StructuredAggregation => Some(QueryPlanProfile {
            include_fetch_rows_ops: false,
            include_aggregate_ops: true,
            include_version_ops: false,
            include_search_ops: false,
        }),
        QueryPlanIntent::EvidenceLookup => Some(QueryPlanProfile {
            include_fetch_rows_ops: false,
            include_aggregate_ops: false,
            include_version_ops: false,
            include_search_ops: true,
        }),
        QueryPlanIntent::VersionReview => Some(QueryPlanProfile {
            include_fetch_rows_ops: false,
            include_aggregate_ops: false,
            include_version_ops: true,
            include_search_ops: true,
        }),
        QueryPlanIntent::StructuredEvidenceLookup => Some(QueryPlanProfile {
            include_fetch_rows_ops: true,
            include_aggregate_ops: false,
            include_version_ops: false,
            include_search_ops: true,
        }),
        QueryPlanIntent::StructuredAggregationEvidence => Some(QueryPlanProfile {
            include_fetch_rows_ops: false,
            include_aggregate_ops: true,
            include_version_ops: false,
            include_search_ops: true,
        }),
        QueryPlanIntent::StructuredVersionReview => Some(QueryPlanProfile {
            include_fetch_rows_ops: true,
            include_aggregate_ops: false,
            include_version_ops: true,
            include_search_ops: true,
        }),
    }
}

fn step_matches_query_profile(step: &BaselinePlanStep, profile: QueryPlanProfile) -> bool {
    match step {
        BaselinePlanStep::Operator { op_name, .. } => match op_name.as_str() {
            "fetch_rows" => profile.include_fetch_rows_ops,
            "aggregate" | "compare" => profile.include_aggregate_ops,
            "list_versions" | "diff" => profile.include_version_ops,
            "search" | "fetch_span" | "lookup_evidence" => profile.include_search_ops,
            _ => true,
        },
        BaselinePlanStep::SearchRefFetchSpan { .. } => profile.include_search_ops,
    }
}

fn filtered_plan_for_profile(
    plan: &[BaselinePlanStep],
    profile: QueryPlanProfile,
) -> Vec<BaselinePlanStep> {
    let mut filtered = plan
        .iter()
        .filter(|step| step_matches_query_profile(step, profile))
        .cloned()
        .collect::<Vec<_>>();

    let includes_search = filtered.iter().any(|step| {
        matches!(
            step,
            BaselinePlanStep::Operator { op_name, .. } if op_name == "search"
        )
    });
    if !includes_search {
        filtered.retain(|step| !matches!(step, BaselinePlanStep::SearchRefFetchSpan { .. }));
    }

    filtered
}

fn collapse_evidence_lookup_steps(
    steps: Vec<BaselinePlanStep>,
    intent: QueryPlanIntent,
) -> Vec<BaselinePlanStep> {
    if !matches!(
        intent,
        QueryPlanIntent::EvidenceLookup | QueryPlanIntent::StructuredEvidenceLookup
    ) {
        return steps;
    }

    let mut out = Vec::new();
    let mut search_params = None;
    let mut max_refs = 2usize;

    for step in steps {
        match step {
            BaselinePlanStep::Operator { op_name, params } if op_name == "search" => {
                search_params = Some(params);
            }
            BaselinePlanStep::SearchRefFetchSpan {
                max_refs: step_max_refs,
            } => {
                max_refs = step_max_refs;
            }
            other => out.push(other),
        }
    }

    if let Some(mut params) = search_params {
        if let Some(map) = params.as_object_mut() {
            map.insert("max_refs".to_string(), serde_json::json!(max_refs));
        }
        out.push(BaselinePlanStep::Operator {
            op_name: "lookup_evidence".to_string(),
            params,
        });
    }

    out
}

fn inject_version_diff_step(
    steps: Vec<BaselinePlanStep>,
    intent: QueryPlanIntent,
) -> Vec<BaselinePlanStep> {
    if intent != QueryPlanIntent::VersionReview
        || !steps.iter().any(|step| {
            matches!(
                step,
                BaselinePlanStep::Operator { op_name, .. } if op_name == "list_versions"
            )
        })
        || steps.iter().any(|step| {
            matches!(
                step,
                BaselinePlanStep::Operator { op_name, .. } if op_name == "diff"
            )
        })
    {
        return steps;
    }

    let mut out = Vec::with_capacity(steps.len().saturating_add(1));
    for step in steps {
        let diff_params = match &step {
            BaselinePlanStep::Operator { op_name, params } if op_name == "list_versions" => {
                Some(version_diff_placeholder_params(params))
            }
            _ => None,
        };
        out.push(step);
        if let Some(params) = diff_params {
            out.push(BaselinePlanStep::Operator {
                op_name: "diff".to_string(),
                params,
            });
        }
    }

    out
}

fn derive_plan_for_intent(
    plan: &[BaselinePlanStep],
    intent: QueryPlanIntent,
) -> Vec<BaselinePlanStep> {
    let Some(profile) = query_plan_profile(intent) else {
        return Vec::new();
    };

    inject_version_diff_step(
        collapse_evidence_lookup_steps(filtered_plan_for_profile(plan, profile), intent),
        intent,
    )
    .into_iter()
    .map(|step| match step {
        BaselinePlanStep::Operator { op_name, params }
            if op_name == "aggregate"
                && matches!(
                    intent,
                    QueryPlanIntent::StructuredAggregation
                        | QueryPlanIntent::StructuredAggregationEvidence
                ) =>
        {
            BaselinePlanStep::Operator {
                op_name: "compare".to_string(),
                params,
            }
        }
        other => other,
    })
    .collect()
}

fn planned_step_dedup_key(step: &BaselinePlanStep) -> &'static str {
    match step {
        BaselinePlanStep::Operator { op_name, .. } => match op_name.as_str() {
            "aggregate" => "aggregate",
            "compare" => "compare",
            "diff" => "diff",
            "fetch_rows" => "fetch_rows",
            "list_versions" => "list_versions",
            "lookup_evidence" => "lookup_evidence",
            "search" => "search",
            _ => "other",
        },
        BaselinePlanStep::SearchRefFetchSpan { .. } => "search_ref_fetch_span",
    }
}

fn query_specificity_score(query: &str) -> usize {
    let semantic_tokens = semantic_query_tokens(query);
    let specific_tokens = semantic_tokens
        .iter()
        .filter(|token| !is_generic_clause_token(token))
        .count();
    specific_tokens * 10 + semantic_tokens.len()
}

fn planned_steps_for_query_context(
    query_context: &str,
    steps: Vec<BaselinePlanStep>,
) -> Vec<PlannedQueryStep> {
    steps
        .into_iter()
        .map(|step| PlannedQueryStep {
            query_context: query_context.to_string(),
            step,
        })
        .collect()
}

fn derive_baseline_plan(plan: &[BaselinePlanStep], query: &str) -> Vec<PlannedQueryStep> {
    let clauses = decompose_query_clauses(query);
    if clauses.len() <= 1 {
        let intent = classify_query_plan_intent(query);
        let filtered = derive_plan_for_intent(plan, intent);
        return planned_steps_for_query_context(
            query,
            if filtered.is_empty() {
                plan.to_vec()
            } else {
                filtered
            },
        );
    }

    let mut combined = Vec::<PlannedQueryStep>::new();
    let mut seen = BTreeMap::<&'static str, (usize, usize)>::new();

    for clause in clauses {
        let clause_intent = classify_query_plan_intent(clause.as_str());
        let clause_steps = derive_plan_for_intent(plan, clause_intent);
        if clause_steps.is_empty() {
            continue;
        }

        let specificity = query_specificity_score(clause.as_str());
        for step in clause_steps {
            let key = planned_step_dedup_key(&step);
            if let Some((existing_index, existing_score)) = seen.get_mut(key) {
                if specificity > *existing_score {
                    combined[*existing_index] = PlannedQueryStep {
                        query_context: clause.clone(),
                        step,
                    };
                    *existing_score = specificity;
                }
                continue;
            }

            seen.insert(key, (combined.len(), specificity));
            combined.push(PlannedQueryStep {
                query_context: clause.clone(),
                step,
            });
        }
    }

    if combined.is_empty() {
        planned_steps_for_query_context(query, plan.to_vec())
    } else {
        combined
    }
}

async fn request_beam_plan(
    state: &AppState,
    request: &PlanRequest,
) -> Result<PlanResponse, PlannerClientError> {
    let Some(url) = state.config.planner_client_url.as_deref() else {
        return Err(PlannerClientError {
            code: "ERR_PLANNER_CLIENT_CONFIG",
            message: "beam planner client requires PECR_CONTROLLER_PLANNER_URL".to_string(),
        });
    };

    let timeout = Duration::from_millis(state.config.planner_client_timeout_ms.max(1));
    let send_fut = async {
        let response = state
            .http
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|_| PlannerClientError {
                code: "ERR_PLANNER_CLIENT_UNAVAILABLE",
                message: "planner client request failed".to_string(),
            })?;

        if !response.status().is_success() {
            return Err(PlannerClientError {
                code: "ERR_PLANNER_CLIENT_UNAVAILABLE",
                message: format!("planner client returned {}", response.status()),
            });
        }

        response
            .json::<PlanResponse>()
            .await
            .map_err(|_| PlannerClientError {
                code: "ERR_PLANNER_CLIENT_PROTOCOL",
                message: "planner client returned an invalid plan response".to_string(),
            })
    };

    tokio::time::timeout(timeout, send_fut)
        .await
        .map_err(|_| PlannerClientError {
            code: "ERR_PLANNER_CLIENT_TIMEOUT",
            message: "planner client timed out".to_string(),
        })?
}

fn validate_planner_output_step(
    request: &PlanRequest,
    step: PlannerStep,
) -> Result<PlannerStep, &'static str> {
    match step {
        PlannerStep::Operator { op_name, params } => {
            let op_name = op_name.trim();
            if op_name.is_empty() {
                return Err("empty_operator_name");
            }
            if !request
                .available_operator_names
                .iter()
                .any(|allowed| allowed == op_name)
            {
                return Err("operator_not_allowlisted");
            }

            Ok(PlannerStep::Operator {
                op_name: op_name.to_string(),
                params,
            })
        }
        PlannerStep::SearchRefFetchSpan { max_refs } => {
            if !request.allow_search_ref_fetch_span {
                return Err("search_ref_fetch_span_not_allowed");
            }
            if max_refs == 0 {
                return Err("search_ref_fetch_span_zero_refs");
            }
            Ok(PlannerStep::SearchRefFetchSpan { max_refs })
        }
    }
}

fn planner_steps_for_planned_steps(steps: &[PlannedQueryStep]) -> Vec<PlannerStep> {
    steps
        .iter()
        .cloned()
        .map(|step| planner_step_for_baseline_step(step.step, step.query_context.as_str()))
        .collect()
}

fn baseline_step_for_planner_step(step: PlannerStep) -> BaselinePlanStep {
    match step {
        PlannerStep::Operator { op_name, params } => BaselinePlanStep::Operator { op_name, params },
        PlannerStep::SearchRefFetchSpan { max_refs } => {
            BaselinePlanStep::SearchRefFetchSpan { max_refs }
        }
    }
}

fn baseline_steps_for_planner_steps(steps: Vec<PlannerStep>) -> Vec<BaselinePlanStep> {
    steps
        .into_iter()
        .map(baseline_step_for_planner_step)
        .collect()
}

fn planned_steps_for_planner_steps(query: &str, steps: Vec<PlannerStep>) -> Vec<PlannedQueryStep> {
    planned_steps_for_query_context(query, baseline_steps_for_planner_steps(steps))
}

fn planner_step_name(step: &PlannerStep) -> &'static str {
    match step {
        PlannerStep::Operator { op_name, .. } => match op_name.as_str() {
            "aggregate" => "aggregate",
            "compare" => "compare",
            "diff" => "diff",
            "discover_dimensions" => "discover_dimensions",
            "fetch_rows" => "fetch_rows",
            "fetch_span" => "fetch_span",
            "list_versions" => "list_versions",
            "lookup_evidence" => "lookup_evidence",
            "redact" => "redact",
            "search" => "search",
            _ => "other",
        },
        PlannerStep::SearchRefFetchSpan { .. } => "search_ref_fetch_span",
    }
}

fn planner_step_names(steps: &[PlannerStep]) -> Vec<&'static str> {
    steps.iter().map(planner_step_name).collect()
}

fn shared_planner_prefix_len(left: &[&'static str], right: &[&'static str]) -> usize {
    left.iter()
        .zip(right.iter())
        .take_while(|(left_name, right_name)| left_name == right_name)
        .count()
}

fn round_4dp(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn clamp_usefulness_score(value: f64) -> f64 {
    round_4dp(value.clamp(0.0, 1.0))
}

fn push_usefulness_reason(reasons: &mut Vec<String>, reason: impl Into<String>) {
    let reason = reason.into();
    if reasons.iter().any(|existing| existing == &reason) {
        return;
    }
    reasons.push(reason);
}

fn assess_expected_usefulness(
    request: &PlanRequest,
    steps: &[PlannerStep],
) -> Option<PlannerUsefulnessAssessment> {
    if steps.is_empty() {
        return None;
    }

    let mut score = 0.35;
    let mut reasons = Vec::new();
    let step_names = planner_step_names(steps);
    let recommended_names = planner_step_names(&request.planner_hints.recommended_path);
    let clause_count = decompose_query_clauses(request.query.as_str()).len().max(1);
    let distinct_step_count = step_names.iter().copied().collect::<BTreeSet<_>>().len();
    let first_step = step_names.first().copied().unwrap_or("other");

    if !recommended_names.is_empty() {
        let prefix_len = shared_planner_prefix_len(&step_names, &recommended_names);
        let prefix_ratio = prefix_len as f64 / recommended_names.len() as f64;
        if prefix_len == recommended_names.len() {
            score += 0.28;
            push_usefulness_reason(
                &mut reasons,
                "matches the benchmarked recommended planner path for this query shape",
            );
        } else if prefix_len > 0 {
            score += 0.20 * prefix_ratio;
            push_usefulness_reason(
                &mut reasons,
                "keeps the strongest prefix of the benchmarked recommended planner path",
            );
        } else {
            score -= 0.12;
            push_usefulness_reason(
                &mut reasons,
                "deviates from the recommended planner path for this query shape",
            );
        }
    }

    let contains = |name: &str| step_names.contains(&name);
    let contains_any = |names: &[&str]| names.iter().any(|name| contains(name));

    match request.planner_hints.intent {
        PlannerIntent::Default => {
            if !contains_any(&["aggregate", "compare"]) {
                score += 0.06;
                push_usefulness_reason(
                    &mut reasons,
                    "avoids jumping to a heavy aggregation path for a generic request",
                );
            }
        }
        PlannerIntent::StructuredLookup => {
            if first_step == "fetch_rows" {
                score += 0.24;
                push_usefulness_reason(
                    &mut reasons,
                    "starts with a direct structured lookup for a row-oriented question",
                );
            } else if contains("fetch_rows") {
                score += 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "still preserves a structured lookup even if it is not the first step",
                );
            } else {
                score -= 0.14;
                push_usefulness_reason(
                    &mut reasons,
                    "misses the direct structured lookup path the query most likely needs",
                );
            }
        }
        PlannerIntent::StructuredAggregation => {
            if matches!(first_step, "compare" | "aggregate") {
                score += 0.24;
                push_usefulness_reason(
                    &mut reasons,
                    "starts with an analyst-friendly compare path for an aggregation ask",
                );
            } else if contains_any(&["compare", "aggregate"]) {
                score += 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "keeps an aggregation step in the plan for a comparison-style ask",
                );
            } else {
                score -= 0.14;
                push_usefulness_reason(
                    &mut reasons,
                    "omits the aggregate or compare step expected for this question",
                );
            }
            if contains("compare") {
                score += 0.05;
            }
        }
        PlannerIntent::EvidenceLookup => {
            if first_step == "lookup_evidence" {
                score += 0.26;
                push_usefulness_reason(
                    &mut reasons,
                    "goes straight to source-backed evidence for a citation-style question",
                );
            } else if contains_any(&["lookup_evidence", "search", "search_ref_fetch_span"]) {
                score += 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "keeps an evidence-oriented path for a source-backed question",
                );
            } else {
                score -= 0.18;
                push_usefulness_reason(
                    &mut reasons,
                    "misses the source-backed retrieval path the question calls for",
                );
            }
        }
        PlannerIntent::VersionReview => {
            if first_step == "list_versions" {
                score += 0.18;
                push_usefulness_reason(
                    &mut reasons,
                    "starts with version history before attempting a change summary",
                );
            }
            if contains("list_versions") && contains("diff") {
                score += 0.16;
                push_usefulness_reason(
                    &mut reasons,
                    "includes both version listing and a concrete diff for a change question",
                );
            } else {
                score -= 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "does not include the list_versions plus diff path that makes changes useful",
                );
            }
        }
        PlannerIntent::StructuredEvidenceLookup => {
            if contains("fetch_rows") && contains("lookup_evidence") {
                score += 0.26;
                push_usefulness_reason(
                    &mut reasons,
                    "combines structured context and source-backed evidence in one path",
                );
            } else {
                score -= 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "drops either the structured lookup or the evidence lookup this mixed ask needs",
                );
            }
        }
        PlannerIntent::StructuredAggregationEvidence => {
            if contains_any(&["compare", "aggregate"]) && contains("lookup_evidence") {
                score += 0.28;
                push_usefulness_reason(
                    &mut reasons,
                    "combines comparison and evidence so the answer can explain the result",
                );
            } else {
                score -= 0.12;
                push_usefulness_reason(
                    &mut reasons,
                    "does not preserve both the comparison and evidence parts of the ask",
                );
            }
            if contains("compare") {
                score += 0.04;
            }
        }
        PlannerIntent::StructuredVersionReview => {
            if contains("fetch_rows") && contains("list_versions") && contains("diff") {
                score += 0.28;
                push_usefulness_reason(
                    &mut reasons,
                    "keeps row context and a concrete diff for a structured change question",
                );
            } else if contains("list_versions") && contains("diff") {
                score += 0.14;
                push_usefulness_reason(
                    &mut reasons,
                    "still keeps a useful version-to-diff flow for a change question",
                );
            } else {
                score -= 0.14;
                push_usefulness_reason(
                    &mut reasons,
                    "does not preserve the structured version-review flow this ask needs",
                );
            }
        }
    }

    if clause_count > 1 {
        if step_names.len() >= clause_count || distinct_step_count >= clause_count.min(3) {
            score += 0.08;
            push_usefulness_reason(
                &mut reasons,
                "covers multiple clauses instead of collapsing the request into one narrow path",
            );
        } else {
            score -= 0.08;
            push_usefulness_reason(
                &mut reasons,
                "may under-cover a multi-part request because the path is too narrow",
            );
        }
    }

    if steps.len() as u32 > request.budget.max_operator_calls {
        score -= 0.25;
        push_usefulness_reason(
            &mut reasons,
            "would exceed the operator budget before producing a useful answer",
        );
    } else if request.budget.max_operator_calls > 0
        && steps.len() as u32 >= request.budget.max_operator_calls.saturating_sub(1)
        && steps.len() > 2
    {
        score -= 0.06;
        push_usefulness_reason(
            &mut reasons,
            "uses most of the operator budget before any recovery headroom remains",
        );
    }

    let repeated_steps = step_names
        .windows(2)
        .filter(|pair| pair[0] == pair[1])
        .count();
    if repeated_steps > 0 {
        score -= (repeated_steps as f64 * 0.05).min(0.15);
        push_usefulness_reason(
            &mut reasons,
            "repeats the same operator shape without adding much new answer value",
        );
    }

    reasons.truncate(4);
    Some(PlannerUsefulnessAssessment {
        score: clamp_usefulness_score(score),
        reasons,
    })
}

fn apply_usefulness_assessment(
    trace: &mut ReplayPlannerTrace,
    assessment: Option<&PlannerUsefulnessAssessment>,
) {
    trace.decision_summary.expected_usefulness_score = assessment.map(|value| value.score);
    trace.decision_summary.expected_usefulness_reasons = assessment
        .map(|value| value.reasons.clone())
        .unwrap_or_default();
}

fn set_trace_selection_rationale(
    planner_traces: &mut [ReplayPlannerTrace],
    planner_source: &str,
    selection_rationale: Option<String>,
) {
    if let Some(trace) = planner_traces
        .iter_mut()
        .rev()
        .find(|trace| trace.decision_summary.planner_source == planner_source)
    {
        trace.decision_summary.selection_rationale = selection_rationale;
    }
}

fn explain_selection_rationale(
    selected_source: &str,
    selected_assessment: Option<&PlannerUsefulnessAssessment>,
    other_source: Option<&str>,
    other_assessment: Option<&PlannerUsefulnessAssessment>,
) -> Option<String> {
    let selected_assessment = selected_assessment?;
    let leading_reason = selected_assessment
        .reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "better fit for the query".to_string());
    match (other_source, other_assessment) {
        (Some(other_source), Some(other_assessment)) => Some(format!(
            "{} was preferred because expected usefulness {:.4} beat {} at {:.4}; {}.",
            selected_source,
            selected_assessment.score,
            other_source,
            other_assessment.score,
            leading_reason
        )),
        _ => Some(format!(
            "{} was preferred because expected usefulness scored {:.4}; {}.",
            selected_source, selected_assessment.score, leading_reason
        )),
    }
}

fn replay_planner_trace(
    plan_request: PlanRequest,
    output_steps: Vec<PlannerStep>,
    planner_source: &str,
    stop_reason: impl Into<String>,
    selected_for_execution: bool,
    planner_summary: Option<String>,
) -> ReplayPlannerTrace {
    let assessment = assess_expected_usefulness(&plan_request, &output_steps);
    ReplayPlannerTrace {
        plan_request,
        output_steps,
        decision_summary: {
            let mut decision_summary = ReplayPlannerDecisionSummary {
                planner_source: planner_source.to_string(),
                stop_reason: stop_reason.into(),
                selected_for_execution,
                used_fallback_plan: false,
                fallback_from_step: None,
                expected_usefulness_score: None,
                expected_usefulness_reasons: Vec::new(),
                selection_rationale: None,
                planner_summary,
            };
            decision_summary.expected_usefulness_score =
                assessment.as_ref().map(|value| value.score);
            decision_summary.expected_usefulness_reasons = assessment
                .as_ref()
                .map(|value| value.reasons.clone())
                .unwrap_or_default();
            decision_summary
        },
    }
}

fn planner_output_steps_from_response(
    request: &PlanRequest,
    response: PlanResponse,
) -> Result<(Vec<PlannerStep>, Option<String>), &'static str> {
    if response.schema_version != request.schema_version {
        return Err("schema_version_mismatch");
    }
    if response.steps.is_empty() {
        return Err("empty_steps");
    }

    let mut steps = Vec::with_capacity(response.steps.len());
    for step in response.steps {
        steps.push(validate_planner_output_step(request, step)?);
    }

    let planner_summary = response
        .planner_summary
        .map(|summary| summary.trim().to_string())
        .filter(|summary| !summary.is_empty());

    Ok((steps, planner_summary))
}

async fn select_execution_plan(
    state: &AppState,
    query: &str,
    budget: &Budget,
) -> SelectedExecutionPlan {
    let beam_execution_enabled = state.config.controller_engine == ControllerEngine::BeamPlanner;
    let rust_steps = derive_baseline_plan(&state.config.baseline_plan, query);
    let plan_request = plan_request_for_query(
        &state.config.baseline_plan,
        query,
        budget,
        &state.config.context_budget,
    );
    let rust_planner_steps = planner_steps_for_planned_steps(&rust_steps);
    let rust_assessment = assess_expected_usefulness(&plan_request, &rust_planner_steps);
    let mut planner_traces = vec![replay_planner_trace(
        plan_request.clone(),
        rust_planner_steps,
        "rust_owned",
        "selected_as_execution_plan",
        true,
        None,
    )];
    set_trace_selection_rationale(
        &mut planner_traces,
        "rust_owned",
        explain_selection_rationale("rust_owned", rust_assessment.as_ref(), None, None),
    );
    if !beam_execution_enabled && state.config.planner_mode == PlannerMode::RustOwned {
        return SelectedExecutionPlan {
            steps: rust_steps,
            planner_source: "rust_owned",
            planner_summary: None,
            planner_traces,
        };
    }

    match state.config.planner_client {
        PlannerClientKind::Disabled => {
            tracing::warn!(
                planner_mode = if beam_execution_enabled {
                    "beam_execution"
                } else {
                    "shadow"
                },
                "planner.client_disabled_rust_owned_execution"
            );
            SelectedExecutionPlan {
                steps: rust_steps,
                planner_source: "rust_owned",
                planner_summary: None,
                planner_traces,
            }
        }
        PlannerClientKind::Beam => {
            let client = BeamPlannerClient { state };
            let planner_source = if beam_execution_enabled {
                "beam_planner"
            } else {
                "beam_shadow"
            };
            match client.plan(&plan_request).await {
                Ok(response) => match planner_output_steps_from_response(&plan_request, response) {
                    Ok((beam_steps, planner_summary)) => {
                        let beam_assessment =
                            assess_expected_usefulness(&plan_request, &beam_steps);
                        if beam_execution_enabled {
                            let beam_score = beam_assessment
                                .as_ref()
                                .map(|value| value.score)
                                .unwrap_or(0.0);
                            let rust_score = rust_assessment
                                .as_ref()
                                .map(|value| value.score)
                                .unwrap_or(0.0);
                            let beam_selected = beam_score >= rust_score;
                            let mut beam_trace = replay_planner_trace(
                                plan_request,
                                beam_steps,
                                planner_source,
                                if beam_selected {
                                    "selected_as_execution_plan"
                                } else {
                                    "lower_expected_usefulness_than_rust_owned"
                                },
                                beam_selected,
                                planner_summary.clone(),
                            );
                            apply_usefulness_assessment(&mut beam_trace, beam_assessment.as_ref());
                            beam_trace.decision_summary.selection_rationale =
                                explain_selection_rationale(
                                    planner_source,
                                    beam_assessment.as_ref(),
                                    Some("rust_owned"),
                                    rust_assessment.as_ref(),
                                );
                            planner_traces.push(beam_trace);
                            if beam_selected {
                                planner_traces[0].decision_summary.selected_for_execution = false;
                                planner_traces[0].decision_summary.stop_reason =
                                    "retained_as_runtime_fallback".to_string();
                                planner_traces[0].decision_summary.selection_rationale = Some(
                                    format!(
                                        "rust_owned stayed available as a runtime fallback because beam_planner scored {:.4} versus {:.4}.",
                                        beam_score, rust_score
                                    ),
                                );
                                let execution_steps = planned_steps_for_planner_steps(
                                    query,
                                    planner_traces
                                        .last()
                                        .map(|trace| trace.output_steps.clone())
                                        .unwrap_or_default(),
                                );
                                SelectedExecutionPlan {
                                    steps: execution_steps,
                                    planner_source,
                                    planner_summary,
                                    planner_traces,
                                }
                            } else {
                                planner_traces[0].decision_summary.selected_for_execution = true;
                                planner_traces[0].decision_summary.stop_reason =
                                    "selected_as_execution_plan".to_string();
                                planner_traces[0].decision_summary.selection_rationale =
                                    explain_selection_rationale(
                                        "rust_owned",
                                        rust_assessment.as_ref(),
                                        Some("beam_planner"),
                                        beam_assessment.as_ref(),
                                    );
                                if let Some(trace) = planner_traces.last_mut() {
                                    trace.decision_summary.selection_rationale = Some(format!(
                                        "beam_planner scored {:.4} below rust_owned at {:.4}, so it was not selected for execution.",
                                        beam_score, rust_score
                                    ));
                                }
                                SelectedExecutionPlan {
                                    steps: rust_steps,
                                    planner_source: "rust_owned",
                                    planner_summary: None,
                                    planner_traces,
                                }
                            }
                        } else {
                            let mut beam_trace = replay_planner_trace(
                                plan_request,
                                beam_steps,
                                planner_source,
                                "shadow_only",
                                false,
                                planner_summary.clone(),
                            );
                            apply_usefulness_assessment(&mut beam_trace, beam_assessment.as_ref());
                            beam_trace.decision_summary.selection_rationale = Some(format!(
                                "beam_shadow scored {:.4} but stayed advisory because the controller remained in rust-owned execution mode.",
                                beam_assessment
                                    .as_ref()
                                    .map(|value| value.score)
                                    .unwrap_or(0.0)
                            ));
                            planner_traces.push(beam_trace);
                            planner_traces[0].decision_summary.selection_rationale = Some(
                                "rust_owned stayed selected because beam_shadow was recorded for comparison only."
                                    .to_string(),
                            );
                            SelectedExecutionPlan {
                                steps: rust_steps,
                                planner_source: "rust_owned",
                                planner_summary: None,
                                planner_traces,
                            }
                        }
                    }
                    Err(reason) => {
                        tracing::warn!(
                            planner_source,
                            planner_reason = reason,
                            "planner.client_response_rejected"
                        );
                        planner_traces.push(replay_planner_trace(
                            plan_request,
                            Vec::new(),
                            planner_source,
                            reason,
                            false,
                            None,
                        ));
                        SelectedExecutionPlan {
                            steps: rust_steps,
                            planner_source: "rust_owned",
                            planner_summary: None,
                            planner_traces,
                        }
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        planner_source,
                        planner_error_code = err.code,
                        planner_error = %err.message,
                        "planner.client_failed"
                    );
                    planner_traces.push(replay_planner_trace(
                        plan_request,
                        Vec::new(),
                        planner_source,
                        err.code,
                        false,
                        None,
                    ));
                    SelectedExecutionPlan {
                        steps: rust_steps,
                        planner_source: "rust_owned",
                        planner_summary: None,
                        planner_traces,
                    }
                }
            }
        }
    }
}

async fn attempt_beam_recovery_plan(
    state: &AppState,
    query: &str,
    budget: &Budget,
    active_steps: &[PlannedQueryStep],
    failed_step: &PlannedQueryStep,
    failure_terminal_mode: TerminalMode,
    fallback_steps: &[BaselinePlanStep],
) -> Result<(Vec<PlannedQueryStep>, ReplayPlannerTrace), ReplayPlannerTrace> {
    let recovery_request = recovery_plan_request_for_query(
        query,
        budget,
        &state.config.context_budget,
        fallback_steps,
        recovery_context_for_failure(active_steps, failed_step, failure_terminal_mode),
    );
    let client = BeamPlannerClient { state };

    match client.plan(&recovery_request).await {
        Ok(response) => match planner_output_steps_from_response(&recovery_request, response) {
            Ok((recovery_steps, planner_summary)) => Ok((
                planned_steps_for_planner_steps(query, recovery_steps.clone()),
                replay_planner_trace(
                    recovery_request,
                    recovery_steps,
                    "beam_recovery",
                    "selected_as_execution_plan",
                    true,
                    planner_summary,
                ),
            )),
            Err(reason) => Err(replay_planner_trace(
                recovery_request,
                Vec::new(),
                "beam_recovery",
                reason,
                false,
                None,
            )),
        },
        Err(err) => Err(replay_planner_trace(
            recovery_request,
            Vec::new(),
            "beam_recovery",
            err.code,
            false,
            None,
        )),
    }
}

fn has_operator(step_list: &[BaselinePlanStep], op_name: &str) -> bool {
    step_list.iter().any(|step| {
        matches!(
            step,
            BaselinePlanStep::Operator {
                op_name: step_op_name,
                ..
            } if step_op_name == op_name
        )
    })
}

fn recoverable_operator_failure(terminal_mode: TerminalMode) -> bool {
    matches!(
        terminal_mode,
        TerminalMode::SourceUnavailable | TerminalMode::InsufficientPermission
    )
}

fn derive_fallback_plan(
    plan: &[BaselinePlanStep],
    plan_intent: QueryPlanIntent,
    failed_step: &BaselinePlanStep,
) -> Vec<BaselinePlanStep> {
    let candidate_intents = match failed_step {
        BaselinePlanStep::Operator { op_name, .. } if op_name == "fetch_rows" => {
            vec![QueryPlanIntent::EvidenceLookup]
        }
        BaselinePlanStep::Operator { op_name, .. }
            if op_name == "aggregate" || op_name == "compare" =>
        {
            vec![
                QueryPlanIntent::StructuredLookup,
                QueryPlanIntent::EvidenceLookup,
            ]
        }
        BaselinePlanStep::Operator { op_name, .. } if op_name == "lookup_evidence" => {
            vec![QueryPlanIntent::StructuredLookup]
        }
        BaselinePlanStep::Operator { op_name, .. }
            if op_name == "list_versions" || op_name == "diff" =>
        {
            vec![
                QueryPlanIntent::EvidenceLookup,
                QueryPlanIntent::StructuredLookup,
            ]
        }
        BaselinePlanStep::Operator { op_name, .. } if op_name == "search" => match plan_intent {
            QueryPlanIntent::StructuredLookup
            | QueryPlanIntent::StructuredEvidenceLookup
            | QueryPlanIntent::StructuredVersionReview => vec![QueryPlanIntent::StructuredLookup],
            QueryPlanIntent::StructuredAggregation
            | QueryPlanIntent::StructuredAggregationEvidence => {
                vec![QueryPlanIntent::StructuredLookup]
            }
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };

    for intent in candidate_intents {
        let candidate = derive_plan_for_intent(plan, intent);
        if candidate.is_empty() {
            continue;
        }

        let failed_op = match failed_step {
            BaselinePlanStep::Operator { op_name, .. } => Some(op_name.as_str()),
            BaselinePlanStep::SearchRefFetchSpan { .. } => None,
        };
        if failed_op
            .is_some_and(|op_name| candidate.len() == 1 && has_operator(&candidate, op_name))
        {
            continue;
        }

        return candidate;
    }

    Vec::new()
}

fn step_name_for_baseline_step(step: &BaselinePlanStep) -> String {
    match step {
        BaselinePlanStep::Operator { op_name, .. } => op_name.clone(),
        BaselinePlanStep::SearchRefFetchSpan { .. } => "search_ref_fetch_span".to_string(),
    }
}

fn recovery_context_for_failure(
    active_steps: &[PlannedQueryStep],
    failed_step: &PlannedQueryStep,
    failure_terminal_mode: TerminalMode,
) -> PlannerRecoveryContext {
    PlannerRecoveryContext {
        failed_step: step_name_for_baseline_step(&failed_step.step),
        failure_terminal_mode,
        attempted_path: planner_steps_for_planned_steps(active_steps),
        failed_step_details: Some(planner_step_for_baseline_step(
            failed_step.step.clone(),
            failed_step.query_context.as_str(),
        )),
    }
}

fn select_trace_source(
    planner_traces: &mut [ReplayPlannerTrace],
    planner_source: &str,
    selected_for_execution: bool,
    stop_reason: &str,
) -> bool {
    if let Some(trace) = planner_traces
        .iter_mut()
        .rev()
        .find(|trace| trace.decision_summary.planner_source == planner_source)
    {
        trace.decision_summary.selected_for_execution = selected_for_execution;
        trace.decision_summary.stop_reason = stop_reason.to_string();
        return true;
    }

    false
}

fn query_mentions_plan_dimension(tokens: &[String]) -> bool {
    query_has_any_token(tokens, &["plan", "plans", "tier", "tiers"])
}

fn query_mentions_status_dimension(tokens: &[String]) -> bool {
    query_has_any_token(tokens, &["status", "statuses", "state", "states"])
}

fn query_mentions_time_trend(tokens: &[String]) -> bool {
    query_has_any_token(
        tokens,
        &[
            "trend", "trends", "time", "times", "daily", "day", "days", "monthly", "month",
            "months", "over",
        ],
    )
}

fn aggregate_group_by_for_query(tokens: &[String]) -> Vec<String> {
    let mut group_by = Vec::new();
    if query_mentions_status_dimension(tokens) {
        group_by.push("status".to_string());
    }
    if query_mentions_plan_dimension(tokens) {
        group_by.push("plan_tier".to_string());
    }
    if group_by.is_empty() && !query_mentions_time_trend(tokens) {
        group_by.push("status".to_string());
    }
    group_by.sort();
    group_by.dedup();
    group_by
}

fn aggregate_filter_spec_for_query(tokens: &[String]) -> serde_json::Value {
    let mut filter_spec = serde_json::Map::new();
    if tokens.iter().any(|token| token == "active") {
        filter_spec.insert("status".to_string(), serde_json::json!("active"));
    } else if tokens.iter().any(|token| token == "inactive") {
        filter_spec.insert("status".to_string(), serde_json::json!("inactive"));
    }

    if tokens.iter().any(|token| token == "starter") {
        filter_spec.insert("plan_tier".to_string(), serde_json::json!("starter"));
    } else if tokens.iter().any(|token| token == "premium") {
        filter_spec.insert("plan_tier".to_string(), serde_json::json!("premium"));
    } else if tokens.iter().any(|token| token == "enterprise") {
        filter_spec.insert("plan_tier".to_string(), serde_json::json!("enterprise"));
    }

    serde_json::Value::Object(filter_spec)
}

fn aggregate_time_granularity_for_query(tokens: &[String]) -> Option<&'static str> {
    if tokens
        .iter()
        .any(|token| token == "monthly" || token == "month" || token == "months")
    {
        Some("month")
    } else if query_mentions_time_trend(tokens) {
        Some("day")
    } else {
        None
    }
}

fn version_review_object_id_for_query(query: &str) -> Option<&'static str> {
    let tokens = semantic_query_tokens(query);
    if tokens.is_empty() {
        return None;
    }

    if query_has_any_token(&tokens, &["billing", "invoice", "invoices"]) {
        Some("public/billing_terms_policy.txt")
    } else if query_has_any_token(&tokens, &["refund", "refunds", "annual"]) {
        Some("public/annual_refund_terms.txt")
    } else if query_has_any_token(&tokens, &["support", "policy", "policies", "document"]) {
        Some("public/support_policy.txt")
    } else {
        None
    }
}

fn version_review_params_for_query(params: &serde_json::Value, query: &str) -> serde_json::Value {
    let mut rendered = params.clone();
    let Some(map) = rendered.as_object_mut() else {
        return rendered;
    };

    let should_override = map
        .get("object_id")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value.trim() == "public/public_1.txt");
    if should_override && let Some(object_id) = version_review_object_id_for_query(query) {
        map.insert("object_id".to_string(), serde_json::json!(object_id));
    }

    rendered
}

fn evidence_lookup_terms_for_query(query: &str) -> Vec<String> {
    let mut terms = semantic_query_tokens(query)
        .into_iter()
        .filter(|token| !is_generic_evidence_token(token) && !is_generic_version_token(token))
        .collect::<Vec<_>>();

    if !terms.is_empty() {
        let raw_tokens = query_tokens(query);
        for token in [
            "policy",
            "policies",
            "term",
            "terms",
            "document",
            "documents",
        ] {
            if raw_tokens.iter().any(|raw| raw == token) && !terms.iter().any(|term| term == token)
            {
                terms.push(token.to_string());
            }
        }
    }

    terms
}

fn evidence_lookup_params_for_query(params: &serde_json::Value, query: &str) -> serde_json::Value {
    let mut rendered = params.clone();
    let Some(map) = rendered.as_object_mut() else {
        return rendered;
    };

    let terms = evidence_lookup_terms_for_query(query);
    if terms.is_empty() {
        return rendered;
    }

    map.insert(
        "terms".to_string(),
        serde_json::Value::Array(
            terms
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    map.entry("match_mode".to_string())
        .or_insert_with(|| serde_json::json!("all"));

    if !map.contains_key("object_prefix")
        && query_has_any_token(&terms, &["support", "billing", "refund", "policy", "terms"])
    {
        map.insert("object_prefix".to_string(), serde_json::json!("public/"));
    }

    rendered
}

fn version_diff_placeholder_params(params: &serde_json::Value) -> serde_json::Value {
    let mut rendered = params.clone();
    let Some(map) = rendered.as_object_mut() else {
        return rendered;
    };

    map.insert("v1".to_string(), serde_json::json!("$previous_version_id"));
    map.insert("v2".to_string(), serde_json::json!("$latest_version_id"));
    rendered
}

fn extract_version_pair_from_list_versions_result(
    result: &serde_json::Value,
) -> Option<(String, String)> {
    let versions = result.get("versions")?.as_array()?;
    let mut ranked_versions = versions
        .iter()
        .enumerate()
        .filter_map(|(index, version)| {
            let version_id = version
                .get("version_id")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())?;
            let as_of_time = version
                .get("as_of_time")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("");
            Some((index, as_of_time.to_string(), version_id.to_string()))
        })
        .collect::<Vec<_>>();

    if ranked_versions.len() < 2 {
        return None;
    }

    if ranked_versions
        .iter()
        .all(|(_, as_of_time, _)| !as_of_time.is_empty())
    {
        ranked_versions
            .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    }

    let mut ordered_ids = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, _, version_id) in ranked_versions {
        if seen.insert(version_id.clone()) {
            ordered_ids.push(version_id);
        }
        if ordered_ids.len() == 2 {
            break;
        }
    }

    if ordered_ids.len() < 2 {
        return None;
    }

    Some((ordered_ids[1].clone(), ordered_ids[0].clone()))
}

fn resolve_version_diff_params(
    params: &serde_json::Value,
    list_versions_result: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    let mut rendered = params.as_object()?.clone();
    let needs_previous = rendered
        .get("v1")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value == "$previous_version_id");
    let needs_latest = rendered
        .get("v2")
        .and_then(|value| value.as_str())
        .is_some_and(|value| value == "$latest_version_id");

    if !(needs_previous || needs_latest) {
        return Some(serde_json::Value::Object(rendered));
    }

    let (previous_version_id, latest_version_id) =
        extract_version_pair_from_list_versions_result(list_versions_result?)?;
    if needs_previous {
        rendered.insert("v1".to_string(), serde_json::json!(previous_version_id));
    }
    if needs_latest {
        rendered.insert("v2".to_string(), serde_json::json!(latest_version_id));
    }

    Some(serde_json::Value::Object(rendered))
}

fn aggregate_params_for_query(params: &serde_json::Value, query: &str) -> serde_json::Value {
    let tokens = query_tokens(query);
    let mut rendered = params.clone();
    let Some(map) = rendered.as_object_mut() else {
        return rendered;
    };

    let group_by = aggregate_group_by_for_query(&tokens);
    map.insert("group_by".to_string(), serde_json::json!(group_by));
    map.insert(
        "metrics".to_string(),
        serde_json::json!([{ "name": "count", "field": "customer_id" }]),
    );

    let filter_spec = aggregate_filter_spec_for_query(&tokens);
    if filter_spec
        .as_object()
        .is_some_and(|value| !value.is_empty())
    {
        map.insert("filter_spec".to_string(), filter_spec);
    } else {
        map.remove("filter_spec");
    }

    if let Some(time_granularity) = aggregate_time_granularity_for_query(&tokens) {
        map.insert(
            "time_granularity".to_string(),
            serde_json::json!(time_granularity),
        );
    } else {
        map.remove("time_granularity");
    }

    rendered
}

fn fetch_rows_params_for_query(params: &serde_json::Value, query: &str) -> serde_json::Value {
    let tokens = query_tokens(query);
    let mut rendered = params.clone();
    let Some(map) = rendered.as_object_mut() else {
        return rendered;
    };

    let mut fields = Vec::new();
    if query_mentions_status_dimension(&tokens) {
        fields.push("status".to_string());
    }
    if query_mentions_plan_dimension(&tokens) {
        fields.push("plan_tier".to_string());
    }
    if fields.is_empty() {
        fields.extend(["plan_tier".to_string(), "status".to_string()]);
    }
    fields.sort();
    fields.dedup();
    map.insert("fields".to_string(), serde_json::json!(fields));
    rendered
}

#[cfg(feature = "rlm")]
fn next_fair_batch_call(
    fairness_ring: &mut VecDeque<String>,
    pending_by_operator: &mut HashMap<String, VecDeque<PendingBatchCall>>,
    in_flight_by_operator: &mut HashMap<String, usize>,
    max_in_flight_by_operator: &HashMap<String, usize>,
) -> Option<(usize, String, serde_json::Value)> {
    let slots = fairness_ring.len();
    for _ in 0..slots {
        let op_name = fairness_ring.pop_front()?;
        fairness_ring.push_back(op_name.clone());

        let max_in_flight = max_in_flight_by_operator
            .get(op_name.as_str())
            .copied()
            .unwrap_or(usize::MAX);
        let in_flight = in_flight_by_operator
            .get(op_name.as_str())
            .copied()
            .unwrap_or(0);
        if in_flight >= max_in_flight {
            continue;
        }

        let Some(queue) = pending_by_operator.get_mut(op_name.as_str()) else {
            continue;
        };
        let Some(next_call) = queue.pop_front() else {
            continue;
        };

        in_flight_by_operator.insert(op_name.clone(), in_flight.saturating_add(1));
        return Some((next_call.idx, op_name, next_call.params));
    }

    None
}

async fn call_operator(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    op_name: &str,
    params: serde_json::Value,
    timeout: Duration,
) -> Result<OperatorCallOutcome, ApiError> {
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
        "compare" => tracing::info_span!(
            "operator.compare",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "compare",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "lookup_evidence" => tracing::info_span!(
            "operator.lookup_evidence",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "lookup_evidence",
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
        let _inflight = InflightOpsGuard::new();
        let url = format!(
            "{}/v1/operators/{}",
            state.config.gateway_url.trim_end_matches('/'),
            op_name
        );

        let send_fut = async {
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
                ctx.local_auth_shared_secret,
            )
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

            Ok::<_, ApiError>((status, bytes))
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

async fn policy_aware_narrowing_guidance(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    intent: QueryPlanIntent,
) -> Option<String> {
    let base_guidance = ambiguity_guidance_for_query(query);

    let mut params = serde_json::Map::new();
    params.insert(
        "query".to_string(),
        serde_json::Value::String(query.trim().to_string()),
    );
    params.insert(
        "intent".to_string(),
        serde_json::Value::String(query_plan_intent_name(intent).to_string()),
    );

    let send_fut = async {
        let builder = state
            .http
            .post(format!(
                "{}/v1/policies/simulate",
                state.config.gateway_url.trim_end_matches('/')
            ))
            .header("x-pecr-request-id", ctx.request_id)
            .header("x-pecr-trace-id", ctx.trace_id);

        let response = apply_gateway_auth(
            builder,
            ctx.principal_id,
            ctx.authz_header,
            ctx.local_auth_shared_secret,
        )
        .json(&PolicySimulateRequest {
            action: "narrow_query".to_string(),
            params,
        })
        .send()
        .await
        .ok()?;

        if !response.status().is_success() {
            return None;
        }

        response.json::<PolicySimulateResponse>().await.ok()
    };

    let Some(simulated) = tokio::time::timeout(Duration::from_millis(250), send_fut)
        .await
        .ok()
        .flatten()
    else {
        return base_guidance;
    };
    if !simulated.allow {
        return base_guidance;
    }

    match simulated.narrowing.as_ref() {
        Some(narrowing) => render_policy_narrowing_guidance(base_guidance, narrowing),
        None => base_guidance,
    }
}

pub(super) async fn run_context_loop(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    let loop_start = Instant::now();
    let query_trimmed = query.trim();
    let SelectedExecutionPlan {
        steps: planned_steps,
        planner_source,
        planner_summary,
        mut planner_traces,
    } = select_execution_plan(state, query_trimmed, budget).await;
    let plan_intent = classify_query_plan_intent(query_trimmed);

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let mut stop_reason: &'static str = "unknown";
    let mut budget_violation = false;
    let mut response_text: Option<String> = None;
    let mut used_fallback_plan = false;
    let mut fallback_from_step: Option<String> = None;
    let mut operator_summaries = Vec::<String>::new();

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();
    let mut search_refs = Vec::<EvidenceUnitRef>::new();
    let mut latest_list_versions_result: Option<serde_json::Value> = None;
    let scheduler = BudgetScheduler::new(budget, loop_start);
    let mut active_steps = planned_steps.clone();
    let mut step_index = 0usize;

    tracing::debug!(
        trace_id = %ctx.trace_id,
        request_id = %ctx.request_id,
        session_id = %ctx.session_id,
        plan_intent = ?plan_intent,
        planner_source,
        planner_summary = planner_summary.as_deref().unwrap_or(""),
        planned_steps = planned_steps.len(),
        "planner.query_plan_selected"
    );

    'plan_loop: while step_index < active_steps.len() {
        let step = active_steps[step_index].clone();
        let step_name = match &step.step {
            BaselinePlanStep::Operator { op_name, .. } => op_name.as_str(),
            BaselinePlanStep::SearchRefFetchSpan { .. } => "search_ref_fetch_span",
        };
        let planner_span = tracing::info_span!(
            "planner.baseline_step",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            step = %step_name,
            used_fallback_plan,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        tracing::debug!(parent: &planner_span, "planner.step_ready");

        let scheduler_span = tracing::info_span!(
            "scheduler.budget_gate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth_used)) {
            stop_reason = reason.as_str();
            budget_violation = true;
            break;
        }

        crate::metrics::inc_loop_iteration();
        if let Err(reason) =
            scheduler_span.in_scope(|| scheduler.check_operator_calls(operator_calls_used))
        {
            stop_reason = reason.as_str();
            budget_violation = true;
            break;
        }

        let Some(timeout) = scheduler.remaining_wallclock() else {
            stop_reason = BudgetStopReason::WallclockMs.as_str();
            budget_violation = true;
            break;
        };

        depth_used = depth_used.saturating_add(1);

        match &step.step {
            BaselinePlanStep::Operator { op_name, params } => {
                if op_name == "search" && step.query_context.trim().is_empty() {
                    step_index += 1;
                    continue;
                }

                let rendered_params =
                    render_plan_params(op_name.as_str(), params, step.query_context.as_str());
                let Some(resolved_params) = (if op_name == "diff" {
                    resolve_version_diff_params(
                        &rendered_params,
                        latest_list_versions_result.as_ref(),
                    )
                } else {
                    Some(rendered_params.clone())
                }) else {
                    step_index += 1;
                    continue;
                };

                let outcome = if op_name == "diff" {
                    match call_operator(state, ctx, op_name.as_str(), resolved_params, timeout)
                        .await
                    {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            step_index += 1;
                            continue;
                        }
                    }
                } else {
                    call_operator(state, ctx, op_name.as_str(), resolved_params, timeout).await?
                };
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                let Some(body) = outcome.body else {
                    if op_name == "diff" {
                        step_index += 1;
                        continue;
                    }
                    let fallback_steps = if !used_fallback_plan
                        && evidence_units.is_empty()
                        && recoverable_operator_failure(outcome.terminal_mode_hint)
                    {
                        derive_fallback_plan(
                            &state.config.baseline_plan,
                            classify_query_plan_intent(step.query_context.as_str()),
                            &step.step,
                        )
                    } else {
                        Vec::new()
                    };
                    if !fallback_steps.is_empty() {
                        tracing::info!(
                            trace_id = %ctx.trace_id,
                            request_id = %ctx.request_id,
                            session_id = %ctx.session_id,
                            failed_step = %op_name,
                            failure_terminal_mode = %outcome.terminal_mode_hint.as_str(),
                            fallback_steps = fallback_steps.len(),
                            "planner.recovery_path_selected"
                        );
                        let mut recovery_steps = planned_steps_for_query_context(
                            step.query_context.as_str(),
                            fallback_steps.clone(),
                        );
                        if state.config.controller_engine == ControllerEngine::BeamPlanner
                            && state.config.planner_client == PlannerClientKind::Beam
                        {
                            match attempt_beam_recovery_plan(
                                state,
                                step.query_context.as_str(),
                                budget,
                                &active_steps,
                                &step,
                                outcome.terminal_mode_hint,
                                &fallback_steps,
                            )
                            .await
                            {
                                Ok((beam_recovery_steps, recovery_trace)) => {
                                    let _ = select_trace_source(
                                        &mut planner_traces,
                                        "beam_planner",
                                        false,
                                        "recovered_by_beam_worker",
                                    );
                                    planner_traces.push(recovery_trace);
                                    recovery_steps = beam_recovery_steps;
                                }
                                Err(recovery_trace) => {
                                    planner_traces.push(recovery_trace);
                                    let _ = select_trace_source(
                                        &mut planner_traces,
                                        "beam_planner",
                                        false,
                                        "recovery_fell_back_to_rust_owned",
                                    );
                                    let _ = select_trace_source(
                                        &mut planner_traces,
                                        "rust_owned",
                                        true,
                                        "selected_as_recovery_plan",
                                    );
                                }
                            }
                        }
                        active_steps = recovery_steps;
                        step_index = 0;
                        used_fallback_plan = true;
                        fallback_from_step = Some(step_name_for_baseline_step(&step.step));
                        terminal_mode = TerminalMode::InsufficientEvidence;
                        search_refs.clear();
                        evidence_refs.clear();
                        continue;
                    }
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = "operator_error";
                    break;
                };

                remember_operator_summary(&mut operator_summaries, body.result_summary.as_deref());
                if op_name == "list_versions" {
                    latest_list_versions_result = Some(body.result.clone());
                }
                if op_name == "search"
                    && let Some(refs_value) = body.result.get("refs").cloned()
                    && let Ok(refs) = serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
                {
                    search_refs = refs;
                    evidence_refs = search_refs.clone();
                }

                if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(body.result.clone())
                {
                    evidence_units.extend(units);
                } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                    evidence_units.push(unit);
                }

                if op_name == "diff" && !evidence_units.is_empty() {
                    terminal_mode = TerminalMode::Supported;
                    response_text = render_operator_summaries_response_text(&operator_summaries);
                    stop_reason = "version_diff_complete";
                    break;
                }
            }
            BaselinePlanStep::SearchRefFetchSpan { max_refs } => {
                let mut refs_to_fetch = search_refs.iter().take(*max_refs).cloned();
                let mut in_flight = FuturesUnordered::new();
                let mut scheduled_calls: u32 = 0;

                loop {
                    let parallelism = scheduler_parallelism(
                        state,
                        scheduler,
                        operator_calls_used,
                        scheduled_calls,
                    );
                    while in_flight.len() < parallelism {
                        if let Err(reason) = scheduler.check_operator_calls_with_reserved(
                            operator_calls_used,
                            scheduled_calls,
                        ) {
                            stop_reason = reason.as_str();
                            budget_violation = true;
                            break 'plan_loop;
                        }

                        let Some(reference) = refs_to_fetch.next() else {
                            break;
                        };
                        let Some(timeout) = scheduler.remaining_wallclock() else {
                            stop_reason = BudgetStopReason::WallclockMs.as_str();
                            budget_violation = true;
                            break 'plan_loop;
                        };

                        scheduled_calls = scheduled_calls.saturating_add(1);
                        let queued_at = Instant::now();
                        in_flight.push(async move {
                            crate::metrics::observe_operator_queue_wait(queued_at.elapsed());
                            let mut params =
                                serde_json::json!({ "object_id": reference.object_id });
                            if let Some(start_byte) = reference.start_byte {
                                params["start_byte"] = serde_json::json!(start_byte);
                            }
                            if let Some(end_byte) = reference.end_byte {
                                params["end_byte"] = serde_json::json!(end_byte);
                            }
                            call_operator(state, ctx, "fetch_span", params, timeout).await
                        });
                    }

                    let Some(outcome) = in_flight.next().await else {
                        break;
                    };
                    scheduled_calls = scheduled_calls.saturating_sub(1);

                    let outcome = outcome?;
                    operator_calls_used = operator_calls_used.saturating_add(1);
                    bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                    let Some(body) = outcome.body else {
                        terminal_mode = outcome.terminal_mode_hint;
                        stop_reason = "operator_error";
                        break 'plan_loop;
                    };

                    if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                        evidence_units.push(unit);
                    }

                    if let Err(reason) = scheduler.check_bytes(bytes_used) {
                        terminal_mode = TerminalMode::InsufficientEvidence;
                        stop_reason = reason.as_str();
                        budget_violation = true;
                        break 'plan_loop;
                    }
                }
            }
        }

        if let Err(reason) = scheduler.check_bytes(bytes_used) {
            terminal_mode = TerminalMode::InsufficientEvidence;
            stop_reason = reason.as_str();
            budget_violation = true;
            break;
        }

        step_index += 1;
    }

    if stop_reason == "unknown" {
        stop_reason = "plan_complete";
    }
    if !budget_violation && stop_reason == "plan_complete" && !evidence_units.is_empty() {
        terminal_mode = TerminalMode::Supported;
        if response_text.is_none() {
            response_text = render_operator_summaries_response_text(&operator_summaries);
        }
    } else if !budget_violation
        && terminal_mode == TerminalMode::InsufficientEvidence
        && evidence_units.is_empty()
    {
        response_text =
            policy_aware_narrowing_guidance(state, ctx, query_trimmed, plan_intent).await;
    }
    if budget_violation {
        crate::metrics::inc_budget_violation();
    }
    crate::metrics::observe_budget_stop_reason(stop_reason);

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    if let Some(selected_trace) = planner_traces
        .iter_mut()
        .find(|trace| trace.decision_summary.selected_for_execution)
    {
        selected_trace.output_steps = planner_steps_for_planned_steps(&active_steps);
        let selected_assessment =
            assess_expected_usefulness(&selected_trace.plan_request, &selected_trace.output_steps);
        apply_usefulness_assessment(selected_trace, selected_assessment.as_ref());
        selected_trace.decision_summary.stop_reason = stop_reason.to_string();
        selected_trace.decision_summary.used_fallback_plan = used_fallback_plan;
        selected_trace.decision_summary.fallback_from_step = fallback_from_step;
    }

    Ok(ContextLoopResult {
        terminal_mode,
        response_text,
        planner_traces,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

fn render_plan_value(params: &serde_json::Value, query: &str) -> serde_json::Value {
    match params {
        serde_json::Value::String(value) if value == "$query" => {
            serde_json::Value::String(query.to_string())
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| render_plan_value(value, query))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert(key.clone(), render_plan_value(value, query));
            }
            serde_json::Value::Object(out)
        }
        _ => params.clone(),
    }
}

fn render_plan_params(op_name: &str, params: &serde_json::Value, query: &str) -> serde_json::Value {
    let rendered = render_plan_value(params, query);
    match op_name {
        "list_versions" | "diff" => version_review_params_for_query(&rendered, query),
        "fetch_rows" => fetch_rows_params_for_query(&rendered, query),
        "aggregate" | "compare" => aggregate_params_for_query(&rendered, query),
        "lookup_evidence" => evidence_lookup_params_for_query(&rendered, query),
        _ => rendered,
    }
}

fn query_plan_intent_name(intent: QueryPlanIntent) -> &'static str {
    match intent {
        QueryPlanIntent::Default => "default",
        QueryPlanIntent::StructuredLookup => "structured_lookup",
        QueryPlanIntent::StructuredAggregation => "structured_aggregation",
        QueryPlanIntent::EvidenceLookup => "evidence_lookup",
        QueryPlanIntent::VersionReview => "version_review",
        QueryPlanIntent::StructuredEvidenceLookup => "structured_evidence_lookup",
        QueryPlanIntent::StructuredAggregationEvidence => "structured_aggregation_evidence",
        QueryPlanIntent::StructuredVersionReview => "structured_version_review",
    }
}

fn planner_intent(intent: QueryPlanIntent) -> PlannerIntent {
    match intent {
        QueryPlanIntent::Default => PlannerIntent::Default,
        QueryPlanIntent::StructuredLookup => PlannerIntent::StructuredLookup,
        QueryPlanIntent::StructuredAggregation => PlannerIntent::StructuredAggregation,
        QueryPlanIntent::EvidenceLookup => PlannerIntent::EvidenceLookup,
        QueryPlanIntent::VersionReview => PlannerIntent::VersionReview,
        QueryPlanIntent::StructuredEvidenceLookup => PlannerIntent::StructuredEvidenceLookup,
        QueryPlanIntent::StructuredAggregationEvidence => {
            PlannerIntent::StructuredAggregationEvidence
        }
        QueryPlanIntent::StructuredVersionReview => PlannerIntent::StructuredVersionReview,
    }
}

pub(super) fn evidence_pack_mode_for_query_intent(intent: QueryPlanIntent) -> EvidencePackMode {
    match intent {
        QueryPlanIntent::StructuredLookup => EvidencePackMode::Raw,
        QueryPlanIntent::StructuredAggregation => EvidencePackMode::Summary,
        QueryPlanIntent::EvidenceLookup => EvidencePackMode::Mixed,
        QueryPlanIntent::VersionReview => EvidencePackMode::Diff,
        QueryPlanIntent::StructuredEvidenceLookup => EvidencePackMode::Mixed,
        QueryPlanIntent::StructuredAggregationEvidence => EvidencePackMode::Mixed,
        QueryPlanIntent::StructuredVersionReview => EvidencePackMode::Diff,
        QueryPlanIntent::Default => EvidencePackMode::Compact,
    }
}

fn planner_step_for_baseline_step(step: BaselinePlanStep, query: &str) -> PlannerStep {
    match step {
        BaselinePlanStep::Operator { op_name, params } => PlannerStep::Operator {
            params: render_plan_params(op_name.as_str(), &params, query),
            op_name,
        },
        BaselinePlanStep::SearchRefFetchSpan { max_refs } => {
            PlannerStep::SearchRefFetchSpan { max_refs }
        }
    }
}

fn planner_hints_for_query(plan: &[BaselinePlanStep], query: &str) -> PlannerHints {
    let clauses = decompose_query_clauses(query);
    let intent = if clauses.len() > 1 {
        clauses
            .iter()
            .map(|clause| classify_query_plan_intent(clause))
            .find(|clause_intent| *clause_intent != QueryPlanIntent::Default)
            .unwrap_or_else(|| classify_query_plan_intent(query))
    } else {
        classify_query_plan_intent(query)
    };
    let recommended_steps = if intent == QueryPlanIntent::Default {
        planned_steps_for_query_context(
            query,
            plan.iter()
                .filter(|step| {
                    !matches!(
                        step,
                        BaselinePlanStep::Operator { op_name, .. }
                            if op_name == "aggregate" || op_name == "compare"
                    )
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    } else {
        derive_baseline_plan(plan, query)
    };
    PlannerHints {
        intent: planner_intent(intent),
        recommended_path: planner_steps_for_planned_steps(&recommended_steps),
    }
}

fn planner_tool_schemas() -> Vec<PlannerToolSchema> {
    vec![
        PlannerToolSchema {
            name: "aggregate".to_string(),
            description:
                "Aggregate rows from an allowlisted safeview for grouped counts or metrics."
                    .to_string(),
            required_params: vec!["view_id".to_string()],
            optional_params: vec![
                "filter_spec".to_string(),
                "group_by".to_string(),
                "include_rank".to_string(),
                "metric".to_string(),
                "metrics".to_string(),
                "rank_direction".to_string(),
                "time_granularity".to_string(),
                "top_n".to_string(),
            ],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["view_id"],
                "properties": {
                    "view_id": { "type": "string" },
                    "filter_spec": { "type": "object" },
                    "group_by": { "type": "array", "items": { "type": "string" } },
                    "metric": { "type": "string" },
                    "metrics": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "field"],
                            "properties": {
                                "name": { "type": "string" },
                                "field": { "type": "string" }
                            }
                        }
                    },
                    "time_granularity": { "type": "string", "enum": ["day", "month"] },
                    "top_n": { "type": "integer", "minimum": 1 },
                    "include_rank": { "type": "boolean" },
                    "rank_direction": { "type": "string", "enum": ["asc", "desc"] }
                }
            })),
        },
        PlannerToolSchema {
            name: "compare".to_string(),
            description:
                "Compare grouped safeview metrics to answer trend or segmentation questions."
                    .to_string(),
            required_params: vec!["view_id".to_string()],
            optional_params: vec![
                "filter_spec".to_string(),
                "group_by".to_string(),
                "include_rank".to_string(),
                "metric".to_string(),
                "metrics".to_string(),
                "rank_direction".to_string(),
                "time_granularity".to_string(),
                "top_n".to_string(),
            ],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["view_id"],
                "properties": {
                    "view_id": { "type": "string" },
                    "filter_spec": { "type": "object" },
                    "group_by": { "type": "array", "items": { "type": "string" } },
                    "metric": { "type": "string" },
                    "metrics": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "field"],
                            "properties": {
                                "name": { "type": "string" },
                                "field": { "type": "string" }
                            }
                        }
                    },
                    "time_granularity": { "type": "string", "enum": ["day", "month"] },
                    "top_n": { "type": "integer", "minimum": 1 },
                    "include_rank": { "type": "boolean" },
                    "rank_direction": { "type": "string", "enum": ["asc", "desc"] }
                }
            })),
        },
        PlannerToolSchema {
            name: "discover_dimensions".to_string(),
            description:
                "Inspect a safeview to discover available dimensions, values, and drilldowns."
                    .to_string(),
            required_params: vec!["view_id".to_string()],
            optional_params: vec![
                "filter_spec".to_string(),
                "max_values_per_dimension".to_string(),
            ],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["view_id"],
                "properties": {
                    "view_id": { "type": "string" },
                    "filter_spec": { "type": "object" },
                    "max_values_per_dimension": { "type": "integer", "minimum": 1 }
                }
            })),
        },
        PlannerToolSchema {
            name: "diff".to_string(),
            description: "Compute a diff between two versions of the same object.".to_string(),
            required_params: vec!["object_id".to_string(), "v1".to_string(), "v2".to_string()],
            optional_params: Vec::new(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["object_id", "v1", "v2"],
                "properties": {
                    "object_id": { "type": "string" },
                    "v1": { "type": "string" },
                    "v2": { "type": "string" }
                }
            })),
        },
        PlannerToolSchema {
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
                    "filter_spec": { "type": "object" }
                }
            })),
        },
        PlannerToolSchema {
            name: "fetch_span".to_string(),
            description: "Fetch a text span from a policy or document object.".to_string(),
            required_params: vec!["object_id".to_string()],
            optional_params: vec!["start_byte".to_string(), "end_byte".to_string()],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["object_id"],
                "properties": {
                    "object_id": { "type": "string" },
                    "start_byte": { "type": "integer", "minimum": 0 },
                    "end_byte": { "type": "integer", "minimum": 0 }
                }
            })),
        },
        PlannerToolSchema {
            name: "list_versions".to_string(),
            description: "List the available versions for a document or object.".to_string(),
            required_params: vec!["object_id".to_string()],
            optional_params: Vec::new(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["object_id"],
                "properties": {
                    "object_id": { "type": "string" }
                }
            })),
        },
        PlannerToolSchema {
            name: "lookup_evidence".to_string(),
            description:
                "Search evidence and fetch a bounded set of supporting spans in one operator."
                    .to_string(),
            required_params: vec!["query".to_string()],
            optional_params: vec![
                "case_sensitive".to_string(),
                "limit".to_string(),
                "match_mode".to_string(),
                "max_refs".to_string(),
                "object_prefix".to_string(),
                "terms".to_string(),
            ],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "terms": { "type": "array", "items": { "type": "string" } },
                    "limit": { "type": "integer", "minimum": 1 },
                    "max_refs": { "type": "integer", "minimum": 1 },
                    "object_prefix": { "type": "string" },
                    "case_sensitive": { "type": "boolean" },
                    "match_mode": { "type": "string", "enum": ["all", "any", "phrase"] }
                }
            })),
        },
        PlannerToolSchema {
            name: "redact".to_string(),
            description: "Apply an allowlisted redaction transform to structured evidence."
                .to_string(),
            required_params: Vec::new(),
            optional_params: vec!["field_redaction".to_string()],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "field_redaction": {
                        "type": "object",
                        "description": "Gateway-defined redaction instruction"
                    }
                }
            })),
        },
        PlannerToolSchema {
            name: "search".to_string(),
            description: "Search policy-scoped documents or files for relevant references."
                .to_string(),
            required_params: vec!["query".to_string()],
            optional_params: vec![
                "case_sensitive".to_string(),
                "limit".to_string(),
                "match_mode".to_string(),
                "object_prefix".to_string(),
                "terms".to_string(),
            ],
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "terms": { "type": "array", "items": { "type": "string" } },
                    "limit": { "type": "integer", "minimum": 1 },
                    "object_prefix": { "type": "string" },
                    "case_sensitive": { "type": "boolean" },
                    "match_mode": { "type": "string", "enum": ["all", "any", "phrase"] }
                }
            })),
        },
    ]
}

fn planner_clarification_opportunities(query: &str) -> Vec<ClarificationPrompt> {
    clarification_prompt_for_query(query).into_iter().collect()
}

fn planner_prior_observations(
    recovery_context: Option<&PlannerRecoveryContext>,
) -> Vec<PlannerObservation> {
    let Some(recovery_context) = recovery_context else {
        return Vec::new();
    };
    let failed_index = recovery_context
        .failed_step_details
        .as_ref()
        .and_then(|failed_step| {
            recovery_context
                .attempted_path
                .iter()
                .rposition(|attempted_step| attempted_step == failed_step)
        })
        .or_else(|| {
            recovery_context
                .attempted_path
                .iter()
                .rposition(|attempted_step| {
                    planner_step_name(attempted_step) == recovery_context.failed_step
                })
        });

    recovery_context
        .attempted_path
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let failed = failed_index == Some(index);
            PlannerObservation {
                step: step.clone(),
                outcome: if failed {
                    PlannerObservationOutcome::Failed
                } else {
                    PlannerObservationOutcome::Succeeded
                },
                terminal_mode: failed.then_some(recovery_context.failure_terminal_mode),
                summary: Some(if failed {
                    format!(
                        "{} failed and triggered recovery planning",
                        planner_step_name(step)
                    )
                } else {
                    format!(
                        "{} completed before recovery planning",
                        planner_step_name(step)
                    )
                }),
            }
        })
        .collect()
}

fn planner_failure_feedback(
    recovery_context: Option<&PlannerRecoveryContext>,
) -> Vec<PlannerFailureFeedback> {
    let Some(recovery_context) = recovery_context else {
        return Vec::new();
    };
    vec![PlannerFailureFeedback {
        failure_code: format!(
            "terminal_mode_{}",
            recovery_context.failure_terminal_mode.as_str()
        ),
        failed_step: recovery_context.failed_step_details.clone(),
        terminal_mode: Some(recovery_context.failure_terminal_mode),
        message: Some(format!(
            "The previous {} attempt ended with {}.",
            recovery_context.failed_step,
            recovery_context.failure_terminal_mode.as_str()
        )),
    }]
}

fn build_plan_request(
    query: &str,
    budget: &Budget,
    context_budget: &ContextBudget,
    planner_hints: PlannerHints,
    recovery_context: Option<PlannerRecoveryContext>,
) -> PlanRequest {
    let operator_schemas = planner_tool_schemas();
    let prior_observations = planner_prior_observations(recovery_context.as_ref());
    let clarification_opportunities = planner_clarification_opportunities(query);
    let failure_feedback = planner_failure_feedback(recovery_context.as_ref());
    PlanRequest {
        schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
        query: query.to_string(),
        budget: budget.clone(),
        context_budget: context_budget.clone(),
        planner_hints,
        preferred_evidence_pack_mode: evidence_pack_mode_for_query_intent(
            classify_query_plan_intent(query),
        ),
        recovery_context,
        available_operator_names: PLANNER_AVAILABLE_OPERATOR_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        operator_schemas,
        allow_search_ref_fetch_span: true,
        prior_observations,
        clarification_opportunities,
        failure_feedback,
    }
}

fn plan_request_for_query(
    plan: &[BaselinePlanStep],
    query: &str,
    budget: &Budget,
    context_budget: &ContextBudget,
) -> PlanRequest {
    build_plan_request(
        query,
        budget,
        context_budget,
        planner_hints_for_query(plan, query),
        None,
    )
}

#[cfg(feature = "rlm")]
fn should_short_circuit_mock_perf_probe(
    query: &str,
    plan_request: &PlanRequest,
    explicit_script_path: Option<&PathBuf>,
) -> bool {
    if explicit_script_path.is_some() {
        return false;
    }

    query.eq_ignore_ascii_case("smoke")
        && plan_request.planner_hints.intent == PlannerIntent::Default
}

#[cfg(feature = "rlm")]
fn default_rlm_python() -> String {
    std::env::var("PECR_RLM_PYTHON")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "python".to_string()
            } else {
                "python3".to_string()
            }
        })
}

#[cfg(feature = "rlm")]
fn resolve_rlm_bridge_process_key(
    explicit_script_path: Option<PathBuf>,
) -> Result<RlmBridgeProcessKey, RlmBridgeSetupError> {
    let python = default_rlm_python();
    let script_path = explicit_script_path
        .or_else(|| {
            let candidates = [
                PathBuf::from("/usr/local/share/pecr/pecr_rlm_bridge.py"),
                PathBuf::from("scripts/rlm/pecr_rlm_bridge.py"),
            ];
            candidates.into_iter().find(|p| p.exists())
        })
        .ok_or_else(|| RlmBridgeSetupError {
            stop_reason: "bridge_script_not_found",
            message: "rlm bridge script not found; set PECR_RLM_SCRIPT_PATH or ensure scripts/rlm/pecr_rlm_bridge.py is present"
                .to_string(),
        })?;

    Ok(RlmBridgeProcessKey {
        python,
        script_path,
    })
}

#[cfg(feature = "rlm")]
async fn reset_cached_rlm_bridge_process(cached: &mut Option<CachedRlmBridgeProcess>) {
    if let Some(process) = cached.as_mut() {
        let _ = process.child.kill().await;
        let _ = tokio::time::timeout(Duration::from_millis(250), process.child.wait()).await;
    }
    *cached = None;
}

#[cfg(feature = "rlm")]
fn cached_rlm_bridge_process_matches(
    cached: &mut CachedRlmBridgeProcess,
    key: &RlmBridgeProcessKey,
) -> bool {
    if &cached.key != key {
        return false;
    }
    cached.child.try_wait().ok().flatten().is_none()
}

#[cfg(feature = "rlm")]
async fn spawn_cached_rlm_bridge_process(
    key: RlmBridgeProcessKey,
) -> Result<CachedRlmBridgeProcess, RlmBridgeSetupError> {
    let mut child = tokio::process::Command::new(&key.python)
        .arg(&key.script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| RlmBridgeSetupError {
            stop_reason: "bridge_spawn_failed",
            message: format!(
                "failed to spawn rlm bridge (python={}, script={})",
                key.python,
                key.script_path.display()
            ),
        })?;

    let stdin = child.stdin.take().ok_or_else(|| RlmBridgeSetupError {
        stop_reason: "bridge_internal",
        message: "failed to open rlm bridge stdin".to_string(),
    })?;
    let stdout = child.stdout.take().ok_or_else(|| RlmBridgeSetupError {
        stop_reason: "bridge_internal",
        message: "failed to open rlm bridge stdout".to_string(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| RlmBridgeSetupError {
        stop_reason: "bridge_internal",
        message: "failed to open rlm bridge stderr".to_string(),
    })?;

    let python = key.python.clone();
    let script_path = key.script_path.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!(
                python = %python,
                script_path = %script_path.display(),
                line = %line,
                "rlm.bridge.stderr"
            );
        }
    });

    Ok(CachedRlmBridgeProcess {
        key,
        child,
        stdin,
        stdout_lines: BufReader::new(stdout).lines(),
    })
}

#[cfg(feature = "rlm")]
async fn ensure_cached_rlm_bridge_process(
    runtime: &RlmBridgeRuntime,
    explicit_script_path: Option<PathBuf>,
) -> Result<tokio::sync::MutexGuard<'_, Option<CachedRlmBridgeProcess>>, RlmBridgeSetupError> {
    let key = resolve_rlm_bridge_process_key(explicit_script_path)?;
    let mut cached = runtime.cached_process.lock().await;
    let needs_respawn = match cached.as_mut() {
        Some(process) => !cached_rlm_bridge_process_matches(process, &key),
        None => true,
    };

    if needs_respawn {
        reset_cached_rlm_bridge_process(&mut cached).await;
        *cached = Some(spawn_cached_rlm_bridge_process(key).await?);
    }

    Ok(cached)
}

#[cfg(feature = "rlm")]
fn rlm_bridge_planner_summary(
    protocol_version: Option<u32>,
    backend: Option<&str>,
    session_mode: Option<&str>,
    detail: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::<String>::new();
    if let Some(version) = protocol_version {
        parts.push(format!("protocol_version={version}"));
    }
    if let Some(backend) = backend.filter(|value| !value.is_empty()) {
        parts.push(format!("backend={backend}"));
    }
    if let Some(session_mode) = session_mode.filter(|value| !value.is_empty()) {
        parts.push(format!("session_mode={session_mode}"));
    }
    if let Some(detail) = detail.map(str::trim).filter(|value| !value.is_empty()) {
        parts.push(detail.to_string());
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(feature = "rlm")]
fn bridge_failure_context_loop_result(
    plan_request: PlanRequest,
    output_steps: Vec<PlannerStep>,
    stop_reason: &str,
    planner_summary: Option<String>,
) -> ContextLoopResult {
    ContextLoopResult {
        terminal_mode: TerminalMode::SourceUnavailable,
        response_text: Some(super::finalize::response_text_for_terminal_mode(
            TerminalMode::SourceUnavailable,
        )),
        planner_traces: vec![replay_planner_trace(
            plan_request,
            output_steps,
            "rlm_bridge",
            stop_reason,
            true,
            planner_summary,
        )],
        evidence_refs: Vec::new(),
        evidence_units: Vec::new(),
        operator_calls_used: 0,
        bytes_used: 0,
        depth_used: 0,
    }
}

fn recovery_plan_request_for_query(
    query: &str,
    budget: &Budget,
    context_budget: &ContextBudget,
    fallback_steps: &[BaselinePlanStep],
    recovery_context: PlannerRecoveryContext,
) -> PlanRequest {
    let planned_steps = planned_steps_for_query_context(query, fallback_steps.to_vec());
    build_plan_request(
        query,
        budget,
        context_budget,
        PlannerHints {
            intent: PlannerIntent::Default,
            recommended_path: planner_steps_for_planned_steps(&planned_steps),
        },
        Some(recovery_context),
    )
}

#[cfg(feature = "rlm")]
pub(super) async fn run_context_loop_rlm(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    let loop_start = Instant::now();
    let query_trimmed = query.trim();
    let plan_intent = classify_query_plan_intent(query_trimmed);
    let scheduler = BudgetScheduler::new(budget, loop_start);

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let mut stop_reason: Option<String> = None;
    let mut budget_violation = false;
    let mut bridge_protocol_version: Option<u32> = None;
    let mut bridge_backend: Option<String> = None;
    let mut bridge_session_mode: Option<String> = None;
    let mut bridge_detail: Option<String> = None;

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();

    let plan_request = plan_request_for_query(
        &state.config.baseline_plan,
        query_trimmed,
        budget,
        &state.config.context_budget,
    );
    let explicit_script_path = state
        .config
        .rlm_script_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("PECR_RLM_SCRIPT_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });
    if should_short_circuit_mock_perf_probe(
        query_trimmed,
        &plan_request,
        explicit_script_path.as_ref(),
    ) {
        tracing::info!(
            request_id = %ctx.request_id,
            trace_id = %ctx.trace_id,
            principal_id = %ctx.principal_id,
            session_id = %ctx.session_id,
            terminal_mode = %TerminalMode::InsufficientEvidence.as_str(),
            stop_reason = "mock_perf_probe_short_circuit",
            budget_violation = false,
            operator_calls_used = 0,
            depth_used = 0,
            bytes_used = 0,
            "controller.context_loop_completed"
        );

        let planner_traces = vec![replay_planner_trace(
            plan_request,
            Vec::new(),
            "rlm_mock_inline",
            "mock_perf_probe_short_circuit",
            true,
            None,
        )];

        return Ok(ContextLoopResult {
            terminal_mode: TerminalMode::InsufficientEvidence,
            response_text: Some("UNKNOWN: insufficient evidence to answer the query.".to_string()),
            planner_traces,
            evidence_refs,
            evidence_units,
            operator_calls_used: 0,
            bytes_used: 0,
            depth_used: 0,
        });
    }

    let mut bridge_process = match ensure_cached_rlm_bridge_process(
        &state.rlm_bridge_runtime,
        explicit_script_path.clone(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(err) => {
            return Ok(bridge_failure_context_loop_result(
                plan_request,
                Vec::new(),
                err.stop_reason,
                Some(err.message),
            ));
        }
    };
    let planner_hints = plan_request.planner_hints.clone();
    let mut planner_output_steps = Vec::<PlannerStep>::new();
    let start_msg = serde_json::json!({
        "type": "start",
        "protocol": {
            "min_version": RLM_BRIDGE_PROTOCOL_MIN_VERSION,
            "max_version": RLM_BRIDGE_PROTOCOL_MAX_VERSION,
        },
        "query": query_trimmed,
        "budget": budget,
        "planner_hints": planner_hints,
        "plan_request": plan_request.clone(),
    });
    let start_line = serde_json::to_string(&start_msg).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to serialize rlm bridge start message".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    bridge_process
        .as_mut()
        .expect("cached bridge process should exist")
        .stdin
        .write_all(format!("{}\n", start_line).as_bytes())
        .await
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_PROTOCOL",
                "failed to write rlm bridge start message".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut response_text: Option<String> = None;
    let mut operator_summaries = Vec::<String>::new();
    let mut pending_msg: Option<serde_json::Value> = None;

    if let Some(timeout) = scheduler.remaining_wallclock() {
        let next_line = tokio::time::timeout(
            timeout,
            bridge_process
                .as_mut()
                .expect("cached bridge process should exist")
                .stdout_lines
                .next_line(),
        )
        .await;
        let first_line = match next_line {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                stop_reason = Some("bridge_eof".to_string());
                String::new()
            }
            Ok(Err(_)) => {
                stop_reason = Some("bridge_read_error".to_string());
                String::new()
            }
            Err(_) => {
                stop_reason = Some(BudgetStopReason::WallclockMs.as_str().to_string());
                budget_violation = true;
                String::new()
            }
        };

        if stop_reason.is_none() {
            let first_msg = match serde_json::from_str::<serde_json::Value>(&first_line) {
                Ok(msg) => msg,
                Err(_) => {
                    stop_reason = Some("bridge_invalid_json".to_string());
                    bridge_detail = Some("rlm bridge emitted invalid json".to_string());
                    serde_json::Value::Null
                }
            };
            let first_msg_type = first_msg
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if first_msg_type == "start_ack" {
                let version = match first_msg
                    .get("protocol_version")
                    .and_then(|v| v.as_u64())
                    .map(|value| value as u32)
                {
                    Some(version) => version,
                    None => {
                        stop_reason = Some("bridge_protocol_missing_version".to_string());
                        bridge_detail =
                            Some("rlm bridge start_ack missing protocol_version".to_string());
                        0
                    }
                };
                if stop_reason.is_some() {
                    // Keep the request replay-visible and let the main loop degrade cleanly.
                } else {
                    bridge_protocol_version = Some(version);
                    bridge_backend = first_msg
                        .get("backend")
                        .and_then(|v| v.as_str())
                        .map(|value| value.to_string());
                    bridge_session_mode = first_msg
                        .get("session_mode")
                        .and_then(|v| v.as_str())
                        .map(|value| value.to_string());
                    if !(RLM_BRIDGE_PROTOCOL_MIN_VERSION..=RLM_BRIDGE_PROTOCOL_MAX_VERSION)
                        .contains(&version)
                    {
                        stop_reason = Some("bridge_protocol_version_unsupported".to_string());
                        bridge_detail = Some(format!(
                            "unsupported rlm bridge protocol_version={} (supported {}-{})",
                            version,
                            RLM_BRIDGE_PROTOCOL_MIN_VERSION,
                            RLM_BRIDGE_PROTOCOL_MAX_VERSION
                        ));
                    }
                }
            } else if first_msg_type == "error" {
                terminal_mode = TerminalMode::SourceUnavailable;
                response_text = Some(super::finalize::response_text_for_terminal_mode(
                    TerminalMode::SourceUnavailable,
                ));
                stop_reason = Some(
                    first_msg
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("bridge_error")
                        .to_string(),
                );
                bridge_detail = first_msg
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|value| value.to_string());
            } else {
                // Backward compatibility: older bridges start directly with protocol messages.
                pending_msg = Some(first_msg);
            }
        }
    } else {
        stop_reason = Some(BudgetStopReason::WallclockMs.as_str().to_string());
        budget_violation = true;
    }

    while stop_reason.is_none() {
        let Some(timeout) = scheduler.remaining_wallclock() else {
            stop_reason = Some(BudgetStopReason::WallclockMs.as_str().to_string());
            budget_violation = true;
            break;
        };

        let msg = if let Some(msg) = pending_msg.take() {
            msg
        } else {
            let next_line = tokio::time::timeout(
                timeout,
                bridge_process
                    .as_mut()
                    .expect("cached bridge process should exist")
                    .stdout_lines
                    .next_line(),
            )
            .await;
            let line = match next_line {
                Ok(Ok(Some(line))) => line,
                Ok(Ok(None)) => {
                    stop_reason = Some("bridge_eof".to_string());
                    break;
                }
                Ok(Err(_)) => {
                    stop_reason = Some("bridge_read_error".to_string());
                    break;
                }
                Err(_) => {
                    stop_reason = Some(BudgetStopReason::WallclockMs.as_str().to_string());
                    budget_violation = true;
                    break;
                }
            };
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(msg) => msg,
                Err(_) => {
                    stop_reason = Some("bridge_invalid_json".to_string());
                    bridge_detail = Some("rlm bridge emitted invalid json".to_string());
                    break;
                }
            }
        };
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or_default();
        let bridge_depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let planner_span = tracing::info_span!(
            "planner.rlm_message",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            msg_type = %msg_type,
            bridge_depth,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        tracing::debug!(parent: &planner_span, "planner.message_ready");
        let scheduler_span = tracing::info_span!(
            "scheduler.budget_gate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            phase = "rlm_loop",
            msg_type = %msg_type,
            bridge_depth,
            depth_used,
            operator_calls_used,
            bytes_used,
        );

        match msg_type {
            "call_operator" => {
                let id = msg
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let op_name = msg
                    .get("op_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

                if id.is_empty() {
                    stop_reason = Some("bridge_invalid_message".to_string());
                    break;
                }
                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth)) {
                    stop_reason = Some(reason.as_str().to_string());
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                if let Err(reason) =
                    scheduler_span.in_scope(|| scheduler.check_operator_calls(operator_calls_used))
                {
                    stop_reason = Some(reason.as_str().to_string());
                    budget_violation = true;
                    break;
                }

                planner_output_steps.push(PlannerStep::Operator {
                    op_name: op_name.clone(),
                    params: params.clone(),
                });

                if !allowed_operator(op_name.as_str()) {
                    stop_reason = Some("bridge_invalid_tool_request".to_string());
                    bridge_detail = Some(format!(
                        "bridge requested disallowed operator '{}'",
                        op_name
                    ));
                    break;
                }

                let outcome = call_operator(state, ctx, op_name.as_str(), params, timeout).await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                if let Some(body) = outcome.body {
                    remember_operator_summary(
                        &mut operator_summaries,
                        body.result_summary.as_deref(),
                    );
                    let terminal_mode_for_resp = body.terminal_mode;
                    if terminal_mode_for_resp == TerminalMode::Supported {
                        terminal_mode = TerminalMode::Supported;
                    }
                    let result = body.result;
                    record_operator_result(
                        op_name.as_str(),
                        &result,
                        &mut evidence_refs,
                        &mut evidence_units,
                    );

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": true,
                        "terminal_mode": terminal_mode_for_resp.as_str(),
                        "result": result,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    bridge_process
                        .as_mut()
                        .expect("cached bridge process should exist")
                        .stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await
                        .map_err(|_| {
                            json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ERR_RLM_BRIDGE_PROTOCOL",
                                "failed to write rlm bridge response".to_string(),
                                TerminalMode::SourceUnavailable,
                                false,
                            )
                        })?;
                } else {
                    terminal_mode = outcome.terminal_mode_hint;

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": false,
                        "terminal_mode": outcome.terminal_mode_hint.as_str(),
                        "result": serde_json::Value::Null,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    bridge_process
                        .as_mut()
                        .expect("cached bridge process should exist")
                        .stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await
                        .map_err(|_| {
                            json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ERR_RLM_BRIDGE_PROTOCOL",
                                "failed to write rlm bridge response".to_string(),
                                TerminalMode::SourceUnavailable,
                                false,
                            )
                        })?;
                }

                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used)) {
                    stop_reason = Some(reason.as_str().to_string());
                    budget_violation = true;
                    break;
                }
            }
            "call_operator_batch" => {
                let id = msg
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let calls = msg
                    .get("calls")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<Vec<BatchBridgeCall>>(value).ok())
                    .unwrap_or_default();

                if id.is_empty() || calls.is_empty() {
                    stop_reason = Some("bridge_invalid_message".to_string());
                    break;
                }
                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth)) {
                    stop_reason = Some(reason.as_str().to_string());
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                let mut batch_results = vec![serde_json::Value::Null; calls.len()];
                let mut break_outer = false;

                if !state.config.batch_mode_enabled {
                    for (idx, call) in calls.iter().enumerate() {
                        if let Err(reason) = scheduler_span
                            .in_scope(|| scheduler.check_operator_calls(operator_calls_used))
                        {
                            stop_reason = Some(reason.as_str().to_string());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }

                        let op_name = call.op_name.trim();
                        planner_output_steps.push(PlannerStep::Operator {
                            op_name: op_name.to_string(),
                            params: call.params.clone(),
                        });
                        if op_name.is_empty() || !allowed_operator(op_name) {
                            stop_reason = Some("bridge_invalid_tool_request".to_string());
                            bridge_detail = Some(format!(
                                "bridge requested disallowed operator '{}'",
                                op_name
                            ));
                            break_outer = true;
                            break;
                        }

                        let Some(timeout) = scheduler.remaining_wallclock() else {
                            stop_reason = Some(BudgetStopReason::WallclockMs.as_str().to_string());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        };

                        let outcome =
                            call_operator(state, ctx, op_name, call.params.clone(), timeout)
                                .await?;
                        operator_calls_used = operator_calls_used.saturating_add(1);
                        bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                        if let Some(body) = outcome.body {
                            remember_operator_summary(
                                &mut operator_summaries,
                                body.result_summary.as_deref(),
                            );
                            let terminal_mode_for_resp = body.terminal_mode;
                            if terminal_mode_for_resp == TerminalMode::Supported {
                                terminal_mode = TerminalMode::Supported;
                            }
                            let result = body.result;
                            record_operator_result(
                                op_name,
                                &result,
                                &mut evidence_refs,
                                &mut evidence_units,
                            );
                            batch_results[idx] = serde_json::json!({
                                "ok": true,
                                "op_name": op_name,
                                "terminal_mode": terminal_mode_for_resp.as_str(),
                                "result": result,
                                "bytes_len": outcome.bytes_len,
                            });
                        } else {
                            terminal_mode = outcome.terminal_mode_hint;
                            stop_reason = Some("operator_error".to_string());
                            batch_results[idx] = serde_json::json!({
                                "ok": false,
                                "op_name": op_name,
                                "terminal_mode": outcome.terminal_mode_hint.as_str(),
                                "result": serde_json::Value::Null,
                                "bytes_len": outcome.bytes_len,
                            });
                            break_outer = true;
                            break;
                        }

                        if let Err(reason) =
                            scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used))
                        {
                            stop_reason = Some(reason.as_str().to_string());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }
                    }
                } else {
                    let mut pending_by_operator: HashMap<String, VecDeque<PendingBatchCall>> =
                        HashMap::new();
                    let mut max_in_flight_by_operator: HashMap<String, usize> = HashMap::new();
                    let mut in_flight_by_operator: HashMap<String, usize> = HashMap::new();
                    let mut fairness_ring = VecDeque::<String>::new();

                    for (idx, call) in calls.iter().enumerate() {
                        let op_name = call.op_name.trim();
                        planner_output_steps.push(PlannerStep::Operator {
                            op_name: op_name.to_string(),
                            params: call.params.clone(),
                        });
                        if op_name.is_empty() || !allowed_operator(op_name) {
                            stop_reason = Some("bridge_invalid_tool_request".to_string());
                            bridge_detail = Some(format!(
                                "bridge requested disallowed operator '{}'",
                                op_name
                            ));
                            break_outer = true;
                            break;
                        }

                        if !pending_by_operator.contains_key(op_name) {
                            let policy = state.config.operator_concurrency_policies.get(op_name);
                            let fairness_weight =
                                policy.and_then(|p| p.fairness_weight).unwrap_or(1) as usize;
                            let max_in_flight =
                                policy.and_then(|p| p.max_in_flight).unwrap_or(usize::MAX);
                            let op_name_owned = op_name.to_string();
                            pending_by_operator.insert(op_name_owned.clone(), VecDeque::new());
                            max_in_flight_by_operator.insert(op_name_owned.clone(), max_in_flight);
                            in_flight_by_operator.insert(op_name_owned.clone(), 0);
                            for _ in 0..fairness_weight {
                                fairness_ring.push_back(op_name_owned.clone());
                            }
                        }

                        if let Some(queue) = pending_by_operator.get_mut(op_name) {
                            queue.push_back(PendingBatchCall {
                                idx,
                                params: call.params.clone(),
                            });
                        }
                    }

                    if break_outer {
                        break;
                    }
                    if fairness_ring.is_empty() {
                        stop_reason = Some("bridge_invalid_message".to_string());
                        break;
                    }

                    let mut in_flight = FuturesUnordered::new();
                    let mut scheduled_calls: u32 = 0;

                    'batch_loop: loop {
                        let parallelism = scheduler_parallelism(
                            state,
                            scheduler,
                            operator_calls_used,
                            scheduled_calls,
                        );
                        while in_flight.len() < parallelism {
                            if let Err(reason) = scheduler_span.in_scope(|| {
                                scheduler.check_operator_calls_with_reserved(
                                    operator_calls_used,
                                    scheduled_calls,
                                )
                            }) {
                                stop_reason = Some(reason.as_str().to_string());
                                budget_violation = true;
                                break_outer = true;
                                break 'batch_loop;
                            }

                            let has_pending_calls =
                                pending_by_operator.values().any(|queue| !queue.is_empty());
                            if !has_pending_calls {
                                break;
                            }

                            let Some((idx, op_name, params)) = next_fair_batch_call(
                                &mut fairness_ring,
                                &mut pending_by_operator,
                                &mut in_flight_by_operator,
                                &max_in_flight_by_operator,
                            ) else {
                                break;
                            };

                            let Some(timeout) = scheduler.remaining_wallclock() else {
                                stop_reason =
                                    Some(BudgetStopReason::WallclockMs.as_str().to_string());
                                budget_violation = true;
                                break_outer = true;
                                break 'batch_loop;
                            };

                            scheduled_calls = scheduled_calls.saturating_add(1);
                            let queued_at = Instant::now();
                            in_flight.push(async move {
                                crate::metrics::observe_operator_queue_wait(queued_at.elapsed());
                                (
                                    idx,
                                    op_name.clone(),
                                    call_operator(state, ctx, op_name.as_str(), params, timeout)
                                        .await,
                                )
                            });
                        }

                        if in_flight.is_empty() {
                            let has_pending_calls =
                                pending_by_operator.values().any(|queue| !queue.is_empty());
                            if !has_pending_calls {
                                break;
                            }
                            stop_reason = Some("bridge_invalid_message".to_string());
                            break_outer = true;
                            break;
                        }

                        let Some((idx, op_name, outcome)) = in_flight.next().await else {
                            break;
                        };
                        scheduled_calls = scheduled_calls.saturating_sub(1);
                        if let Some(in_flight) = in_flight_by_operator.get_mut(op_name.as_str()) {
                            *in_flight = in_flight.saturating_sub(1);
                        }

                        let outcome = outcome?;
                        operator_calls_used = operator_calls_used.saturating_add(1);
                        bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                        if let Some(body) = outcome.body {
                            remember_operator_summary(
                                &mut operator_summaries,
                                body.result_summary.as_deref(),
                            );
                            let terminal_mode_for_resp = body.terminal_mode;
                            if terminal_mode_for_resp == TerminalMode::Supported {
                                terminal_mode = TerminalMode::Supported;
                            }
                            let result = body.result;
                            record_operator_result(
                                op_name.as_str(),
                                &result,
                                &mut evidence_refs,
                                &mut evidence_units,
                            );
                            batch_results[idx] = serde_json::json!({
                                "ok": true,
                                "op_name": op_name,
                                "terminal_mode": terminal_mode_for_resp.as_str(),
                                "result": result,
                                "bytes_len": outcome.bytes_len,
                            });
                        } else {
                            terminal_mode = outcome.terminal_mode_hint;
                            stop_reason = Some("operator_error".to_string());
                            batch_results[idx] = serde_json::json!({
                                "ok": false,
                                "op_name": op_name,
                                "terminal_mode": outcome.terminal_mode_hint.as_str(),
                                "result": serde_json::Value::Null,
                                "bytes_len": outcome.bytes_len,
                            });
                            break_outer = true;
                            break;
                        }

                        if let Err(reason) =
                            scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used))
                        {
                            stop_reason = Some(reason.as_str().to_string());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }
                    }
                }

                if break_outer {
                    break;
                }

                let resp = serde_json::json!({
                    "type": "operator_batch_result",
                    "id": id,
                    "results": batch_results,
                });
                let resp_line = serde_json::to_string(&resp).map_err(|_| {
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_RLM_BRIDGE_INTERNAL",
                        "failed to serialize rlm bridge batch response".to_string(),
                        TerminalMode::SourceUnavailable,
                        false,
                    )
                })?;
                bridge_process
                    .as_mut()
                    .expect("cached bridge process should exist")
                    .stdin
                    .write_all(format!("{}\n", resp_line).as_bytes())
                    .await
                    .map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_PROTOCOL",
                            "failed to write rlm bridge batch response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
            }
            "done" => {
                response_text = msg
                    .get("final_answer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                stop_reason = Some(
                    msg.get("stop_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("rlm_done")
                        .to_string(),
                );
                bridge_detail = msg
                    .get("planner_summary")
                    .and_then(|v| v.as_str())
                    .map(|value| value.to_string())
                    .or(bridge_detail);
                if bridge_protocol_version.is_none() {
                    bridge_protocol_version = msg
                        .get("protocol_version")
                        .and_then(|v| v.as_u64())
                        .map(|value| value as u32);
                }
                if let Some(stop_reason_value) = stop_reason.as_deref()
                    && stop_reason_value.starts_with("rlm_")
                {
                    bridge_backend = bridge_backend.or_else(|| {
                        stop_reason_value
                            .strip_prefix("rlm_")
                            .and_then(|value| value.strip_suffix("_done"))
                            .map(|value| value.to_string())
                    });
                }
                break;
            }
            "error" => {
                terminal_mode = TerminalMode::SourceUnavailable;
                response_text = Some(super::finalize::response_text_for_terminal_mode(
                    TerminalMode::SourceUnavailable,
                ));
                stop_reason = Some(
                    msg.get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("bridge_error")
                        .to_string(),
                );
                bridge_detail = msg
                    .get("message")
                    .and_then(|v| v.as_str())
                    .map(|value| value.to_string());
                if bridge_protocol_version.is_none() {
                    bridge_protocol_version = msg
                        .get("protocol_version")
                        .and_then(|v| v.as_u64())
                        .map(|value| value as u32);
                }
                break;
            }
            _ => {
                stop_reason = Some("bridge_unknown_message".to_string());
                bridge_detail = Some(format!(
                    "rlm bridge emitted unsupported message type '{msg_type}'"
                ));
                break;
            }
        }
    }

    if budget_violation {
        crate::metrics::inc_budget_violation();
    }

    let stop_reason = stop_reason.unwrap_or_else(|| "unknown".to_string());
    crate::metrics::observe_budget_stop_reason(stop_reason.as_str());
    if response_text.is_none() && terminal_mode == TerminalMode::Supported {
        response_text = render_operator_summaries_response_text(&operator_summaries);
    }
    let stop_is_bridge_failure = is_rlm_bridge_failure_stop_reason(stop_reason.as_str());
    if !stop_is_bridge_failure
        && !budget_violation
        && stop_reason == "rlm_done"
        && response_text.is_none()
        && terminal_mode == TerminalMode::InsufficientEvidence
        && evidence_units.is_empty()
    {
        response_text =
            policy_aware_narrowing_guidance(state, ctx, query_trimmed, plan_intent).await;
    }
    let planner_summary = rlm_bridge_planner_summary(
        bridge_protocol_version,
        bridge_backend.as_deref(),
        bridge_session_mode.as_deref(),
        bridge_detail.as_deref(),
    );
    if stop_is_bridge_failure {
        terminal_mode = TerminalMode::SourceUnavailable;
        if response_text.is_none() {
            response_text = Some(super::finalize::response_text_for_terminal_mode(
                TerminalMode::SourceUnavailable,
            ));
        }
        reset_cached_rlm_bridge_process(&mut bridge_process).await;
    } else if let Some(status) = bridge_process
        .as_mut()
        .expect("cached bridge process should exist")
        .child
        .try_wait()
        .ok()
        .flatten()
        && !status.success()
    {
        terminal_mode = TerminalMode::SourceUnavailable;
        response_text = Some(super::finalize::response_text_for_terminal_mode(
            TerminalMode::SourceUnavailable,
        ));
        reset_cached_rlm_bridge_process(&mut bridge_process).await;
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    let planner_traces = vec![replay_planner_trace(
        plan_request,
        planner_output_steps,
        "rlm_bridge",
        stop_reason.as_str(),
        true,
        planner_summary,
    )];

    Ok(ContextLoopResult {
        terminal_mode,
        response_text,
        planner_traces,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

#[cfg(not(feature = "rlm"))]
pub(super) async fn run_context_loop_rlm(
    _state: &AppState,
    _ctx: GatewayCallContext<'_>,
    _query: &str,
    _budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    Err(json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "ERR_RLM_FEATURE_DISABLED",
        "rlm controller engine is not enabled in this build".to_string(),
        TerminalMode::InsufficientEvidence,
        false,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        clarification_prompt_for_query, evidence_lookup_params_for_query,
        extract_version_pair_from_list_versions_result, render_policy_narrowing_guidance,
        version_review_object_id_for_query,
    };

    #[test]
    fn render_policy_narrowing_guidance_surfaces_views_fields_and_scopes() {
        let narrowing = serde_json::json!({
            "scope_labels": [
                "customer rows in safe_customer_view_public",
                "public documents under public/"
            ],
            "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
            "field_labels": ["customer_id", "status", "plan_tier"],
            "dimension_labels": ["status", "plan_tier"],
            "source_scopes": ["public/", "injection/"],
            "document_hints": ["policy documents", "versioned documents"],
            "examples": [
                "What is the customer status and plan tier in safe_customer_view_public?",
                "Show the source text and evidence for the support policy in public documents."
            ]
        });

        let rendered = render_policy_narrowing_guidance(
            Some("UNKNOWN: the request is too broad.".to_string()),
            &narrowing,
        )
        .expect("guidance should render");

        assert!(rendered.contains("Safe scopes for the current principal"));
        assert!(rendered.contains("Available safe views"));
        assert!(rendered.contains("Useful filters or fields"));
        assert!(rendered.contains("Useful comparison dimensions"));
        assert!(rendered.contains("Safe document scopes"));
        assert!(rendered.contains("Relevant document types"));
        assert!(rendered.contains("Try:"));
    }

    #[test]
    fn clarification_prompt_for_generic_version_query_requests_a_subject() {
        let prompt = clarification_prompt_for_query("What changed in the latest version?")
            .expect("version review query should need clarification");

        assert_eq!(
            prompt.question,
            "Which document or object should I compare versions for"
        );
        assert!(
            prompt
                .options
                .iter()
                .any(|option| option == "support policy")
        );
    }

    #[test]
    fn version_review_query_prefers_useful_document_object_ids() {
        assert_eq!(
            version_review_object_id_for_query(
                "What changed in the latest version of the support document?"
            ),
            Some("public/support_policy.txt")
        );
        assert_eq!(
            version_review_object_id_for_query("What changed in the billing policy?"),
            Some("public/billing_terms_policy.txt")
        );
        assert_eq!(
            version_review_object_id_for_query("What changed in annual refund terms?"),
            Some("public/annual_refund_terms.txt")
        );
    }

    #[test]
    fn evidence_lookup_query_uses_subject_terms_instead_of_full_sentence() {
        let params = serde_json::json!({
            "query": "{{query}}",
            "limit": 3
        });

        let rendered = evidence_lookup_params_for_query(
            &params,
            "Show the source text and evidence for the support policy",
        );

        assert_eq!(rendered["query"], serde_json::json!("{{query}}"));
        assert_eq!(rendered["terms"], serde_json::json!(["support", "policy"]));
        assert_eq!(rendered["match_mode"], serde_json::json!("all"));
        assert_eq!(rendered["object_prefix"], serde_json::json!("public/"));
    }

    #[test]
    fn extract_version_pair_prefers_latest_and_previous_as_of_time() {
        let pair = extract_version_pair_from_list_versions_result(&serde_json::json!({
            "versions": [
                {
                    "version_id": "1111111111111111111111111111111111111111111111111111111111111111",
                    "as_of_time": "2026-03-01T00:00:00Z"
                },
                {
                    "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
                    "as_of_time": "2026-03-02T00:00:00Z"
                }
            ]
        }))
        .expect("version pair should be available");

        assert_eq!(
            pair,
            (
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                "9999999999999999999999999999999999999999999999999999999999999999".to_string()
            )
        );
    }
}
