use super::*;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use pecr_contracts::{
    Budget, Claim, ClaimEvidenceSnippet, ClaimMap, ClaimStatus, ClarificationPrompt,
    ClientResponseKind, EngineComparisonSummary, EngineMode, PLANNER_CONTRACT_SCHEMA_VERSION,
    PlanRequest, PlanResponse, PlannerHints, PlannerIntent, PlannerRecoveryContext, PlannerStep,
    ReplayBundle, ReplayBundleMetadata, ReplayEvaluationResult, ReplayEvaluationSubmission,
    ReplayPlannerDecisionSummary, ReplayPlannerTrace, ReplayRunScore, RunQualityScorecard,
    SafeAskCapability, SafeAskCatalog, TerminalMode,
};
use std::collections::BTreeSet;
#[cfg(feature = "rlm")]
use std::collections::HashMap;
#[cfg(feature = "rlm")]
use std::fs;
use std::net::SocketAddr;
#[cfg(feature = "rlm")]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
#[cfg(feature = "rlm")]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use ulid::Ulid;

use super::replay_api::ReplayListQuery;
use crate::http::orchestration::decompose_query_clauses;
use crate::replay::hash_principal_id;

fn contract_manifest() -> &'static serde_json::Value {
    static MANIFEST: OnceLock<serde_json::Value> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/openapi/contract_manifest.json"
        )))
        .expect("contract manifest must parse")
    })
}

fn assert_contract_shape(name: &str, value: &serde_json::Value) {
    let schema = &contract_manifest()["schemas"][name];
    let required = schema["required"]
        .as_array()
        .expect("required fields must be an array")
        .iter()
        .map(|value| value.as_str().expect("field must be string").to_string())
        .collect::<BTreeSet<_>>();
    let optional = schema["optional"]
        .as_array()
        .expect("optional fields must be an array")
        .iter()
        .map(|value| value.as_str().expect("field must be string").to_string())
        .collect::<BTreeSet<_>>();
    let actual = value
        .as_object()
        .expect("shape value must be an object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    let expected = required.union(&optional).cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "shape drift for {name}");
}

#[test]
fn controller_http_shapes_match_contract_manifest() {
    let budget = Budget {
        max_operator_calls: 10,
        max_bytes: 2048,
        max_wallclock_ms: 1000,
        max_recursion_depth: 2,
        max_parallelism: Some(1),
    };
    let claim_map = ClaimMap {
        claim_map_id: "claim_map".to_string(),
        terminal_mode: TerminalMode::InsufficientEvidence,
        claims: Vec::new(),
        coverage_threshold: 0.95,
        coverage_observed: 0.0,
        clarification_prompt: None,
        notes: None,
    };
    let clarification_prompt = ClarificationPrompt {
        question: "Which field or filter should I use for the customer lookup".to_string(),
        options: vec!["customer status".to_string(), "plan tier".to_string()],
    };
    let safe_ask_catalog = SafeAskCatalog {
        capabilities: vec![SafeAskCapability {
            capability_id: "structured_lookup".to_string(),
            intent: PlannerIntent::StructuredLookup,
            title: "Look up customer fields".to_string(),
            description: "Use safe structured views for direct field lookups.".to_string(),
            examples: vec!["What is the customer status and plan tier?".to_string()],
            scope_labels: vec!["customer rows in safe_customer_view_public".to_string()],
            view_ids: vec!["safe_customer_view_public".to_string()],
            field_labels: vec![
                "customer_id".to_string(),
                "status".to_string(),
                "plan_tier".to_string(),
            ],
            dimension_labels: vec!["status".to_string(), "plan_tier".to_string()],
            source_scopes: vec!["public/".to_string()],
            document_hints: vec!["policy documents".to_string()],
        }],
        suggested_queries: vec!["What is the customer status and plan tier?".to_string()],
    };
    let run_score = ReplayRunScore {
        run_id: "run_01".to_string(),
        trace_id: "trace_01".to_string(),
        engine_mode: EngineMode::Baseline,
        terminal_mode: TerminalMode::Supported,
        quality_score: 98.0,
        coverage_observed: 1.0,
        citation_quality: 1.0,
        response_kind: Some(ClientResponseKind::PartialAnswer),
    };
    let scorecard = RunQualityScorecard {
        engine_mode: EngineMode::Baseline,
        run_count: 1,
        average_quality_score: 98.0,
        minimum_quality_score: 98.0,
        maximum_quality_score: 98.0,
        supported_rate: 1.0,
        source_unavailable_rate: 0.0,
        ambiguity_rate: 0.0,
        partial_answer_rate: 1.0,
        refusal_friction_rate: 0.0,
        average_coverage_observed: 1.0,
        average_citation_quality: 1.0,
    };
    let engine_comparison = EngineComparisonSummary {
        primary_engine_mode: EngineMode::Baseline,
        secondary_engine_mode: EngineMode::Rlm,
        paired_query_count: 1,
        average_quality_score_delta: 15.0,
        supported_rate_delta: 1.0,
        source_unavailable_rate_delta: -1.0,
        average_coverage_observed_delta: 0.25,
        average_citation_quality_delta: 1.0,
        primary_win_rate: 1.0,
        secondary_win_rate: 0.0,
        tie_rate: 0.0,
        more_helpful_engine_mode: Some(EngineMode::Baseline),
    };
    let evidence_snippet = ClaimEvidenceSnippet {
        evidence_unit_id: "a".repeat(64),
        location: "fs_corpus/public/public_1.txt line 1".to_string(),
        snippet: "refunds are available within 30 days".to_string(),
    };
    let claim = Claim {
        claim_id: "b".repeat(64),
        claim_text: "Refunds are available within 30 days.".to_string(),
        status: ClaimStatus::Supported,
        evidence_unit_ids: vec![evidence_snippet.evidence_unit_id.clone()],
        evidence_snippets: vec![evidence_snippet.clone()],
    };
    let planner_hints = PlannerHints {
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
    };
    let planner_trace = ReplayPlannerTrace {
        plan_request: PlanRequest {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            query: "What is the customer status and plan tier?".to_string(),
            budget: budget.clone(),
            planner_hints: planner_hints.clone(),
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
            }),
            available_operator_names: vec![
                "fetch_rows".to_string(),
                "lookup_evidence".to_string(),
                "search".to_string(),
                "fetch_span".to_string(),
            ],
            allow_search_ref_fetch_span: true,
        },
        output_steps: planner_hints.recommended_path.clone(),
        decision_summary: ReplayPlannerDecisionSummary {
            planner_source: "rust_owned".to_string(),
            stop_reason: "plan_complete".to_string(),
            selected_for_execution: true,
            used_fallback_plan: false,
            fallback_from_step: Some("fetch_rows".to_string()),
            expected_usefulness_score: Some(0.91),
            expected_usefulness_reasons: vec![
                "starts with a direct structured lookup for a row-oriented question"
                    .to_string(),
            ],
            selection_rationale: Some(
                "rust_owned was preferred because expected usefulness scored 0.9100; starts with a direct structured lookup for a row-oriented question."
                    .to_string(),
            ),
            planner_summary: Some("Prefer direct structured lookup.".to_string()),
        },
    };

    assert_contract_shape(
        "controller.RunRequest",
        &serde_json::to_value(RunRequest {
            query: "find status".to_string(),
            budget: Some(budget.clone()),
        })
        .expect("run request should serialize"),
    );
    assert_contract_shape(
        "controller.RunResponse",
        &serde_json::to_value(RunResponse {
            terminal_mode: TerminalMode::Supported,
            trace_id: "trace_01".to_string(),
            claim_map: claim_map.clone(),
            response_text: "supported".to_string(),
            response_kind: Some(ClientResponseKind::PartialAnswer),
        })
        .expect("run response should serialize"),
    );
    assert_contract_shape(
        "ClaimEvidenceSnippet",
        &serde_json::to_value(&evidence_snippet).expect("snippet should serialize"),
    );
    assert_contract_shape(
        "Claim",
        &serde_json::to_value(claim).expect("claim should serialize"),
    );
    assert_contract_shape(
        "ClarificationPrompt",
        &serde_json::to_value(clarification_prompt.clone())
            .expect("clarification prompt should serialize"),
    );
    assert_contract_shape(
        "SafeAskCapability",
        &serde_json::to_value(&safe_ask_catalog.capabilities[0])
            .expect("safe ask capability should serialize"),
    );
    assert_contract_shape(
        "SafeAskCatalog",
        &serde_json::to_value(safe_ask_catalog.clone()).expect("safe ask catalog should serialize"),
    );
    assert_contract_shape(
        "controller.SafeAskCatalogResponse",
        &serde_json::to_value(safe_ask_catalog).expect("safe ask response should serialize"),
    );
    assert_contract_shape(
        "ClaimMap",
        &serde_json::to_value(ClaimMap {
            notes: Some("Needs one narrowing detail.".to_string()),
            clarification_prompt: Some(clarification_prompt.clone()),
            ..claim_map.clone()
        })
        .expect("claim map should serialize"),
    );
    assert_contract_shape(
        "PlannerOperatorStep",
        &serde_json::to_value(&planner_hints.recommended_path[0]).expect("step should serialize"),
    );
    assert_contract_shape(
        "PlannerSearchRefFetchSpanStep",
        &serde_json::to_value(&planner_hints.recommended_path[1]).expect("step should serialize"),
    );
    assert_contract_shape(
        "PlannerHints",
        &serde_json::to_value(planner_hints.clone()).expect("planner hints should serialize"),
    );
    assert_contract_shape(
        "PlannerRecoveryContext",
        &serde_json::to_value(PlannerRecoveryContext {
            failed_step: "fetch_rows".to_string(),
            failure_terminal_mode: TerminalMode::SourceUnavailable,
            attempted_path: vec![PlannerStep::Operator {
                op_name: "fetch_rows".to_string(),
                params: serde_json::json!({
                    "view_id": "safe_customer_view_public",
                    "fields": ["status", "plan_tier"],
                }),
            }],
        })
        .expect("planner recovery context should serialize"),
    );
    assert_contract_shape(
        "PlanRequest",
        &serde_json::to_value(PlanRequest {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            query: "What is the customer status and plan tier?".to_string(),
            budget: budget.clone(),
            planner_hints: planner_hints.clone(),
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
            }),
            available_operator_names: vec![
                "fetch_rows".to_string(),
                "lookup_evidence".to_string(),
                "search".to_string(),
                "fetch_span".to_string(),
            ],
            allow_search_ref_fetch_span: true,
        })
        .expect("plan request should serialize"),
    );
    assert_contract_shape(
        "PlanResponse",
        &serde_json::to_value(PlanResponse {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            steps: planner_hints.recommended_path.clone(),
            planner_summary: Some("Prefer direct structured lookup.".to_string()),
        })
        .expect("plan response should serialize"),
    );
    assert_contract_shape(
        "ReplayPlannerDecisionSummary",
        &serde_json::to_value(planner_trace.decision_summary.clone())
            .expect("planner decision summary should serialize"),
    );
    assert_contract_shape(
        "ReplayPlannerTrace",
        &serde_json::to_value(planner_trace.clone()).expect("planner trace should serialize"),
    );
    assert_contract_shape(
        "ReplayBundle",
        &serde_json::to_value(ReplayBundle {
            metadata: pecr_contracts::ReplayBundleMetadata {
                schema_version: 1,
                run_id: "run_01".to_string(),
                trace_id: "trace_01".to_string(),
                request_id: "req_01".to_string(),
                principal_id_hash: "a".repeat(64),
                engine_mode: EngineMode::Baseline,
                recorded_at_unix_ms: 1,
                terminal_mode: TerminalMode::Supported,
                quality_score: 98.0,
                bundle_hash: "b".repeat(64),
            },
            query: "What is the customer status and plan tier?".to_string(),
            budget: budget.clone(),
            session_id: "session_01".to_string(),
            policy_snapshot_id: "policy_01".to_string(),
            loop_terminal_mode: TerminalMode::Supported,
            loop_response_text: Some("SUPPORTED".to_string()),
            response_text: "SUPPORTED".to_string(),
            claim_map: claim_map.clone(),
            operator_calls_used: 1,
            bytes_used: 64,
            depth_used: 1,
            evidence_ref_count: 1,
            evidence_unit_ids: vec![evidence_snippet.evidence_unit_id.clone()],
            planner_traces: vec![planner_trace.clone()],
        })
        .expect("replay bundle should serialize"),
    );
    assert_contract_shape(
        "controller.ReplayListResponse",
        &serde_json::to_value(super::replay_api::ReplayListResponse {
            replays: Vec::new(),
        })
        .expect("replay list response should serialize"),
    );
    assert_contract_shape(
        "controller.ReplayScorecardsResponse",
        &serde_json::to_value(super::replay_api::ReplayScorecardsResponse {
            scorecards: vec![scorecard.clone()],
        })
        .expect("scorecards response should serialize"),
    );
    assert_contract_shape(
        "ReplayEvaluationSubmission",
        &serde_json::to_value(ReplayEvaluationSubmission {
            evaluation_name: "baseline".to_string(),
            replay_ids: vec!["run_01".to_string()],
            engine_mode: Some(EngineMode::Baseline),
            min_quality_score: Some(90.0),
            max_source_unavailable_rate: Some(0.1),
        })
        .expect("evaluation submission should serialize"),
    );
    assert_contract_shape(
        "ReplayRunScore",
        &serde_json::to_value(run_score.clone()).expect("run score should serialize"),
    );
    assert_contract_shape(
        "RunQualityScorecard",
        &serde_json::to_value(scorecard.clone()).expect("scorecard should serialize"),
    );
    assert_contract_shape(
        "EngineComparisonSummary",
        &serde_json::to_value(engine_comparison.clone()).expect("comparison should serialize"),
    );
    assert_contract_shape(
        "ReplayEvaluationResult",
        &serde_json::to_value(ReplayEvaluationResult {
            evaluation_id: "eval_01".to_string(),
            evaluation_name: "baseline".to_string(),
            principal_id_hash: "a".repeat(64),
            created_at_unix_ms: 1,
            replay_ids: vec!["run_01".to_string()],
            missing_replay_ids: vec!["run_02".to_string()],
            run_results: vec![run_score],
            scorecards: vec![scorecard],
            engine_comparisons: vec![engine_comparison],
            overall_pass: true,
        })
        .expect("evaluation result should serialize"),
    );
    assert_contract_shape(
        "ErrorResponse",
        &serde_json::to_value(ErrorResponse {
            code: "ERR_INVALID_PARAMS".to_string(),
            message: "bad request".to_string(),
            terminal_mode_hint: TerminalMode::InsufficientEvidence,
            retryable: false,
            response_kind: Some(ClientResponseKind::Ambiguous),
            what_failed: Some("field validation failed".to_string()),
            safe_alternative: Some("Fix the request body and retry.".to_string()),
            detail: Some(serde_json::json!({"field": "query"})),
        })
        .expect("error response should serialize"),
    );
}

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

#[derive(Clone, Default)]
struct PlannedGatewayMetrics {
    calls: Arc<Mutex<Vec<String>>>,
    params: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

impl PlannedGatewayMetrics {
    fn record(&self, op_name: &str, payload: &serde_json::Value) {
        self.calls
            .lock()
            .expect("planned gateway call log lock should not be poisoned")
            .push(op_name.to_string());
        self.params
            .lock()
            .expect("planned gateway params lock should not be poisoned")
            .push((
                op_name.to_string(),
                payload
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            ));
    }

    fn snapshot(&self) -> Vec<String> {
        self.calls
            .lock()
            .expect("planned gateway call log lock should not be poisoned")
            .clone()
    }

    fn params_for(&self, op_name: &str) -> Vec<serde_json::Value> {
        self.params
            .lock()
            .expect("planned gateway params lock should not be poisoned")
            .iter()
            .filter(|(name, _)| name == op_name)
            .map(|(_, params)| params.clone())
            .collect()
    }
}

#[derive(Clone)]
struct PlannedGatewayState {
    metrics: PlannedGatewayMetrics,
    fail_once: Arc<Mutex<std::collections::HashMap<String, TerminalMode>>>,
}

impl PlannedGatewayState {
    fn new(
        metrics: PlannedGatewayMetrics,
        fail_once: std::collections::HashMap<String, TerminalMode>,
    ) -> Self {
        Self {
            metrics,
            fail_once: Arc::new(Mutex::new(fail_once)),
        }
    }

    fn failure_for(&self, op_name: &str) -> Option<TerminalMode> {
        self.fail_once
            .lock()
            .expect("planned gateway failures lock should not be poisoned")
            .remove(op_name)
    }
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
    async fn policy_simulate(
        headers: HeaderMap,
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let principal_id = headers
            .get("x-pecr-principal-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("dev");
        let intent = payload
            .get("params")
            .and_then(|value| value.get("intent"))
            .and_then(|value| value.as_str())
            .unwrap_or("default");

        let narrowing = match intent {
            "structured_lookup"
            | "structured_aggregation"
            | "structured_evidence_lookup"
            | "structured_aggregation_evidence" => Some(serde_json::json!({
                "scope_labels": ["customer rows in safe_customer_view_public"],
                "view_ids": ["safe_customer_view_public"],
                "field_labels": ["customer_id", "status", "plan_tier"],
                "dimension_labels": ["status", "plan_tier"],
                "examples": [
                    "What is the customer status and plan tier in safe_customer_view_public?",
                    "Compare customer counts by plan tier in safe_customer_view_public."
                ]
            })),
            "evidence_lookup" | "version_review" | "structured_version_review" => {
                Some(serde_json::json!({
                    "scope_labels": ["public documents under public/"],
                    "source_scopes": ["public/"],
                    "document_hints": ["policy documents", "versioned documents"],
                    "examples": [
                        "Show the source text and evidence for the support policy in public documents.",
                        "What changed in the latest version of the support policy document under public/?"
                    ]
                }))
            }
            _ if principal_id == "dev" => Some(serde_json::json!({
                "scope_labels": ["customer rows in safe_customer_view_public", "public documents under public/"],
                "view_ids": ["safe_customer_view_public"],
                "field_labels": ["customer_id", "status", "plan_tier"],
                "dimension_labels": ["status", "plan_tier"],
                "source_scopes": ["public/"],
                "document_hints": ["policy documents", "versioned documents"],
                "examples": [
                    "What is the customer status and plan tier in safe_customer_view_public?",
                    "Show the source text and evidence for the support policy in public documents."
                ]
            })),
            _ if principal_id == "support" => Some(serde_json::json!({
                "scope_labels": [
                    "customer rows in safe_customer_view_public",
                    "customer rows in safe_customer_view_support",
                    "public documents under public/",
                    "support-visible documents under injection/"
                ],
                "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
                "field_labels": ["customer_id", "status", "plan_tier"],
                "dimension_labels": ["status", "plan_tier"],
                "source_scopes": ["public/", "injection/"],
                "document_hints": ["policy documents", "versioned documents"],
                "examples": [
                    "What is the customer status and plan tier in safe_customer_view_support?",
                    "Show the source text and evidence for the support policy in public documents."
                ]
            })),
            _ => None,
        };

        Json(serde_json::json!({
            "allow": narrowing.is_some(),
            "cacheable": true,
            "reason": if narrowing.is_some() { "narrow_query_mock" } else { "default_deny" },
            "redaction": {},
            "narrowing": narrowing
        }))
    }

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

    async fn aggregate(
        State(counter): State<Arc<AtomicUsize>>,
        Json(_): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        counter.fetch_add(1, Ordering::Relaxed);
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": {
                "source_system": "pg_safeview",
                "object_id": "safe_customer_view_public",
                "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
                "span_or_row_spec": {
                    "type": "db_aggregate",
                    "view_id": "safe_customer_view_public",
                    "group_by": ["status"]
                },
                "content_type": "application/json",
                "content": {
                    "rows": [
                        {
                            "group": { "status": "active" },
                            "metrics": [{ "name": "count", "field": "customer_id", "value": 10 }]
                        }
                    ]
                },
                "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "retrieved_at": "1970-01-01T00:00:00Z",
                "as_of_time": "1970-01-01T00:00:00Z",
                "policy_snapshot_id": "policy",
                "policy_snapshot_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "transform_chain": [],
                "evidence_unit_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
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

    async fn lookup_evidence(
        State(counter): State<Arc<AtomicUsize>>,
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        counter.fetch_add(1, Ordering::Relaxed);
        let query = payload
            .get("params")
            .and_then(|value| value.get("query"))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if query == "policy" {
            return Json(serde_json::json!({
                "terminal_mode": "INSUFFICIENT_EVIDENCE",
                "result": []
            }));
        }
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result_summary": "public/public_1.txt line 1: unit-test",
            "result": [{
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
            }]
        }))
    }

    let app = Router::new()
        .route("/v1/policies/simulate", post(policy_simulate))
        .route("/v1/operators/list_versions", post(list_versions))
        .route("/v1/operators/fetch_rows", post(fetch_rows))
        .route("/v1/operators/aggregate", post(aggregate))
        .route("/v1/operators/compare", post(aggregate))
        .route("/v1/operators/search", post(search))
        .route("/v1/operators/fetch_span", post(fetch_span))
        .route("/v1/operators/lookup_evidence", post(lookup_evidence))
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

fn planned_gateway_failure_response(terminal_mode: TerminalMode) -> Response {
    let status = match terminal_mode {
        TerminalMode::InsufficientPermission => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(serde_json::json!({
            "terminal_mode_hint": terminal_mode.as_str(),
        })),
    )
        .into_response()
}

fn planned_gateway_response(
    state: &PlannedGatewayState,
    op_name: &str,
    payload: &serde_json::Value,
    success_body: serde_json::Value,
) -> Response {
    state.metrics.record(op_name, payload);
    if let Some(terminal_mode) = state.failure_for(op_name) {
        return planned_gateway_failure_response(terminal_mode);
    }

    Json(success_body).into_response()
}

fn planned_aggregate_body(payload: &serde_json::Value) -> serde_json::Value {
    let params = payload
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let group_by = params
        .get("group_by")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let time_granularity = params
        .get("time_granularity")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let is_trend = time_granularity.is_some();

    let rows = if is_trend {
        vec![
            serde_json::json!({
                "group": { "time_bucket": "2026-03-01" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 12 }]
            }),
            serde_json::json!({
                "group": { "time_bucket": "2026-03-02" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 15 }]
            }),
        ]
    } else if group_by
        .iter()
        .any(|value| value.as_str() == Some("plan_tier"))
    {
        vec![
            serde_json::json!({
                "group": { "plan_tier": "starter" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
            }),
            serde_json::json!({
                "group": { "plan_tier": "premium" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 4 }]
            }),
        ]
    } else {
        vec![
            serde_json::json!({
                "group": { "status": "active" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 10 }]
            }),
            serde_json::json!({
                "group": { "status": "inactive" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 3 }]
            }),
        ]
    };

    let mut content = serde_json::json!({ "rows": rows });
    if let Some(map) = content.as_object_mut() {
        let comparison_summary = if is_trend {
            serde_json::json!({
                "kind": "trend",
                "summary": "count(customer_id) increased from 12 to 15 across 2 time buckets",
                "highlights": [
                    "2026-03-01 count(customer_id)=12",
                    "2026-03-02 count(customer_id)=15"
                ]
            })
        } else if group_by
            .iter()
            .any(|value| value.as_str() == Some("plan_tier"))
        {
            serde_json::json!({
                "kind": "group_compare",
                "summary": "count(customer_id) is highest for plan_tier=starter (9) and lowest for plan_tier=premium (4)",
                "highlights": [
                    "plan_tier=starter count(customer_id)=9",
                    "plan_tier=premium count(customer_id)=4"
                ]
            })
        } else {
            serde_json::json!({
                "kind": "group_compare",
                "summary": "count(customer_id) is highest for status=active (10) and lowest for status=inactive (3)",
                "highlights": [
                    "status=active count(customer_id)=10",
                    "status=inactive count(customer_id)=3"
                ]
            })
        };
        map.insert("comparison_summary".to_string(), comparison_summary);
    }

    let result_summary = if is_trend {
        "safe_customer_view_public aggregate: count(customer_id) increased from 12 to 15 across 2 time buckets"
    } else if group_by
        .iter()
        .any(|value| value.as_str() == Some("plan_tier"))
    {
        "safe_customer_view_public aggregate: count(customer_id) is highest for plan_tier=starter (9) and lowest for plan_tier=premium (4)"
    } else {
        "safe_customer_view_public aggregate: count(customer_id) is highest for status=active (10) and lowest for status=inactive (3)"
    };

    serde_json::json!({
        "terminal_mode": "SUPPORTED",
        "result_summary": result_summary,
        "result": {
            "source_system": "pg_safeview",
            "object_id": "safe_customer_view_public",
            "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
            "span_or_row_spec": {
                "type": "db_aggregate",
                "view_id": "safe_customer_view_public",
                "group_by": group_by,
                "time_granularity": time_granularity.clone(),
                "comparison_mode": if is_trend { "trend" } else { "group_compare" }
            },
            "content_type": "application/json",
            "content": content,
            "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "retrieved_at": "1970-01-01T00:00:00Z",
            "as_of_time": "1970-01-01T00:00:00Z",
            "policy_snapshot_id": "policy",
            "policy_snapshot_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transform_chain": [],
            "evidence_unit_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
    })
}

async fn spawn_planned_gateway_with_failures(
    metrics: PlannedGatewayMetrics,
    fail_once: std::collections::HashMap<String, TerminalMode>,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    async fn list_versions(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "list_versions",
            &payload,
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result_summary": "2 versions available; latest 999999999999 compared with previous 111111111111",
                "result": {
                    "versions": [
                        {
                            "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
                            "as_of_time": "2026-03-02T00:00:00Z"
                        },
                        {
                            "version_id": "1111111111111111111111111111111111111111111111111111111111111111",
                            "as_of_time": "2026-03-01T00:00:00Z"
                        }
                    ]
                }
            }),
        )
    }

    async fn diff(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "diff",
            &payload,
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result_summary": "public/support_policy.txt changed: added 'Annual plans may request refunds within 30 days of purchase.'; removed 'Refunds are unavailable for annual plans.'",
                "result": [{
                    "source_system": "fs_corpus",
                    "object_id": "public/support_policy.txt",
                    "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
                    "span_or_row_spec": {
                        "type": "diff",
                        "object_id": "public/support_policy.txt",
                        "v1": "1111111111111111111111111111111111111111111111111111111111111111",
                        "v2": "9999999999999999999999999999999999999999999999999999999999999999"
                    },
                    "content_type": "text/plain",
                    "content": "--- a/public/support_policy.txt\n+++ b/public/support_policy.txt\n@@\n-Refunds are unavailable for annual plans.\n+Annual plans may request refunds within 30 days of purchase.\n",
                    "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "retrieved_at": "1970-01-01T00:00:00Z",
                    "as_of_time": "1970-01-01T00:00:00Z",
                    "policy_snapshot_id": "policy",
                    "policy_snapshot_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "transform_chain": [{
                        "transform_type": "diff_unified_v1",
                        "transform_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                        "params": {
                            "object_id": "public/support_policy.txt",
                            "v1": "1111111111111111111111111111111111111111111111111111111111111111",
                            "v2": "9999999999999999999999999999999999999999999999999999999999999999"
                        }
                    }],
                    "evidence_unit_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }]
            }),
        )
    }

    async fn fetch_rows(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "fetch_rows",
            &payload,
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": [
                    {
                        "source_system": "pg_safeview",
                        "object_id": "safe_customer_view_public/cust_public_1",
                        "version_id": "1111111111111111111111111111111111111111111111111111111111111111",
                        "span_or_row_spec": {
                            "type": "row",
                            "view_id": "safe_customer_view_public",
                            "row_pk": "cust_public_1"
                        },
                        "content_type": "application/json",
                        "content": {
                            "status": "active",
                            "plan_tier": "starter"
                        },
                        "content_hash": "2222222222222222222222222222222222222222222222222222222222222222",
                        "retrieved_at": "1970-01-01T00:00:00Z",
                        "as_of_time": "1970-01-01T00:00:00Z",
                        "policy_snapshot_id": "policy",
                        "policy_snapshot_hash": "3333333333333333333333333333333333333333333333333333333333333333",
                        "transform_chain": [],
                        "evidence_unit_id": "4444444444444444444444444444444444444444444444444444444444444444"
                    }
                ]
            }),
        )
    }

    async fn aggregate(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "aggregate",
            &payload,
            planned_aggregate_body(&payload),
        )
    }

    async fn compare(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "compare",
            &payload,
            planned_aggregate_body(&payload),
        )
    }

    async fn search(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "search",
            &payload,
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": {
                    "refs": [
                        {
                            "evidence_unit_id": "4444444444444444444444444444444444444444444444444444444444444444",
                            "source_system": "fs_corpus",
                            "object_id": "public/public_1.txt",
                            "version_id": "5555555555555555555555555555555555555555555555555555555555555555",
                            "start_byte": 5,
                            "end_byte": 24,
                            "line_start": 1,
                            "line_end": 1,
                            "match_preview": "public support text",
                            "match_score": 14
                        }
                    ]
                }
            }),
        )
    }

    async fn fetch_span(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        planned_gateway_response(
            &state,
            "fetch_span",
            &payload,
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result": {
                    "source_system": "fs_corpus",
                    "object_id": "public/public_1.txt",
                    "version_id": "5555555555555555555555555555555555555555555555555555555555555555",
                    "span_or_row_spec": {
                        "type": "text_span",
                        "start_byte": 5,
                        "end_byte": 24,
                        "line_start": 1,
                        "line_end": 1
                    },
                    "content_type": "text/plain",
                    "content": "public support text",
                    "content_hash": "6666666666666666666666666666666666666666666666666666666666666666",
                    "retrieved_at": "1970-01-01T00:00:00Z",
                    "as_of_time": "1970-01-01T00:00:00Z",
                    "policy_snapshot_id": "policy",
                    "policy_snapshot_hash": "7777777777777777777777777777777777777777777777777777777777777777",
                    "transform_chain": [],
                    "evidence_unit_id": "8888888888888888888888888888888888888888888888888888888888888888"
                }
            }),
        )
    }

    async fn lookup_evidence(
        State(state): State<PlannedGatewayState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Response {
        let query = payload
            .get("params")
            .and_then(|value| value.get("query"))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let success_body = if query == "policy" {
            serde_json::json!({
                "terminal_mode": "INSUFFICIENT_EVIDENCE",
                "result": []
            })
        } else {
            serde_json::json!({
                "terminal_mode": "SUPPORTED",
                "result_summary": "public/public_1.txt line 1: public support text",
                "result": [{
                    "source_system": "fs_corpus",
                    "object_id": "public/public_1.txt",
                    "version_id": "5555555555555555555555555555555555555555555555555555555555555555",
                    "span_or_row_spec": {
                        "type": "text_span",
                        "start_byte": 5,
                        "end_byte": 24,
                        "line_start": 1,
                        "line_end": 1
                    },
                    "content_type": "text/plain",
                    "content": "public support text",
                    "content_hash": "6666666666666666666666666666666666666666666666666666666666666666",
                    "retrieved_at": "1970-01-01T00:00:00Z",
                    "as_of_time": "1970-01-01T00:00:00Z",
                    "policy_snapshot_id": "policy",
                    "policy_snapshot_hash": "7777777777777777777777777777777777777777777777777777777777777777",
                    "transform_chain": [],
                    "evidence_unit_id": "8888888888888888888888888888888888888888888888888888888888888888"
                }]
            })
        };
        planned_gateway_response(&state, "lookup_evidence", &payload, success_body)
    }

    let state = PlannedGatewayState::new(metrics, fail_once);
    let app = Router::new()
        .route("/v1/operators/list_versions", post(list_versions))
        .route("/v1/operators/diff", post(diff))
        .route("/v1/operators/fetch_rows", post(fetch_rows))
        .route("/v1/operators/aggregate", post(aggregate))
        .route("/v1/operators/compare", post(compare))
        .route("/v1/operators/search", post(search))
        .route("/v1/operators/fetch_span", post(fetch_span))
        .route("/v1/operators/lookup_evidence", post(lookup_evidence))
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

async fn spawn_planned_gateway(
    metrics: PlannedGatewayMetrics,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    spawn_planned_gateway_with_failures(metrics, std::collections::HashMap::new()).await
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

async fn spawn_run_gateway() -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    async fn create_session(
        headers: HeaderMap,
        Json(req): Json<serde_json::Value>,
    ) -> (HeaderMap, Json<serde_json::Value>) {
        let trace_id = headers
            .get("x-pecr-trace-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("trace");
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            "x-pecr-session-token",
            HeaderValue::from_static("session-token"),
        );
        (
            response_headers,
            Json(serde_json::json!({
                "session_id": "session-01",
                "trace_id": trace_id,
                "policy_snapshot_id": "policy-01",
                "budget": req.get("budget").cloned().unwrap_or_else(|| serde_json::json!({}))
            })),
        )
    }

    async fn finalize(
        headers: HeaderMap,
        Json(req): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let trace_id = headers
            .get("x-pecr-trace-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("trace");
        let mut claim_map = req
            .get("claim_map")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let mut supported_claims = 0u64;
        let mut covered_supported_claims = 0u64;
        if let Some(claims) = claim_map
            .get_mut("claims")
            .and_then(|value| value.as_array_mut())
        {
            for claim in claims {
                let status = claim
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("UNKNOWN");
                if status != "SUPPORTED" {
                    continue;
                }

                let evidence_count = claim
                    .get("evidence_unit_ids")
                    .and_then(|value| value.as_array())
                    .map(|ids| ids.iter().filter(|id| id.as_str().is_some()).count())
                    .unwrap_or(0);
                if evidence_count == 0 {
                    if let Some(obj) = claim.as_object_mut() {
                        obj.insert("status".to_string(), serde_json::json!("UNKNOWN"));
                    }
                } else {
                    supported_claims += 1;
                    covered_supported_claims += 1;
                }
            }
        }
        let coverage_observed = if supported_claims == 0 {
            0.0
        } else {
            covered_supported_claims as f64 / supported_claims as f64
        };
        let terminal_mode = if supported_claims > 0 && coverage_observed >= 0.95 {
            "SUPPORTED"
        } else {
            "INSUFFICIENT_EVIDENCE"
        };
        if let Some(obj) = claim_map.as_object_mut() {
            obj.insert("coverage_threshold".to_string(), serde_json::json!(0.95));
            obj.insert(
                "coverage_observed".to_string(),
                serde_json::json!(coverage_observed),
            );
            obj.insert(
                "terminal_mode".to_string(),
                serde_json::json!(terminal_mode),
            );
        }
        Json(serde_json::json!({
            "terminal_mode": terminal_mode,
            "trace_id": trace_id,
            "claim_map": claim_map,
            "response_text": req.get("response_text").cloned().unwrap_or_else(|| serde_json::json!(""))
        }))
    }

    async fn list_versions(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": {
                "versions": [
                    {
                        "version_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                ]
            }
        }))
    }

    async fn fetch_rows(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": [
                {
                    "source_system": "pg_safeview",
                    "object_id": "safe_customer_view_public/cust_public_1",
                    "version_id": "1111111111111111111111111111111111111111111111111111111111111111",
                    "span_or_row_spec": {
                        "type": "row",
                        "view_id": "safe_customer_view_public",
                        "row_pk": "cust_public_1"
                    },
                    "content_type": "application/json",
                    "content": {
                        "status": "active",
                        "plan_tier": "starter"
                    },
                    "content_hash": "2222222222222222222222222222222222222222222222222222222222222222",
                    "retrieved_at": "1970-01-01T00:00:00Z",
                    "as_of_time": "1970-01-01T00:00:00Z",
                    "policy_snapshot_id": "policy-01",
                    "policy_snapshot_hash": "3333333333333333333333333333333333333333333333333333333333333333",
                    "transform_chain": [],
                    "evidence_unit_id": "4444444444444444444444444444444444444444444444444444444444444444"
                }
            ]
        }))
    }

    async fn aggregate(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": {
                "source_system": "pg_safeview",
                "object_id": "safe_customer_view_public",
                "version_id": "9999999999999999999999999999999999999999999999999999999999999999",
                "span_or_row_spec": {
                    "type": "db_aggregate",
                    "view_id": "safe_customer_view_public",
                    "group_by": ["status"]
                },
                "content_type": "application/json",
                "content": {
                    "rows": [
                        {
                            "group": { "status": "active" },
                            "metrics": [{ "name": "count", "field": "customer_id", "value": 10 }]
                        },
                        {
                            "group": { "status": "inactive" },
                            "metrics": [{ "name": "count", "field": "customer_id", "value": 3 }]
                        }
                    ]
                },
                "content_hash": "9999999999999999999999999999999999999999999999999999999999999999",
                "retrieved_at": "1970-01-01T00:00:00Z",
                "as_of_time": "1970-01-01T00:00:00Z",
                "policy_snapshot_id": "policy-01",
                "policy_snapshot_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "transform_chain": [],
                "evidence_unit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        }))
    }

    async fn search(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": {
                "refs": [
                    {
                        "evidence_unit_id": "4444444444444444444444444444444444444444444444444444444444444444",
                        "source_system": "fs_corpus",
                        "object_id": "public/public_1.txt",
                        "version_id": "5555555555555555555555555555555555555555555555555555555555555555"
                    }
                ]
            }
        }))
    }

    async fn fetch_span(Json(_): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result": {
                "source_system": "fs_corpus",
                "object_id": "public/public_1.txt",
                "version_id": "5555555555555555555555555555555555555555555555555555555555555555",
                "span_or_row_spec": {
                    "type": "text_span",
                    "line_start": 1,
                    "line_end": 1
                },
                "content_type": "text/plain",
                "content": "public support text",
                "content_hash": "6666666666666666666666666666666666666666666666666666666666666666",
                "retrieved_at": "1970-01-01T00:00:00Z",
                "as_of_time": "1970-01-01T00:00:00Z",
                "policy_snapshot_id": "policy-01",
                "policy_snapshot_hash": "7777777777777777777777777777777777777777777777777777777777777777",
                "transform_chain": [],
                "evidence_unit_id": "8888888888888888888888888888888888888888888888888888888888888888"
            }
        }))
    }

    async fn lookup_evidence(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let query = payload
            .get("params")
            .and_then(|value| value.get("query"))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if query == "policy" {
            return Json(serde_json::json!({
                "terminal_mode": "INSUFFICIENT_EVIDENCE",
                "result": []
            }));
        }
        Json(serde_json::json!({
            "terminal_mode": "SUPPORTED",
            "result_summary": "public/public_1.txt line 1: public support text",
            "result": [{
                "source_system": "fs_corpus",
                "object_id": "public/public_1.txt",
                "version_id": "5555555555555555555555555555555555555555555555555555555555555555",
                "span_or_row_spec": {
                    "type": "text_span",
                    "line_start": 1,
                    "line_end": 1
                },
                "content_type": "text/plain",
                "content": "public support text",
                "content_hash": "6666666666666666666666666666666666666666666666666666666666666666",
                "retrieved_at": "1970-01-01T00:00:00Z",
                "as_of_time": "1970-01-01T00:00:00Z",
                "policy_snapshot_id": "policy-01",
                "policy_snapshot_hash": "7777777777777777777777777777777777777777777777777777777777777777",
                "transform_chain": [],
                "evidence_unit_id": "8888888888888888888888888888888888888888888888888888888888888888"
            }]
        }))
    }

    async fn capabilities() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "capabilities": [{
                "capability_id": "structured_lookup",
                "intent": "structured_lookup",
                "title": "Look up customer fields",
                "description": "Use safe structured views for direct field lookups.",
                "examples": ["What is the customer status and plan tier?"],
                "scope_labels": ["customer rows in safe_customer_view_public"],
                "view_ids": ["safe_customer_view_public"],
                "field_labels": ["customer_id", "status", "plan_tier"],
                "dimension_labels": ["status", "plan_tier"],
                "source_scopes": [],
                "document_hints": []
            }],
            "suggested_queries": ["What is the customer status and plan tier?"]
        }))
    }

    let app = Router::new()
        .route("/v1/sessions", post(create_session))
        .route("/v1/finalize", post(finalize))
        .route(
            "/v1/policies/capabilities",
            axum::routing::get(capabilities),
        )
        .route("/v1/operators/list_versions", post(list_versions))
        .route("/v1/operators/fetch_rows", post(fetch_rows))
        .route("/v1/operators/aggregate", post(aggregate))
        .route("/v1/operators/compare", post(aggregate))
        .route("/v1/operators/search", post(search))
        .route("/v1/operators/fetch_span", post(fetch_span))
        .route("/v1/operators/lookup_evidence", post(lookup_evidence));

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

async fn wait_for_replays(
    state: &AppState,
    principal_hash: &str,
    minimum: usize,
) -> Vec<ReplayBundleMetadata> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let replays = state
            .replay_store
            .list_replay_metadata(principal_hash, 10, None)
            .expect("replay list should succeed");
        if replays.len() >= minimum {
            return replays;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for replay persistence"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn controller_state(
    gateway_addr: SocketAddr,
    budget: Budget,
    baseline_plan: Vec<crate::config::BaselinePlanStep>,
) -> AppState {
    let replay_store_dir =
        std::env::temp_dir().join(format!("pecr-controller-http-tests-{}", Ulid::new()));
    let replay_store =
        ReplayStore::new(replay_store_dir.clone(), 30).expect("replay store should initialize");
    let replay_persist_queue = crate::replay::ReplayPersistQueue::new(replay_store.clone())
        .expect("replay persist queue should initialize");
    AppState {
        config: ControllerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr must parse"),
            gateway_url: format!("http://{}", gateway_addr),
            controller_engine: crate::config::ControllerEngine::Baseline,
            model_provider: crate::config::ModelProvider::Mock,
            budget_defaults: budget,
            baseline_plan,
            planner_mode: crate::config::PlannerMode::RustOwned,
            planner_client: crate::config::PlannerClientKind::Disabled,
            planner_client_url: None,
            planner_client_timeout_ms: 500,
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
        replay_store,
        replay_persist_queue,
    }
}

async fn spawn_mock_planner(
    response: PlanResponse,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("planner listener should bind");
    let addr = listener
        .local_addr()
        .expect("planner local addr should be available");

    let app = Router::new().route(
        "/plan",
        post({
            let response = response.clone();
            move |Json(_request): Json<PlanRequest>| {
                let response = response.clone();
                async move { Json(response) }
            }
        }),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("planner server should shut down cleanly");
    });

    (addr, shutdown_tx, handle)
}

async fn spawn_recovery_mock_planner(
    initial_response: PlanResponse,
    recovery_response: PlanResponse,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("planner listener should bind");
    let addr = listener
        .local_addr()
        .expect("planner local addr should be available");

    let app = Router::new().route(
        "/plan",
        post({
            let initial_response = initial_response.clone();
            let recovery_response = recovery_response.clone();
            move |Json(request): Json<PlanRequest>| {
                let initial_response = initial_response.clone();
                let recovery_response = recovery_response.clone();
                async move {
                    if request.recovery_context.is_some() {
                        Json(recovery_response)
                    } else {
                        Json(initial_response)
                    }
                }
            }
        }),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("planner server should shut down cleanly");
    });

    (addr, shutdown_tx, handle)
}

async fn spawn_invalid_planner_response_server()
-> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("invalid planner listener should bind");
    let addr = listener
        .local_addr()
        .expect("invalid planner local addr should be available");

    let app = Router::new().route(
        "/plan",
        post(|| async move {
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                "{\"schema_version\":1,\"steps\":[{\"kind\":\"operator\",\"op_name\":\"not_allowed\",\"params\":{}}]}",
            )
        }),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("invalid planner server should shut down cleanly");
    });

    (addr, shutdown_tx, handle)
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
            planner_traces: Vec::new(),
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
async fn run_returns_supported_claims_and_persists_replay() {
    let budget = Budget {
        max_operator_calls: 10,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: Some(2),
    };
    let (gateway_addr, shutdown, task) = spawn_run_gateway().await;
    let state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-pecr-principal-id", HeaderValue::from_static("dev"));
    headers.insert(
        "x-pecr-request-id",
        HeaderValue::from_static("req-supported"),
    );
    headers.insert(
        "x-pecr-trace-id",
        HeaderValue::from_static("trace-supported"),
    );

    let response = run(
        State(state.clone()),
        headers,
        Json(RunRequest {
            query: "support".to_string(),
            budget: None,
        }),
    )
    .await
    .expect("run should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(response.0.terminal_mode, TerminalMode::Supported);
    assert!(
        response
            .0
            .claim_map
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Supported
                && !claim.evidence_unit_ids.is_empty())
    );
    assert!(response.0.response_text.contains("SUPPORTED:"));
    assert!(response.0.response_text.contains("Source:"));

    let principal_hash = hash_principal_id("dev");
    let replays = wait_for_replays(&state, &principal_hash, 1).await;
    assert_eq!(replays.len(), 1);

    let replay = state
        .replay_store
        .load_replay(&principal_hash, &replays[0].run_id)
        .expect("replay load should succeed")
        .expect("replay should exist");
    assert_eq!(replay.metadata.terminal_mode, TerminalMode::Supported);
    assert!(
        replay
            .claim_map
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Supported
                && !claim.evidence_unit_ids.is_empty())
    );
}

#[cfg(feature = "rlm")]
#[tokio::test]
async fn run_rlm_unknown_only_loop_text_still_returns_supported_finalize_output() {
    let _env_lock = RLM_SCRIPT_ENV_LOCK
        .lock()
        .expect("rlm script env lock should not be poisoned");
    let script_path = write_temp_bridge_script(
        r#"#!/usr/bin/env python3
import json
import sys

json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 1}) + "\n")
sys.stdout.flush()

call_id = "rows_1"
sys.stdout.write(json.dumps({
    "type": "call_operator",
    "id": call_id,
    "depth": 0,
    "op_name": "fetch_rows",
    "params": {"view_id": "safe_customer_view_public"}
}) + "\n")
sys.stdout.flush()

resp = json.loads(sys.stdin.readline())
if resp.get("type") != "operator_result" or resp.get("id") != call_id:
    raise SystemExit("unexpected operator response")

sys.stdout.write(json.dumps({"type": "done", "final_answer": "UNKNOWN: plan request captured"}) + "\n")
sys.stdout.flush()
"#,
    );

    let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
    // Safety: this test scopes env var mutation to setup/teardown in the same thread.
    unsafe {
        std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
    }

    let budget = Budget {
        max_operator_calls: 10,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: Some(2),
    };
    let (gateway_addr, shutdown, task) = spawn_run_gateway().await;
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::Rlm;

    let mut headers = HeaderMap::new();
    headers.insert("x-pecr-principal-id", HeaderValue::from_static("dev"));
    headers.insert(
        "x-pecr-request-id",
        HeaderValue::from_static("req-rlm-finalize-fix"),
    );
    headers.insert(
        "x-pecr-trace-id",
        HeaderValue::from_static("trace-rlm-finalize-fix"),
    );

    let response = run(
        State(state),
        headers,
        Json(RunRequest {
            query: "What is the customer status and plan tier?".to_string(),
            budget: None,
        }),
    )
    .await
    .expect("run should succeed");

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

    assert_eq!(response.0.terminal_mode, TerminalMode::Supported);
    assert!(response.0.response_text.contains("SUPPORTED:"));
    assert!(
        response
            .0
            .claim_map
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Supported
                && !claim.evidence_unit_ids.is_empty())
    );
}

#[cfg(feature = "rlm")]
#[tokio::test]
async fn run_recovers_supported_finalize_output_for_rlm_unknown_placeholder() {
    let _env_lock = RLM_SCRIPT_ENV_LOCK
        .lock()
        .expect("rlm script env lock should not be poisoned");
    let script_path = write_temp_bridge_script(
        r#"#!/usr/bin/env python3
import json
import sys

start = json.loads(sys.stdin.readline())
if start.get("type") != "start":
    raise SystemExit("expected start")

sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 1}) + "\n")
sys.stdout.flush()

call_id = "call-fetch-rows"
sys.stdout.write(json.dumps({
    "type": "call_operator",
    "id": call_id,
    "depth": 0,
    "op_name": "fetch_rows",
    "params": {
        "view_id": "safe_customer_view_public",
        "filter_spec": {"customer_id": "cust_public_1"},
        "fields": ["status", "plan_tier"]
    }
}) + "\n")
sys.stdout.flush()

result = json.loads(sys.stdin.readline())
if result.get("type") != "operator_result" or result.get("id") != call_id:
    raise SystemExit("expected operator_result for fetch_rows")

sys.stdout.write(json.dumps({
    "type": "done",
    "final_answer": "UNKNOWN: insufficient evidence to answer the query."
}) + "\n")
sys.stdout.flush()
"#,
    );

    let previous_script_path = std::env::var("PECR_RLM_SCRIPT_PATH").ok();
    // Safety: this test scopes env var mutation to setup/teardown in the same thread.
    unsafe {
        std::env::set_var("PECR_RLM_SCRIPT_PATH", script_path.display().to_string());
    }

    let budget = Budget {
        max_operator_calls: 10,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: Some(2),
    };
    let (gateway_addr, shutdown, task) = spawn_run_gateway().await;
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::Rlm;

    let mut headers = HeaderMap::new();
    headers.insert("x-pecr-principal-id", HeaderValue::from_static("dev"));
    headers.insert("x-pecr-request-id", HeaderValue::from_static("req-rlm-run"));
    headers.insert("x-pecr-trace-id", HeaderValue::from_static("trace-rlm-run"));

    let response = run(
        State(state),
        headers,
        Json(RunRequest {
            query: "What is the customer status and plan tier?".to_string(),
            budget: Some(budget),
        }),
    )
    .await
    .expect("run should succeed");

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

    assert_eq!(response.0.terminal_mode, TerminalMode::Supported);
    assert!(
        response
            .0
            .claim_map
            .claims
            .iter()
            .any(|claim| claim.status == ClaimStatus::Supported
                && !claim.evidence_unit_ids.is_empty()),
        "finalize should convert the placeholder UNKNOWN into supported claims when evidence exists"
    );
    assert!(response.0.response_text.contains("SUPPORTED:"));
}

#[test]
fn run_request_rejects_unknown_fields() {
    let err = serde_json::from_value::<RunRequest>(serde_json::json!({
        "query": "smoke",
        "unexpected": true
    }))
    .expect_err("unknown fields should be rejected");

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn replay_store_errors_map_to_service_unavailable() {
    let err = map_replay_store_error(std::io::Error::other("disk offline"));

    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.1.0.code, "ERR_REPLAY_STORE");
    assert_eq!(err.1.0.terminal_mode_hint, TerminalMode::SourceUnavailable);
    assert!(err.1.0.retryable);
}

#[tokio::test]
async fn capabilities_endpoint_proxies_gateway_safe_ask_catalog() {
    let (gateway_addr, gateway_shutdown, gateway_task) = spawn_run_gateway().await;
    let state = controller_state(
        gateway_addr,
        Budget {
            max_operator_calls: 10,
            max_bytes: 1024,
            max_wallclock_ms: 1000,
            max_recursion_depth: 2,
            max_parallelism: Some(1),
        },
        crate::config::default_baseline_plan(),
    );
    let app = super::router(state.config.clone())
        .await
        .expect("controller router should initialize");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("controller listener should bind");
    let addr = listener
        .local_addr()
        .expect("controller local addr should be available");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v1/capabilities"))
        .header("x-pecr-principal-id", "dev")
        .send()
        .await
        .expect("request should succeed");
    let status = response.status();
    let payload = response
        .json::<SafeAskCatalog>()
        .await
        .expect("catalog should parse");

    shutdown_tx.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = server.await;
    let _ = gateway_task.await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(payload.capabilities.len(), 1);
    assert_eq!(payload.capabilities[0].capability_id, "structured_lookup");
    assert_eq!(
        payload.suggested_queries,
        vec!["What is the customer status and plan tier?".to_string()]
    );
}

#[test]
fn json_error_adds_actionable_permission_guidance() {
    let (_, Json(err)) = json_error(
        StatusCode::UNAUTHORIZED,
        "ERR_POLICY_DENIED",
        "denied".to_string(),
        TerminalMode::InsufficientPermission,
        false,
    );

    assert_eq!(
        err.what_failed.as_deref(),
        Some(
            "The current principal is not allowed to access the required session or evidence for this request."
        )
    );
    assert!(
        err.safe_alternative
            .as_deref()
            .is_some_and(|text| text.contains("narrow the request"))
    );
    assert_eq!(err.response_kind, Some(ClientResponseKind::Blocked));
}

#[test]
fn upstream_errors_receive_actionable_source_guidance_when_missing() {
    let err = with_actionable_guidance(ErrorResponse {
        code: "ERR_SOURCE_UNAVAILABLE".to_string(),
        message: "gateway unavailable".to_string(),
        terminal_mode_hint: TerminalMode::SourceUnavailable,
        retryable: true,
        response_kind: None,
        what_failed: None,
        safe_alternative: None,
        detail: None,
    });

    assert!(
        err.what_failed
            .as_deref()
            .is_some_and(|text| text.contains("upstream dependency"))
    );
    assert!(
        err.safe_alternative
            .as_deref()
            .is_some_and(|text| text.contains("Retry the same request"))
    );
    assert_eq!(err.response_kind, Some(ClientResponseKind::SourceDown));
}

#[test]
fn permission_guidance_sets_blocked_response_kind() {
    let (_, Json(err)) = json_error(
        StatusCode::FORBIDDEN,
        "ERR_POLICY_DENIED",
        "denied".to_string(),
        TerminalMode::InsufficientPermission,
        false,
    );

    assert_eq!(err.response_kind, Some(ClientResponseKind::Blocked));
}

#[test]
fn classify_run_response_kind_marks_partial_and_ambiguous_responses() {
    let partial_claim_map = ClaimMap {
        claim_map_id: "claim_map".to_string(),
        terminal_mode: TerminalMode::Supported,
        claims: Vec::new(),
        coverage_threshold: 0.95,
        coverage_observed: 1.0,
        clarification_prompt: None,
        notes: Some(
            "Partial answer: supported claims are grounded, but some requested details remain unresolved."
                .to_string(),
        ),
    };
    assert_eq!(
        classify_run_response_kind(
            TerminalMode::Supported,
            "SUPPORTED: refunds are available within 30 days.",
            &partial_claim_map,
        ),
        Some(ClientResponseKind::PartialAnswer)
    );

    let ambiguous_claim_map = ClaimMap {
        claim_map_id: "claim_map".to_string(),
        terminal_mode: TerminalMode::InsufficientEvidence,
        claims: Vec::new(),
        coverage_threshold: 0.95,
        coverage_observed: 0.0,
        clarification_prompt: Some(ClarificationPrompt {
            question: "Which field or filter should I use for the customer lookup".to_string(),
            options: vec!["customer status".to_string(), "plan tier".to_string()],
        }),
        notes: None,
    };
    assert_eq!(
        classify_run_response_kind(
            TerminalMode::InsufficientEvidence,
            "UNKNOWN: the structured lookup is underspecified. Narrow it to a specific field or filter. Safe scopes for the current principal: customer rows in safe_customer_view_public. Available safe views: `safe_customer_view_public`. Useful filters or fields: `customer_id`, `status`, `plan_tier`.",
            &ambiguous_claim_map,
        ),
        Some(ClientResponseKind::Ambiguous)
    );
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

    assert!(counter.load(Ordering::Relaxed) >= 1);
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

    assert!(counter.load(Ordering::Relaxed) >= 1);
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

    assert_eq!(counter.load(Ordering::Relaxed), 4);
    assert_eq!(result.operator_calls_used, 4);
    assert_eq!(result.depth_used, 5);
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

    assert_eq!(counter.load(Ordering::Relaxed), 4);
    assert_eq!(result.operator_calls_used, 4);
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

#[tokio::test]
async fn context_loop_prefers_structured_plan_for_status_queries() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_structured_plan",
        trace_id: "trace_structured_plan",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await
    .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(metrics.snapshot(), vec!["fetch_rows".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
}

#[tokio::test]
async fn context_loop_prefers_evidence_plan_for_source_queries() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_evidence_plan",
        trace_id: "trace_evidence_plan",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("public support text"))
    );
}

#[tokio::test]
async fn context_loop_prefers_version_plan_for_change_queries() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_version_plan",
        trace_id: "trace_version_plan",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What changed in the latest version of the support document?",
        &budget,
    )
    .await
    .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["list_versions".to_string(), "diff".to_string()]
    );
    assert_eq!(result.operator_calls_used, 2);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    let list_versions_params = metrics.params_for("list_versions");
    assert_eq!(list_versions_params.len(), 1);
    assert_eq!(
        list_versions_params[0]["object_id"],
        serde_json::json!("public/support_policy.txt")
    );
    let diff_params = metrics.params_for("diff");
    assert_eq!(diff_params.len(), 1);
    assert_eq!(
        diff_params[0],
        serde_json::json!({
            "object_id": "public/support_policy.txt",
            "v1": "1111111111111111111111111111111111111111111111111111111111111111",
            "v2": "9999999999999999999999999999999999999999999999999999999999999999"
        })
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("changed: added"))
    );
}

#[tokio::test]
async fn context_loop_prefers_compare_plan_for_compare_queries() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_compare_plan",
        trace_id: "trace_compare_plan",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Compare active customer counts by plan tier",
        &budget,
    )
    .await
    .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(metrics.snapshot(), vec!["compare".to_string()]);
    let compare_params = metrics.params_for("compare");
    assert_eq!(compare_params.len(), 1);
    assert_eq!(
        compare_params[0]["group_by"],
        serde_json::json!(["plan_tier"])
    );
    assert_eq!(
        compare_params[0]["metrics"],
        serde_json::json!([{ "name": "count", "field": "customer_id" }])
    );
    assert_eq!(
        compare_params[0]["filter_spec"],
        serde_json::json!({ "status": "active" })
    );
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("highest for plan_tier=starter"))
    );
}

#[tokio::test]
async fn context_loop_prefers_compare_time_series_for_trend_queries() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_trend_plan",
        trace_id: "trace_trend_plan",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show monthly customer trend over time",
        &budget,
    )
    .await
    .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(metrics.snapshot(), vec!["compare".to_string()]);
    let compare_params = metrics.params_for("compare");
    assert_eq!(compare_params.len(), 1);
    assert_eq!(
        compare_params[0]["time_granularity"],
        serde_json::json!("month")
    );
    assert_eq!(compare_params[0]["group_by"], serde_json::json!([]));
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
}

#[tokio::test]
async fn useful_query_scenarios_remain_supported() {
    let scenarios = [
        (
            "What is the customer status and plan tier?",
            vec!["fetch_rows".to_string()],
        ),
        (
            "Show the source text and evidence for the support policy",
            vec!["lookup_evidence".to_string()],
        ),
        (
            "What changed in the latest version of the support document?",
            vec!["list_versions".to_string(), "diff".to_string()],
        ),
        (
            "Show the source text for annual refund terms",
            vec!["lookup_evidence".to_string()],
        ),
        (
            "Show evidence for the billing terms policy",
            vec!["lookup_evidence".to_string()],
        ),
        (
            "Compare active customer counts by plan tier",
            vec!["compare".to_string()],
        ),
        (
            "Show monthly customer trend over time",
            vec!["compare".to_string()],
        ),
    ];

    for (index, (query, expected_calls)) in scenarios.into_iter().enumerate() {
        let metrics = PlannedGatewayMetrics::default();
        let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

        let budget = Budget {
            max_operator_calls: 100,
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
        let request_id = format!("req_useful_scenario_{index}");
        let trace_id = format!("trace_useful_scenario_{index}");
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: request_id.as_str(),
            trace_id: trace_id.as_str(),
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop(&state, ctx, query, &budget)
            .await
            .expect("context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(
            metrics.snapshot(),
            expected_calls,
            "scenario {query} should use the expected operator path"
        );
        assert_eq!(
            result.terminal_mode,
            TerminalMode::Supported,
            "scenario {query} should remain supported"
        );
        assert!(
            !result.evidence_units.is_empty(),
            "scenario {query} should produce evidence units"
        );
    }
}

#[tokio::test]
async fn decompose_query_clauses_splits_compare_and_evidence_request() {
    let clauses = decompose_query_clauses(
        "Compare active customer counts by plan tier and show the source text for the billing terms policy",
    );

    assert_eq!(clauses.len(), 2);
    assert_eq!(clauses[0], "Compare active customer counts by plan tier");
    assert_eq!(
        clauses[1],
        "show the source text for the billing terms policy"
    );
}

#[tokio::test]
async fn decompose_query_clauses_contextualizes_summary_and_citation_request() {
    let clauses = decompose_query_clauses("Summarize the billing terms and cite the source text");

    assert_eq!(clauses.len(), 2);
    assert_eq!(clauses[0], "Summarize the billing terms");
    assert_eq!(clauses[1], "cite the source text for billing terms");
}

#[tokio::test]
async fn context_loop_executes_multi_part_compare_and_evidence_subplans() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_multi_part_compare_evidence",
        trace_id: "trace_multi_part_compare_evidence",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Compare active customer counts by plan tier and show the source text for the billing terms policy",
        &budget,
    )
    .await
    .expect("context loop should decompose the multi-part ask");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["compare".to_string(), "lookup_evidence".to_string()]
    );
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.lines().count() >= 2),
        "multi-part query should recombine into a multi-line supported answer: {:?}",
        result.response_text
    );
}

#[tokio::test]
async fn context_loop_keeps_rust_owned_path_when_beam_shadow_planner_is_enabled() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;
    let (planner_addr, planner_shutdown, planner_task) = spawn_mock_planner(PlanResponse {
        schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
        steps: vec![PlannerStep::Operator {
            op_name: "fetch_rows".to_string(),
            params: serde_json::json!({
                "view_id": "safe_customer_view_public",
                "fields": ["status", "plan_tier"],
            }),
        }],
        planner_summary: Some("Use the direct structured lookup path.".to_string()),
    })
    .await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.planner_mode = crate::config::PlannerMode::Shadow;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_advisory",
        trace_id: "trace_beam_advisory",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should succeed with shadow planner");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert_eq!(result.planner_traces.len(), 2);
    assert!(
        result
            .planner_traces
            .iter()
            .any(
                |trace| trace.decision_summary.planner_source == "beam_shadow"
                    && !trace.decision_summary.selected_for_execution
                    && trace.decision_summary.stop_reason == "shadow_only"
            )
    );
}

#[tokio::test]
async fn context_loop_falls_back_cleanly_when_beam_shadow_plan_is_rejected() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;
    let (planner_addr, planner_shutdown, planner_task) =
        spawn_invalid_planner_response_server().await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.planner_mode = crate::config::PlannerMode::Shadow;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_rust_fallback",
        trace_id: "trace_beam_rust_fallback",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should fall back to rust-owned planning");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert_eq!(result.planner_traces.len(), 2);
    assert!(
        result
            .planner_traces
            .iter()
            .any(
                |trace| trace.decision_summary.planner_source == "beam_shadow"
                    && !trace.decision_summary.selected_for_execution
                    && trace.decision_summary.stop_reason == "operator_not_allowlisted"
            )
    );
}

#[tokio::test]
async fn context_loop_executes_beam_planner_path_when_beam_planner_engine_is_enabled() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;
    let (planner_addr, planner_shutdown, planner_task) = spawn_mock_planner(PlanResponse {
        schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
        steps: vec![PlannerStep::Operator {
            op_name: "fetch_rows".to_string(),
            params: serde_json::json!({
                "view_id": "safe_customer_view_public",
                "fields": ["status", "plan_tier"],
            }),
        }],
        planner_summary: Some("Prefer a direct structured lookup.".to_string()),
    })
    .await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::BeamPlanner;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_execution",
        trace_id: "trace_beam_execution",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await
    .expect("context loop should succeed with beam planner execution");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["fetch_rows".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert_eq!(result.planner_traces.len(), 2);
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_planner"
                && trace.decision_summary.selected_for_execution
                && trace.decision_summary.planner_summary.as_deref()
                    == Some("Prefer a direct structured lookup.")
                && trace
                    .decision_summary
                    .expected_usefulness_score
                    .is_some_and(|score| score >= 0.8)
        }),
        "beam planner trace should be selected for execution"
    );
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "rust_owned"
                && !trace.decision_summary.selected_for_execution
                && trace.decision_summary.stop_reason == "retained_as_runtime_fallback"
        }),
        "rust-owned baseline path should remain visible as fallback"
    );
}

#[tokio::test]
async fn context_loop_prefers_rust_owned_path_when_beam_plan_has_lower_expected_usefulness() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;
    let (planner_addr, planner_shutdown, planner_task) = spawn_mock_planner(PlanResponse {
        schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
        steps: vec![PlannerStep::Operator {
            op_name: "fetch_rows".to_string(),
            params: serde_json::json!({
                "view_id": "safe_customer_view_public",
                "fields": ["status", "plan_tier"],
            }),
        }],
        planner_summary: Some("Prefer a direct structured lookup.".to_string()),
    })
    .await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::BeamPlanner;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_usefulness_guard",
        trace_id: "trace_beam_usefulness_guard",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should keep the more useful rust-owned plan");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "rust_owned"
                && trace.decision_summary.selected_for_execution
                && trace
                    .decision_summary
                    .selection_rationale
                    .as_deref()
                    .is_some_and(|reason| reason.contains("expected usefulness"))
        }),
        "rust-owned trace should explain why it remained selected"
    );
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_planner"
                && !trace.decision_summary.selected_for_execution
                && trace.decision_summary.stop_reason == "lower_expected_usefulness_than_rust_owned"
        }),
        "beam planner trace should remain replay-visible with a lower-usefulness reason"
    );
}

#[tokio::test]
async fn context_loop_falls_back_to_rust_owned_path_when_beam_planner_plan_is_rejected() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;
    let (planner_addr, planner_shutdown, planner_task) =
        spawn_invalid_planner_response_server().await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::BeamPlanner;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_rejected",
        trace_id: "trace_beam_rejected",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should fall back to rust-owned execution");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_planner"
                && !trace.decision_summary.selected_for_execution
                && trace.decision_summary.stop_reason == "operator_not_allowlisted"
        }),
        "rejected beam plan should remain visible in replay traces"
    );
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "rust_owned"
                && trace.decision_summary.selected_for_execution
        }),
        "rust-owned fallback should execute"
    );
}

#[tokio::test]
async fn context_loop_falls_back_to_rust_owned_path_when_beam_planner_is_unavailable() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) =
        spawn_planned_gateway(metrics.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::BeamPlanner;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some("http://127.0.0.1:9/plan".to_string());

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_unavailable",
        trace_id: "trace_beam_unavailable",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "Show the source text and evidence for the support policy",
        &budget,
    )
    .await
    .expect("context loop should fall back when beam planner is unavailable");

    gateway_shutdown.send(()).ok();
    let _ = gateway_task.await;

    assert_eq!(metrics.snapshot(), vec!["lookup_evidence".to_string()]);
    assert_eq!(result.operator_calls_used, 1);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_planner"
                && !trace.decision_summary.selected_for_execution
                && trace
                    .decision_summary
                    .stop_reason
                    .starts_with("ERR_PLANNER_CLIENT_")
        }),
        "planner unavailability should be visible in replay traces"
    );
}

#[tokio::test]
async fn context_loop_records_beam_recovery_trace_when_beam_planner_recovers_from_source_failure() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, gateway_shutdown, gateway_task) = spawn_planned_gateway_with_failures(
        metrics.clone(),
        std::collections::HashMap::from([(
            "fetch_rows".to_string(),
            TerminalMode::SourceUnavailable,
        )]),
    )
    .await;
    let (planner_addr, planner_shutdown, planner_task) = spawn_recovery_mock_planner(
        PlanResponse {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            steps: vec![PlannerStep::Operator {
                op_name: "fetch_rows".to_string(),
                params: serde_json::json!({
                    "view_id": "safe_customer_view_public",
                    "fields": ["status", "plan_tier"],
                }),
            }],
            planner_summary: Some("Try the direct structured lookup first.".to_string()),
        },
        PlanResponse {
            schema_version: PLANNER_CONTRACT_SCHEMA_VERSION,
            steps: vec![PlannerStep::Operator {
                op_name: "lookup_evidence".to_string(),
                params: serde_json::json!({}),
            }],
            planner_summary: Some(
                "Recover through lookup_evidence after fetch_rows failed.".to_string(),
            ),
        },
    )
    .await;

    let budget = Budget {
        max_operator_calls: 100,
        max_bytes: 1024 * 1024,
        max_wallclock_ms: 10_000,
        max_recursion_depth: 10,
        max_parallelism: None,
    };
    let mut state = controller_state(
        gateway_addr,
        budget.clone(),
        crate::config::default_baseline_plan(),
    );
    state.config.controller_engine = crate::config::ControllerEngine::BeamPlanner;
    state.config.planner_client = crate::config::PlannerClientKind::Beam;
    state.config.planner_client_url = Some(format!("http://{planner_addr}/plan"));

    let ctx = GatewayCallContext {
        principal_id: "dev",
        authz_header: None,
        local_auth_shared_secret: None,
        request_id: "req_beam_recovery",
        trace_id: "trace_beam_recovery",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await
    .expect("context loop should recover through the beam recovery planner");

    planner_shutdown.send(()).ok();
    gateway_shutdown.send(()).ok();
    let _ = planner_task.await;
    let _ = gateway_task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["fetch_rows".to_string(), "lookup_evidence".to_string()]
    );
    assert_eq!(result.operator_calls_used, 2);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_recovery"
                && trace.decision_summary.selected_for_execution
                && trace.decision_summary.used_fallback_plan
                && trace.decision_summary.fallback_from_step.as_deref() == Some("fetch_rows")
                && trace
                    .plan_request
                    .recovery_context
                    .as_ref()
                    .is_some_and(|recovery| {
                        recovery.failed_step == "fetch_rows"
                            && recovery.failure_terminal_mode == TerminalMode::SourceUnavailable
                    })
        }),
        "beam recovery plan should remain replay-visible"
    );
    assert!(
        result.planner_traces.iter().any(|trace| {
            trace.decision_summary.planner_source == "beam_planner"
                && !trace.decision_summary.selected_for_execution
                && trace.decision_summary.stop_reason == "recovered_by_beam_worker"
        }),
        "original beam plan should show handoff to the recovery worker"
    );
}

#[tokio::test]
async fn context_loop_falls_back_from_structured_lookup_to_search_on_source_failure() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway_with_failures(
        metrics.clone(),
        std::collections::HashMap::from([(
            "fetch_rows".to_string(),
            TerminalMode::SourceUnavailable,
        )]),
    )
    .await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_fallback_source",
        trace_id: "trace_fallback_source",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await
    .expect("context loop should recover with fallback");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["fetch_rows".to_string(), "lookup_evidence".to_string()]
    );
    assert_eq!(result.operator_calls_used, 2);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(!result.evidence_units.is_empty());
}

#[tokio::test]
async fn context_loop_falls_back_from_structured_lookup_to_search_on_permission_failure() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway_with_failures(
        metrics.clone(),
        std::collections::HashMap::from([(
            "fetch_rows".to_string(),
            TerminalMode::InsufficientPermission,
        )]),
    )
    .await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_fallback_permission",
        trace_id: "trace_fallback_permission",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await
    .expect("context loop should recover through another safe path");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["fetch_rows".to_string(), "lookup_evidence".to_string()]
    );
    assert_eq!(result.operator_calls_used, 2);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(!result.evidence_units.is_empty());
}

#[tokio::test]
async fn context_loop_falls_back_from_version_review_to_evidence_lookup() {
    let metrics = PlannedGatewayMetrics::default();
    let (gateway_addr, shutdown, task) = spawn_planned_gateway_with_failures(
        metrics.clone(),
        std::collections::HashMap::from([(
            "list_versions".to_string(),
            TerminalMode::SourceUnavailable,
        )]),
    )
    .await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_fallback_version",
        trace_id: "trace_fallback_version",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(
        &state,
        ctx,
        "What changed in the latest version of the support document?",
        &budget,
    )
    .await
    .expect("context loop should recover with evidence fallback");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(
        metrics.snapshot(),
        vec!["list_versions".to_string(), "lookup_evidence".to_string()]
    );
    assert_eq!(result.operator_calls_used, 2);
    assert_eq!(result.terminal_mode, TerminalMode::Supported);
    assert!(!result.evidence_units.is_empty());
}

#[cfg(feature = "rlm")]
#[tokio::test]
async fn rlm_loop_uses_task_aware_operator_paths_for_useful_queries() {
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

    let scenarios = [
        (
            "What is the customer status and plan tier?",
            vec!["fetch_rows".to_string()],
        ),
        (
            "Show the source text and evidence for the support policy",
            vec!["lookup_evidence".to_string()],
        ),
        (
            "What changed in the latest version of the support document?",
            vec![
                "list_versions".to_string(),
                "diff".to_string(),
                "search".to_string(),
                "fetch_span".to_string(),
            ],
        ),
        (
            "Compare active customer counts by plan tier",
            vec!["compare".to_string()],
        ),
        (
            "Show monthly customer trend over time",
            vec!["compare".to_string()],
        ),
    ];

    for (index, (query, expected_calls)) in scenarios.into_iter().enumerate() {
        let metrics = PlannedGatewayMetrics::default();
        let (gateway_addr, shutdown, task) = spawn_planned_gateway(metrics.clone()).await;

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
        let request_id = format!("req_rlm_useful_scenario_{index}");
        let trace_id = format!("trace_rlm_useful_scenario_{index}");
        let ctx = GatewayCallContext {
            principal_id: "dev",
            authz_header: None,
            local_auth_shared_secret: None,
            request_id: request_id.as_str(),
            trace_id: trace_id.as_str(),
            session_token: "token",
            session_id: "session",
        };
        let result = run_context_loop_rlm(&state, ctx, query, &budget)
            .await
            .expect("rlm context loop should succeed");

        shutdown.send(()).ok();
        let _ = task.await;

        assert_eq!(
            metrics.snapshot(),
            expected_calls,
            "scenario {query} should use the expected rlm operator path"
        );
        assert_eq!(
            result.terminal_mode,
            TerminalMode::Supported,
            "scenario {query} should remain supported in rlm mode"
        );
        assert!(
            !result.evidence_units.is_empty(),
            "scenario {query} should produce evidence units in rlm mode"
        );
    }

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
}

#[cfg(feature = "rlm")]
#[tokio::test]
async fn rlm_loop_start_message_includes_typed_plan_request() {
    let _env_lock = RLM_SCRIPT_ENV_LOCK
        .lock()
        .expect("rlm script env lock should not be poisoned");
    let script_path = write_temp_bridge_script(
        r#"#!/usr/bin/env python3
import json
import sys

start = json.loads(sys.stdin.readline())
plan_request = start.get("plan_request")
if not isinstance(plan_request, dict):
    raise SystemExit("missing plan_request")
if plan_request.get("schema_version") != 1:
    raise SystemExit("unexpected plan_request schema version")
if plan_request.get("query") != "What is the customer status and plan tier?":
    raise SystemExit("unexpected query")
if plan_request.get("budget") != start.get("budget"):
    raise SystemExit("budget mismatch")
if plan_request.get("planner_hints") != start.get("planner_hints"):
    raise SystemExit("planner hints mismatch")
if plan_request.get("allow_search_ref_fetch_span") is not True:
    raise SystemExit("search_ref_fetch_span should be allowed")
operator_names = plan_request.get("available_operator_names")
if not isinstance(operator_names, list) or "fetch_rows" not in operator_names or "lookup_evidence" not in operator_names:
    raise SystemExit("missing advertised operator names")
planner_hints = plan_request.get("planner_hints")
if planner_hints.get("intent") != "structured_lookup":
    raise SystemExit("unexpected planner intent")
recommended_path = planner_hints.get("recommended_path")
if not isinstance(recommended_path, list) or not recommended_path:
    raise SystemExit("missing recommended path")
first_step = recommended_path[0]
if first_step.get("kind") != "operator" or first_step.get("op_name") != "fetch_rows":
    raise SystemExit("unexpected first planner step")

sys.stdout.write(json.dumps({"type": "start_ack", "protocol_version": 1}) + "\n")
sys.stdout.flush()
sys.stdout.write(json.dumps({"type": "done", "final_answer": "UNKNOWN: plan request captured"}) + "\n")
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
        request_id: "req_test_rlm_plan_request",
        trace_id: "trace_test_rlm_plan_request",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop_rlm(
        &state,
        ctx,
        "What is the customer status and plan tier?",
        &budget,
    )
    .await;

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
    assert_eq!(
        result.response_text.as_deref(),
        Some("UNKNOWN: plan request captured")
    );
    assert_eq!(result.operator_calls_used, 0);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn context_loop_returns_structured_narrowing_guidance_for_broad_query() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_broad_structured",
        trace_id: "trace_broad_structured",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(&state, ctx, "customer", &budget)
        .await
        .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert_eq!(result.terminal_mode, TerminalMode::InsufficientEvidence);
    assert!(result.response_text.as_deref().is_some_and(|text| {
        text.contains("Which field or filter should I use for the customer lookup")
    }));
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("safe_customer_view_public"))
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("Useful filters or fields"))
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("`status`"))
    );
}

#[tokio::test]
async fn context_loop_returns_evidence_narrowing_guidance_for_broad_policy_query() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (gateway_addr, shutdown, task) = spawn_mock_gateway(counter.clone()).await;

    let budget = Budget {
        max_operator_calls: 100,
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
        request_id: "req_broad_evidence",
        trace_id: "trace_broad_evidence",
        session_token: "token",
        session_id: "session",
    };
    let result = run_context_loop(&state, ctx, "policy", &budget)
        .await
        .expect("context loop should succeed");

    shutdown.send(()).ok();
    let _ = task.await;

    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert_eq!(result.terminal_mode, TerminalMode::InsufficientEvidence);
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("Which document or policy should I quote or cite"))
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("public documents under public/"))
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("Safe document scopes"))
    );
    assert!(
        result
            .response_text
            .as_deref()
            .is_some_and(|text| text.contains("policy documents"))
    );
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
