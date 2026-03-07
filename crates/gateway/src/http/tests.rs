use super::*;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::sync::OnceLock;

use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, ClientResponseKind, EvidenceContentType, EvidenceUnit, PlannerIntent,
    SafeAskCapability, SafeAskCatalog, TerminalMode,
};

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
        as_of_time: "1970-01-01T00:00:00Z".to_string(),
        budget,
        session_token_hash: sha256_hex("token".as_bytes()),
        session_token_expires_at_epoch_ms: unix_epoch_ms_now() + 60_000,
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
        clarification_prompt: None,
        notes: None,
    }
}

#[test]
fn gateway_http_shapes_match_contract_manifest() {
    let budget = Budget {
        max_operator_calls: 10,
        max_bytes: 1024,
        max_wallclock_ms: 1000,
        max_recursion_depth: 1,
        max_parallelism: None,
    };
    let claim_map = make_claim_map(Vec::new(), TerminalMode::InsufficientEvidence);
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

    assert_contract_shape(
        "gateway.CreateSessionRequest",
        &serde_json::to_value(super::session_api::CreateSessionRequest {
            budget: budget.clone(),
            as_of_time: Some("1970-01-01T00:00:00Z".to_string()),
        })
        .expect("create session request should serialize"),
    );
    assert_contract_shape(
        "gateway.CreateSessionResponse",
        &serde_json::to_value(super::session_api::CreateSessionResponse {
            session_id: "sess".to_string(),
            trace_id: "trace".to_string(),
            policy_snapshot_id: "policy".to_string(),
            budget: budget.clone(),
        })
        .expect("create session response should serialize"),
    );
    assert_contract_shape(
        "gateway.PolicySimulateRequest",
        &serde_json::to_value(super::policy_api::PolicySimulateRequest {
            action: "search".to_string(),
            params: serde_json::Map::from_iter([("query".to_string(), serde_json::json!("alpha"))]),
            policy_snapshot_hash: Some("a".repeat(64)),
            policy_bundle_hash: Some("b".repeat(64)),
            as_of_time: Some("1970-01-01T00:00:00Z".to_string()),
        })
        .expect("policy request should serialize"),
    );
    assert_contract_shape(
        "gateway.PolicySimulateResponse",
        &serde_json::to_value(super::policy_api::PolicySimulateResponse {
            allow: true,
            cacheable: true,
            reason: Some("policy_allow".to_string()),
            redaction: Some(serde_json::json!({"allow_fields": ["name"]})),
            narrowing: Some(serde_json::json!({
                "scope_labels": ["public documents under public/"],
                "source_scopes": ["public/"],
                "document_hints": ["policy documents", "versioned documents"],
                "examples": ["Show the source text for the support policy in public documents."]
            })),
        })
        .expect("policy response should serialize"),
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
        "gateway.SafeAskCatalogResponse",
        &serde_json::to_value(safe_ask_catalog).expect("safe ask response should serialize"),
    );
    assert_contract_shape(
        "gateway.OperatorCallRequest",
        &serde_json::to_value(super::operator_api::OperatorCallRequest {
            session_id: "sess".to_string(),
            params: serde_json::json!({"query": "alpha"}),
        })
        .expect("operator request should serialize"),
    );
    assert_contract_shape(
        "gateway.OperatorCallResponse",
        &serde_json::to_value(super::operator_api::OperatorCallResponse {
            terminal_mode: TerminalMode::Supported,
            result: serde_json::json!({"refs": []}),
            result_summary: Some("0 matching evidence refs".to_string()),
            policy_decision: Some(serde_json::json!({"allow": true, "cacheable": true})),
        })
        .expect("operator response should serialize"),
    );
    assert_contract_shape(
        "gateway.FinalizeRequest",
        &serde_json::to_value(super::finalize::FinalizeRequest {
            session_id: "sess".to_string(),
            response_text: "finalized".to_string(),
            claim_map: claim_map.clone(),
        })
        .expect("finalize request should serialize"),
    );
    assert_contract_shape(
        "gateway.FinalizeResponse",
        &serde_json::to_value(super::finalize::FinalizeResponse {
            terminal_mode: TerminalMode::InsufficientEvidence,
            trace_id: "trace".to_string(),
            claim_map,
            response_text: "finalized".to_string(),
        })
        .expect("finalize response should serialize"),
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

#[test]
fn finalize_gate_rejects_unknown_evidence_unit_ids() {
    let emitted = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let missing = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

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
            evidence_snippets: Vec::new(),
        }],
        TerminalMode::Supported,
    );

    let err = finalize_gate(&session, claim_map, 0.95).unwrap_err();
    assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(err.error_response().code, "ERR_INVALID_PARAMS");
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
            evidence_snippets: Vec::new(),
        }],
        TerminalMode::Supported,
    );

    let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
    assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
    assert_eq!(out.coverage_observed, 0.0);
    assert_eq!(out.claims.len(), 1);

    let claim = &out.claims[0];
    assert_eq!(claim.status, ClaimStatus::Unknown);
    assert!(claim.evidence_unit_ids.is_empty());
    assert!(canonical::is_sha256_hex(&claim.claim_id));
}

#[test]
fn finalize_gate_allows_supported_claims_with_emitted_evidence() {
    let emitted = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

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
            evidence_snippets: Vec::new(),
        }],
        TerminalMode::Supported,
    );

    let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
    assert_eq!(out.terminal_mode, TerminalMode::Supported);
    assert_eq!(out.coverage_observed, 1.0);
    assert_eq!(out.claims.len(), 1);
    assert_eq!(out.claims[0].status, ClaimStatus::Supported);
    assert!(canonical::is_sha256_hex(&out.claims[0].claim_id));
}

#[test]
fn finalize_gate_budget_violation_forces_insufficient_evidence() {
    let emitted = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

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
            evidence_snippets: Vec::new(),
        }],
        TerminalMode::Supported,
    );

    let out = finalize_gate(&session, claim_map, 0.95).expect("gate should succeed");
    assert_eq!(out.terminal_mode, TerminalMode::InsufficientEvidence);
}

#[test]
fn field_redaction_parse_allows_and_denies() {
    let allow = parse_field_redaction(Some(&serde_json::json!({
        "allow_fields": ["b", "a", "a"]
    })))
    .expect("allow parse should succeed")
    .expect("allow spec should exist");

    assert!(matches!(
        allow,
        FieldRedaction::Allow(fields) if fields == vec!["a".to_string(), "b".to_string()]
    ));

    let deny = parse_field_redaction(Some(&serde_json::json!({
        "deny_fields": ["secret"]
    })))
    .expect("deny parse should succeed")
    .expect("deny spec should exist");

    assert!(matches!(
        deny,
        FieldRedaction::Deny(fields) if fields == vec!["secret".to_string()]
    ));
}

#[test]
fn field_redaction_applies_recursively() {
    let redaction = FieldRedaction::Deny(vec!["secret".to_string()]);
    let input = serde_json::json!({
        "ok": 1,
        "secret": "top",
        "nested": {
            "secret": "hidden",
            "keep": true
        },
        "arr": [
            {"secret": "x", "keep": 1},
            {"keep": 2}
        ]
    });

    let out = apply_field_redaction(&input, &redaction);
    assert_eq!(
        out,
        serde_json::json!({
            "ok": 1,
            "nested": { "keep": true },
            "arr": [
                {"keep": 1},
                {"keep": 2}
            ]
        })
    );
}

#[test]
fn evidence_unit_redaction_updates_hashes_and_ids() {
    let content = serde_json::json!({
        "ok": "1",
        "secret": "x",
    });

    let mut evidence = EvidenceUnit {
        source_system: "pg_safeview".to_string(),
        object_id: "obj".to_string(),
        version_id: "v1".to_string(),
        span_or_row_spec: serde_json::json!({
            "type": "db_row",
            "fields": ["ok", "secret"],
        }),
        content_type: EvidenceContentType::ApplicationJson,
        content: Some(content),
        content_hash: canonical::hash_canonical_json(&serde_json::json!({
            "ok": "1",
            "secret": "x",
        })),
        retrieved_at: "t".to_string(),
        as_of_time: "t".to_string(),
        policy_snapshot_id: "p".to_string(),
        policy_snapshot_hash: "h".to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id: String::new(),
    };
    evidence.evidence_unit_id = compute_evidence_unit_id(&evidence);
    let original_id = evidence.evidence_unit_id.clone();

    let redaction = FieldRedaction::Deny(vec!["secret".to_string()]);
    let redacted =
        apply_field_redaction_to_evidence_unit(evidence, &redaction).expect("redaction ok");

    let out_content = redacted.content.as_ref().expect("content preserved");
    assert_eq!(out_content, &serde_json::json!({ "ok": "1" }));
    assert_eq!(
        redacted.content_hash,
        canonical::hash_canonical_json(out_content)
    );
    assert_ne!(redacted.evidence_unit_id, original_id);
    assert_eq!(redacted.transform_chain.len(), 1);

    let fields = redacted
        .span_or_row_spec
        .get("fields")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(fields, vec![serde_json::Value::String("ok".to_string())]);
}

#[test]
fn safeview_schema_missing_columns_are_detected() {
    let spec = safeview_spec("safe_customer_view_public").expect("spec must exist");
    let available = BTreeSet::from([
        "tenant_id".to_string(),
        "customer_id".to_string(),
        "status".to_string(),
        "plan_tier".to_string(),
    ]);

    let missing = missing_safeview_columns(spec, &available);
    assert!(missing.contains(&"updated_at".to_string()));
}

#[test]
fn safeview_schema_complete_columns_pass() {
    let spec = safeview_spec("safe_customer_view_public").expect("spec must exist");
    let available = BTreeSet::from([
        "tenant_id".to_string(),
        "customer_id".to_string(),
        "status".to_string(),
        "plan_tier".to_string(),
        "updated_at".to_string(),
    ]);

    let missing = missing_safeview_columns(spec, &available);
    assert!(missing.is_empty());
}
