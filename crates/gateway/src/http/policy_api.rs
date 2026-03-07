use std::collections::BTreeSet;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use pecr_contracts::{PlannerIntent, SafeAskCapability, SafeAskCatalog, TerminalMode, canonical};
use serde::{Deserialize, Serialize};

use super::auth::{
    extract_principal, extract_request_id, parse_optional_sha256_hash, sanitize_as_of_time,
};
use super::runtime::safeview_narrowing_hints;
use super::{ApiError, AppState, json_error};
use crate::opa::OpaCacheKey;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicySimulateRequest {
    pub(super) action: String,
    pub(super) params: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub(super) policy_snapshot_hash: Option<String>,
    #[serde(default)]
    pub(super) policy_bundle_hash: Option<String>,
    #[serde(default)]
    pub(super) as_of_time: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PolicySimulateResponse {
    pub(super) allow: bool,
    pub(super) cacheable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) redaction: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) narrowing: Option<serde_json::Value>,
}

struct PolicyRequestInput {
    principal_id: String,
    request_id: String,
    action: String,
    request_params: serde_json::Map<String, serde_json::Value>,
    policy_snapshot_hash: Option<String>,
    policy_bundle_hash: Option<String>,
    as_of_time: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct SafeAskCapabilitySpec {
    capability_id: &'static str,
    intent: PlannerIntent,
    title: &'static str,
    description: &'static str,
}

const SAFE_ASK_CAPABILITY_SPECS: &[SafeAskCapabilitySpec] = &[
    SafeAskCapabilitySpec {
        capability_id: "structured_lookup",
        intent: PlannerIntent::StructuredLookup,
        title: "Look up customer fields",
        description: "Use safe structured views to answer direct field questions like status, plan tier, or specific customer rows.",
    },
    SafeAskCapabilitySpec {
        capability_id: "structured_aggregation",
        intent: PlannerIntent::StructuredAggregation,
        title: "Compare counts and trends",
        description: "Ask for grouped counts, comparisons, or simple trends over safe structured data.",
    },
    SafeAskCapabilitySpec {
        capability_id: "evidence_lookup",
        intent: PlannerIntent::EvidenceLookup,
        title: "Quote or cite source text",
        description: "Ask for grounded snippets from allowed documents instead of relying on paraphrase or guesswork.",
    },
    SafeAskCapabilitySpec {
        capability_id: "version_review",
        intent: PlannerIntent::VersionReview,
        title: "Review what changed",
        description: "Ask what changed between versions of an allowed document or object and get a concrete delta summary.",
    },
];

fn policy_narrowing_string_list(
    narrowing: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
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

fn write_policy_narrowing_string_list(
    out: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    values: &[String],
) {
    if values.is_empty() {
        return;
    }

    out.insert(
        key.to_string(),
        serde_json::Value::Array(
            values
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
}

fn normalize_policy_narrowing(
    params: &serde_json::Map<String, serde_json::Value>,
    narrowing: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let serde_json::Value::Object(input) = narrowing? else {
        return None;
    };

    let known_keys = [
        "scope_labels",
        "examples",
        "view_ids",
        "field_labels",
        "dimension_labels",
        "source_scopes",
        "document_hints",
    ];

    let mut out = serde_json::Map::new();
    for (key, value) in &input {
        if !known_keys.contains(&key.as_str()) {
            out.insert(key.clone(), value.clone());
        }
    }

    let scope_labels = policy_narrowing_string_list(&input, "scope_labels");
    let examples = policy_narrowing_string_list(&input, "examples");
    let view_ids = policy_narrowing_string_list(&input, "view_ids");
    let source_scopes = policy_narrowing_string_list(&input, "source_scopes");
    let mut field_labels = policy_narrowing_string_list(&input, "field_labels");
    let mut dimension_labels = policy_narrowing_string_list(&input, "dimension_labels");
    let document_hints = policy_narrowing_string_list(&input, "document_hints");

    let mut field_seen = field_labels
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut dimension_seen = dimension_labels
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    for view_id in &view_ids {
        let Some(hints) = safeview_narrowing_hints(view_id) else {
            continue;
        };

        for field in hints.field_labels {
            let lowered = field.to_ascii_lowercase();
            if field_seen.insert(lowered) {
                field_labels.push(field.to_string());
            }
        }
        for dimension in hints.dimension_labels {
            let lowered = dimension.to_ascii_lowercase();
            if dimension_seen.insert(lowered) {
                dimension_labels.push(dimension.to_string());
            }
        }
    }

    if document_hints.is_empty()
        && matches!(
            params
                .get("intent")
                .and_then(|value| value.as_str())
                .map(str::trim),
            Some("evidence_lookup" | "version_review" | "structured_version_review")
        )
        && !source_scopes.is_empty()
    {
        write_policy_narrowing_string_list(
            &mut out,
            "document_hints",
            &[
                "policy documents".to_string(),
                "versioned documents".to_string(),
            ],
        );
    } else {
        write_policy_narrowing_string_list(&mut out, "document_hints", &document_hints);
    }

    write_policy_narrowing_string_list(&mut out, "scope_labels", &scope_labels);
    write_policy_narrowing_string_list(&mut out, "view_ids", &view_ids);
    write_policy_narrowing_string_list(&mut out, "field_labels", &field_labels);
    write_policy_narrowing_string_list(&mut out, "dimension_labels", &dimension_labels);
    write_policy_narrowing_string_list(&mut out, "source_scopes", &source_scopes);
    write_policy_narrowing_string_list(&mut out, "examples", &examples);

    Some(serde_json::Value::Object(out))
}

fn safe_ask_capability_from_narrowing(
    spec: SafeAskCapabilitySpec,
    narrowing: Option<serde_json::Value>,
) -> Option<SafeAskCapability> {
    let serde_json::Value::Object(narrowing) = narrowing? else {
        return None;
    };

    Some(SafeAskCapability {
        capability_id: spec.capability_id.to_string(),
        intent: spec.intent,
        title: spec.title.to_string(),
        description: spec.description.to_string(),
        examples: policy_narrowing_string_list(&narrowing, "examples"),
        scope_labels: policy_narrowing_string_list(&narrowing, "scope_labels"),
        view_ids: policy_narrowing_string_list(&narrowing, "view_ids"),
        field_labels: policy_narrowing_string_list(&narrowing, "field_labels"),
        dimension_labels: policy_narrowing_string_list(&narrowing, "dimension_labels"),
        source_scopes: policy_narrowing_string_list(&narrowing, "source_scopes"),
        document_hints: policy_narrowing_string_list(&narrowing, "document_hints"),
    })
}

fn safe_ask_catalog(capabilities: Vec<SafeAskCapability>) -> SafeAskCatalog {
    let mut seen_queries = BTreeSet::new();
    let mut suggested_queries = Vec::new();
    for capability in &capabilities {
        for example in &capability.examples {
            let lowered = example.to_ascii_lowercase();
            if seen_queries.insert(lowered) {
                suggested_queries.push(example.clone());
            }
        }
    }

    SafeAskCatalog {
        capabilities,
        suggested_queries,
    }
}

async fn evaluate_policy_request(
    state: &AppState,
    request: PolicyRequestInput,
) -> Result<PolicySimulateResponse, ApiError> {
    let PolicyRequestInput {
        principal_id,
        request_id,
        action,
        request_params,
        policy_snapshot_hash,
        policy_bundle_hash,
        as_of_time,
    } = request;
    let params_value = serde_json::Value::Object(request_params.clone());
    let params_hash = canonical::hash_canonical_json(&params_value);

    let mut opa_input = serde_json::Map::new();
    opa_input.insert(
        "action".to_string(),
        serde_json::Value::String(action.to_string()),
    );
    opa_input.insert(
        "principal_id".to_string(),
        serde_json::Value::String(principal_id.to_string()),
    );
    opa_input.insert(
        "request_id".to_string(),
        serde_json::Value::String(request_id.to_string()),
    );
    opa_input.insert("params".to_string(), params_value);

    if let Some(hash) = policy_snapshot_hash.as_ref() {
        opa_input.insert(
            "policy_snapshot_hash".to_string(),
            serde_json::Value::String(hash.clone()),
        );
    }
    if let Some(hash) = policy_bundle_hash.as_ref() {
        opa_input.insert(
            "policy_bundle_hash".to_string(),
            serde_json::Value::String(hash.clone()),
        );
    }
    if let Some(value) = as_of_time.as_ref() {
        opa_input.insert(
            "as_of_time".to_string(),
            serde_json::Value::String(value.clone()),
        );
    }

    for (key, value) in &request_params {
        if key == "params" || opa_input.contains_key(key.as_str()) {
            continue;
        }
        opa_input.insert(key.clone(), value.clone());
    }

    let cache_key = OpaCacheKey::policy_simulation(
        principal_id.as_str(),
        action.as_str(),
        params_hash.as_str(),
        policy_snapshot_hash.as_deref(),
        policy_bundle_hash.as_deref(),
        as_of_time.as_deref(),
    );
    let decision = state
        .opa
        .decide(serde_json::Value::Object(opa_input), Some(cache_key))
        .await
        .map_err(|err| super::opa_error_response(&err))?;

    Ok(PolicySimulateResponse {
        allow: decision.allow,
        cacheable: decision.cacheable,
        reason: decision.reason,
        redaction: decision.redaction,
        narrowing: normalize_policy_narrowing(&request_params, decision.narrowing),
    })
}

pub(super) async fn simulate_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Result<Json<PolicySimulateRequest>, JsonRejection>,
) -> Result<Json<PolicySimulateResponse>, ApiError> {
    let started = Instant::now();
    let result = async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id.clone();
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

        let action = req.action.trim();
        if action.is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "action must be a non-empty string".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        let policy_snapshot_hash = parse_optional_sha256_hash(
            req.policy_snapshot_hash.as_deref(),
            "policy_snapshot_hash",
        )?;
        let policy_bundle_hash =
            parse_optional_sha256_hash(req.policy_bundle_hash.as_deref(), "policy_bundle_hash")?
                .or_else(|| Some(state.config.policy_bundle_hash.clone()));
        let as_of_time = match req
            .as_of_time
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(raw) => Some(sanitize_as_of_time(raw).ok_or_else(|| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    "as_of_time must be RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ)".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?),
            None => Some(state.config.as_of_time_default.clone()),
        };

        let request_params = req.params.clone();
        Ok(Json(
            evaluate_policy_request(
                &state,
                PolicyRequestInput {
                    principal_id,
                    request_id,
                    action: action.to_string(),
                    request_params,
                    policy_snapshot_hash,
                    policy_bundle_hash,
                    as_of_time,
                },
            )
            .await?,
        ))
    }
    .await;

    let status = match &result {
        Ok(_) => StatusCode::OK,
        Err(err) => err.status_code(),
    };
    crate::metrics::observe_http_request(
        "/v1/policies/simulate",
        "POST",
        status.as_u16(),
        started.elapsed(),
    );

    result
}

pub(super) async fn policy_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SafeAskCatalog>, ApiError> {
    let started = Instant::now();
    let result: Result<Json<SafeAskCatalog>, ApiError> = async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id;
        let request_id = extract_request_id(&headers);
        let mut capabilities = Vec::new();

        for spec in SAFE_ASK_CAPABILITY_SPECS {
            let params = serde_json::Map::from_iter([(
                "intent".to_string(),
                serde_json::json!(spec.intent.as_str()),
            )]);
            let response = evaluate_policy_request(
                &state,
                PolicyRequestInput {
                    principal_id: principal_id.clone(),
                    request_id: request_id.clone(),
                    action: "narrow_query".to_string(),
                    request_params: params,
                    policy_snapshot_hash: None,
                    policy_bundle_hash: Some(state.config.policy_bundle_hash.clone()),
                    as_of_time: Some(state.config.as_of_time_default.clone()),
                },
            )
            .await?;

            if response.allow
                && let Some(capability) =
                    safe_ask_capability_from_narrowing(*spec, response.narrowing)
            {
                capabilities.push(capability);
            }
        }

        Ok(Json(safe_ask_catalog(capabilities)))
    }
    .await;

    let status = match &result {
        Ok(_) => StatusCode::OK,
        Err(err) => err.status_code(),
    };
    crate::metrics::observe_http_request(
        "/v1/policies/capabilities",
        "GET",
        status.as_u16(),
        started.elapsed(),
    );

    result
}

#[cfg(test)]
mod tests {
    use super::{
        SAFE_ASK_CAPABILITY_SPECS, normalize_policy_narrowing, safe_ask_capability_from_narrowing,
        safe_ask_catalog,
    };
    use pecr_contracts::PlannerIntent;

    #[test]
    fn normalize_policy_narrowing_derives_fields_and_dimensions_from_views() {
        let params = serde_json::Map::from_iter([(
            "intent".to_string(),
            serde_json::json!("structured_lookup"),
        )]);
        let narrowing = serde_json::json!({
            "scope_labels": ["customer rows in safe_customer_view_public"],
            "view_ids": ["safe_customer_view_public", "safe_customer_view_public"],
            "examples": ["What is the customer status in safe_customer_view_public?"]
        });

        let normalized = normalize_policy_narrowing(&params, Some(narrowing))
            .expect("narrowing should remain available");

        assert_eq!(
            normalized["view_ids"],
            serde_json::json!(["safe_customer_view_public"])
        );
        assert_eq!(
            normalized["field_labels"],
            serde_json::json!(["customer_id", "status", "plan_tier"])
        );
        assert_eq!(
            normalized["dimension_labels"],
            serde_json::json!(["status", "plan_tier"])
        );
    }

    #[test]
    fn normalize_policy_narrowing_adds_document_hints_for_doc_scopes() {
        let params = serde_json::Map::from_iter([(
            "intent".to_string(),
            serde_json::json!("evidence_lookup"),
        )]);
        let narrowing = serde_json::json!({
            "scope_labels": ["public documents under public/"],
            "source_scopes": ["public/"],
            "examples": ["Show the source text for the support policy in public documents."]
        });

        let normalized = normalize_policy_narrowing(&params, Some(narrowing))
            .expect("narrowing should remain available");

        assert_eq!(normalized["source_scopes"], serde_json::json!(["public/"]));
        assert_eq!(
            normalized["document_hints"],
            serde_json::json!(["policy documents", "versioned documents"])
        );
    }

    #[test]
    fn safe_ask_capability_maps_normalized_narrowing_into_catalog_entry() {
        let capability = safe_ask_capability_from_narrowing(
            SAFE_ASK_CAPABILITY_SPECS[0],
            Some(serde_json::json!({
                "scope_labels": ["customer rows in safe_customer_view_public"],
                "view_ids": ["safe_customer_view_public"],
                "field_labels": ["customer_id", "status", "plan_tier"],
                "dimension_labels": ["status", "plan_tier"],
                "examples": ["What is the customer status and plan tier?"]
            })),
        )
        .expect("capability should be built");

        assert_eq!(capability.capability_id, "structured_lookup");
        assert_eq!(capability.intent, PlannerIntent::StructuredLookup);
        assert_eq!(capability.view_ids, vec!["safe_customer_view_public"]);
        assert_eq!(
            capability.examples,
            vec!["What is the customer status and plan tier?"]
        );
    }

    #[test]
    fn safe_ask_catalog_deduplicates_suggested_queries() {
        let catalog = safe_ask_catalog(vec![
            pecr_contracts::SafeAskCapability {
                capability_id: "structured_lookup".to_string(),
                intent: PlannerIntent::StructuredLookup,
                title: "Look up customer fields".to_string(),
                description: "Structured lookup".to_string(),
                examples: vec![
                    "What is the customer status and plan tier?".to_string(),
                    "What is the customer status and plan tier?".to_string(),
                ],
                scope_labels: Vec::new(),
                view_ids: Vec::new(),
                field_labels: Vec::new(),
                dimension_labels: Vec::new(),
                source_scopes: Vec::new(),
                document_hints: Vec::new(),
            },
            pecr_contracts::SafeAskCapability {
                capability_id: "evidence_lookup".to_string(),
                intent: PlannerIntent::EvidenceLookup,
                title: "Quote or cite source text".to_string(),
                description: "Evidence lookup".to_string(),
                examples: vec![
                    "Show the source text and evidence for the support policy".to_string(),
                ],
                scope_labels: Vec::new(),
                view_ids: Vec::new(),
                field_labels: Vec::new(),
                dimension_labels: Vec::new(),
                source_scopes: Vec::new(),
                document_hints: Vec::new(),
            },
        ]);

        assert_eq!(catalog.suggested_queries.len(), 2);
    }
}
