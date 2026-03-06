use std::time::Instant;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use pecr_adapters::{
    normalize_fields, normalize_resource_id, normalize_resource_prefix, normalize_safeview_id,
    normalize_search_query,
};
use pecr_contracts::canonical;
use pecr_contracts::{EvidenceContentType, EvidenceUnit, TerminalMode, TransformStep};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::auth::{extract_principal, extract_request_id, extract_session_token};
use super::operator::is_allowlisted_operator;
use super::policy::{
    apply_field_redaction, apply_field_redaction_to_evidence_unit, compute_content_hash,
    compute_evidence_unit_id, parse_field_redaction, redact_span_or_row_spec_fields,
};
use super::runtime::{
    PgSafeviewContext, aggregate_from_pg_safeview, compare_from_pg_safeview, diff_from_fs,
    discover_dimensions_from_pg_safeview, fetch_rows_from_pg_safeview, fetch_span_from_fs,
    list_versions_from_fs, search_from_fs, sha256_hex,
};
use super::session::{
    acquire_session_lock, load_session_runtime, persist_session_runtime, unix_epoch_ms_now,
};
use super::{ApiError, AppState, ErrorResponse, json_error, opa_error_response};
use crate::opa::OpaCacheKey;
use crate::operator_cache::OperatorCacheKey;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorCallRequest {
    pub(super) session_id: String,
    pub(super) params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub(super) struct OperatorCallResponse {
    pub(super) terminal_mode: TerminalMode,
    pub(super) result: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) result_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) policy_decision: Option<serde_json::Value>,
}

fn invalid_params_error(message: impl Into<String>) -> ApiError {
    json_error(
        StatusCode::BAD_REQUEST,
        "ERR_INVALID_PARAMS",
        message.into(),
        TerminalMode::InsufficientEvidence,
        false,
    )
}

fn adapter_params_error(param_name: &str, message: impl AsRef<str>) -> ApiError {
    invalid_params_error(format!(
        "invalid params.{}: {}",
        param_name,
        message.as_ref()
    ))
}

fn normalize_operator_params(
    op_name: &str,
    params: &serde_json::Value,
    max_safeview_fields: usize,
) -> Result<serde_json::Value, ApiError> {
    let Some(map) = params.as_object() else {
        return Err(invalid_params_error("params must be an object"));
    };

    let mut normalized = map.clone();
    match op_name {
        "search" => normalize_search_params(&mut normalized)?,
        "lookup_evidence" => normalize_lookup_evidence_params(&mut normalized)?,
        "list_versions" | "fetch_span" => normalize_object_id_param(&mut normalized)?,
        "diff" => {
            normalize_object_id_param(&mut normalized)?;
            normalize_required_string_param(&mut normalized, "v1")?;
            normalize_required_string_param(&mut normalized, "v2")?;
        }
        "fetch_rows" => normalize_safeview_params(&mut normalized, max_safeview_fields)?,
        "aggregate" | "compare" => normalize_aggregate_params(&mut normalized)?,
        "discover_dimensions" => normalize_dimension_discovery_params(&mut normalized)?,
        _ => {}
    }

    Ok(serde_json::Value::Object(normalized))
}

fn normalize_object_id_param(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid_params_error("params.object_id is required"))?;
    let normalized = normalize_resource_id(object_id)
        .map_err(|err| adapter_params_error("object_id", err.to_string()))?;
    params.insert("object_id".to_string(), serde_json::json!(normalized));
    Ok(())
}

fn normalize_required_string_param(
    params: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
) -> Result<(), ApiError> {
    let value = params
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_params_error(format!("params.{} is required", key)))?;
    params.insert(key.to_string(), serde_json::json!(value));
    Ok(())
}

fn normalize_search_params(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    let normalized_query = if let Some(query) = params.get("query").and_then(|value| value.as_str())
    {
        normalize_search_query(query)
            .map_err(|err| adapter_params_error("query", err.to_string()))?
    } else {
        let terms = parse_string_list(params.get("terms"), "terms")?;
        if terms.is_empty() {
            return Err(invalid_params_error("params.query is required"));
        }
        normalize_search_query(&terms.join(" "))
            .map_err(|err| adapter_params_error("query", err.to_string()))?
    };
    params.insert("query".to_string(), serde_json::json!(normalized_query));

    if let Some(terms) = params.get("terms") {
        let normalized_terms = parse_string_list(Some(terms), "terms")?
            .into_iter()
            .map(|term| normalize_search_query(&term))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| adapter_params_error("terms", err.to_string()))?;
        params.insert("terms".to_string(), serde_json::json!(normalized_terms));
    }

    let limit = params
        .get("limit")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, 50))
        .unwrap_or(10);
    params.insert("limit".to_string(), serde_json::json!(limit));

    if let Some(prefix) = params.get("object_prefix").and_then(|value| value.as_str()) {
        let normalized_prefix = normalize_resource_prefix(prefix)
            .map_err(|err| adapter_params_error("object_prefix", err.to_string()))?;
        params.insert(
            "object_prefix".to_string(),
            serde_json::json!(normalized_prefix),
        );
    }

    if let Some(case_sensitive) = params.get("case_sensitive") {
        let case_sensitive = case_sensitive
            .as_bool()
            .ok_or_else(|| invalid_params_error("params.case_sensitive must be a boolean"))?;
        params.insert(
            "case_sensitive".to_string(),
            serde_json::json!(case_sensitive),
        );
    }

    if let Some(match_mode) = params.get("match_mode").and_then(|value| value.as_str()) {
        let normalized_match_mode = match_mode.trim().to_ascii_lowercase();
        if !matches!(normalized_match_mode.as_str(), "all" | "any" | "phrase") {
            return Err(invalid_params_error(
                "params.match_mode must be one of: all, any, phrase",
            ));
        }
        params.insert(
            "match_mode".to_string(),
            serde_json::json!(normalized_match_mode),
        );
    }

    Ok(())
}

fn normalize_safeview_params(
    params: &mut serde_json::Map<String, serde_json::Value>,
    max_safeview_fields: usize,
) -> Result<(), ApiError> {
    let view_id = params
        .get("view_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid_params_error("params.view_id is required"))?;
    let normalized_view_id = normalize_safeview_id(view_id)
        .map_err(|err| adapter_params_error("view_id", err.to_string()))?;
    params.insert("view_id".to_string(), serde_json::json!(normalized_view_id));

    let fields = parse_string_list(params.get("fields"), "fields")?;
    if fields.is_empty() {
        return Err(invalid_params_error(
            "params.fields must be a non-empty array",
        ));
    }
    if fields.len() > max_safeview_fields {
        return Err(invalid_params_error(
            "params.fields exceeds max field count",
        ));
    }
    let normalized_fields =
        normalize_fields(&fields).map_err(|err| adapter_params_error("fields", err.to_string()))?;
    params.insert("fields".to_string(), serde_json::json!(normalized_fields));
    normalize_filter_spec_param(params)?;
    Ok(())
}

fn normalize_aggregate_params(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    let view_id = params
        .get("view_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid_params_error("params.view_id is required"))?;
    let normalized_view_id = normalize_safeview_id(view_id)
        .map_err(|err| adapter_params_error("view_id", err.to_string()))?;
    params.insert("view_id".to_string(), serde_json::json!(normalized_view_id));

    if let Some(group_by) = params.get("group_by") {
        let normalized = normalize_fields(&parse_string_list(Some(group_by), "group_by")?)
            .map_err(|err| adapter_params_error("group_by", err.to_string()))?;
        params.insert("group_by".to_string(), serde_json::json!(normalized));
    }

    normalize_filter_spec_param(params)?;

    if let Some(metrics) = params.get("metrics") {
        let metrics = metrics.as_array().ok_or_else(|| {
            invalid_params_error("params.metrics must be an array of metric objects")
        })?;
        let mut normalized_metrics = metrics
            .iter()
            .map(|metric| {
                let Some(metric_map) = metric.as_object() else {
                    return Err(invalid_params_error(
                        "params.metrics must be an array of metric objects",
                    ));
                };
                let name = metric_map
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid_params_error("params.metrics[].name is required"))?
                    .to_ascii_lowercase();
                let field = metric_map
                    .get("field")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| invalid_params_error("params.metrics[].field is required"))?;
                let normalized_field = normalize_fields(&[field.to_string()])
                    .map_err(|err| adapter_params_error("metrics[].field", err.to_string()))?
                    .into_iter()
                    .next()
                    .ok_or_else(|| invalid_params_error("params.metrics[].field is required"))?;

                Ok::<_, ApiError>(serde_json::json!({
                    "name": name,
                    "field": normalized_field,
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        normalized_metrics.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
        normalized_metrics.dedup();
        params.insert("metrics".to_string(), serde_json::json!(normalized_metrics));
    }

    if let Some(metric) = params.get("metric").and_then(|value| value.as_str()) {
        let normalized_metric = metric.trim().to_ascii_lowercase();
        if normalized_metric.is_empty() {
            return Err(invalid_params_error(
                "params.metric must be a non-empty string",
            ));
        }
        params.insert("metric".to_string(), serde_json::json!(normalized_metric));
    }

    if let Some(time_granularity) = params
        .get("time_granularity")
        .and_then(|value| value.as_str())
    {
        let normalized_time_granularity = time_granularity.trim().to_ascii_lowercase();
        if !matches!(normalized_time_granularity.as_str(), "day" | "month") {
            return Err(invalid_params_error(
                "params.time_granularity must be one of: day, month",
            ));
        }
        params.insert(
            "time_granularity".to_string(),
            serde_json::json!(normalized_time_granularity),
        );
    }

    if let Some(top_n) = params.get("top_n") {
        let top_n = top_n
            .as_u64()
            .ok_or_else(|| invalid_params_error("params.top_n must be a positive integer"))?
            .clamp(1, 50);
        params.insert("top_n".to_string(), serde_json::json!(top_n));
    }

    if let Some(include_rank) = params.get("include_rank") {
        let include_rank = include_rank
            .as_bool()
            .ok_or_else(|| invalid_params_error("params.include_rank must be a boolean"))?;
        params.insert("include_rank".to_string(), serde_json::json!(include_rank));
    }

    if let Some(rank_direction) = params
        .get("rank_direction")
        .and_then(|value| value.as_str())
    {
        let rank_direction = rank_direction.trim().to_ascii_lowercase();
        if !matches!(rank_direction.as_str(), "asc" | "desc") {
            return Err(invalid_params_error(
                "params.rank_direction must be one of: asc, desc",
            ));
        }
        params.insert(
            "rank_direction".to_string(),
            serde_json::json!(rank_direction),
        );
    }

    if let Some(drilldown_dimension) = params
        .get("drilldown_dimension")
        .and_then(|value| value.as_str())
    {
        let normalized = normalize_fields(&[drilldown_dimension.to_string()])
            .map_err(|err| adapter_params_error("drilldown_dimension", err.to_string()))?;
        let value = normalized
            .into_iter()
            .next()
            .ok_or_else(|| invalid_params_error("params.drilldown_dimension is required"))?;
        params.insert("drilldown_dimension".to_string(), serde_json::json!(value));
    }

    Ok(())
}

fn normalize_dimension_discovery_params(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    let view_id = params
        .get("view_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid_params_error("params.view_id is required"))?;
    let normalized_view_id = normalize_safeview_id(view_id)
        .map_err(|err| adapter_params_error("view_id", err.to_string()))?;
    params.insert("view_id".to_string(), serde_json::json!(normalized_view_id));

    normalize_filter_spec_param(params)?;

    if let Some(max_values) = params.get("max_values_per_dimension") {
        let max_values = max_values
            .as_u64()
            .ok_or_else(|| {
                invalid_params_error("params.max_values_per_dimension must be a positive integer")
            })?
            .clamp(1, 10);
        params.insert(
            "max_values_per_dimension".to_string(),
            serde_json::json!(max_values),
        );
    }

    Ok(())
}

fn normalize_lookup_evidence_params(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    normalize_search_params(params)?;

    let max_refs = params
        .get("max_refs")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, 5))
        .unwrap_or(2);
    params.insert("max_refs".to_string(), serde_json::json!(max_refs));

    Ok(())
}

fn normalize_filter_spec_param(
    params: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), ApiError> {
    let Some(filter_spec) = params.get("filter_spec") else {
        return Ok(());
    };
    let filter_spec = filter_spec
        .as_object()
        .ok_or_else(|| invalid_params_error("params.filter_spec must be an object"))?;

    let mut normalized_filter_spec = serde_json::Map::new();

    for original_key in filter_spec.keys() {
        let normalized_key = normalize_fields(&[original_key.to_string()])
            .map_err(|err| adapter_params_error("filter_spec", err.to_string()))?
            .into_iter()
            .next()
            .ok_or_else(|| invalid_params_error("params.filter_spec must contain valid fields"))?;
        let value = filter_spec
            .get(original_key)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                invalid_params_error(format!(
                    "params.filter_spec.{} must be a non-empty string",
                    original_key
                ))
            })?;
        normalized_filter_spec.insert(normalized_key, serde_json::json!(value));
    }

    params.insert(
        "filter_spec".to_string(),
        serde_json::Value::Object(normalized_filter_spec),
    );
    Ok(())
}

fn parse_string_list(
    value: Option<&serde_json::Value>,
    key: &'static str,
) -> Result<Vec<String>, ApiError> {
    match value {
        None => Ok(Vec::new()),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        invalid_params_error(format!(
                            "params.{} must be an array of non-empty strings",
                            key
                        ))
                    })
            })
            .collect(),
        Some(serde_json::Value::String(value)) => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()),
        Some(_) => Err(invalid_params_error(format!(
            "params.{} must be a string or array of strings",
            key
        ))),
    }
}

fn summarize_operator_result(
    op_name: &str,
    result: &serde_json::Value,
    evidence_units: &[EvidenceUnit],
) -> Option<String> {
    match op_name {
        "search" => summarize_search_result(result),
        "list_versions" => summarize_versions_result(result),
        "diff" => summarize_diff_result(evidence_units),
        "fetch_span" | "aggregate" | "compare" => {
            evidence_units.first().map(summarize_operator_evidence_unit)
        }
        "fetch_rows" | "lookup_evidence" | "redact" | "discover_dimensions" => {
            summarize_operator_evidence_units(evidence_units)
        }
        _ => None,
    }
}

async fn lookup_evidence_from_fs_sources(
    state: &AppState,
    session: &super::session::Session,
    normalized_params: &serde_json::Value,
) -> Result<(TerminalMode, Vec<EvidenceUnit>), ApiError> {
    let refs = search_from_fs(
        &state.fs_search_index,
        state.config.fs_corpus_path.as_str(),
        session.as_of_time.as_str(),
        session.policy_snapshot_hash.as_str(),
        normalized_params,
    )
    .await?;

    if refs.is_empty() {
        return Ok((TerminalMode::InsufficientEvidence, Vec::new()));
    }

    let max_refs = normalized_params
        .get("max_refs")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, 5) as usize)
        .unwrap_or(2);

    let mut evidence = Vec::new();
    let mut last_source_error = None;

    for reference in refs.into_iter().take(max_refs) {
        let mut params = serde_json::json!({ "object_id": reference.object_id });
        if let Some(start_byte) = reference.start_byte {
            params["start_byte"] = serde_json::json!(start_byte);
        }
        if let Some(end_byte) = reference.end_byte {
            params["end_byte"] = serde_json::json!(end_byte);
        }

        match fetch_span_from_fs(
            &state.fs_versions,
            state.config.fs_corpus_path.as_str(),
            session.as_of_time.as_str(),
            session.policy_snapshot_id.as_str(),
            session.policy_snapshot_hash.as_str(),
            &params,
        )
        .await
        {
            Ok(unit) => evidence.push(unit),
            Err(err) if err.1.0.terminal_mode_hint == TerminalMode::SourceUnavailable => {
                last_source_error = Some(err);
            }
            Err(err) => return Err(err),
        }
    }

    if !evidence.is_empty() {
        Ok((TerminalMode::Supported, evidence))
    } else if let Some(err) = last_source_error {
        Err(err)
    } else {
        Ok((TerminalMode::InsufficientEvidence, Vec::new()))
    }
}

fn summarize_search_result(result: &serde_json::Value) -> Option<String> {
    let refs = result.get("refs")?.as_array()?;
    if refs.is_empty() {
        return Some("0 matching evidence refs".to_string());
    }

    let first = refs.first()?.as_object()?;
    let object_id = first
        .get("object_id")
        .and_then(|value| value.as_str())
        .unwrap_or("source");
    let line_summary = match (
        first.get("line_start").and_then(|value| value.as_u64()),
        first.get("line_end").and_then(|value| value.as_u64()),
    ) {
        (Some(line_start), Some(line_end)) if line_start == line_end => {
            format!(" line {}", line_start)
        }
        (Some(line_start), Some(line_end)) => format!(" lines {}-{}", line_start, line_end),
        _ => String::new(),
    };
    let preview = first
        .get("match_preview")
        .and_then(|value| value.as_str())
        .map(normalize_summary_text)
        .filter(|value| !value.is_empty())
        .map(|value| abbreviate_summary(&value, 120));

    let count = refs.len();
    Some(match preview {
        Some(preview) => format!(
            "{} matching evidence refs; top match {}{}: {}",
            count, object_id, line_summary, preview
        ),
        None => format!(
            "{} matching evidence refs; top match {}{}",
            count, object_id, line_summary
        ),
    })
}

fn summarize_versions_result(result: &serde_json::Value) -> Option<String> {
    let versions = result.get("versions")?.as_array()?;
    if versions.is_empty() {
        return Some("0 versions available".to_string());
    }

    let latest_version = versions
        .first()
        .and_then(|value| value.get("version_id"))
        .and_then(|value| value.as_str())
        .map(|value| abbreviate_summary(value, 12));
    let previous_version = versions
        .get(1)
        .and_then(|value| value.get("version_id"))
        .and_then(|value| value.as_str())
        .map(|value| abbreviate_summary(value, 12));

    Some(match (latest_version, previous_version) {
        (Some(latest_version), Some(previous_version)) => format!(
            "{} versions available; latest {} compared with previous {}",
            versions.len(),
            latest_version,
            previous_version
        ),
        (Some(latest_version), None) => format!(
            "{} versions available; latest {}",
            versions.len(),
            latest_version
        ),
        (None, _) => format!("{} versions available", versions.len()),
    })
}

fn summarize_diff_result(evidence_units: &[EvidenceUnit]) -> Option<String> {
    let unit = evidence_units.first()?;
    let location = summarize_evidence_location(unit);
    let patch = unit
        .content
        .as_ref()
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let patch_summary = patch
        .as_deref()
        .and_then(summarize_diff_patch)
        .filter(|value| !value.is_empty());

    match patch_summary {
        Some(summary) => Some(format!("{location} changed: {summary}")),
        None => Some(summarize_operator_evidence_unit(unit)),
    }
}

fn summarize_diff_patch(patch: &str) -> Option<String> {
    let mut additions = Vec::new();
    let mut removals = Vec::new();

    for line in patch.lines() {
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("@@") {
            continue;
        }

        let Some((prefix, content)) = line.chars().next().map(|prefix| (prefix, line[1..].trim()))
        else {
            continue;
        };
        if content.is_empty() {
            continue;
        }

        match prefix {
            '+' => additions.push(content.to_string()),
            '-' => removals.push(content.to_string()),
            _ => {}
        }
    }

    if additions.is_empty() && removals.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    if !additions.is_empty() {
        parts.push(format!("added {}", summarize_diff_fragments(&additions, 2)));
    }
    if !removals.is_empty() {
        parts.push(format!(
            "removed {}",
            summarize_diff_fragments(&removals, 2)
        ));
    }

    Some(parts.join("; "))
}

fn summarize_diff_fragments(lines: &[String], limit: usize) -> String {
    let fragments = lines
        .iter()
        .take(limit)
        .map(|line| {
            format!(
                "'{}'",
                abbreviate_summary(&normalize_summary_text(line), 60)
            )
        })
        .collect::<Vec<_>>();
    let remaining = lines.len().saturating_sub(limit);
    if remaining == 0 {
        fragments.join(" and ")
    } else {
        format!("{} and {} more", fragments.join(", "), remaining)
    }
}

fn summarize_operator_evidence_units(evidence_units: &[EvidenceUnit]) -> Option<String> {
    if evidence_units.is_empty() {
        return None;
    }

    let first = summarize_operator_evidence_unit(&evidence_units[0]);
    if evidence_units.len() == 1 {
        Some(first)
    } else {
        Some(format!(
            "{} evidence units; strongest support: {}",
            evidence_units.len(),
            first
        ))
    }
}

fn summarize_operator_evidence_unit(unit: &EvidenceUnit) -> String {
    let location = summarize_evidence_location(unit);
    let snippet = unit
        .content
        .as_ref()
        .map(summarize_operator_content)
        .filter(|value| !value.is_empty());

    match snippet {
        Some(snippet) => format!("{} (source: {})", snippet, location),
        None => location,
    }
}

fn summarize_evidence_location(unit: &EvidenceUnit) -> String {
    match unit
        .span_or_row_spec
        .get("type")
        .and_then(|value| value.as_str())
    {
        Some("text_span") => match (
            unit.span_or_row_spec
                .get("line_start")
                .and_then(|value| value.as_u64()),
            unit.span_or_row_spec
                .get("line_end")
                .and_then(|value| value.as_u64()),
        ) {
            (Some(line_start), Some(line_end)) if line_start == line_end => {
                format!("{} line {}", unit.object_id, line_start)
            }
            (Some(line_start), Some(line_end)) => {
                format!("{} lines {}-{}", unit.object_id, line_start, line_end)
            }
            _ => unit.object_id.clone(),
        },
        Some("db_row") => unit
            .span_or_row_spec
            .get("primary_key")
            .and_then(|value| value.as_object())
            .map(|primary_key| {
                let mut parts = primary_key
                    .iter()
                    .filter_map(|(key, value)| {
                        scalar_value_summary(value).map(|summary| format!("{}={}", key, summary))
                    })
                    .collect::<Vec<_>>();
                parts.sort();
                if parts.is_empty() {
                    format!("{} row", unit.object_id)
                } else {
                    format!("{} row {}", unit.object_id, parts.join(", "))
                }
            })
            .unwrap_or_else(|| format!("{} row", unit.object_id)),
        Some("db_aggregate") => format!("{} aggregate", unit.object_id),
        Some("db_dimension_discovery") => format!("{} dimension discovery", unit.object_id),
        _ => unit.object_id.clone(),
    }
}

fn summarize_operator_content(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(text) => abbreviate_summary(&normalize_summary_text(text), 120),
        serde_json::Value::Object(map) => summarize_object_content(map),
        serde_json::Value::Array(values) => summarize_array_content(values),
        other => other.to_string(),
    }
}

fn summarize_object_content(map: &serde_json::Map<String, serde_json::Value>) -> String {
    if let Some(comparison_summary) = map
        .get("comparison_summary")
        .and_then(|value| value.as_object())
    {
        let summary = comparison_summary
            .get("summary")
            .and_then(|value| value.as_str())
            .map(normalize_summary_text)
            .filter(|value| !value.is_empty());
        let highlights = comparison_summary
            .get("highlights")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(normalize_summary_text)
                    .filter(|value| !value.is_empty())
                    .take(2)
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty());
        match (summary, highlights) {
            (Some(summary), Some(highlights)) => {
                return abbreviate_summary(
                    &format!("{} ({})", summary, highlights.join("; ")),
                    120,
                );
            }
            (Some(summary), None) => return abbreviate_summary(&summary, 120),
            (None, Some(highlights)) => {
                return abbreviate_summary(&highlights.join("; "), 120);
            }
            (None, None) => {}
        }
    }

    if let Some(dimensions) = map.get("dimensions").and_then(|value| value.as_array()) {
        let summaries = dimensions
            .iter()
            .filter_map(|dimension| {
                let dimension = dimension.as_object()?;
                let field = dimension.get("field")?.as_str()?.trim();
                let top_values = dimension
                    .get("top_values")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| {
                                let value = value.as_object()?;
                                let label = value.get("value")?.as_str()?.trim();
                                let count = value.get("count")?.as_i64()?;
                                Some(format!("{}={}", label, count))
                            })
                            .take(2)
                            .collect::<Vec<_>>()
                    })
                    .filter(|values| !values.is_empty())?;
                Some(format!("{} [{}]", field, top_values.join(", ")))
            })
            .take(2)
            .collect::<Vec<_>>();
        if !summaries.is_empty() {
            return abbreviate_summary(&format!("dimensions: {}", summaries.join("; ")), 120);
        }
    }

    if let Some(rows) = map.get("rows").and_then(|value| value.as_array()) {
        let row_summaries = rows
            .iter()
            .filter_map(|row| row.as_object())
            .map(|row| {
                let group = row
                    .get("group")
                    .and_then(|value| value.as_object())
                    .map(|group| {
                        let mut parts = group
                            .iter()
                            .filter_map(|(key, value)| {
                                scalar_value_summary(value)
                                    .map(|summary| format!("{}={}", key, summary))
                            })
                            .collect::<Vec<_>>();
                        parts.sort();
                        parts.join(", ")
                    })
                    .filter(|value| !value.is_empty());
                let metrics = row
                    .get("metrics")
                    .and_then(|value| value.as_array())
                    .map(|metrics| {
                        let mut parts = metrics
                            .iter()
                            .filter_map(|metric| {
                                let metric = metric.as_object()?;
                                let name = metric.get("name")?.as_str()?;
                                let field = metric.get("field")?.as_str()?;
                                let value = scalar_value_summary(metric.get("value")?)?;
                                Some(format!("{}({})={}", name, field, value))
                            })
                            .collect::<Vec<_>>();
                        parts.sort();
                        parts.join(", ")
                    })
                    .filter(|value| !value.is_empty());
                match (group, metrics) {
                    (Some(group), Some(metrics)) => Some(format!("{} {}", group, metrics)),
                    (Some(group), None) => Some(group),
                    (None, Some(metrics)) => Some(metrics),
                    (None, None) => None,
                }
            })
            .flatten()
            .take(2)
            .collect::<Vec<_>>();
        if !row_summaries.is_empty() {
            return abbreviate_summary(&row_summaries.join("; "), 120);
        }
    }

    let mut pairs = map
        .iter()
        .filter_map(|(key, value)| {
            scalar_value_summary(value).map(|summary| format!("{}={}", key, summary))
        })
        .take(3)
        .collect::<Vec<_>>();
    pairs.sort();
    if pairs.is_empty() {
        abbreviate_summary(&serde_json::Value::Object(map.clone()).to_string(), 120)
    } else {
        abbreviate_summary(&pairs.join("; "), 120)
    }
}

fn summarize_array_content(values: &[serde_json::Value]) -> String {
    let values = values
        .iter()
        .filter_map(scalar_value_summary)
        .take(3)
        .collect::<Vec<_>>();
    if values.is_empty() {
        "[]".to_string()
    } else {
        format!("values [{}]", values.join(", "))
    }
}

fn scalar_value_summary(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            let normalized = normalize_summary_text(text);
            (!normalized.is_empty()).then(|| abbreviate_summary(&normalized, 48))
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn normalize_summary_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn abbreviate_summary(text: &str, max_chars: usize) -> String {
    let text = text.trim();
    let mut chars = text.chars();
    let abbreviated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", abbreviated)
    } else {
        abbreviated
    }
}

pub(super) async fn call_operator(
    State(state): State<AppState>,
    Path(op_name): Path<String>,
    headers: HeaderMap,
    req: Result<Json<OperatorCallRequest>, JsonRejection>,
) -> Result<Json<OperatorCallResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_started = Instant::now();
    let op_name_for_metrics = op_name.clone();

    let handler_result = (async move {
        let principal = extract_principal(&state, &headers).await?;
        let principal_id = principal.principal_id.clone();

        if !state.rate_limiter.allow(
            format!("operators:{}", principal_id).as_str(),
            state.config.rate_limit_operators_per_window,
        ) {
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_RATE_LIMITED",
                "rate limit exceeded for operator calls".to_string(),
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
        let normalized_params =
            normalize_operator_params(op_name.as_str(), &req.params, state.config.pg_safeview_max_fields)?;
        let _session_lock = acquire_session_lock(&state, &req.session_id).await?;

        let params_bytes = serde_json::to_vec(&normalized_params)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let params_hash =
            sha256_hex(&serde_json::to_vec(&normalized_params).unwrap_or_else(|_| Vec::new()));

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

        if session.session_id != req.session_id {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "ERR_INVALID_PARAMS",
                "unknown session_id".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

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

        let session_token_hash = sha256_hex(session_token.as_bytes());
        if unix_epoch_ms_now() > session.session_token_expires_at_epoch_ms
            || session.session_token_hash != session_token_hash
        {
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

            crate::metrics::inc_budget_violation();
            return Err(json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_BUDGET_EXCEEDED",
                "budget exceeded".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if session.budget.max_bytes > 0
            && session
                .bytes_used
                .saturating_add(params_bytes)
                .gt(&session.budget.max_bytes)
        {
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
                        "bytes_used": session.bytes_used,
                        "params_bytes": params_bytes,
                        "max_bytes": session.budget.max_bytes,
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

            crate::metrics::inc_budget_violation();
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

        let object_id = normalized_params.get("object_id").and_then(|v| v.as_str());
        let view_id = normalized_params
            .get("view_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty());

        let fields_hash = normalized_params
            .get("fields")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let mut fields = arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(|v| serde_json::Value::String(v.to_string()))
                    .collect::<Vec<_>>();
                fields.sort_by(|a, b| a.as_str().unwrap_or("").cmp(b.as_str().unwrap_or("")));
                canonical::hash_canonical_json(&serde_json::Value::Array(fields))
            });

        let filter_fingerprint = normalized_params
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
            "as_of_time": session.as_of_time.as_str(),
            "op_name": op_name.as_str(),
            "params_hash": params_hash.as_str(),
            "params_bytes": params_bytes,
            "object_id": object_id,
            "view_id": view_id,
            "fields_hash": fields_hash,
            "filter_fingerprint": filter_fingerprint,
            "request_id": request_id.as_str(),
        });

        let cache_key =
            OpaCacheKey::operator_call(&session.policy_snapshot_hash, op_name.as_str(), &params_hash);
        let policy_span = tracing::info_span!(
            "policy.evaluate",
            trace_id = %session.trace_id,
            request_id = %request_id,
            session_id = %session.session_id,
            principal_id = %principal_id,
            policy_snapshot_id = %session.policy_snapshot_id,
            policy_snapshot_hash = %session.policy_snapshot_hash,
            operator_name = %op_name,
            action = "operator_call",
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

        let policy_decision_payload = serde_json::json!({
            "allow": decision.allow,
            "cacheable": decision.cacheable,
            "reason": decision.reason,
            "redaction": decision.redaction,
        });

        let build_response = |terminal_mode: TerminalMode, result: serde_json::Value| {
            OperatorCallResponse {
                terminal_mode,
                result,
                result_summary: None,
                policy_decision: Some(policy_decision_payload.clone()),
            }
        };

        let field_redaction = parse_field_redaction(decision.redaction.as_ref())?;

        let operator_span = match op_name.as_str() {
            "search" => tracing::info_span!(
                "operator.search",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "search",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "fetch_span" => tracing::info_span!(
                "operator.fetch_span",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "fetch_span",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "fetch_rows" => tracing::info_span!(
                "operator.fetch_rows",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "fetch_rows",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "aggregate" => tracing::info_span!(
                "operator.aggregate",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "aggregate",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "compare" => tracing::info_span!(
                "operator.compare",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "compare",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "discover_dimensions" => tracing::info_span!(
                "operator.discover_dimensions",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "discover_dimensions",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "lookup_evidence" => tracing::info_span!(
                "operator.lookup_evidence",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "lookup_evidence",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "list_versions" => tracing::info_span!(
                "operator.list_versions",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "list_versions",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            "diff" => tracing::info_span!(
                "operator.diff",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = "diff",
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
            _ => tracing::info_span!(
                "operator.unknown",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                principal_id = %principal_id,
                policy_snapshot_id = %session.policy_snapshot_id,
                policy_snapshot_hash = %session.policy_snapshot_hash,
                operator_name = %op_name,
                params_hash = %params_hash,
                params_bytes,
                result_bytes = tracing::field::Empty,
                terminal_mode = tracing::field::Empty,
                operator_calls_used = tracing::field::Empty,
                bytes_used = tracing::field::Empty,
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            ),
        };

        async {
            let started = Instant::now();

            let mut cache_hit = false;
            let operator_cache_key = OperatorCacheKey::operator_call(
                principal_id.as_str(),
                session.policy_snapshot_hash.as_str(),
                session.as_of_time.as_str(),
                op_name.as_str(),
                params_hash.as_str(),
            );

            let (status, error_code, mut response, evidence_emitted) = match op_name.as_str() {
                "search" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.fs_corpus",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "fs_corpus",
                        operator_name = "search",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let (terminal_mode, result, hit) = async {
                        let started = Instant::now();
                        if let Some((terminal_mode, result)) =
                            state.operator_cache.get(&operator_cache_key).await
                        {
                            let latency_ms = started.elapsed().as_millis() as u64;
                            tracing::Span::current().record("latency_ms", latency_ms);
                            tracing::Span::current().record("outcome", "cache_hit");
                            return Ok::<_, ApiError>((terminal_mode, result, true));
                        }

                        let refs = search_from_fs(
                            &state.fs_search_index,
                            state.config.fs_corpus_path.as_str(),
                            session.as_of_time.as_str(),
                            session.policy_snapshot_hash.as_str(),
                            &normalized_params,
                        )
                        .await?;
                        let result = serde_json::json!({ "refs": refs });
                        state
                            .operator_cache
                            .put(
                                operator_cache_key.clone(),
                                TerminalMode::Supported,
                                result.clone(),
                            )
                            .await;

                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");

                        Ok::<_, ApiError>((TerminalMode::Supported, result, false))
                    }
                    .instrument(adapter_span)
                    .await?;

                    if hit {
                        cache_hit = true;
                        crate::metrics::inc_operator_cache_hit("search");
                    }

                    (
                        StatusCode::OK,
                        None,
                        build_response(terminal_mode, result),
                        Vec::new(),
                    )
                }
                "list_versions" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.fs_corpus",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "fs_corpus",
                        operator_name = "list_versions",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );
                    let versions = async {
                        let started = Instant::now();
                        let versions = list_versions_from_fs(
                            &state.fs_versions,
                            &state.config.fs_corpus_path,
                            session.as_of_time.as_str(),
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(versions)
                    }
                    .instrument(adapter_span)
                    .await?;

                    (
                        StatusCode::OK,
                        None,
                        build_response(
                            TerminalMode::Supported,
                            serde_json::json!({ "versions": versions }),
                        ),
                        Vec::new(),
                    )
                }
                "diff" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.fs_corpus",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "fs_corpus",
                        operator_name = "diff",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );
                    let evidence = async {
                        let started = Instant::now();
                        let evidence = diff_from_fs(
                            &state.fs_versions,
                            &state.config.fs_corpus_path,
                            session.as_of_time.as_str(),
                            state.config.fs_diff_max_bytes,
                            &session.policy_snapshot_id,
                            &session.policy_snapshot_hash,
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        evidence,
                    )
                }
                "fetch_span" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.fs_corpus",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "fs_corpus",
                        operator_name = "fetch_span",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let evidence = async {
                        let started = Instant::now();
                        let evidence = fetch_span_from_fs(
                            &state.fs_versions,
                            &state.config.fs_corpus_path,
                            session.as_of_time.as_str(),
                            &session.policy_snapshot_id,
                            &session.policy_snapshot_hash,
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        vec![evidence],
                    )
                }
                "fetch_rows" => {
                    let ctx = PgSafeviewContext {
                        pool: &state.pg_pool,
                        config: &state.config,
                        versions: &state.pg_versions,
                        tenant_id: session.tenant_id.as_str(),
                        policy_snapshot_id: session.policy_snapshot_id.as_str(),
                        policy_snapshot_hash: session.policy_snapshot_hash.as_str(),
                        as_of_time: session.as_of_time.as_str(),
                    };

                    let adapter_span = tracing::info_span!(
                        "adapter.pg_safeview",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "pg_safeview",
                        operator_name = "fetch_rows",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let evidence = async {
                        let started = Instant::now();
                        let evidence = fetch_rows_from_pg_safeview(ctx, &normalized_params).await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let evidence = if let Some(redaction) = field_redaction.as_ref() {
                        evidence
                            .into_iter()
                            .map(|unit| apply_field_redaction_to_evidence_unit(unit, redaction))
                            .collect::<Result<Vec<_>, ApiError>>()?
                    } else {
                        evidence
                    };

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        evidence,
                    )
                }
                "aggregate" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.pg_safeview",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "pg_safeview",
                        operator_name = "aggregate",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let evidence = async {
                        let started = Instant::now();
                        let evidence = aggregate_from_pg_safeview(
                            &state.pg_pool,
                            &state.config,
                            &session.tenant_id,
                            &session.policy_snapshot_id,
                            &session.policy_snapshot_hash,
                            session.as_of_time.as_str(),
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let evidence = if let Some(redaction) = field_redaction.as_ref() {
                        apply_field_redaction_to_evidence_unit(evidence, redaction)?
                    } else {
                        evidence
                    };

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        vec![evidence],
                    )
                }
                "compare" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.pg_safeview",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "pg_safeview",
                        operator_name = "compare",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let evidence = async {
                        let started = Instant::now();
                        let evidence = compare_from_pg_safeview(
                            &state.pg_pool,
                            &state.config,
                            &session.tenant_id,
                            &session.policy_snapshot_id,
                            &session.policy_snapshot_hash,
                            session.as_of_time.as_str(),
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let evidence = if let Some(redaction) = field_redaction.as_ref() {
                        apply_field_redaction_to_evidence_unit(evidence, redaction)?
                    } else {
                        evidence
                    };

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        vec![evidence],
                    )
                }
                "discover_dimensions" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.pg_safeview",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "pg_safeview",
                        operator_name = "discover_dimensions",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let evidence = async {
                        let started = Instant::now();
                        let evidence = discover_dimensions_from_pg_safeview(
                            &state.pg_pool,
                            &state.config,
                            &session.tenant_id,
                            &session.policy_snapshot_id,
                            &session.policy_snapshot_hash,
                            session.as_of_time.as_str(),
                            &normalized_params,
                        )
                        .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(evidence)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let evidence = if let Some(redaction) = field_redaction.as_ref() {
                        apply_field_redaction_to_evidence_unit(evidence, redaction)?
                    } else {
                        evidence
                    };

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!({}));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        vec![evidence],
                    )
                }
                "lookup_evidence" => {
                    let adapter_span = tracing::info_span!(
                        "adapter.evidence_lookup",
                        trace_id = %session.trace_id,
                        request_id = %request_id,
                        session_id = %session.session_id,
                        source_system = "fs_corpus",
                        operator_name = "lookup_evidence",
                        latency_ms = tracing::field::Empty,
                        outcome = tracing::field::Empty,
                    );

                    let (terminal_mode, evidence) = async {
                        let started = Instant::now();
                        let outcome =
                            lookup_evidence_from_fs_sources(&state, &session, &normalized_params)
                                .await?;
                        let latency_ms = started.elapsed().as_millis() as u64;
                        tracing::Span::current().record("latency_ms", latency_ms);
                        tracing::Span::current().record("outcome", "ok");
                        Ok::<_, ApiError>(outcome)
                    }
                    .instrument(adapter_span)
                    .await?;

                    let evidence = if let Some(redaction) = field_redaction.as_ref() {
                        evidence
                            .into_iter()
                            .map(|unit| apply_field_redaction_to_evidence_unit(unit, redaction))
                            .collect::<Result<Vec<_>, ApiError>>()?
                    } else {
                        evidence
                    };

                    let result =
                        serde_json::to_value(&evidence).unwrap_or_else(|_| serde_json::json!([]));
                    (
                        StatusCode::OK,
                        None,
                        build_response(terminal_mode, result),
                        evidence,
                    )
                }
                "redact" => {
                    let evidence_units = req
                        .params
                        .get("evidence_units")
                        .and_then(|v| v.as_array())
                        .ok_or_else(|| {
                            json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "params.evidence_units must be an array".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            )
                        })?;

                    if evidence_units.len() > 200 {
                        return Err(json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "evidence_units too large".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        ));
                    }

                    let mut out_units = Vec::with_capacity(evidence_units.len());
                    let mut evidence_emitted = Vec::new();

                    for raw in evidence_units {
                        let unit: EvidenceUnit =
                            serde_json::from_value(raw.clone()).map_err(|_| {
                                json_error(
                                    StatusCode::BAD_REQUEST,
                                    "ERR_INVALID_PARAMS",
                                    "invalid EvidenceUnit".to_string(),
                                    TerminalMode::InsufficientEvidence,
                                    false,
                                )
                            })?;

                        if !canonical::is_sha256_hex(&unit.evidence_unit_id) {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "EvidenceUnit.evidence_unit_id must be sha256 hex".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        if !session.evidence_unit_ids.contains(&unit.evidence_unit_id) {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "evidence_unit_id not emitted in this session".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        if unit.policy_snapshot_hash != session.policy_snapshot_hash
                            || unit.as_of_time != session.as_of_time
                        {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "evidence_unit must match current session policy_snapshot_hash and as_of_time".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        let content = unit.content.as_ref().ok_or_else(|| {
                            json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "EvidenceUnit.content is required".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            )
                        })?;
                        let expected_content_hash = compute_content_hash(unit.content_type, content)?;
                        if unit.content_hash != expected_content_hash {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "EvidenceUnit.content_hash mismatch".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        let expected_id = compute_evidence_unit_id(&unit);
                        if unit.evidence_unit_id != expected_id {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "EvidenceUnit.evidence_unit_id mismatch".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        let Some(redaction) = field_redaction.as_ref() else {
                            out_units.push(unit);
                            continue;
                        };

                        if unit.content_type != EvidenceContentType::ApplicationJson {
                            return Err(json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                "redact supports application/json evidence only".to_string(),
                                TerminalMode::InsufficientEvidence,
                                false,
                            ));
                        }

                        let redacted_content = apply_field_redaction(content, redaction);
                        if redacted_content == *content {
                            out_units.push(unit);
                            continue;
                        }

                        let mut redacted = unit.clone();
                        redacted.content = Some(redacted_content);
                        redacted.content_hash = compute_content_hash(
                            EvidenceContentType::ApplicationJson,
                            redacted.content.as_ref().unwrap(),
                        )?;
                        redacted.span_or_row_spec =
                            redact_span_or_row_spec_fields(&redacted.span_or_row_spec, redaction);
                        redacted.policy_snapshot_id = session.policy_snapshot_id.clone();
                        redacted.policy_snapshot_hash = session.policy_snapshot_hash.clone();

                        let step_params = redaction.params_value();
                        let step_hash = canonical::hash_canonical_json(&step_params);
                        redacted.transform_chain.push(TransformStep {
                            transform_type: "redaction".to_string(),
                            transform_hash: step_hash,
                            params: Some(step_params),
                        });
                        redacted.evidence_unit_id = compute_evidence_unit_id(&redacted);

                        evidence_emitted.push(redacted.clone());
                        out_units.push(redacted);
                    }

                    let result =
                        serde_json::to_value(&out_units).unwrap_or_else(|_| serde_json::json!([]));
                    (
                        StatusCode::OK,
                        None,
                        build_response(TerminalMode::Supported, result),
                        evidence_emitted,
                    )
                }
                _ => (
                    StatusCode::NOT_IMPLEMENTED,
                    Some("ERR_INTERNAL"),
                    build_response(
                        TerminalMode::SourceUnavailable,
                        serde_json::json!({"message":"operator execution not implemented yet"}),
                    ),
                    Vec::new(),
                ),
            };

            response.result_summary =
                summarize_operator_result(op_name.as_str(), &response.result, &evidence_emitted);

            let result_bytes = serde_json::to_vec(&response.result)
                .map(|v| v.len() as u64)
                .unwrap_or(0);

            let ledger_span = tracing::info_span!(
                "ledger.append",
                trace_id = %session.trace_id,
                request_id = %request_id,
                session_id = %session.session_id,
                event_type = "OPERATOR_CALL",
                latency_ms = tracing::field::Empty,
                outcome = tracing::field::Empty,
            );

            async {
                let started = Instant::now();
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

                let next_operator_calls_used = session.operator_calls_used.saturating_add(1);
                let next_bytes_used =
                    session.bytes_used.saturating_add(params_bytes + result_bytes);

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
                            "cache_hit": cache_hit,
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
                persist_session_runtime(&state, &session)
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

                tracing::Span::current().record(
                    "latency_ms",
                    started.elapsed().as_millis() as u64,
                );
                tracing::Span::current().record("outcome", "ok");

                Ok::<_, ApiError>(())
            }
            .instrument(ledger_span)
            .await?;

            let latency_ms = started.elapsed().as_millis() as u64;
            let terminal_mode = response.terminal_mode.as_str();
            let operator_calls_used = session.operator_calls_used;
            let bytes_used = session.bytes_used;
            let outcome = if status == StatusCode::OK {
                "ok"
            } else {
                "error"
            };

            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("result_bytes", result_bytes);
            tracing::Span::current().record("terminal_mode", terminal_mode);
            tracing::Span::current().record("operator_calls_used", operator_calls_used);
            tracing::Span::current().record("bytes_used", bytes_used);
            tracing::Span::current().record("outcome", outcome);

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
        .instrument(operator_span)
        .await
    })
    .await;

    let status = match &handler_result {
        Ok(_) => StatusCode::OK,
        Err((status, _)) => *status,
    };
    crate::metrics::observe_http_request(
        "/v1/operators",
        "POST",
        status.as_u16(),
        request_started.elapsed(),
    );

    let outcome = if handler_result.is_ok() {
        "success"
    } else {
        "error"
    };
    crate::metrics::observe_operator_call(op_name_for_metrics.as_str(), outcome);
    match &handler_result {
        Ok(Json(body)) => {
            crate::metrics::observe_terminal_mode("/v1/operators", body.terminal_mode.as_str());
        }
        Err((_, Json(err))) => {
            crate::metrics::observe_terminal_mode("/v1/operators", err.terminal_mode_hint.as_str())
        }
    }

    handler_result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence_unit(
        span_or_row_spec: serde_json::Value,
        content: serde_json::Value,
        content_type: EvidenceContentType,
    ) -> EvidenceUnit {
        EvidenceUnit {
            source_system: "pg_safeview".to_string(),
            object_id: "safe_customer_view_public:cust_public_1".to_string(),
            version_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            span_or_row_spec,
            content_type,
            content: Some(content),
            content_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            retrieved_at: "1970-01-01T00:00:00Z".to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            policy_snapshot_id: "policy".to_string(),
            policy_snapshot_hash:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        }
    }

    #[test]
    fn normalize_operator_params_normalizes_search_inputs() {
        let params = serde_json::json!({
            "query": "  refund   policy ",
            "limit": 0,
            "object_prefix": "\\public\\support\\",
            "match_mode": "PHRASE"
        });

        let normalized = normalize_operator_params("search", &params, 8)
            .expect("search params should normalize");

        assert_eq!(normalized["query"], serde_json::json!("refund policy"));
        assert_eq!(normalized["limit"], serde_json::json!(1));
        assert_eq!(
            normalized["object_prefix"],
            serde_json::json!("public/support")
        );
        assert_eq!(normalized["match_mode"], serde_json::json!("phrase"));
    }

    #[test]
    fn normalize_operator_params_normalizes_safeview_inputs() {
        let params = serde_json::json!({
            "view_id": "SAFE-Customer View Public",
            "fields": "status, planTier"
        });

        let normalized = normalize_operator_params("fetch_rows", &params, 8)
            .expect("safeview params should normalize");

        assert_eq!(
            normalized["view_id"],
            serde_json::json!("safe_customer_view_public")
        );
        assert_eq!(
            normalized["fields"],
            serde_json::json!(["plan_tier", "status"])
        );
    }

    #[test]
    fn normalize_operator_params_rejects_invalid_search_match_mode() {
        let params = serde_json::json!({
            "query": "refund policy",
            "match_mode": "fuzzy"
        });

        let err =
            normalize_operator_params("search", &params, 8).expect_err("invalid mode must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.0.message.contains("match_mode"));
    }

    #[test]
    fn normalize_operator_params_normalizes_aggregate_inputs() {
        let params = serde_json::json!({
            "view_id": "SAFE Customer View Public",
            "group_by": "planTier, status",
            "metrics": [{ "name": "COUNT", "field": "customerId" }],
            "time_granularity": "MONTH"
        });

        let normalized = normalize_operator_params("aggregate", &params, 8)
            .expect("aggregate params should normalize");

        assert_eq!(
            normalized["view_id"],
            serde_json::json!("safe_customer_view_public")
        );
        assert_eq!(
            normalized["group_by"],
            serde_json::json!(["plan_tier", "status"])
        );
        assert_eq!(
            normalized["metrics"],
            serde_json::json!([{ "name": "count", "field": "customer_id" }])
        );
        assert_eq!(normalized["time_granularity"], serde_json::json!("month"));
    }

    #[test]
    fn normalize_operator_params_normalizes_compare_inputs() {
        let params = serde_json::json!({
            "view_id": "SAFE Customer View Public",
            "group_by": "planTier",
            "metrics": [{ "name": "COUNT", "field": "customerId" }],
            "filter_spec": { "status": "active" }
        });

        let normalized = normalize_operator_params("compare", &params, 8)
            .expect("compare params should normalize");

        assert_eq!(
            normalized["view_id"],
            serde_json::json!("safe_customer_view_public")
        );
        assert_eq!(normalized["group_by"], serde_json::json!(["plan_tier"]));
        assert_eq!(
            normalized["metrics"],
            serde_json::json!([{ "name": "count", "field": "customer_id" }])
        );
        assert_eq!(
            normalized["filter_spec"],
            serde_json::json!({ "status": "active" })
        );
    }

    #[test]
    fn normalize_operator_params_supports_ranking_and_drilldown_inputs() {
        let params = serde_json::json!({
            "view_id": "SAFE Customer View Public",
            "group_by": "planTier",
            "metrics": [{ "name": "COUNT", "field": "customerId" }],
            "top_n": 99,
            "include_rank": true,
            "rank_direction": "ASC",
            "drilldown_dimension": "status",
            "filter_spec": { "planTier": "starter" }
        });

        let normalized = normalize_operator_params("aggregate", &params, 8)
            .expect("aggregate ranking params should normalize");

        assert_eq!(normalized["group_by"], serde_json::json!(["plan_tier"]));
        assert_eq!(normalized["top_n"], serde_json::json!(50));
        assert_eq!(normalized["include_rank"], serde_json::json!(true));
        assert_eq!(normalized["rank_direction"], serde_json::json!("asc"));
        assert_eq!(
            normalized["drilldown_dimension"],
            serde_json::json!("status")
        );
        assert_eq!(
            normalized["filter_spec"],
            serde_json::json!({ "plan_tier": "starter" })
        );
    }

    #[test]
    fn normalize_operator_params_normalizes_dimension_discovery_inputs() {
        let params = serde_json::json!({
            "view_id": "SAFE Customer View Public",
            "filter_spec": { "planTier": "starter" },
            "max_values_per_dimension": 50
        });

        let normalized = normalize_operator_params("discover_dimensions", &params, 8)
            .expect("dimension discovery params should normalize");

        assert_eq!(
            normalized["view_id"],
            serde_json::json!("safe_customer_view_public")
        );
        assert_eq!(
            normalized["filter_spec"],
            serde_json::json!({ "plan_tier": "starter" })
        );
        assert_eq!(
            normalized["max_values_per_dimension"],
            serde_json::json!(10)
        );
    }

    #[test]
    fn normalize_operator_params_normalizes_lookup_evidence_inputs() {
        let params = serde_json::json!({
            "query": "  support   policy ",
            "limit": 0,
            "max_refs": 9,
            "object_prefix": "\\public\\"
        });

        let normalized = normalize_operator_params("lookup_evidence", &params, 8)
            .expect("lookup evidence params should normalize");

        assert_eq!(normalized["query"], serde_json::json!("support policy"));
        assert_eq!(normalized["limit"], serde_json::json!(1));
        assert_eq!(normalized["max_refs"], serde_json::json!(5));
        assert_eq!(normalized["object_prefix"], serde_json::json!("public"));
    }

    #[test]
    fn summarize_operator_result_surfaces_search_preview() {
        let result = serde_json::json!({
            "refs": [
                {
                    "object_id": "public/refund_policy.txt",
                    "line_start": 2,
                    "line_end": 2,
                    "match_preview": "Annual plan refunds are available within 30 days."
                }
            ]
        });

        let summary = summarize_operator_result("search", &result, &[])
            .expect("search summary should be available");

        assert!(summary.contains("1 matching evidence refs"));
        assert!(summary.contains("public/refund_policy.txt line 2"));
        assert!(summary.contains("Annual plan refunds are available within 30 days"));
    }

    #[test]
    fn summarize_operator_result_surfaces_structured_evidence_summary() {
        let unit = sample_evidence_unit(
            serde_json::json!({
                "type": "db_row",
                "view_id": "safe_customer_view_public",
                "primary_key": { "customer_id": "cust_public_1" }
            }),
            serde_json::json!({
                "status": "active",
                "plan_tier": "starter"
            }),
            EvidenceContentType::ApplicationJson,
        );

        let summary = summarize_operator_result("fetch_rows", &serde_json::json!([]), &[unit])
            .expect("structured evidence summary should be available");

        assert!(
            summary
                .contains("safe_customer_view_public:cust_public_1 row customer_id=cust_public_1")
        );
        assert!(summary.contains("plan_tier=starter"));
        assert!(summary.contains("status=active"));
    }

    #[test]
    fn summarize_operator_result_prefers_compare_summary_when_available() {
        let unit = sample_evidence_unit(
            serde_json::json!({
                "type": "db_aggregate",
                "view_id": "safe_customer_view_public"
            }),
            serde_json::json!({
                "rows": [
                    {
                        "group": { "plan_tier": "starter" },
                        "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
                    }
                ],
                "comparison_summary": {
                    "kind": "group_compare",
                    "summary": "count(customer_id) is highest for plan_tier=starter (9)",
                    "highlights": ["plan_tier=starter count(customer_id)=9"]
                }
            }),
            EvidenceContentType::ApplicationJson,
        );

        let summary = summarize_operator_result("compare", &serde_json::json!({}), &[unit])
            .expect("compare summary should be available");

        assert!(summary.contains("aggregate"));
        assert!(summary.contains("highest for plan_tier=starter"));
    }

    #[test]
    fn summarize_operator_result_surfaces_version_and_diff_summaries() {
        let versions_summary = summarize_operator_result(
            "list_versions",
            &serde_json::json!({
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
            }),
            &[],
        )
        .expect("version summary should be available");
        assert!(versions_summary.contains("latest 999999999999"));
        assert!(versions_summary.contains("previous 111111111111"));

        let diff_unit = EvidenceUnit {
            source_system: "fs_corpus".to_string(),
            object_id: "public/support_policy.txt".to_string(),
            version_id: "9999999999999999999999999999999999999999999999999999999999999999"
                .to_string(),
            span_or_row_spec: serde_json::json!({
                "type": "diff",
                "object_id": "public/support_policy.txt",
                "v1": "1111111111111111111111111111111111111111111111111111111111111111",
                "v2": "9999999999999999999999999999999999999999999999999999999999999999"
            }),
            content_type: EvidenceContentType::TextPlain,
            content: Some(serde_json::json!(
                "--- a/public/support_policy.txt\n+++ b/public/support_policy.txt\n@@\n-Refunds are unavailable for annual plans.\n+Annual plans may request refunds within 30 days of purchase.\n"
            )),
            content_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            retrieved_at: "1970-01-01T00:00:00Z".to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            policy_snapshot_id: "policy".to_string(),
            policy_snapshot_hash:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        };

        let diff_summary = summarize_operator_result("diff", &serde_json::json!({}), &[diff_unit])
            .expect("diff summary should be available");
        assert!(diff_summary.contains("changed:"));
        assert!(diff_summary.contains("added 'Annual plans may request refunds"));
        assert!(diff_summary.contains("removed 'Refunds are unavailable"));
    }

    #[test]
    fn summarize_operator_result_surfaces_dimension_discovery_summary() {
        let unit = sample_evidence_unit(
            serde_json::json!({
                "type": "db_dimension_discovery",
                "view_id": "safe_customer_view_public"
            }),
            serde_json::json!({
                "view_id": "safe_customer_view_public",
                "available_dimensions": ["status", "plan_tier"],
                "metrics": [{ "name": "count", "field": "customer_id" }],
                "dimensions": [
                    {
                        "field": "status",
                        "top_values": [
                            { "value": "active", "count": 10 },
                            { "value": "inactive", "count": 3 }
                        ],
                        "drilldown_supported": true
                    }
                ]
            }),
            EvidenceContentType::ApplicationJson,
        );

        let summary =
            summarize_operator_result("discover_dimensions", &serde_json::json!({}), &[unit])
                .expect("discover_dimensions summary should be available");

        assert!(summary.contains("dimensions:"));
        assert!(summary.contains("status [active=10, inactive=3]"));
    }
}
