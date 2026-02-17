use axum::http::StatusCode;
use pecr_contracts::canonical;
use pecr_contracts::{EvidenceContentType, EvidenceUnit, TerminalMode, TransformStep};
use pecr_policy::{FieldRedaction, parse_field_redaction as parse_policy_field_redaction};

use super::{ApiError, json_error};

pub(super) fn parse_field_redaction(
    redaction: Option<&serde_json::Value>,
) -> Result<Option<FieldRedaction>, ApiError> {
    parse_policy_field_redaction(redaction).map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            err.to_string(),
            TerminalMode::InsufficientPermission,
            false,
        )
    })
}

pub(super) fn apply_field_redaction(
    value: &serde_json::Value,
    redaction: &FieldRedaction,
) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if redaction.keeps_key(k.as_str()) {
                    out.insert(k.clone(), apply_field_redaction(v, redaction));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|v| apply_field_redaction(v, redaction))
                .collect::<Vec<_>>(),
        ),
        _ => value.clone(),
    }
}

pub(super) fn redact_span_or_row_spec_fields(
    span_or_row_spec: &serde_json::Value,
    redaction: &FieldRedaction,
) -> serde_json::Value {
    let Some(obj) = span_or_row_spec.as_object() else {
        return span_or_row_spec.clone();
    };

    let Some(fields_value) = obj.get("fields") else {
        return span_or_row_spec.clone();
    };
    let Some(fields) = fields_value.as_array() else {
        return span_or_row_spec.clone();
    };

    let mut parsed = fields
        .iter()
        .filter_map(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect::<Vec<_>>();
    parsed.sort();
    parsed.dedup();

    let redacted_fields = redaction.apply_to_field_list(&parsed);

    let mut out = obj.clone();
    out.insert(
        "fields".to_string(),
        serde_json::Value::Array(
            redacted_fields
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    serde_json::Value::Object(out)
}

pub(super) fn compute_content_hash(
    content_type: EvidenceContentType,
    content: &serde_json::Value,
) -> Result<String, ApiError> {
    match content_type {
        EvidenceContentType::ApplicationJson => Ok(canonical::hash_canonical_json(content)),
        EvidenceContentType::TextPlain => {
            let text = content.as_str().ok_or_else(|| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    "text/plain evidence content must be a string".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?;
            let canonical_text = canonical::canonicalize_text_plain(text);
            Ok(canonical::sha256_hex(canonical_text.as_bytes()))
        }
    }
}

pub(super) fn compute_evidence_unit_id(evidence: &EvidenceUnit) -> String {
    let identity = serde_json::json!({
        "source_system": evidence.source_system.as_str(),
        "object_id": evidence.object_id.as_str(),
        "version_id": evidence.version_id.as_str(),
        "span_or_row_spec": &evidence.span_or_row_spec,
        "content_hash": evidence.content_hash.as_str(),
        "as_of_time": evidence.as_of_time.as_str(),
        "policy_snapshot_hash": evidence.policy_snapshot_hash.as_str(),
        "transform_chain": &evidence.transform_chain,
    });
    canonical::hash_canonical_json(&identity)
}

pub(super) fn apply_field_redaction_to_evidence_unit(
    mut evidence: EvidenceUnit,
    redaction: &FieldRedaction,
) -> Result<EvidenceUnit, ApiError> {
    if evidence.content_type != EvidenceContentType::ApplicationJson {
        return Ok(evidence);
    }

    let Some(content) = evidence.content.as_ref() else {
        return Ok(evidence);
    };

    let redacted_content = apply_field_redaction(content, redaction);
    if redacted_content == *content {
        return Ok(evidence);
    }

    evidence.content = Some(redacted_content);
    evidence.content_hash = compute_content_hash(
        EvidenceContentType::ApplicationJson,
        evidence.content.as_ref().unwrap(),
    )?;
    evidence.span_or_row_spec =
        redact_span_or_row_spec_fields(&evidence.span_or_row_spec, redaction);

    let step_params = redaction.params_value();
    let step_hash = canonical::hash_canonical_json(&step_params);
    evidence.transform_chain.push(TransformStep {
        transform_type: "redaction".to_string(),
        transform_hash: step_hash,
        params: Some(step_params),
    });

    evidence.evidence_unit_id = compute_evidence_unit_id(&evidence);
    Ok(evidence)
}
