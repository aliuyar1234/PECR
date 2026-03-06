use std::fmt;

const MAX_REQUEST_FIELDS: usize = 32;
const MAX_SEARCH_QUERY_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterSurface {
    Filesystem,
    Safeview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRequest {
    pub surface: AdapterSurface,
    pub resource_id: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInputError {
    message: String,
}

impl AdapterInputError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AdapterInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AdapterInputError {}

impl AdapterRequest {
    pub fn filesystem(object_id: &str) -> Result<Self, AdapterInputError> {
        Ok(Self {
            surface: AdapterSurface::Filesystem,
            resource_id: normalize_resource_id(object_id)?,
            fields: Vec::new(),
        })
    }

    pub fn safeview(view_id: &str, fields: &[String]) -> Result<Self, AdapterInputError> {
        let normalized_view_id = normalize_safeview_id(view_id)?;
        let normalized_fields = normalize_fields(fields)?;
        Ok(Self {
            surface: AdapterSurface::Safeview,
            resource_id: normalized_view_id,
            fields: normalized_fields,
        })
    }
}

pub fn normalize_resource_id(raw: &str) -> Result<String, AdapterInputError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdapterInputError::new("resource_id must be non-empty"));
    }
    normalize_resource_path(trimmed)
}

pub fn normalize_resource_prefix(raw: &str) -> Result<String, AdapterInputError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdapterInputError::new("resource prefix must be non-empty"));
    }
    normalize_resource_path(trimmed)
}

pub fn normalize_safeview_id(raw: &str) -> Result<String, AdapterInputError> {
    let normalized = normalize_identifier(raw)?;
    if normalized.is_empty() {
        return Err(AdapterInputError::new("view_id must be non-empty"));
    }
    if !normalized.starts_with("safe_") {
        return Err(AdapterInputError::new("view_id must start with 'safe_'"));
    }
    Ok(normalized)
}

pub fn normalize_fields(fields: &[String]) -> Result<Vec<String>, AdapterInputError> {
    if fields.len() > MAX_REQUEST_FIELDS {
        return Err(AdapterInputError::new(format!(
            "requested field count exceeds {}",
            MAX_REQUEST_FIELDS
        )));
    }

    let mut normalized = Vec::with_capacity(fields.len());
    for field in fields {
        let normalized_field = normalize_identifier(field)?;
        if normalized_field.is_empty() {
            return Err(AdapterInputError::new("field names must be non-empty"));
        }
        normalized.push(normalized_field);
    }

    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

pub fn normalize_search_query(raw: &str) -> Result<String, AdapterInputError> {
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err(AdapterInputError::new("query must be non-empty"));
    }
    if normalized.chars().any(char::is_control) {
        return Err(AdapterInputError::new(
            "query must not contain control characters",
        ));
    }
    if normalized.len() > MAX_SEARCH_QUERY_CHARS {
        return Err(AdapterInputError::new(format!(
            "query exceeds {} characters",
            MAX_SEARCH_QUERY_CHARS
        )));
    }
    Ok(normalized)
}

fn normalize_resource_path(raw: &str) -> Result<String, AdapterInputError> {
    let replaced = raw.replace('\\', "/");
    let trimmed = replaced.trim_matches('/');
    if trimmed.is_empty() {
        return Err(AdapterInputError::new("resource_id must be non-empty"));
    }
    if replaced.starts_with("//") || replaced.contains(':') {
        return Err(AdapterInputError::new(
            "resource_id must be a relative path",
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AdapterInputError::new(
            "resource_id must not contain control characters",
        ));
    }

    let segments = trimmed
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Err(AdapterInputError::new("resource_id must be non-empty"));
    }

    let mut normalized = Vec::with_capacity(segments.len());
    for segment in segments {
        if segment == "." || segment == ".." {
            return Err(AdapterInputError::new(
                "resource_id must not contain parent traversal segments",
            ));
        }
        if segment.chars().any(char::is_control) {
            return Err(AdapterInputError::new(
                "resource_id must not contain control characters",
            ));
        }
        normalized.push(segment);
    }

    let joined = normalized.join("/");
    if joined.is_empty() {
        return Err(AdapterInputError::new("resource_id must be non-empty"));
    }
    Ok(joined)
}

fn normalize_identifier(raw: &str) -> Result<String, AdapterInputError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdapterInputError::new("identifier must be non-empty"));
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut previous_was_separator = false;
    let mut previous_was_lower_or_digit = false;

    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && previous_was_lower_or_digit && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
            previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
            continue;
        }

        if matches!(ch, '_' | '-' | ' ' | '\t') {
            if !out.is_empty() && !previous_was_separator {
                out.push('_');
            }
            previous_was_separator = true;
            previous_was_lower_or_digit = false;
            continue;
        }

        return Err(AdapterInputError::new(
            "identifiers must contain only ASCII letters, digits, spaces, '-', or '_'",
        ));
    }

    let normalized = out.trim_matches('_').to_string();
    if normalized.is_empty() {
        return Err(AdapterInputError::new("identifier must be non-empty"));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_request_normalizes_resource_id() {
        let request = AdapterRequest::filesystem(" public\\public_1.txt ").expect("request ok");
        assert_eq!(request.surface, AdapterSurface::Filesystem);
        assert_eq!(request.resource_id, "public/public_1.txt");
        assert!(request.fields.is_empty());
    }

    #[test]
    fn normalize_resource_id_rejects_parent_traversal() {
        let err = normalize_resource_id("../secrets.txt").expect_err("must reject traversal");
        assert!(err.to_string().contains("parent traversal"));
    }

    #[test]
    fn safeview_request_normalizes_fields() {
        let request = AdapterRequest::safeview(
            " Safe-Customer View Public ",
            &[
                "planTier".to_string(),
                "status".to_string(),
                "status ".to_string(),
            ],
        )
        .expect("request ok");
        assert_eq!(request.surface, AdapterSurface::Safeview);
        assert_eq!(request.resource_id, "safe_customer_view_public");
        assert_eq!(
            request.fields,
            vec!["plan_tier".to_string(), "status".to_string()]
        );
    }

    #[test]
    fn normalize_safeview_id_rejects_non_safe_prefix() {
        let err = normalize_safeview_id("customer_view_public").expect_err("must reject prefix");
        assert!(err.to_string().contains("safe_"));
    }

    #[test]
    fn normalize_fields_rejects_invalid_characters() {
        let err = normalize_fields(&["admin.note".to_string()]).expect_err("must reject field");
        assert!(err.to_string().contains("ASCII letters"));
    }

    #[test]
    fn normalize_resource_prefix_trims_slashes() {
        let prefix = normalize_resource_prefix(" /public/support// ").expect("prefix ok");
        assert_eq!(prefix, "public/support");
    }

    #[test]
    fn normalize_search_query_collapses_whitespace() {
        let query = normalize_search_query("  refund   policy \n terms ").expect("query ok");
        assert_eq!(query, "refund policy terms");
    }
}
