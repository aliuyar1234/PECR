use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyDecision {
    pub allow: bool,
    #[serde(default)]
    pub cacheable: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub redaction: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRedaction {
    Allow(Vec<String>),
    Deny(Vec<String>),
}

impl FieldRedaction {
    pub fn keeps_key(&self, key: &str) -> bool {
        match self {
            FieldRedaction::Allow(fields) => {
                fields.binary_search_by(|f| f.as_str().cmp(key)).is_ok()
            }
            FieldRedaction::Deny(fields) => {
                fields.binary_search_by(|f| f.as_str().cmp(key)).is_err()
            }
        }
    }

    pub fn apply_to_field_list(&self, fields: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(fields.len());
        for field in fields {
            if self.keeps_key(field.as_str()) {
                out.push(field.clone());
            }
        }
        out
    }

    pub fn params_value(&self) -> Value {
        match self {
            FieldRedaction::Allow(fields) => serde_json::json!({ "allow_fields": fields }),
            FieldRedaction::Deny(fields) => serde_json::json!({ "deny_fields": fields }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRedactionError {
    message: String,
}

impl ParseRedactionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseRedactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseRedactionError {}

pub fn parse_field_redaction(
    redaction: Option<&Value>,
) -> Result<Option<FieldRedaction>, ParseRedactionError> {
    let Some(redaction) = redaction else {
        return Ok(None);
    };

    let Some(obj) = redaction.as_object() else {
        return Err(ParseRedactionError::new(
            "policy redaction must be an object",
        ));
    };

    if obj.is_empty() {
        return Ok(None);
    }

    let allow_fields = parse_fields(obj, "allow_fields")?;
    let deny_fields = parse_fields(obj, "deny_fields")?;

    if allow_fields.is_some() && deny_fields.is_some() {
        return Err(ParseRedactionError::new(
            "policy redaction cannot specify both allow_fields and deny_fields",
        ));
    }

    Ok(match (allow_fields, deny_fields) {
        (Some(fields), None) => Some(FieldRedaction::Allow(fields)),
        (None, Some(fields)) => Some(FieldRedaction::Deny(fields)),
        _ => None,
    })
}

fn parse_fields(
    obj: &Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, ParseRedactionError> {
    let Some(value) = obj.get(key) else {
        return Ok(None);
    };

    let Some(arr) = value.as_array() else {
        return Err(ParseRedactionError::new(format!(
            "policy redaction `{}` must be an array",
            key
        )));
    };

    let mut out = Vec::with_capacity(arr.len());
    for raw in arr {
        let field = raw
            .as_str()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ParseRedactionError::new(format!(
                    "policy redaction `{}` must be a string array",
                    key
                ))
            })?;
        out.push(field.to_string());
    }

    out.sort();
    out.dedup();
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_redaction_allow_and_deny() {
        let allow = parse_field_redaction(Some(&serde_json::json!({
            "allow_fields": ["b", "a", "a"]
        })))
        .expect("allow redaction should parse")
        .expect("allow redaction should exist");
        assert_eq!(
            allow,
            FieldRedaction::Allow(vec!["a".to_string(), "b".to_string()])
        );

        let deny = parse_field_redaction(Some(&serde_json::json!({
            "deny_fields": ["secret"]
        })))
        .expect("deny redaction should parse")
        .expect("deny redaction should exist");
        assert_eq!(deny, FieldRedaction::Deny(vec!["secret".to_string()]));
    }

    #[test]
    fn parse_redaction_rejects_invalid_shapes() {
        let err = parse_field_redaction(Some(&serde_json::json!({
            "allow_fields": "secret"
        })))
        .unwrap_err();
        assert!(err.to_string().contains("must be an array"));

        let err = parse_field_redaction(Some(&serde_json::json!({
            "allow_fields": ["a"],
            "deny_fields": ["b"]
        })))
        .unwrap_err();
        assert!(err.to_string().contains("cannot specify both"));
    }

    #[test]
    fn keeps_key_and_apply_to_field_list_follow_rule() {
        let deny = FieldRedaction::Deny(vec!["secret".to_string()]);
        assert!(deny.keeps_key("status"));
        assert!(!deny.keeps_key("secret"));

        let filtered = deny.apply_to_field_list(&[
            "tenant_id".to_string(),
            "secret".to_string(),
            "status".to_string(),
        ]);
        assert_eq!(
            filtered,
            vec!["tenant_id".to_string(), "status".to_string()]
        );
    }
}
