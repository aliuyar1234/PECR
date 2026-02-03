use hex::ToHex;
use sha2::Digest;
use unicode_normalization::UnicodeNormalization;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().encode_hex::<String>()
}

pub fn is_sha256_hex(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn canonicalize_text_plain(input: &str) -> String {
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");
    normalized.nfc().collect::<String>()
}

pub fn canonicalize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Null => serde_json::Value::Null,
        serde_json::Value::Bool(v) => serde_json::Value::Bool(*v),
        serde_json::Value::Number(v) => serde_json::Value::Number(v.clone()),
        serde_json::Value::String(v) => serde_json::Value::String(v.clone()),
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(canonicalize_json_value)
                .collect::<Vec<_>>(),
        ),
        serde_json::Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in entries {
                out.insert(k.clone(), canonicalize_json_value(v));
            }
            serde_json::Value::Object(out)
        }
    }
}

pub fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    let canonical = canonicalize_json_value(value);
    serde_json::to_vec(&canonical).unwrap_or_else(|_| b"null".to_vec())
}

pub fn canonical_json_string(value: &serde_json::Value) -> String {
    String::from_utf8(canonical_json_bytes(value)).unwrap_or_else(|_| "null".to_string())
}

pub fn hash_canonical_json(value: &serde_json::Value) -> String {
    sha256_hex(&canonical_json_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = serde_json::json!({
            "b": 1,
            "a": {
                "d": 4,
                "c": 3
            }
        });

        assert_eq!(
            canonical_json_string(&value),
            r#"{"a":{"c":3,"d":4},"b":1}"#
        );
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        let value = serde_json::json!({"a":[{"b":2},{"a":1}]});
        assert_eq!(canonical_json_string(&value), r#"{"a":[{"b":2},{"a":1}]}"#);
    }

    #[test]
    fn text_plain_normalizes_line_endings_and_unicode_nfc() {
        let input = "line1\r\nline2\rline3\ne\u{0301}";
        let canonical = canonicalize_text_plain(input);
        assert_eq!(canonical, "line1\nline2\nline3\n\u{00e9}");
    }

    #[test]
    fn sha256_hex_is_lowercase_and_valid() {
        let h = sha256_hex(b"abc");
        assert!(is_sha256_hex(&h));
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
