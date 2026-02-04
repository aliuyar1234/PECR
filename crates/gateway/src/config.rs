use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub db_url: String,
    pub opa_url: String,
    pub opa_timeout_ms: u64,
    pub policy_bundle_hash: String,
    pub ledger_write_timeout_ms: u64,
    pub cache_max_entries: usize,
    pub cache_ttl_ms: u64,
    pub session_token_ttl_secs: u64,
    pub evidence_payload_store_mode: EvidencePayloadStoreMode,
    pub auth_mode: AuthMode,
    pub fs_corpus_path: String,
    pub fs_version_cache_max_bytes: usize,
    pub fs_version_cache_max_versions_per_object: usize,
    pub fs_diff_max_bytes: usize,
    pub pg_safeview_query_timeout_ms: u64,
    pub pg_safeview_max_rows: usize,
    pub pg_safeview_max_fields: usize,
    pub pg_safeview_max_groups: usize,
    pub coverage_threshold: f64,
    pub as_of_time_default: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidencePayloadStoreMode {
    MetadataOnly,
    PayloadEnabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Local,
    Oidc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StartupError {}

impl GatewayConfig {
    pub fn load() -> Result<Self, StartupError> {
        let mut merged = HashMap::new();

        if let Ok(config_path) = std::env::var("PECR_CONFIG_PATH") {
            let config_path = config_path.trim();
            if !config_path.is_empty() {
                let file_kv = parse_env_file(config_path)?;
                merged.extend(file_kv);
            }
        }

        merged.extend(std::env::vars());

        Self::from_kv(&merged)
    }

    pub fn from_kv(kv: &HashMap<String, String>) -> Result<Self, StartupError> {
        let bind_addr = parse_socket_addr(
            kv.get("PECR_BIND_ADDR"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            "PECR_BIND_ADDR",
        )?;

        let auth_mode = parse_auth_mode(kv.get("PECR_AUTH_MODE"))?;

        let dev_allow_nonlocal_bind =
            parse_bool(kv.get("PECR_DEV_ALLOW_NONLOCAL_BIND")).unwrap_or(false);

        if !bind_addr.ip().is_loopback() && auth_mode != AuthMode::Oidc {
            if dev_allow_nonlocal_bind && is_unspecified_ip(bind_addr.ip()) {
                // Explicit dev-only escape hatch for docker compose / local containers.
            } else {
                return Err(StartupError {
                    code: "ERR_NONLOCAL_BIND_REQUIRES_AUTH",
                    message: "non-local bind requires production auth mode; refuse startup"
                        .to_string(),
                });
            }
        }

        if auth_mode == AuthMode::Oidc {
            return Err(StartupError {
                code: "ERR_AUTH_MODE_UNIMPLEMENTED",
                message: "oidc auth mode is not implemented yet; refuse startup".to_string(),
            });
        }

        let db_url = require_nonempty(kv, "PECR_DB_URL")?;
        let opa_url = require_nonempty(kv, "PECR_OPA_URL")?;

        let opa_timeout_ms = parse_u64(kv.get("PECR_OPA_TIMEOUT_MS"), 200, "PECR_OPA_TIMEOUT_MS")?;

        let policy_bundle_hash = require_nonempty(kv, "PECR_POLICY_BUNDLE_HASH")?;
        if !is_lower_hex_64(&policy_bundle_hash) {
            return Err(StartupError {
                code: "ERR_INVALID_POLICY_BUNDLE_HASH",
                message: "PECR_POLICY_BUNDLE_HASH must be 64 lowercase hex chars".to_string(),
            });
        }

        let cache_max_entries = parse_usize(
            kv.get("PECR_CACHE_MAX_ENTRIES"),
            0,
            "PECR_CACHE_MAX_ENTRIES",
        )?;
        let cache_ttl_ms = parse_u64(kv.get("PECR_CACHE_TTL_MS"), 0, "PECR_CACHE_TTL_MS")?;

        let ledger_write_timeout_ms = parse_u64(
            kv.get("PECR_LEDGER_WRITE_TIMEOUT_MS"),
            500,
            "PECR_LEDGER_WRITE_TIMEOUT_MS",
        )?;

        let session_token_ttl_secs = parse_u64(
            kv.get("PECR_SESSION_TOKEN_TTL_SECS"),
            15 * 60,
            "PECR_SESSION_TOKEN_TTL_SECS",
        )?;

        let evidence_payload_store_mode =
            parse_store_mode(kv.get("PECR_EVIDENCE_PAYLOAD_STORE_MODE"))?;

        let fs_corpus_path = kv
            .get("PECR_FS_CORPUS_PATH")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("fixtures/fs_corpus")
            .to_string();

        let fs_version_cache_max_bytes = parse_usize(
            kv.get("PECR_FS_VERSION_CACHE_MAX_BYTES"),
            2 * 1024 * 1024,
            "PECR_FS_VERSION_CACHE_MAX_BYTES",
        )?;

        let fs_version_cache_max_versions_per_object = parse_usize(
            kv.get("PECR_FS_VERSION_CACHE_MAX_VERSIONS_PER_OBJECT"),
            16,
            "PECR_FS_VERSION_CACHE_MAX_VERSIONS_PER_OBJECT",
        )?;

        let fs_diff_max_bytes = parse_usize(
            kv.get("PECR_FS_DIFF_MAX_BYTES"),
            32 * 1024,
            "PECR_FS_DIFF_MAX_BYTES",
        )?;

        let pg_safeview_query_timeout_ms = parse_u64(
            kv.get("PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS"),
            200,
            "PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS",
        )?;

        let pg_safeview_max_rows = parse_usize(
            kv.get("PECR_PG_SAFEVIEW_MAX_ROWS"),
            200,
            "PECR_PG_SAFEVIEW_MAX_ROWS",
        )?;

        let pg_safeview_max_fields = parse_usize(
            kv.get("PECR_PG_SAFEVIEW_MAX_FIELDS"),
            50,
            "PECR_PG_SAFEVIEW_MAX_FIELDS",
        )?;

        let pg_safeview_max_groups = parse_usize(
            kv.get("PECR_PG_SAFEVIEW_MAX_GROUPS"),
            200,
            "PECR_PG_SAFEVIEW_MAX_GROUPS",
        )?;

        let coverage_threshold = parse_f64(
            kv.get("PECR_COVERAGE_THRESHOLD"),
            0.95,
            "PECR_COVERAGE_THRESHOLD",
        )?;
        if !coverage_threshold.is_finite() || !(0.0..=1.0).contains(&coverage_threshold) {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: "PECR_COVERAGE_THRESHOLD must be between 0 and 1".to_string(),
            });
        }

        let as_of_time_default = kv
            .get("PECR_AS_OF_TIME_DEFAULT")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("1970-01-01T00:00:00Z")
            .to_string();

        Ok(Self {
            bind_addr,
            db_url,
            opa_url,
            opa_timeout_ms,
            policy_bundle_hash,
            ledger_write_timeout_ms,
            cache_max_entries,
            cache_ttl_ms,
            session_token_ttl_secs,
            evidence_payload_store_mode,
            auth_mode,
            fs_corpus_path,
            fs_version_cache_max_bytes,
            fs_version_cache_max_versions_per_object,
            fs_diff_max_bytes,
            pg_safeview_query_timeout_ms,
            pg_safeview_max_rows,
            pg_safeview_max_fields,
            pg_safeview_max_groups,
            coverage_threshold,
            as_of_time_default,
        })
    }
}

fn parse_env_file(path: &str) -> Result<HashMap<String, String>, StartupError> {
    let contents = std::fs::read_to_string(path).map_err(|_| StartupError {
        code: "ERR_CONFIG_FILE_READ",
        message: format!("failed to read config file at {}", path),
    })?;

    let mut kv = HashMap::new();

    for (idx, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| StartupError {
            code: "ERR_CONFIG_FILE_PARSE",
            message: format!("invalid config line {} (expected KEY=VALUE)", idx + 1),
        })?;

        let key = key.trim();
        if key.is_empty() {
            return Err(StartupError {
                code: "ERR_CONFIG_FILE_PARSE",
                message: format!("invalid config line {} (empty key)", idx + 1),
            });
        }

        let mut value = value.trim().to_string();
        value = strip_quotes(&value);
        kv.insert(key.to_string(), value);
    }

    Ok(kv)
}

fn strip_quotes(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return s[1..bytes.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn require_nonempty(
    kv: &HashMap<String, String>,
    key: &'static str,
) -> Result<String, StartupError> {
    let Some(value) = kv.get(key) else {
        return Err(StartupError {
            code: "ERR_MISSING_CONFIG",
            message: format!("missing required config key {}", key),
        });
    };

    let value = value.trim();
    if value.is_empty() {
        return Err(StartupError {
            code: "ERR_MISSING_CONFIG",
            message: format!("missing required config key {}", key),
        });
    }

    Ok(value.to_string())
}

fn parse_socket_addr(
    value: Option<&String>,
    default: SocketAddr,
    key: &'static str,
) -> Result<SocketAddr, StartupError> {
    match value {
        None => Ok(default),
        Some(v) => v.parse::<SocketAddr>().map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: format!("{} must be a valid host:port socket address", key),
        }),
    }
}

fn parse_usize(
    value: Option<&String>,
    default: usize,
    key: &'static str,
) -> Result<usize, StartupError> {
    match value {
        None => Ok(default),
        Some(v) if v.trim().is_empty() => Ok(default),
        Some(v) => v.parse::<usize>().map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: format!("{} must be an integer", key),
        }),
    }
}

fn parse_u64(value: Option<&String>, default: u64, key: &'static str) -> Result<u64, StartupError> {
    match value {
        None => Ok(default),
        Some(v) if v.trim().is_empty() => Ok(default),
        Some(v) => v.parse::<u64>().map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: format!("{} must be an integer", key),
        }),
    }
}

fn parse_f64(value: Option<&String>, default: f64, key: &'static str) -> Result<f64, StartupError> {
    match value {
        None => Ok(default),
        Some(v) if v.trim().is_empty() => Ok(default),
        Some(v) => v.parse::<f64>().map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: format!("{} must be a number", key),
        }),
    }
}

fn parse_store_mode(value: Option<&String>) -> Result<EvidencePayloadStoreMode, StartupError> {
    let mode = value
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("metadata-only");

    match mode {
        "metadata-only" => Ok(EvidencePayloadStoreMode::MetadataOnly),
        "payload-enabled" => Ok(EvidencePayloadStoreMode::PayloadEnabled),
        _ => Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_EVIDENCE_PAYLOAD_STORE_MODE must be metadata-only or payload-enabled"
                .to_string(),
        }),
    }
}

fn parse_auth_mode(value: Option<&String>) -> Result<AuthMode, StartupError> {
    let mode = value
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("local");

    match mode {
        "local" => Ok(AuthMode::Local),
        "oidc" => Ok(AuthMode::Oidc),
        _ => Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_AUTH_MODE must be local or oidc".to_string(),
        }),
    }
}

fn parse_bool(value: Option<&String>) -> Option<bool> {
    let value = value.map(|v| v.trim()).filter(|v| !v.is_empty())?;

    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" => Some(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Some(false),
        _ => None,
    }
}

fn is_unspecified_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn is_lower_hex_64(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ok_env() -> HashMap<String, String> {
        HashMap::from([
            (
                "PECR_DB_URL".to_string(),
                "postgres://user:pass@localhost:5432/pecr".to_string(),
            ),
            (
                "PECR_OPA_URL".to_string(),
                "http://localhost:8181".to_string(),
            ),
            (
                "PECR_POLICY_BUNDLE_HASH".to_string(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        ])
    }

    #[test]
    fn non_local_bind_without_auth_config_fails() {
        let mut env = minimal_ok_env();
        env.insert("PECR_BIND_ADDR".to_string(), "0.0.0.0:8080".to_string());
        let err = GatewayConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_NONLOCAL_BIND_REQUIRES_AUTH");
    }

    #[test]
    fn invalid_policy_bundle_hash_fails() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_POLICY_BUNDLE_HASH".to_string(),
            "not-a-hash".to_string(),
        );
        let err = GatewayConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_INVALID_POLICY_BUNDLE_HASH");
    }
}
