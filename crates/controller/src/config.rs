use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use pecr_auth::OidcConfig;
use pecr_contracts::Budget;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ControllerConfig {
    pub bind_addr: SocketAddr,
    pub gateway_url: String,
    pub controller_engine: ControllerEngine,
    pub model_provider: ModelProvider,
    pub budget_defaults: Budget,
    pub baseline_plan: Vec<BaselinePlanStep>,
    pub adaptive_parallelism_enabled: bool,
    pub batch_mode_enabled: bool,
    pub operator_concurrency_policies: HashMap<String, OperatorConcurrencyPolicy>,
    pub auth_mode: AuthMode,
    pub local_auth_shared_secret: Option<String>,
    pub oidc: Option<OidcConfig>,
    pub metrics_require_auth: bool,
    pub rate_limit_window_secs: u64,
    pub rate_limit_run_per_window: u32,
    pub replay_store_dir: String,
    pub replay_retention_days: u64,
    pub replay_list_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BaselinePlanStep {
    Operator {
        op_name: String,
        #[serde(default = "default_plan_params")]
        params: serde_json::Value,
    },
    SearchRefFetchSpan {
        #[serde(default = "default_max_refs")]
        max_refs: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OperatorConcurrencyPolicy {
    #[serde(default)]
    pub max_in_flight: Option<usize>,
    #[serde(default)]
    pub fairness_weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelProvider {
    Mock,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Local,
    Oidc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerEngine {
    Baseline,
    Rlm,
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

const ADAPTIVE_PARALLELISM_ENV_KEYS: &[&str] = &[
    "PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED",
    "PECR_CONTROLLER_ADAPTIVE_PARALLELISM",
    "PECR_ADAPTIVE_PARALLELISM_ENABLED",
    "PECR_ADAPTIVE_PARALLELISM",
];

const BATCH_MODE_ENV_KEYS: &[&str] = &[
    "PECR_CONTROLLER_BATCH_MODE_ENABLED",
    "PECR_CONTROLLER_BATCH_MODE",
    "PECR_BATCH_MODE_ENABLED",
    "PECR_BATCH_MODE",
];

const OPERATOR_CONCURRENCY_POLICY_ENV_KEYS: &[&str] = &[
    "PECR_CONTROLLER_OPERATOR_CONCURRENCY_POLICIES",
    "PECR_CONTROLLER_OPERATOR_CONCURRENCY_POLICY",
    "PECR_OPERATOR_CONCURRENCY_POLICIES",
    "PECR_OPERATOR_CONCURRENCY_POLICY",
];

impl ControllerConfig {
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
            kv.get("PECR_CONTROLLER_BIND_ADDR"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081),
            "PECR_CONTROLLER_BIND_ADDR",
        )?;

        let auth_mode = parse_auth_mode(kv.get("PECR_AUTH_MODE"))?;

        let local_auth_shared_secret = kv
            .get("PECR_LOCAL_AUTH_SHARED_SECRET")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let dev_allow_nonlocal_bind =
            parse_bool(kv.get("PECR_DEV_ALLOW_NONLOCAL_BIND")).unwrap_or(false);

        if !bind_addr.ip().is_loopback() && auth_mode != AuthMode::Oidc {
            let can_run_local_nonloopback = dev_allow_nonlocal_bind
                && is_unspecified_ip(bind_addr.ip())
                && local_auth_shared_secret.is_some();
            if !can_run_local_nonloopback {
                return Err(StartupError {
                    code: "ERR_NONLOCAL_BIND_REQUIRES_AUTH",
                    message: "non-local bind requires oidc auth, or dev override + PECR_LOCAL_AUTH_SHARED_SECRET"
                        .to_string(),
                });
            }
        }

        let gateway_url = require_nonempty(kv, "PECR_GATEWAY_URL")?;
        let controller_engine = parse_controller_engine(kv.get("PECR_CONTROLLER_ENGINE"))?;

        #[cfg(not(feature = "rlm"))]
        if controller_engine == ControllerEngine::Rlm {
            return Err(StartupError {
                code: "ERR_RLM_FEATURE_DISABLED",
                message:
                    "PECR_CONTROLLER_ENGINE=rlm requires building pecr-controller with feature rlm"
                        .to_string(),
            });
        }

        if controller_engine == ControllerEngine::Rlm {
            let sandbox_ack = parse_bool(kv.get("PECR_RLM_SANDBOX_ACK")).unwrap_or(false);
            if !sandbox_ack {
                return Err(StartupError {
                    code: "ERR_RLM_REQUIRES_SANDBOX_ACK",
                    message: "rlm engine requires PECR_RLM_SANDBOX_ACK=1 to confirm a sandboxed execution environment"
                        .to_string(),
                });
            }
        }

        let model_provider = parse_model_provider(kv.get("PECR_MODEL_PROVIDER"))?;
        if model_provider == ModelProvider::External {
            return Err(StartupError {
                code: "ERR_MODEL_PROVIDER_UNIMPLEMENTED",
                message: "external model provider is not implemented yet; refuse startup"
                    .to_string(),
            });
        }

        let budget_defaults_raw = require_nonempty(kv, "PECR_BUDGET_DEFAULTS")?;
        let budget_defaults =
            serde_json::from_str::<Budget>(&budget_defaults_raw).map_err(|_| StartupError {
                code: "ERR_INVALID_BUDGET_JSON",
                message: "PECR_BUDGET_DEFAULTS must be valid JSON per Budget schema".to_string(),
            })?;

        budget_defaults.validate().map_err(|reason| StartupError {
            code: "ERR_INVALID_BUDGET",
            message: format!("PECR_BUDGET_DEFAULTS invalid: {}", reason),
        })?;
        let baseline_plan = parse_baseline_plan(kv.get("PECR_BASELINE_PLAN"))?;
        let adaptive_parallelism_enabled =
            parse_bool_from_env_keys(kv, ADAPTIVE_PARALLELISM_ENV_KEYS, true);
        let batch_mode_enabled = parse_bool_from_env_keys(kv, BATCH_MODE_ENV_KEYS, true);
        let operator_concurrency_policies = parse_operator_concurrency_policies(
            first_nonempty_env_value(kv, OPERATOR_CONCURRENCY_POLICY_ENV_KEYS),
        )?;

        let oidc = if auth_mode == AuthMode::Oidc {
            Some(parse_oidc_config(kv)?)
        } else {
            None
        };

        let metrics_require_auth = parse_bool(kv.get("PECR_METRICS_REQUIRE_AUTH"))
            .unwrap_or(!bind_addr.ip().is_loopback());
        let rate_limit_window_secs = parse_u64(
            kv.get("PECR_RATE_LIMIT_WINDOW_SECS"),
            60,
            "PECR_RATE_LIMIT_WINDOW_SECS",
        )?;
        let rate_limit_run_per_window = parse_u32(
            kv.get("PECR_RATE_LIMIT_RUN_PER_WINDOW"),
            60,
            "PECR_RATE_LIMIT_RUN_PER_WINDOW",
        )?;
        let replay_store_dir = kv
            .get("PECR_REPLAY_STORE_DIR")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .unwrap_or("target/replay")
            .to_string();
        let replay_retention_days = parse_u64(
            kv.get("PECR_REPLAY_RETENTION_DAYS"),
            30,
            "PECR_REPLAY_RETENTION_DAYS",
        )?;
        let replay_list_limit = parse_usize(
            kv.get("PECR_REPLAY_LIST_LIMIT"),
            200,
            "PECR_REPLAY_LIST_LIMIT",
        )?;
        if replay_list_limit == 0 {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: "PECR_REPLAY_LIST_LIMIT must be > 0".to_string(),
            });
        }

        Ok(Self {
            bind_addr,
            gateway_url,
            controller_engine,
            model_provider,
            budget_defaults,
            baseline_plan,
            adaptive_parallelism_enabled,
            batch_mode_enabled,
            operator_concurrency_policies,
            auth_mode,
            local_auth_shared_secret,
            oidc,
            metrics_require_auth,
            rate_limit_window_secs,
            rate_limit_run_per_window,
            replay_store_dir,
            replay_retention_days,
            replay_list_limit,
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

fn parse_u32(value: Option<&String>, default: u32, key: &'static str) -> Result<u32, StartupError> {
    match value {
        None => Ok(default),
        Some(v) if v.trim().is_empty() => Ok(default),
        Some(v) => v.parse::<u32>().map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: format!("{} must be an integer", key),
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

fn default_plan_params() -> serde_json::Value {
    serde_json::json!({})
}

fn default_max_refs() -> usize {
    2
}

pub fn default_baseline_plan() -> Vec<BaselinePlanStep> {
    vec![
        BaselinePlanStep::Operator {
            op_name: "list_versions".to_string(),
            params: serde_json::json!({ "object_id": "public/public_1.txt" }),
        },
        BaselinePlanStep::Operator {
            op_name: "fetch_rows".to_string(),
            params: serde_json::json!({
                "view_id": "safe_customer_view_public",
                "filter_spec": { "customer_id": "cust_public_1" },
                "fields": ["status", "plan_tier"]
            }),
        },
        BaselinePlanStep::Operator {
            op_name: "search".to_string(),
            params: serde_json::json!({ "query": "$query", "limit": 5 }),
        },
        BaselinePlanStep::SearchRefFetchSpan { max_refs: 2 },
    ]
}

fn parse_baseline_plan(value: Option<&String>) -> Result<Vec<BaselinePlanStep>, StartupError> {
    let Some(raw) = value.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
        return Ok(default_baseline_plan());
    };

    let plan = serde_json::from_str::<Vec<BaselinePlanStep>>(raw).map_err(|_| StartupError {
        code: "ERR_INVALID_CONFIG",
        message: "PECR_BASELINE_PLAN must be valid JSON plan array".to_string(),
    })?;

    if plan.is_empty() {
        return Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_BASELINE_PLAN must contain at least one step".to_string(),
        });
    }

    for step in &plan {
        match step {
            BaselinePlanStep::Operator { op_name, .. } => {
                let op_name = op_name.trim();
                if op_name.is_empty() {
                    return Err(StartupError {
                        code: "ERR_INVALID_CONFIG",
                        message: "PECR_BASELINE_PLAN operator step requires non-empty op_name"
                            .to_string(),
                    });
                }
            }
            BaselinePlanStep::SearchRefFetchSpan { max_refs } => {
                if *max_refs == 0 {
                    return Err(StartupError {
                        code: "ERR_INVALID_CONFIG",
                        message:
                            "PECR_BASELINE_PLAN search_ref_fetch_span step requires max_refs > 0"
                                .to_string(),
                    });
                }
            }
        }
    }

    Ok(plan)
}

fn parse_operator_concurrency_policies(
    value: Option<&String>,
) -> Result<HashMap<String, OperatorConcurrencyPolicy>, StartupError> {
    let Some(raw) = value.map(|v| v.trim()).filter(|v| !v.is_empty()) else {
        return Ok(HashMap::new());
    };

    let raw_policies = serde_json::from_str::<HashMap<String, OperatorConcurrencyPolicy>>(raw)
        .map_err(|_| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_OPERATOR_CONCURRENCY_POLICIES must be a valid JSON map".to_string(),
        })?;

    let mut policies = HashMap::with_capacity(raw_policies.len());
    for (raw_op_name, policy) in raw_policies {
        let op_name = raw_op_name.trim();
        if op_name.is_empty() {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: "PECR_OPERATOR_CONCURRENCY_POLICIES requires non-empty operator names"
                    .to_string(),
            });
        }
        if policy.max_in_flight == Some(0) {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "PECR_OPERATOR_CONCURRENCY_POLICIES[{}].max_in_flight must be > 0 when set",
                    op_name
                ),
            });
        }
        if policy.fairness_weight == Some(0) {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "PECR_OPERATOR_CONCURRENCY_POLICIES[{}].fairness_weight must be > 0 when set",
                    op_name
                ),
            });
        }
        if policies
            .insert(op_name.to_string(), policy)
            .as_ref()
            .is_some()
        {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "PECR_OPERATOR_CONCURRENCY_POLICIES has duplicate operator after trimming: {}",
                    op_name
                ),
            });
        }
    }

    Ok(policies)
}

fn parse_bool_from_env_keys(kv: &HashMap<String, String>, keys: &[&str], default: bool) -> bool {
    keys.iter()
        .find_map(|key| parse_bool(kv.get(*key)))
        .unwrap_or(default)
}

fn first_nonempty_env_value<'a>(
    kv: &'a HashMap<String, String>,
    keys: &[&str],
) -> Option<&'a String> {
    keys.iter()
        .find_map(|key| kv.get(*key).filter(|value| !value.trim().is_empty()))
}

fn parse_model_provider(value: Option<&String>) -> Result<ModelProvider, StartupError> {
    let mode = value
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("mock");

    match mode {
        "mock" => Ok(ModelProvider::Mock),
        "external" => Ok(ModelProvider::External),
        _ => Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_MODEL_PROVIDER must be mock or external".to_string(),
        }),
    }
}

fn parse_controller_engine(value: Option<&String>) -> Result<ControllerEngine, StartupError> {
    let engine = value
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("baseline");

    match engine {
        "baseline" => Ok(ControllerEngine::Baseline),
        "rlm" => Ok(ControllerEngine::Rlm),
        _ => Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "PECR_CONTROLLER_ENGINE must be baseline or rlm".to_string(),
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

fn parse_oidc_config(kv: &HashMap<String, String>) -> Result<OidcConfig, StartupError> {
    let issuer = require_nonempty(kv, "PECR_OIDC_ISSUER")?;

    let jwks_json = kv
        .get("PECR_OIDC_JWKS_JSON")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let jwks_url = kv
        .get("PECR_OIDC_JWKS_URL")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if jwks_json.is_none() && jwks_url.is_none() {
        return Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "oidc requires PECR_OIDC_JWKS_URL or PECR_OIDC_JWKS_JSON".to_string(),
        });
    }

    let audience = kv
        .get("PECR_OIDC_AUDIENCE")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let principal_id_claim = kv
        .get("PECR_OIDC_PRINCIPAL_ID_CLAIM")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("sub")
        .to_string();

    let tenant_claim = kv
        .get("PECR_OIDC_TENANT_CLAIM")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let tenant_id_static = kv
        .get("PECR_OIDC_TENANT_ID_STATIC")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    if tenant_claim.is_none() && tenant_id_static.is_none() {
        return Err(StartupError {
            code: "ERR_INVALID_CONFIG",
            message:
                "oidc requires tenant mapping via PECR_OIDC_TENANT_CLAIM or PECR_OIDC_TENANT_ID_STATIC"
                    .to_string(),
        });
    }

    let roles_claim = kv
        .get("PECR_OIDC_ROLES_CLAIM")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let jwks_timeout_ms = parse_u64(
        kv.get("PECR_OIDC_JWKS_TIMEOUT_MS"),
        2000,
        "PECR_OIDC_JWKS_TIMEOUT_MS",
    )?;
    let jwks_refresh_ttl_secs = parse_u64(
        kv.get("PECR_OIDC_JWKS_REFRESH_TTL_SECS"),
        300,
        "PECR_OIDC_JWKS_REFRESH_TTL_SECS",
    )?;
    let clock_skew_secs = parse_u64(
        kv.get("PECR_OIDC_CLOCK_SKEW_SECS"),
        60,
        "PECR_OIDC_CLOCK_SKEW_SECS",
    )?;

    let abac_claims_raw = kv
        .get("PECR_OIDC_ABAC_CLAIMS")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let mut abac_claims = abac_claims_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    abac_claims.sort();
    abac_claims.dedup();

    Ok(OidcConfig {
        issuer,
        audience,
        jwks_url,
        jwks_json,
        jwks_timeout: Duration::from_millis(jwks_timeout_ms),
        jwks_refresh_ttl: Duration::from_secs(jwks_refresh_ttl_secs),
        clock_skew: Duration::from_secs(clock_skew_secs),
        principal_id_claim,
        tenant_claim,
        tenant_id_static,
        roles_claim,
        abac_claims,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ok_env() -> HashMap<String, String> {
        HashMap::from([
            ("PECR_GATEWAY_URL".to_string(), "http://127.0.0.1:8080".to_string()),
            ("PECR_MODEL_PROVIDER".to_string(), "mock".to_string()),
            (
                "PECR_BUDGET_DEFAULTS".to_string(),
                r#"{"max_operator_calls":10,"max_bytes":1024,"max_wallclock_ms":1000,"max_recursion_depth":3}"#
                    .to_string(),
            ),
        ])
    }

    #[test]
    fn invalid_budget_json_fails() {
        let mut env = minimal_ok_env();
        env.insert("PECR_BUDGET_DEFAULTS".to_string(), "not-json".to_string());
        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_INVALID_BUDGET_JSON");
    }

    #[test]
    fn non_local_bind_without_auth_config_fails() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_CONTROLLER_BIND_ADDR".to_string(),
            "0.0.0.0:8081".to_string(),
        );
        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_NONLOCAL_BIND_REQUIRES_AUTH");
    }

    #[test]
    fn non_local_bind_dev_override_requires_shared_secret() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_CONTROLLER_BIND_ADDR".to_string(),
            "0.0.0.0:8081".to_string(),
        );
        env.insert("PECR_DEV_ALLOW_NONLOCAL_BIND".to_string(), "1".to_string());
        env.insert(
            "PECR_LOCAL_AUTH_SHARED_SECRET".to_string(),
            "dev-secret".to_string(),
        );
        let cfg = ControllerConfig::from_kv(&env).expect("config should load");
        assert_eq!(cfg.auth_mode, AuthMode::Local);
        assert_eq!(cfg.local_auth_shared_secret.as_deref(), Some("dev-secret"));
    }

    #[test]
    fn invalid_controller_engine_fails() {
        let mut env = minimal_ok_env();
        env.insert("PECR_CONTROLLER_ENGINE".to_string(), "nope".to_string());
        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[test]
    fn baseline_plan_can_be_overridden_via_config() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_BASELINE_PLAN".to_string(),
            r#"[
                {"kind":"operator","op_name":"search","params":{"query":"$query","limit":1}},
                {"kind":"search_ref_fetch_span","max_refs":1}
            ]"#
            .to_string(),
        );

        let cfg = ControllerConfig::from_kv(&env).expect("config should load");
        assert_eq!(cfg.baseline_plan.len(), 2);
    }

    #[test]
    fn baseline_plan_rejects_invalid_step_values() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_BASELINE_PLAN".to_string(),
            r#"[{"kind":"search_ref_fetch_span","max_refs":0}]"#.to_string(),
        );

        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[test]
    fn runtime_flags_default_to_enabled_for_compatibility() {
        let env = minimal_ok_env();
        let cfg = ControllerConfig::from_kv(&env).expect("config should load");

        assert!(cfg.adaptive_parallelism_enabled);
        assert!(cfg.batch_mode_enabled);
        assert!(cfg.operator_concurrency_policies.is_empty());
        assert_eq!(cfg.replay_store_dir, "target/replay");
        assert_eq!(cfg.replay_retention_days, 30);
        assert_eq!(cfg.replay_list_limit, 200);
    }

    #[test]
    fn runtime_flags_and_operator_policy_parse_from_env() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED".to_string(),
            "0".to_string(),
        );
        env.insert(
            "PECR_CONTROLLER_BATCH_MODE_ENABLED".to_string(),
            "false".to_string(),
        );
        env.insert(
            "PECR_OPERATOR_CONCURRENCY_POLICIES".to_string(),
            r#"{
                " search ": {"max_in_flight": 2, "fairness_weight": 3},
                "fetch_span": {"max_in_flight": 1}
            }"#
            .to_string(),
        );

        let cfg = ControllerConfig::from_kv(&env).expect("config should load");
        assert!(!cfg.adaptive_parallelism_enabled);
        assert!(!cfg.batch_mode_enabled);

        let search_policy = cfg
            .operator_concurrency_policies
            .get("search")
            .expect("search policy should exist");
        assert_eq!(search_policy.max_in_flight, Some(2));
        assert_eq!(search_policy.fairness_weight, Some(3));

        let fetch_span_policy = cfg
            .operator_concurrency_policies
            .get("fetch_span")
            .expect("fetch_span policy should exist");
        assert_eq!(fetch_span_policy.max_in_flight, Some(1));
        assert_eq!(fetch_span_policy.fairness_weight, None);
    }

    #[test]
    fn operator_policy_rejects_empty_operator_name() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_OPERATOR_CONCURRENCY_POLICIES".to_string(),
            r#"{" ": {"max_in_flight": 1}}"#.to_string(),
        );

        let err = ControllerConfig::from_kv(&env).expect_err("config must reject empty operator");
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[test]
    fn operator_policy_rejects_zero_max_in_flight() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_OPERATOR_CONCURRENCY_POLICIES".to_string(),
            r#"{"search": {"max_in_flight": 0}}"#.to_string(),
        );

        let err = ControllerConfig::from_kv(&env).expect_err("config must reject zero cap");
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[test]
    fn operator_policy_rejects_zero_fairness_weight() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_OPERATOR_CONCURRENCY_POLICIES".to_string(),
            r#"{"search": {"fairness_weight": 0}}"#.to_string(),
        );

        let err =
            ControllerConfig::from_kv(&env).expect_err("config must reject zero fairness weight");
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[test]
    fn replay_config_overrides_parse_from_env() {
        let mut env = minimal_ok_env();
        env.insert(
            "PECR_REPLAY_STORE_DIR".to_string(),
            "target/custom-replay".to_string(),
        );
        env.insert("PECR_REPLAY_RETENTION_DAYS".to_string(), "7".to_string());
        env.insert("PECR_REPLAY_LIST_LIMIT".to_string(), "25".to_string());

        let cfg = ControllerConfig::from_kv(&env).expect("config should load");
        assert_eq!(cfg.replay_store_dir, "target/custom-replay");
        assert_eq!(cfg.replay_retention_days, 7);
        assert_eq!(cfg.replay_list_limit, 25);
    }

    #[test]
    fn replay_list_limit_requires_positive_value() {
        let mut env = minimal_ok_env();
        env.insert("PECR_REPLAY_LIST_LIMIT".to_string(), "0".to_string());

        let err = ControllerConfig::from_kv(&env).expect_err("config must reject zero list limit");
        assert_eq!(err.code, "ERR_INVALID_CONFIG");
    }

    #[cfg(not(feature = "rlm"))]
    #[test]
    fn rlm_engine_requires_feature_flag() {
        let mut env = minimal_ok_env();
        env.insert("PECR_CONTROLLER_ENGINE".to_string(), "rlm".to_string());
        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_RLM_FEATURE_DISABLED");
    }

    #[cfg(feature = "rlm")]
    #[test]
    fn rlm_engine_requires_sandbox_ack() {
        let mut env = minimal_ok_env();
        env.insert("PECR_CONTROLLER_ENGINE".to_string(), "rlm".to_string());
        let err = ControllerConfig::from_kv(&env).unwrap_err();
        assert_eq!(err.code, "ERR_RLM_REQUIRES_SANDBOX_ACK");
    }
}
