use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pecr_contracts::Budget;

#[derive(Debug, Clone)]
pub struct ControllerConfig {
    pub bind_addr: SocketAddr,
    pub gateway_url: String,
    pub controller_engine: ControllerEngine,
    pub model_provider: ModelProvider,
    pub budget_defaults: Budget,
    pub auth_mode: AuthMode,
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

        Ok(Self {
            bind_addr,
            gateway_url,
            controller_engine,
            model_provider,
            budget_defaults,
            auth_mode,
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
    fn invalid_controller_engine_fails() {
        let mut env = minimal_ok_env();
        env.insert("PECR_CONTROLLER_ENGINE".to_string(), "nope".to_string());
        let err = ControllerConfig::from_kv(&env).unwrap_err();
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
