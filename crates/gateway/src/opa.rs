use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct OpaDecision {
    pub allow: bool,
    #[serde(default)]
    pub cacheable: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub redaction: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaCacheKey {
    pub policy_snapshot_hash: String,
    pub action: String,
    pub op_name: Option<String>,
    pub params_hash: Option<String>,
}

impl OpaCacheKey {
    pub fn create_session(policy_snapshot_hash: &str) -> Self {
        Self {
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            action: "create_session".to_string(),
            op_name: None,
            params_hash: None,
        }
    }

    pub fn finalize(policy_snapshot_hash: &str) -> Self {
        Self {
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            action: "finalize".to_string(),
            op_name: None,
            params_hash: None,
        }
    }

    pub fn operator_call(policy_snapshot_hash: &str, op_name: &str, params_hash: &str) -> Self {
        Self {
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            action: "operator_call".to_string(),
            op_name: Some(op_name.to_string()),
            params_hash: Some(params_hash.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum OpaError {
    Timeout,
    Http(reqwest::Error),
    BadStatus(reqwest::StatusCode),
    InvalidResponse,
    CircuitOpen,
}

impl std::fmt::Display for OpaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpaError::Timeout => write!(f, "OPA request timed out"),
            OpaError::Http(err) => write!(f, "OPA HTTP error: {}", err),
            OpaError::BadStatus(status) => write!(f, "OPA returned status {}", status),
            OpaError::InvalidResponse => write!(f, "OPA returned invalid JSON response"),
            OpaError::CircuitOpen => write!(f, "OPA circuit breaker is open"),
        }
    }
}

impl std::error::Error for OpaError {}

impl From<reqwest::Error> for OpaError {
    fn from(value: reqwest::Error) -> Self {
        if value.is_timeout() {
            OpaError::Timeout
        } else {
            OpaError::Http(value)
        }
    }
}

#[derive(Deserialize)]
struct OpaDataResponse<T> {
    result: T,
}

#[derive(Clone)]
pub struct OpaClient {
    base_url: String,
    http: reqwest::Client,
    cache: Arc<RwLock<HashMap<OpaCacheKey, CachedDecision>>>,
    cache_max_entries: usize,
    cache_ttl: Duration,
    retry_max_attempts: u32,
    retry_base_backoff: Duration,
    circuit_breaker_failure_threshold: u32,
    circuit_breaker_open_for: Duration,
    breaker_state: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Clone)]
struct CachedDecision {
    decision: OpaDecision,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct OpaClientConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub cache_max_entries: usize,
    pub cache_ttl: Duration,
    pub retry_max_attempts: u32,
    pub retry_base_backoff: Duration,
    pub circuit_breaker_failure_threshold: u32,
    pub circuit_breaker_open_for: Duration,
}

impl OpaClient {
    pub fn new(config: OpaClientConfig) -> Result<Self, OpaError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(OpaError::Http)?;

        Ok(Self {
            base_url: config.base_url,
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_max_entries: config.cache_max_entries,
            cache_ttl: config.cache_ttl,
            retry_max_attempts: config.retry_max_attempts,
            retry_base_backoff: config.retry_base_backoff,
            circuit_breaker_failure_threshold: config.circuit_breaker_failure_threshold,
            circuit_breaker_open_for: config.circuit_breaker_open_for,
            breaker_state: Arc::new(RwLock::new(CircuitBreakerState {
                consecutive_failures: 0,
                open_until: None,
            })),
        })
    }

    pub async fn ready(&self) -> Result<(), OpaError> {
        let resp = self.http.get(self.health_url()).send().await?;
        if !resp.status().is_success() {
            return Err(OpaError::BadStatus(resp.status()));
        }
        Ok(())
    }

    pub async fn decide(
        &self,
        input: serde_json::Value,
        cache_key: Option<OpaCacheKey>,
    ) -> Result<OpaDecision, OpaError> {
        if self.is_circuit_open().await {
            return Err(OpaError::CircuitOpen);
        }

        let cache_enabled =
            self.cache_max_entries > 0 && self.cache_ttl > Duration::ZERO && cache_key.is_some();

        if cache_enabled && let Some(decision) = self.get_cached(cache_key.as_ref().unwrap()).await
        {
            return Ok(decision);
        }

        let mut attempt = 0_u32;
        let mut last_err = None;
        let max_attempts = self.retry_max_attempts.saturating_add(1);
        let url = self.decision_url();
        let payload = serde_json::json!({ "input": input });

        while attempt < max_attempts {
            let response = self.http.post(url.clone()).json(&payload).send().await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let decoded = resp
                        .json::<OpaDataResponse<OpaDecision>>()
                        .await
                        .map_err(|_| OpaError::InvalidResponse)?;

                    self.register_success().await;
                    if cache_enabled && decoded.result.cacheable {
                        self.put_cached(cache_key.unwrap(), decoded.result.clone())
                            .await;
                    }
                    return Ok(decoded.result);
                }
                Ok(resp) => {
                    let err = OpaError::BadStatus(resp.status());
                    if !is_retryable(&err) {
                        self.register_failure().await;
                        return Err(err);
                    }
                    last_err = Some(err);
                }
                Err(err) => {
                    let mapped = OpaError::from(err);
                    if !is_retryable(&mapped) {
                        self.register_failure().await;
                        return Err(mapped);
                    }
                    last_err = Some(mapped);
                }
            }

            attempt = attempt.saturating_add(1);
            if attempt < max_attempts {
                let shift = attempt.saturating_sub(1).min(8);
                let factor = 1_u64 << shift;
                let sleep_ms = self
                    .retry_base_backoff
                    .as_millis()
                    .saturating_mul(factor as u128)
                    .min(5_000) as u64;
                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
        }

        self.register_failure().await;
        let err = last_err.unwrap_or(OpaError::Timeout);
        Err(err)
    }

    async fn is_circuit_open(&self) -> bool {
        let now = Instant::now();
        let mut state = self.breaker_state.write().await;
        if let Some(until) = state.open_until {
            if until > now {
                return true;
            }
            state.open_until = None;
            state.consecutive_failures = 0;
        }
        false
    }

    async fn register_failure(&self) {
        let mut state = self.breaker_state.write().await;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.circuit_breaker_failure_threshold {
            state.open_until = Some(Instant::now() + self.circuit_breaker_open_for);
        }
    }

    async fn register_success(&self) {
        let mut state = self.breaker_state.write().await;
        state.consecutive_failures = 0;
        state.open_until = None;
    }

    fn decision_url(&self) -> String {
        format!(
            "{}/v1/data/pecr/authz/decision",
            self.base_url.trim_end_matches('/')
        )
    }

    fn health_url(&self) -> String {
        format!("{}/health", self.base_url.trim_end_matches('/'))
    }

    async fn get_cached(&self, key: &OpaCacheKey) -> Option<OpaDecision> {
        let now = Instant::now();
        let cache = self.cache.read().await;
        cache
            .get(key)
            .and_then(|entry| (entry.expires_at > now).then(|| entry.decision.clone()))
    }

    async fn put_cached(&self, key: OpaCacheKey, decision: OpaDecision) {
        let now = Instant::now();
        let expires_at = now + self.cache_ttl;
        let mut cache = self.cache.write().await;

        cache.retain(|_, entry| entry.expires_at > now);
        cache.insert(
            key,
            CachedDecision {
                decision,
                expires_at,
            },
        );

        if cache.len() <= self.cache_max_entries {
            return;
        }

        let mut overflow = cache.len() - self.cache_max_entries;
        let keys = cache.keys().cloned().collect::<Vec<_>>();
        for k in keys {
            if overflow == 0 {
                break;
            }
            if cache.remove(&k).is_some() {
                overflow -= 1;
            }
        }
    }
}

fn is_retryable(err: &OpaError) -> bool {
    match err {
        OpaError::Timeout | OpaError::Http(_) | OpaError::InvalidResponse => true,
        OpaError::BadStatus(status) => status.is_server_error(),
        OpaError::CircuitOpen => false,
    }
}
