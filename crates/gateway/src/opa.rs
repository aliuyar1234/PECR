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
}

impl std::fmt::Display for OpaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpaError::Timeout => write!(f, "OPA request timed out"),
            OpaError::Http(err) => write!(f, "OPA HTTP error: {}", err),
            OpaError::BadStatus(status) => write!(f, "OPA returned status {}", status),
            OpaError::InvalidResponse => write!(f, "OPA returned invalid JSON response"),
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
}

#[derive(Clone)]
struct CachedDecision {
    decision: OpaDecision,
    expires_at: Instant,
}

impl OpaClient {
    pub fn new(
        base_url: String,
        timeout: Duration,
        cache_max_entries: usize,
        cache_ttl: Duration,
    ) -> Result<Self, OpaError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(OpaError::Http)?;

        Ok(Self {
            base_url,
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_max_entries,
            cache_ttl,
        })
    }

    pub async fn decide(
        &self,
        input: serde_json::Value,
        cache_key: Option<OpaCacheKey>,
    ) -> Result<OpaDecision, OpaError> {
        let cache_enabled =
            self.cache_max_entries > 0 && self.cache_ttl > Duration::ZERO && cache_key.is_some();

        if cache_enabled && let Some(decision) = self.get_cached(cache_key.as_ref().unwrap()).await
        {
            return Ok(decision);
        }

        let url = self.decision_url();
        let resp = self
            .http
            .post(url)
            .json(&serde_json::json!({ "input": input }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(OpaError::BadStatus(resp.status()));
        }

        let decoded = resp
            .json::<OpaDataResponse<OpaDecision>>()
            .await
            .map_err(|_| OpaError::InvalidResponse)?;

        if cache_enabled && decoded.result.cacheable {
            self.put_cached(cache_key.unwrap(), decoded.result.clone())
                .await;
        }

        Ok(decoded.result)
    }

    fn decision_url(&self) -> String {
        format!(
            "{}/v1/data/pecr/authz/decision",
            self.base_url.trim_end_matches('/')
        )
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
