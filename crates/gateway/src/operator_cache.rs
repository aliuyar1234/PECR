use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pecr_contracts::TerminalMode;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperatorCacheKey {
    pub principal_id: String,
    pub policy_snapshot_hash: String,
    pub as_of_time: String,
    pub op_name: String,
    pub params_hash: String,
}

impl OperatorCacheKey {
    pub fn operator_call(
        principal_id: &str,
        policy_snapshot_hash: &str,
        as_of_time: &str,
        op_name: &str,
        params_hash: &str,
    ) -> Self {
        Self {
            principal_id: principal_id.to_string(),
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            as_of_time: as_of_time.to_string(),
            op_name: op_name.to_string(),
            params_hash: params_hash.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct OperatorCache {
    cache: Arc<RwLock<HashMap<OperatorCacheKey, CachedOperatorResponse>>>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Clone)]
struct CachedOperatorResponse {
    terminal_mode: TerminalMode,
    result: serde_json::Value,
    expires_at: Instant,
}

impl OperatorCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            ttl,
        }
    }

    pub fn enabled(&self) -> bool {
        self.max_entries > 0 && self.ttl > Duration::ZERO
    }

    pub async fn get(&self, key: &OperatorCacheKey) -> Option<(TerminalMode, serde_json::Value)> {
        if !self.enabled() {
            return None;
        }

        let now = Instant::now();
        let cache = self.cache.read().await;
        cache.get(key).and_then(|entry| {
            (entry.expires_at > now).then(|| (entry.terminal_mode, entry.result.clone()))
        })
    }

    pub async fn put(
        &self,
        key: OperatorCacheKey,
        terminal_mode: TerminalMode,
        result: serde_json::Value,
    ) {
        if !self.enabled() {
            return;
        }

        let now = Instant::now();
        let expires_at = now + self.ttl;
        let mut cache = self.cache.write().await;

        cache.retain(|_, entry| entry.expires_at > now);
        cache.insert(
            key,
            CachedOperatorResponse {
                terminal_mode,
                result,
                expires_at,
            },
        );

        if cache.len() <= self.max_entries {
            return;
        }

        let mut overflow = cache.len() - self.max_entries;
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
