use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use hex::ToHex;
use pecr_adapters::{normalize_resource_prefix, normalize_search_query};
use pecr_contracts::canonical;
use pecr_contracts::{
    EvidenceUnitRef, StructuredDimensionDescriptor, StructuredDimensionDiscoveryResult,
    StructuredDimensionValueCount, StructuredDrilldownHint, StructuredMetricDescriptor,
    TerminalMode,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use similar::TextDiff;
use sqlx::{PgPool, Row};
use tokio::sync::RwLock;

use crate::config::{GatewayConfig, StartupError};

use super::{ApiError, FilterEq, json_error};

#[derive(Debug, Serialize)]
pub(super) struct VersionInfo {
    version_id: String,
    as_of_time: String,
    metadata_hash: String,
}

#[derive(Debug, Clone)]
struct FsSearchIndexEntry {
    path: std::path::PathBuf,
    object_id: String,
}

#[derive(Debug, Clone)]
struct FsSearchIndexSnapshot {
    root: std::path::PathBuf,
    files: Arc<Vec<FsSearchIndexEntry>>,
    indexed_at: Instant,
}

#[derive(Debug)]
pub(super) struct FsSearchIndexCache {
    ttl: Duration,
    snapshot: Option<FsSearchIndexSnapshot>,
}

impl FsSearchIndexCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            snapshot: None,
        }
    }

    fn get_if_fresh(&self, root: &std::path::Path) -> Option<Arc<Vec<FsSearchIndexEntry>>> {
        let snapshot = self.snapshot.as_ref()?;
        if snapshot.root != root {
            return None;
        }
        if self.ttl.is_zero() {
            return None;
        }
        if snapshot.indexed_at.elapsed() >= self.ttl {
            return None;
        }

        Some(snapshot.files.clone())
    }

    fn set_snapshot(
        &mut self,
        root: std::path::PathBuf,
        files: Vec<FsSearchIndexEntry>,
    ) -> Arc<Vec<FsSearchIndexEntry>> {
        let files = Arc::new(files);
        self.snapshot = Some(FsSearchIndexSnapshot {
            root,
            files: files.clone(),
            indexed_at: Instant::now(),
        });
        files
    }

    fn invalidate(&mut self, root: &std::path::Path) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.root == root)
        {
            self.snapshot = None;
        }
    }
}

#[derive(Debug)]
pub(super) struct FsVersionCache {
    max_total_bytes: usize,
    max_versions_per_object: usize,
    total_bytes: usize,
    fifo: VecDeque<(String, String, usize)>,
    entries: HashMap<String, HashMap<String, Vec<u8>>>,
    observed_versions: HashMap<String, BTreeMap<String, String>>,
}

impl FsVersionCache {
    pub(super) fn new(max_total_bytes: usize, max_versions_per_object: usize) -> Self {
        Self {
            max_total_bytes,
            max_versions_per_object: max_versions_per_object.max(1),
            total_bytes: 0,
            fifo: VecDeque::new(),
            entries: HashMap::new(),
            observed_versions: HashMap::new(),
        }
    }

    fn observe_version(&mut self, object_id: &str, as_of_time: &str, version_id: &str) {
        self.observed_versions
            .entry(object_id.to_string())
            .or_default()
            .insert(as_of_time.to_string(), version_id.to_string());
    }

    fn select_version_at(&self, object_id: &str, as_of_time: &str) -> Option<String> {
        let observed = self.observed_versions.get(object_id)?;
        let object_entry = self.entries.get(object_id)?;

        if let Some((latest_as_of_time, _)) = observed.last_key_value()
            && as_of_time > latest_as_of_time.as_str()
        {
            return None;
        }

        observed
            .range(..=as_of_time.to_string())
            .rev()
            .find_map(|(_, version_id)| {
                object_entry
                    .contains_key(version_id)
                    .then(|| version_id.clone())
            })
    }

    fn insert(&mut self, object_id: &str, version_id: &str, bytes: Vec<u8>) {
        if self.max_total_bytes == 0 {
            return;
        }

        let size = bytes.len();
        if size == 0 || size > self.max_total_bytes {
            return;
        }

        let object_entry = self.entries.entry(object_id.to_string()).or_default();

        if object_entry.contains_key(version_id) {
            return;
        }

        object_entry.insert(version_id.to_string(), bytes);
        self.total_bytes = self.total_bytes.saturating_add(size);
        self.fifo
            .push_back((object_id.to_string(), version_id.to_string(), size));

        self.enforce_object_limit(object_id, version_id);
        while self.total_bytes > self.max_total_bytes {
            self.evict_one();
        }
    }

    fn get(&self, object_id: &str, version_id: &str) -> Option<&[u8]> {
        self.entries
            .get(object_id)
            .and_then(|m| m.get(version_id))
            .map(|v| v.as_slice())
    }

    fn list_version_ids(&self, object_id: &str) -> Vec<String> {
        self.entries
            .get(object_id)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn ordered_versions(&self, object_id: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();

        if let Some(observed) = self.observed_versions.get(object_id)
            && let Some(object_entry) = self.entries.get(object_id)
        {
            for (as_of_time, version_id) in observed.iter().rev() {
                if object_entry.contains_key(version_id) && seen.insert(version_id.clone()) {
                    out.push((version_id.clone(), as_of_time.clone()));
                }
            }
        }

        if out.is_empty() {
            let mut version_ids = self.list_version_ids(object_id);
            version_ids.sort();
            version_ids.reverse();
            out.extend(
                version_ids
                    .into_iter()
                    .map(|version_id| (version_id, String::new())),
            );
        }

        out
    }

    fn enforce_object_limit(&mut self, object_id: &str, keep_version_id: &str) {
        while self.entries.get(object_id).map(|m| m.len()).unwrap_or(0)
            > self.max_versions_per_object
        {
            let Some(object_entry) = self.entries.get(object_id) else {
                return;
            };

            let mut candidates = object_entry.keys().cloned().collect::<Vec<_>>();
            candidates.sort();

            let version_to_evict = candidates
                .into_iter()
                .find(|v| v != keep_version_id)
                .unwrap_or_else(|| keep_version_id.to_string());

            self.remove_entry(object_id, &version_to_evict);
        }
    }

    fn remove_entry(&mut self, object_id: &str, version_id: &str) {
        let Some(object_entry) = self.entries.get_mut(object_id) else {
            return;
        };

        let Some(bytes) = object_entry.remove(version_id) else {
            return;
        };

        self.total_bytes = self.total_bytes.saturating_sub(bytes.len());
        if object_entry.is_empty() {
            self.entries.remove(object_id);
        }

        let mut idx = 0;
        while idx < self.fifo.len() {
            if let Some((obj, ver, _)) = self.fifo.get(idx)
                && obj == object_id
                && ver == version_id
            {
                let _ = self.fifo.remove(idx);
                break;
            }
            idx += 1;
        }
    }

    fn evict_one(&mut self) {
        while let Some((object_id, version_id, size)) = self.fifo.pop_front() {
            let Some(object_entry) = self.entries.get_mut(&object_id) else {
                continue;
            };

            if object_entry.remove(&version_id).is_none() {
                continue;
            }

            self.total_bytes = self.total_bytes.saturating_sub(size);
            if object_entry.is_empty() {
                self.entries.remove(&object_id);
            }
            return;
        }
    }
}

async fn read_object_bytes_from_fs(
    fs_corpus_path: &str,
    object_id: &str,
) -> Result<Vec<u8>, ApiError> {
    let object_rel = std::path::Path::new(object_id);
    if object_rel.is_absolute() || !is_safe_rel_path(object_rel) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "object_id must be a relative path without parent components".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let base = std::path::Path::new(fs_corpus_path);
    let base_canon = tokio::fs::canonicalize(base).await.map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let full_path = base.join(object_rel);
    let full_canon = tokio::fs::canonicalize(full_path).await.map_err(|_| {
        json_error(
            StatusCode::NOT_FOUND,
            "ERR_SOURCE_UNAVAILABLE",
            "object not found".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    if !full_canon.starts_with(&base_canon) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "object_id escapes corpus root".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    tokio::fs::read(&full_canon).await.map_err(|_| {
        json_error(
            StatusCode::NOT_FOUND,
            "ERR_SOURCE_UNAVAILABLE",
            "object not found".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })
}

pub(super) async fn list_versions_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time_default: &str,
    params: &serde_json::Value,
) -> Result<Vec<VersionInfo>, ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;

    let version_id = sha256_hex(&bytes);
    let metadata_hash = sha256_hex(object_id.as_bytes());

    let mut cache = fs_versions.write().await;
    cache.insert(object_id, &version_id, bytes);
    cache.observe_version(object_id, as_of_time_default, &version_id);
    let mut ordered_versions = cache.ordered_versions(object_id);
    if !ordered_versions
        .iter()
        .any(|(observed_version_id, _)| observed_version_id == &version_id)
    {
        ordered_versions.insert(0, (version_id.clone(), as_of_time_default.to_string()));
    }

    Ok(ordered_versions
        .into_iter()
        .map(|(version_id, as_of_time)| VersionInfo {
            version_id,
            as_of_time: if as_of_time.is_empty() {
                as_of_time_default.to_string()
            } else {
                as_of_time
            },
            metadata_hash: metadata_hash.clone(),
        })
        .collect())
}

pub(super) async fn diff_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time_default: &str,
    max_diff_bytes: usize,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<Vec<pecr_contracts::EvidenceUnit>, ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let v1 = params
        .get("v1")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.v1 is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let v2 = params
        .get("v2")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.v2 is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    if !canonical::is_sha256_hex(v1) || !canonical::is_sha256_hex(v2) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "v1 and v2 must be sha256 hex version ids".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    async fn version_bytes(
        fs_versions: &Arc<RwLock<FsVersionCache>>,
        fs_corpus_path: &str,
        object_id: &str,
        version_id: &str,
    ) -> Result<Vec<u8>, ApiError> {
        if let Some(bytes) = fs_versions
            .read()
            .await
            .get(object_id, version_id)
            .map(|v| v.to_vec())
        {
            return Ok(bytes);
        }

        let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
        let current_version = sha256_hex(&bytes);
        if current_version != version_id {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "ERR_SOURCE_UNAVAILABLE",
                "requested version not found".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            ));
        }

        let mut cache = fs_versions.write().await;
        cache.insert(object_id, &current_version, bytes.clone());
        Ok(bytes)
    }

    let bytes_v1 = version_bytes(fs_versions, fs_corpus_path, object_id, v1).await?;
    let bytes_v2 = version_bytes(fs_versions, fs_corpus_path, object_id, v2).await?;

    let text_v1 = std::str::from_utf8(&bytes_v1).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "version v1 is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let text_v2 = std::str::from_utf8(&bytes_v2).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "version v2 is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let text_v1 = canonical::canonicalize_text_plain(text_v1);
    let text_v2 = canonical::canonicalize_text_plain(text_v2);

    let header_before = format!("a/{}@{}", object_id, v1);
    let header_after = format!("b/{}@{}", object_id, v2);
    let patch = TextDiff::from_lines(&text_v1, &text_v2)
        .unified_diff()
        .context_radius(3)
        .header(&header_before, &header_after)
        .to_string();

    let patch = canonical::canonicalize_text_plain(&patch);
    let patch_len = patch.len();

    if max_diff_bytes != 0 && patch_len > max_diff_bytes {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "diff exceeds size cap".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let content_hash = canonical::sha256_hex(patch.as_bytes());

    let newline_count = patch.as_bytes().iter().filter(|b| **b == b'\n').count() as u64;
    let span_or_row_spec = serde_json::json!({
        "type": "text_span",
        "start_byte": 0,
        "end_byte": patch_len as u64,
        "line_start": 1,
        "line_end": 1 + newline_count,
    });

    let diff_params = serde_json::json!({
        "object_id": object_id,
        "v1": v1,
        "v2": v2,
    });
    let transform_chain = vec![pecr_contracts::TransformStep {
        transform_type: "diff_unified_v1".to_string(),
        transform_hash: canonical::hash_canonical_json(&diff_params),
        params: Some(diff_params),
    }];

    let identity = serde_json::json!({
        "source_system": "fs_corpus",
        "object_id": object_id,
        "version_id": v2,
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time_default,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(vec![pecr_contracts::EvidenceUnit {
        source_system: "fs_corpus".to_string(),
        object_id: object_id.to_string(),
        version_id: v2.to_string(),
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::TextPlain,
        content: Some(serde_json::Value::String(patch)),
        content_hash,
        retrieved_at: as_of_time_default.to_string(),
        as_of_time: as_of_time_default.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain,
        evidence_unit_id,
    }])
}

pub(super) async fn fetch_span_from_fs(
    fs_versions: &Arc<RwLock<FsVersionCache>>,
    fs_corpus_path: &str,
    as_of_time: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, ApiError> {
    let object_id = params
        .get("object_id")
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.object_id is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;

    let selected_version_id = fs_versions
        .read()
        .await
        .select_version_at(object_id, as_of_time);

    let (bytes, version_id) = if let Some(version_id) = selected_version_id {
        if let Some(bytes) = fs_versions.read().await.get(object_id, &version_id) {
            (bytes.to_vec(), version_id)
        } else {
            let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
            let version_id = sha256_hex(&bytes);

            let mut cache = fs_versions.write().await;
            cache.insert(object_id, &version_id, bytes.clone());
            cache.observe_version(object_id, as_of_time, &version_id);

            (bytes, version_id)
        }
    } else {
        let bytes = read_object_bytes_from_fs(fs_corpus_path, object_id).await?;
        let version_id = sha256_hex(&bytes);

        let mut cache = fs_versions.write().await;
        cache.insert(object_id, &version_id, bytes.clone());
        cache.observe_version(object_id, as_of_time, &version_id);

        (bytes, version_id)
    };

    let start_byte = params
        .get("start_byte")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let end_byte = params
        .get("end_byte")
        .and_then(|v| v.as_u64())
        .unwrap_or(bytes.len() as u64);

    if end_byte > bytes.len() as u64 || start_byte > end_byte {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "invalid span range".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let start = start_byte as usize;
    let end = end_byte as usize;

    let span_bytes = &bytes[start..end];
    let content = std::str::from_utf8(span_bytes).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "span is not valid UTF-8".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let line_start = 1 + bytes[..start].iter().filter(|b| **b == b'\n').count() as u64;
    let line_end = line_start + span_bytes.iter().filter(|b| **b == b'\n').count() as u64;

    let span_or_row_spec = serde_json::json!({
        "type": "text_span",
        "start_byte": start_byte,
        "end_byte": end_byte,
        "line_start": line_start,
        "line_end": line_end,
    });

    let canonical_content = canonical::canonicalize_text_plain(content);
    let content_hash = canonical::sha256_hex(canonical_content.as_bytes());

    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "fs_corpus",
        "object_id": object_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(pecr_contracts::EvidenceUnit {
        source_system: "fs_corpus".to_string(),
        object_id: object_id.to_string(),
        version_id,
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::TextPlain,
        content: Some(serde_json::Value::String(content.to_string())),
        content_hash,
        retrieved_at: as_of_time.to_string(),
        as_of_time: as_of_time.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchMatchMode {
    All,
    Any,
    Phrase,
}

#[derive(Debug, Clone)]
struct FsSearchRequest {
    query: String,
    terms: Vec<String>,
    object_prefix: Option<String>,
    case_sensitive: bool,
    limit: usize,
    match_mode: SearchMatchMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FsSearchMatch {
    start_byte: u64,
    end_byte: u64,
    line_start: u64,
    line_end: u64,
    preview: String,
    score: u32,
}

pub(super) async fn search_from_fs(
    fs_search_index: &Arc<RwLock<FsSearchIndexCache>>,
    fs_corpus_path: &str,
    as_of_time_default: &str,
    policy_snapshot_hash: &str,
    params: &serde_json::Value,
) -> Result<Vec<EvidenceUnitRef>, ApiError> {
    let request = parse_fs_search_request(params)?;
    let base = std::path::Path::new(fs_corpus_path);
    let base_canon = tokio::fs::canonicalize(base).await.map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "filesystem corpus path does not exist".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let mut retried_after_invalidation = false;
    loop {
        let files = if retried_after_invalidation {
            rebuild_fs_search_index(fs_search_index, &base_canon).await?
        } else {
            get_or_rebuild_fs_search_index(fs_search_index, &base_canon).await?
        };

        let mut ranked_refs = Vec::new();
        let mut retry_needed = false;

        for entry in files.iter() {
            if let Some(object_prefix) = request.object_prefix.as_ref() {
                let object_id = if request.case_sensitive {
                    entry.object_id.clone()
                } else {
                    entry.object_id.to_ascii_lowercase()
                };
                if !object_id.starts_with(object_prefix) {
                    continue;
                }
            }

            let bytes = match tokio::fs::read(&entry.path).await {
                Ok(bytes) => bytes,
                Err(_) if !retried_after_invalidation => {
                    fs_search_index.write().await.invalidate(&base_canon);
                    retried_after_invalidation = true;
                    retry_needed = true;
                    break;
                }
                Err(_) => {
                    return Err(json_error(
                        StatusCode::NOT_FOUND,
                        "ERR_SOURCE_UNAVAILABLE",
                        "object not found".to_string(),
                        TerminalMode::SourceUnavailable,
                        false,
                    ));
                }
            };

            let text = match std::str::from_utf8(&bytes) {
                Ok(text) => text,
                Err(_) => continue,
            };

            let Some(search_match) = best_fs_search_match(text, &entry.object_id, &request) else {
                continue;
            };

            let version_id = sha256_hex(&bytes);
            let matched_content =
                &text[search_match.start_byte as usize..search_match.end_byte as usize];
            let canonical_content = canonical::canonicalize_text_plain(matched_content);
            let content_hash = canonical::sha256_hex(canonical_content.as_bytes());
            let span_or_row_spec = serde_json::json!({
                "type": "text_span",
                "start_byte": search_match.start_byte,
                "end_byte": search_match.end_byte,
                "line_start": search_match.line_start,
                "line_end": search_match.line_end,
            });

            let identity = serde_json::json!({
                "source_system": "fs_corpus",
                "object_id": entry.object_id.clone(),
                "version_id": version_id.clone(),
                "span_or_row_spec": span_or_row_spec,
                "content_hash": content_hash,
                "as_of_time": as_of_time_default,
                "policy_snapshot_hash": policy_snapshot_hash,
                "transform_chain": [],
            });
            let evidence_unit_id = canonical::hash_canonical_json(&identity);

            ranked_refs.push((
                search_match.score,
                entry.object_id.clone(),
                EvidenceUnitRef {
                    evidence_unit_id,
                    source_system: "fs_corpus".to_string(),
                    object_id: entry.object_id.clone(),
                    version_id,
                    start_byte: Some(search_match.start_byte),
                    end_byte: Some(search_match.end_byte),
                    line_start: Some(search_match.line_start),
                    line_end: Some(search_match.line_end),
                    match_preview: Some(search_match.preview),
                    match_score: Some(search_match.score),
                },
            ));
        }

        if retry_needed {
            continue;
        }

        ranked_refs.sort_by(|(score_a, object_id_a, _), (score_b, object_id_b, _)| {
            score_b
                .cmp(score_a)
                .then_with(|| object_id_a.cmp(object_id_b))
        });
        ranked_refs.truncate(request.limit);
        return Ok(ranked_refs
            .into_iter()
            .map(|(_, _, reference)| reference)
            .collect());
    }
}

fn parse_fs_search_request(params: &serde_json::Value) -> Result<FsSearchRequest, ApiError> {
    let query = params
        .get("query")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.query is required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })
        .and_then(|value| {
            normalize_search_query(value).map_err(|err| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    format!("invalid params.query: {}", err),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })
        })?;

    let terms = match params.get("terms") {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| {
                        json_error(
                            StatusCode::BAD_REQUEST,
                            "ERR_INVALID_PARAMS",
                            "params.terms must be an array of strings".to_string(),
                            TerminalMode::InsufficientEvidence,
                            false,
                        )
                    })
                    .and_then(|value| {
                        normalize_search_query(value).map_err(|err| {
                            json_error(
                                StatusCode::BAD_REQUEST,
                                "ERR_INVALID_PARAMS",
                                format!("invalid params.terms: {}", err),
                                TerminalMode::InsufficientEvidence,
                                false,
                            )
                        })
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(normalize_search_query)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    format!("invalid params.terms: {}", err),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?,
        Some(_) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.terms must be a string or array of strings".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
        None => query.split_whitespace().map(ToOwned::to_owned).collect(),
    };

    let case_sensitive = params
        .get("case_sensitive")
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    "params.case_sensitive must be a boolean".to_string(),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })
        })
        .transpose()?
        .unwrap_or(false);

    let object_prefix = params
        .get("object_prefix")
        .and_then(|value| value.as_str())
        .map(|value| {
            normalize_resource_prefix(value).map_err(|err| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    format!("invalid params.object_prefix: {}", err),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })
        })
        .transpose()?;

    let limit = params
        .get("limit")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, 50) as usize)
        .unwrap_or(10);

    let match_mode = params
        .get("match_mode")
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| match value.as_str() {
            "all" => Ok(SearchMatchMode::All),
            "any" => Ok(SearchMatchMode::Any),
            "phrase" => Ok(SearchMatchMode::Phrase),
            _ => Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.match_mode must be one of: all, any, phrase".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )),
        })
        .transpose()?
        .unwrap_or(SearchMatchMode::All);

    let query = if case_sensitive {
        query
    } else {
        query.to_ascii_lowercase()
    };
    let terms = terms
        .into_iter()
        .flat_map(|term| {
            term.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .map(|term| {
            if case_sensitive {
                term
            } else {
                term.to_ascii_lowercase()
            }
        })
        .collect::<Vec<_>>();
    let object_prefix = object_prefix.map(|prefix| {
        if case_sensitive {
            prefix
        } else {
            prefix.to_ascii_lowercase()
        }
    });

    Ok(FsSearchRequest {
        query,
        terms,
        object_prefix,
        case_sensitive,
        limit,
        match_mode,
    })
}

fn best_fs_search_match(
    text: &str,
    object_id: &str,
    request: &FsSearchRequest,
) -> Option<FsSearchMatch> {
    let comparable_text = if request.case_sensitive {
        text.to_string()
    } else {
        text.to_ascii_lowercase()
    };
    let comparable_object_id = if request.case_sensitive {
        object_id.to_string()
    } else {
        object_id.to_ascii_lowercase()
    };

    let mut best_match: Option<FsSearchMatch> = None;
    let mut offset = 0usize;
    let mut line_number = 1u64;

    for raw_line in text.split_inclusive('\n') {
        let line_len = raw_line.trim_end_matches('\n').len();
        let line_end = offset + line_len;
        let line_text = raw_line.trim_end_matches('\n').trim();
        let comparable_line = if request.case_sensitive {
            line_text.to_string()
        } else {
            line_text.to_ascii_lowercase()
        };

        let token_hits = request
            .terms
            .iter()
            .filter(|term| comparable_line.contains(term.as_str()))
            .count() as u32;
        let phrase_match = comparable_line.contains(request.query.as_str());
        let object_hits = request
            .terms
            .iter()
            .filter(|term| comparable_object_id.contains(term.as_str()))
            .count() as u32;

        let is_match = match request.match_mode {
            SearchMatchMode::Phrase => phrase_match,
            SearchMatchMode::All => {
                !request.terms.is_empty()
                    && request
                        .terms
                        .iter()
                        .all(|term| comparable_line.contains(term.as_str()))
            }
            SearchMatchMode::Any => token_hits > 0 || phrase_match,
        };

        if is_match {
            let mut score = token_hits * 10 + object_hits * 3;
            if phrase_match {
                score += 20;
            }
            if comparable_object_id.contains(request.query.as_str()) {
                score += 5;
            }
            if !line_text.is_empty() {
                score += 1;
            }

            let search_match = FsSearchMatch {
                start_byte: offset as u64,
                end_byte: line_end as u64,
                line_start: line_number,
                line_end: line_number,
                preview: abbreviate_search_preview(line_text, 160),
                score,
            };

            match &best_match {
                Some(current)
                    if current.score > search_match.score
                        || (current.score == search_match.score
                            && current.start_byte <= search_match.start_byte) => {}
                _ => best_match = Some(search_match),
            }
        }

        offset += raw_line.len();
        line_number = line_number.saturating_add(1);
    }

    if best_match.is_none() {
        let whole_text_matches = match request.match_mode {
            SearchMatchMode::Phrase => comparable_text.contains(request.query.as_str()),
            SearchMatchMode::All => request
                .terms
                .iter()
                .all(|term| comparable_text.contains(term.as_str())),
            SearchMatchMode::Any => request
                .terms
                .iter()
                .any(|term| comparable_text.contains(term.as_str())),
        };
        if whole_text_matches {
            return Some(FsSearchMatch {
                start_byte: 0,
                end_byte: text.len() as u64,
                line_start: 1,
                line_end: 1 + text.bytes().filter(|byte| *byte == b'\n').count() as u64,
                preview: abbreviate_search_preview(text.trim(), 160),
                score: 25,
            });
        }
    }

    best_match
}

fn abbreviate_search_preview(text: &str, max_chars: usize) -> String {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = normalized.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", preview)
    } else {
        preview
    }
}

async fn get_or_rebuild_fs_search_index(
    fs_search_index: &Arc<RwLock<FsSearchIndexCache>>,
    base_canon: &std::path::Path,
) -> Result<Arc<Vec<FsSearchIndexEntry>>, ApiError> {
    if let Some(files) = fs_search_index.read().await.get_if_fresh(base_canon) {
        return Ok(files);
    }

    rebuild_fs_search_index(fs_search_index, base_canon).await
}

async fn rebuild_fs_search_index(
    fs_search_index: &Arc<RwLock<FsSearchIndexCache>>,
    base_canon: &std::path::Path,
) -> Result<Arc<Vec<FsSearchIndexEntry>>, ApiError> {
    let files = build_fs_search_index(base_canon).await?;
    let mut cache = fs_search_index.write().await;
    Ok(cache.set_snapshot(base_canon.to_path_buf(), files))
}

async fn build_fs_search_index(
    base_canon: &std::path::Path,
) -> Result<Vec<FsSearchIndexEntry>, ApiError> {
    let mut pending_dirs = vec![base_canon.to_path_buf()];
    let mut visited_dirs = std::collections::HashSet::new();
    visited_dirs.insert(base_canon.to_path_buf());
    let mut files = Vec::new();

    while let Some(dir) = pending_dirs.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await.map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_INTERNAL",
                "failed to enumerate filesystem corpus".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_INTERNAL",
                "failed to enumerate filesystem corpus".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })? {
            let path = entry.path();
            let meta = tokio::fs::metadata(&path).await.map_err(|_| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "failed to enumerate filesystem corpus".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;

            if meta.is_dir() {
                let dir_canon = tokio::fs::canonicalize(&path).await.map_err(|_| {
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_INTERNAL",
                        "failed to enumerate filesystem corpus".to_string(),
                        TerminalMode::SourceUnavailable,
                        false,
                    )
                })?;

                if !dir_canon.starts_with(base_canon) {
                    continue;
                }

                if visited_dirs.insert(dir_canon.clone()) {
                    pending_dirs.push(dir_canon);
                }
                continue;
            }

            if !meta.is_file() {
                continue;
            }

            let file_canon = tokio::fs::canonicalize(&path).await.map_err(|_| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "failed to enumerate filesystem corpus".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;
            if !file_canon.starts_with(base_canon) {
                continue;
            }

            let rel = match path.strip_prefix(base_canon) {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            if !is_safe_rel_path(rel) {
                continue;
            }

            let object_id = rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");

            files.push(FsSearchIndexEntry { path, object_id });
        }
    }

    files.sort_by(|a, b| a.path.to_string_lossy().cmp(&b.path.to_string_lossy()));
    Ok(files)
}

fn is_safe_rel_path(path: &std::path::Path) -> bool {
    use std::path::Component;
    path.components().all(|c| match c {
        Component::Normal(_) => true,
        Component::CurDir => false,
        Component::ParentDir => false,
        Component::RootDir => false,
        Component::Prefix(_) => false,
    })
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().encode_hex::<String>()
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SafeViewSpec {
    view_id: &'static str,
    primary_key_fields: &'static [&'static str],
    version_field: &'static str,
    allowlisted_fields: &'static [&'static str],
    allowlisted_filter_fields: &'static [&'static str],
    allowlisted_group_by_fields: &'static [&'static str],
    allowlisted_metrics: &'static [SafeMetricAllowlist],
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SafeViewNarrowingHints {
    pub(super) field_labels: &'static [&'static str],
    pub(super) dimension_labels: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SafeMetricAllowlist {
    name: &'static str,
    field: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateRankDirection {
    Asc,
    Desc,
}

impl AggregateRankDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

pub(super) fn safeview_spec(view_id: &str) -> Option<SafeViewSpec> {
    const PK: &[&str] = &["tenant_id", "customer_id"];
    const METRICS: &[SafeMetricAllowlist] = &[SafeMetricAllowlist {
        name: "count",
        field: "customer_id",
    }];

    match view_id {
        "safe_customer_view_public" => Some(SafeViewSpec {
            view_id: "safe_customer_view_public",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_public_slow" => Some(SafeViewSpec {
            view_id: "safe_customer_view_public_slow",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_admin" => Some(SafeViewSpec {
            view_id: "safe_customer_view_admin",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "admin_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_support" => Some(SafeViewSpec {
            view_id: "safe_customer_view_support",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "support_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        "safe_customer_view_injection" => Some(SafeViewSpec {
            view_id: "safe_customer_view_injection",
            primary_key_fields: PK,
            version_field: "updated_at",
            allowlisted_fields: &[
                "tenant_id",
                "customer_id",
                "status",
                "plan_tier",
                "injection_note",
                "updated_at",
            ],
            allowlisted_filter_fields: &["customer_id", "status", "plan_tier"],
            allowlisted_group_by_fields: &["status", "plan_tier"],
            allowlisted_metrics: METRICS,
        }),
        _ => None,
    }
}

pub(super) fn safeview_narrowing_hints(view_id: &str) -> Option<SafeViewNarrowingHints> {
    let spec = safeview_spec(view_id)?;
    Some(SafeViewNarrowingHints {
        field_labels: spec.allowlisted_filter_fields,
        dimension_labels: spec.allowlisted_group_by_fields,
    })
}

const ALLOWLISTED_SAFEVIEW_IDS: &[&str] = &[
    "safe_customer_view_public",
    "safe_customer_view_public_slow",
    "safe_customer_view_admin",
    "safe_customer_view_support",
    "safe_customer_view_injection",
];

pub(super) async fn validate_safeview_schema(pool: &PgPool) -> Result<(), StartupError> {
    for view_id in ALLOWLISTED_SAFEVIEW_IDS {
        let spec = safeview_spec(view_id).ok_or_else(|| StartupError {
            code: "ERR_INTERNAL",
            message: format!("internal safe-view allowlist mismatch for `{}`", view_id),
        })?;

        let rows = sqlx::query(
            "SELECT column_name \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1",
        )
        .bind(spec.view_id)
        .fetch_all(pool)
        .await
        .map_err(|_| StartupError {
            code: "ERR_DB_UNAVAILABLE",
            message: format!(
                "failed to introspect safe-view schema for `{}`",
                spec.view_id
            ),
        })?;

        if rows.is_empty() {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "safe-view schema mismatch: required view `{}` does not exist in current schema",
                    spec.view_id
                ),
            });
        }

        let available_columns = rows
            .into_iter()
            .filter_map(|row| row.try_get::<String, _>("column_name").ok())
            .map(|c| c.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();

        let missing = missing_safeview_columns(spec, &available_columns);
        if !missing.is_empty() {
            return Err(StartupError {
                code: "ERR_INVALID_CONFIG",
                message: format!(
                    "safe-view schema mismatch for `{}`: missing columns [{}]",
                    spec.view_id,
                    missing.join(", ")
                ),
            });
        }
    }

    Ok(())
}

pub(super) fn missing_safeview_columns(
    spec: SafeViewSpec,
    available_columns: &BTreeSet<String>,
) -> Vec<String> {
    let mut required_columns = BTreeSet::<&str>::new();
    required_columns.extend(spec.primary_key_fields.iter().copied());
    required_columns.extend(spec.allowlisted_fields.iter().copied());
    required_columns.extend(spec.allowlisted_filter_fields.iter().copied());
    required_columns.extend(spec.allowlisted_group_by_fields.iter().copied());
    required_columns.insert(spec.version_field);
    for metric in spec.allowlisted_metrics {
        required_columns.insert(metric.field);
    }

    required_columns
        .into_iter()
        .filter(|field| !available_columns.contains(*field))
        .map(str::to_string)
        .collect()
}

fn parse_safeview_string(
    value: Option<&serde_json::Value>,
    key: &'static str,
) -> Result<String, ApiError> {
    value
        .and_then(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("params.{} is required", key),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })
}

fn parse_safeview_fields(
    params: &serde_json::Value,
    spec: SafeViewSpec,
    max_fields: usize,
) -> Result<Vec<String>, ApiError> {
    let mut fields = params
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.fields must be an array of strings".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?
        .iter()
        .filter_map(|v| v.as_str())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect::<Vec<_>>();

    fields.sort();
    fields.dedup();

    if fields.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.fields must be a non-empty array".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    if fields.len() > max_fields {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.fields exceeds max field count".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    for field in &fields {
        if !spec.allowlisted_fields.contains(&field.as_str()) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
    }

    Ok(fields)
}

fn parse_safeview_filter_spec(
    params: &serde_json::Value,
    spec: SafeViewSpec,
) -> Result<Vec<FilterEq>, ApiError> {
    let Some(filter) = params.get("filter_spec") else {
        return Ok(Vec::new());
    };

    let Some(map) = filter.as_object() else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.filter_spec must be an object".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    };

    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let field = k.trim();
        if field.is_empty() {
            continue;
        }

        if !spec.allowlisted_filter_fields.contains(&field) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("filter field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        let value = v
            .as_str()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                json_error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PARAMS",
                    format!("filter_spec.{} must be a non-empty string", field),
                    TerminalMode::InsufficientEvidence,
                    false,
                )
            })?;

        out.push((field.to_string(), value.to_string()));
    }

    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

pub(super) struct PgSafeviewContext<'a> {
    pub(super) pool: &'a PgPool,
    pub(super) config: &'a GatewayConfig,
    pub(super) versions: &'a Arc<RwLock<FsVersionCache>>,
    pub(super) tenant_id: &'a str,
    pub(super) policy_snapshot_id: &'a str,
    pub(super) policy_snapshot_hash: &'a str,
    pub(super) as_of_time: &'a str,
}

pub(super) async fn fetch_rows_from_pg_safeview(
    ctx: PgSafeviewContext<'_>,
    params: &serde_json::Value,
) -> Result<Vec<pecr_contracts::EvidenceUnit>, ApiError> {
    let PgSafeviewContext {
        pool,
        config,
        versions: pg_versions,
        tenant_id,
        policy_snapshot_id,
        policy_snapshot_hash,
        as_of_time,
    } = ctx;
    let view_id = parse_safeview_string(params.get("view_id"), "view_id")?;
    let spec = safeview_spec(&view_id).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "view_id not allowlisted".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let fields = parse_safeview_fields(params, spec, config.pg_safeview_max_fields)?;
    let filters = parse_safeview_filter_spec(params, spec)?;

    if let Some(customer_id) = filters
        .iter()
        .find(|(field, _)| field == "customer_id")
        .map(|(_, value)| value.as_str())
    {
        let cache_object_id = format!("{}:{}:{}", spec.view_id, tenant_id, customer_id);
        let cache = pg_versions.read().await;
        if let Some(version_id) = cache.select_version_at(cache_object_id.as_str(), as_of_time)
            && let Some(snapshot_bytes) = cache.get(cache_object_id.as_str(), version_id.as_str())
            && let Ok(snapshot_value) = serde_json::from_slice::<serde_json::Value>(snapshot_bytes)
            && let Some(snapshot_obj) = snapshot_value.as_object()
            && filters.iter().all(|(field, expected)| {
                snapshot_obj
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(|actual| actual == expected)
                    .unwrap_or(false)
            })
        {
            let mut primary_key = serde_json::Map::new();
            let mut pk_values = Vec::with_capacity(spec.primary_key_fields.len());
            for pk in spec.primary_key_fields {
                let value = snapshot_obj
                    .get(*pk)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_INTERNAL",
                            "safe view snapshot missing primary key field".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                pk_values.push(value.to_string());
                primary_key.insert(pk.to_string(), serde_json::Value::String(value.to_string()));
            }

            let mut content = serde_json::Map::new();
            for field in &fields {
                content.insert(
                    field.clone(),
                    snapshot_obj
                        .get(field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                );
            }
            let content = serde_json::Value::Object(content);
            let content_hash = canonical::hash_canonical_json(&content);

            let span_or_row_spec = serde_json::json!({
                "type": "db_row",
                "view_id": spec.view_id,
                "primary_key": primary_key,
                "fields": &fields,
            });

            let object_id = format!("{}:{}", spec.view_id, pk_values.join(":"));
            let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
            let identity = serde_json::json!({
                "source_system": "pg_safeview",
                "object_id": object_id.as_str(),
                "version_id": version_id.clone(),
                "span_or_row_spec": span_or_row_spec.clone(),
                "content_hash": content_hash.clone(),
                "as_of_time": as_of_time,
                "policy_snapshot_hash": policy_snapshot_hash,
                "transform_chain": transform_chain,
            });
            let evidence_unit_id = canonical::hash_canonical_json(&identity);

            return Ok(vec![pecr_contracts::EvidenceUnit {
                source_system: "pg_safeview".to_string(),
                object_id,
                version_id,
                span_or_row_spec,
                content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
                content: Some(content),
                content_hash,
                retrieved_at: as_of_time.to_string(),
                as_of_time: as_of_time.to_string(),
                policy_snapshot_id: policy_snapshot_id.to_string(),
                policy_snapshot_hash: policy_snapshot_hash.to_string(),
                transform_chain: Vec::new(),
                evidence_unit_id,
            }]);
        }
    }

    let select_fields = spec
        .allowlisted_fields
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let select_sql = select_fields
        .iter()
        .map(|f| {
            if f == spec.version_field {
                format!(
                    "to_char({} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as {}",
                    f, f
                )
            } else {
                format!("{}::text as {}", f, f)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    let mut sql = format!("SELECT {} FROM {}", select_sql, spec.view_id);
    if !filters.is_empty() {
        sql.push_str(" WHERE ");
        for (idx, (field, _)) in filters.iter().enumerate() {
            if idx != 0 {
                sql.push_str(" AND ");
            }
            sql.push_str(field);
            sql.push_str(" = $");
            sql.push_str(&(idx + 1).to_string());
        }
    }

    sql.push_str(" ORDER BY ");
    sql.push_str(&spec.primary_key_fields.join(", "));
    sql.push_str(" LIMIT ");
    sql.push_str(&config.pg_safeview_max_rows.to_string());

    let timeout_str = format!("{}ms", config.pg_safeview_query_timeout_ms);
    let mut tx = pool.begin().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    sqlx::query("SELECT set_config('pecr.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let mut query = sqlx::query(&sql);
    for (_, value) in &filters {
        query = query.bind(value.as_str());
    }

    let rows = query.fetch_all(&mut *tx).await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database query failed".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    tx.commit().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    let schema_error = || {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "safe view schema mismatch".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    };

    let mut out = Vec::with_capacity(rows.len());
    let mut cache = pg_versions.write().await;
    for row in rows {
        let mut snapshot = serde_json::Map::new();
        for field in spec.allowlisted_fields {
            let value: Option<String> = row.try_get(field).map_err(|_| schema_error())?;
            snapshot.insert(
                field.to_string(),
                value
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }

        let mut primary_key = serde_json::Map::new();
        let mut pk_values = Vec::with_capacity(spec.primary_key_fields.len());
        for pk in spec.primary_key_fields {
            let value = snapshot
                .get(*pk)
                .and_then(|v| v.as_str())
                .ok_or_else(&schema_error)?;
            pk_values.push(value.to_string());
            primary_key.insert(pk.to_string(), serde_json::Value::String(value.to_string()));
        }

        let updated_at = snapshot
            .get(spec.version_field)
            .and_then(|v| v.as_str())
            .ok_or_else(&schema_error)?;
        let version_id = sha256_hex(updated_at.as_bytes());

        let mut content = serde_json::Map::new();
        for field in &fields {
            content.insert(
                field.clone(),
                snapshot
                    .get(field)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        let content = serde_json::Value::Object(content);
        let content_hash = canonical::hash_canonical_json(&content);

        let span_or_row_spec = serde_json::json!({
            "type": "db_row",
            "view_id": spec.view_id,
            "primary_key": primary_key,
            "fields": &fields,
        });

        let object_id = format!("{}:{}", spec.view_id, pk_values.join(":"));
        let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
        let identity = serde_json::json!({
            "source_system": "pg_safeview",
            "object_id": object_id.as_str(),
            "version_id": version_id.clone(),
            "span_or_row_spec": span_or_row_spec.clone(),
            "content_hash": content_hash.clone(),
            "as_of_time": as_of_time,
            "policy_snapshot_hash": policy_snapshot_hash,
            "transform_chain": transform_chain,
        });
        let evidence_unit_id = canonical::hash_canonical_json(&identity);

        let snapshot_bytes =
            serde_json::to_vec(&serde_json::Value::Object(snapshot)).unwrap_or_else(|_| Vec::new());
        cache.insert(object_id.as_str(), version_id.as_str(), snapshot_bytes);
        cache.observe_version(object_id.as_str(), as_of_time, version_id.as_str());

        out.push(pecr_contracts::EvidenceUnit {
            source_system: "pg_safeview".to_string(),
            object_id,
            version_id,
            span_or_row_spec,
            content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
            content: Some(content),
            content_hash,
            retrieved_at: as_of_time.to_string(),
            as_of_time: as_of_time.to_string(),
            policy_snapshot_id: policy_snapshot_id.to_string(),
            policy_snapshot_hash: policy_snapshot_hash.to_string(),
            transform_chain: Vec::new(),
            evidence_unit_id,
        });
    }
    drop(cache);

    Ok(out)
}

pub(super) async fn aggregate_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    as_of_time: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, ApiError> {
    let view_id = parse_safeview_string(params.get("view_id"), "view_id")?;
    let spec = safeview_spec(&view_id).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "view_id not allowlisted".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TimeGranularity {
        Day,
        Month,
    }

    impl TimeGranularity {
        fn label(self) -> &'static str {
            match self {
                Self::Day => "day",
                Self::Month => "month",
            }
        }

        fn sql_projection(self, field: &str) -> String {
            match self {
                Self::Day => format!(
                    "to_char(date_trunc('day', {} AT TIME ZONE 'UTC'), 'YYYY-MM-DD') as time_bucket",
                    field
                ),
                Self::Month => format!(
                    "to_char(date_trunc('month', {} AT TIME ZONE 'UTC'), 'YYYY-MM') as time_bucket",
                    field
                ),
            }
        }
    }

    let time_granularity = params
        .get("time_granularity")
        .and_then(|value| value.as_str())
        .map(|value| match value.trim() {
            "day" => Ok(TimeGranularity::Day),
            "month" => Ok(TimeGranularity::Month),
            _ => Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.time_granularity must be one of: day, month".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )),
        })
        .transpose()?;

    let mut group_by = params
        .get("group_by")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    group_by.sort();
    group_by.dedup();

    for field in &group_by {
        if !spec.allowlisted_group_by_fields.contains(&field.as_str()) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("group_by field not allowlisted: {}", field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
    }

    let top_n = params
        .get("top_n")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, config.pg_safeview_max_groups as u64) as usize);
    let include_rank = params
        .get("include_rank")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let rank_direction = match params
        .get("rank_direction")
        .and_then(|value| value.as_str())
    {
        Some("asc") => AggregateRankDirection::Asc,
        _ => AggregateRankDirection::Desc,
    };
    let drilldown_dimension = params
        .get("drilldown_dimension")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if let Some(drilldown_dimension) = drilldown_dimension.as_deref() {
        if !spec
            .allowlisted_group_by_fields
            .contains(&drilldown_dimension)
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!(
                    "drilldown_dimension not allowlisted: {}",
                    drilldown_dimension
                ),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
        if group_by.iter().any(|field| field == drilldown_dimension) {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.drilldown_dimension must not repeat group_by".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MetricParam {
        name: String,
        field: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct MetricSpec {
        name: String,
        field: String,
    }

    let metrics_raw = params
        .get("metrics")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "params.metrics must be an array".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?
        .to_vec();

    let mut metrics = Vec::with_capacity(metrics_raw.len());
    for raw in metrics_raw {
        let metric: MetricParam = serde_json::from_value(raw).map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "invalid metric object".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            )
        })?;
        let name = metric.name.trim();
        let field = metric.field.trim();
        if name.is_empty() || field.is_empty() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                "metric name and field are required".to_string(),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        if !spec
            .allowlisted_metrics
            .iter()
            .any(|m| m.name == name && m.field == field)
        {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PARAMS",
                format!("metric not allowlisted: {}({})", name, field),
                TerminalMode::InsufficientEvidence,
                false,
            ));
        }

        metrics.push(MetricSpec {
            name: name.to_string(),
            field: field.to_string(),
        });
    }

    metrics.sort();
    metrics.dedup();

    if metrics.is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "params.metrics must be a non-empty array".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        ));
    }

    let ranking_requested = !group_by.is_empty()
        && (top_n.is_some() || include_rank || params.get("rank_direction").is_some());
    let limit = if group_by.is_empty() && time_granularity.is_none() {
        1usize
    } else {
        top_n.unwrap_or(config.pg_safeview_max_groups)
    };

    let filters = parse_safeview_filter_spec(params, spec)?;
    let default_filter = serde_json::json!({});
    let filter_value = params.get("filter_spec").unwrap_or(&default_filter);
    let filter_fingerprint = canonical::hash_canonical_json(filter_value);
    let available_dimensions = spec
        .allowlisted_group_by_fields
        .iter()
        .map(|field| field.to_string())
        .collect::<Vec<_>>();
    let available_drilldown_dimensions = available_dimensions
        .iter()
        .filter(|field| !group_by.iter().any(|group_field| group_field == *field))
        .cloned()
        .collect::<Vec<_>>();

    let mut select_parts = Vec::new();
    let mut sql_group_by_parts = Vec::new();
    let mut sql_order_by_parts = Vec::new();
    if let Some(granularity) = time_granularity {
        select_parts.push(granularity.sql_projection(spec.version_field));
        sql_group_by_parts.push("time_bucket".to_string());
        sql_order_by_parts.push("time_bucket".to_string());
    }
    for field in &group_by {
        select_parts.push(format!("{}::text as {}", field, field));
        sql_group_by_parts.push(field.clone());
        sql_order_by_parts.push(field.clone());
    }
    for metric in &metrics {
        if metric.name.as_str() == "count" {
            select_parts.push(format!(
                "COUNT({})::bigint as {}_{}",
                metric.field.as_str(),
                metric.name.as_str(),
                metric.field.as_str()
            ));
        }
    }

    let primary_metric_alias =
        format!("{}_{}", metrics[0].name.as_str(), metrics[0].field.as_str());
    if ranking_requested {
        sql_order_by_parts.clear();
        sql_order_by_parts.push(format!(
            "{} {}",
            primary_metric_alias,
            rank_direction.as_str().to_ascii_uppercase()
        ));
        for field in &group_by {
            sql_order_by_parts.push(field.clone());
        }
    }

    let mut sql = format!("SELECT {} FROM {}", select_parts.join(", "), spec.view_id);
    if !filters.is_empty() {
        sql.push_str(" WHERE ");
        for (idx, (field, _)) in filters.iter().enumerate() {
            if idx != 0 {
                sql.push_str(" AND ");
            }
            sql.push_str(field);
            sql.push_str(" = $");
            sql.push_str(&(idx + 1).to_string());
        }
    }

    if !sql_group_by_parts.is_empty() {
        sql.push_str(" GROUP BY ");
        sql.push_str(&sql_group_by_parts.join(", "));
        sql.push_str(" ORDER BY ");
        sql.push_str(&sql_order_by_parts.join(", "));
        sql.push_str(" LIMIT ");
        sql.push_str(&limit.to_string());
    } else {
        sql.push_str(" LIMIT 1");
    }

    let timeout_str = format!("{}ms", config.pg_safeview_query_timeout_ms);
    let mut tx = pool.begin().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    sqlx::query("SELECT set_config('pecr.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let mut query = sqlx::query(&sql);
    for (_, value) in &filters {
        query = query.bind(value.as_str());
    }

    let rows = query.fetch_all(&mut *tx).await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database query failed".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    tx.commit().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    let schema_error = || {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "safe view schema mismatch".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    };

    let mut result_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let mut group = serde_json::Map::new();
        if time_granularity.is_some() {
            let time_bucket: Option<String> =
                row.try_get("time_bucket").map_err(|_| schema_error())?;
            group.insert(
                "time_bucket".to_string(),
                time_bucket
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        for field in &group_by {
            let value: Option<String> = row.try_get(field.as_str()).map_err(|_| schema_error())?;
            group.insert(
                field.clone(),
                value
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }

        let mut metric_values = Vec::with_capacity(metrics.len());
        for metric in &metrics {
            let col = format!("{}_{}", metric.name.as_str(), metric.field.as_str());
            let value: i64 = row.try_get(col.as_str()).map_err(|_| schema_error())?;
            metric_values.push(serde_json::json!({
                "name": metric.name.as_str(),
                "field": metric.field.as_str(),
                "value": value,
            }));
        }

        result_rows.push(serde_json::json!({
            "group": group,
            "metrics": metric_values,
        }));
    }

    decorate_aggregate_rows(
        &mut result_rows,
        &filters,
        include_rank && ranking_requested,
        drilldown_dimension.as_deref(),
    );

    let mut content_map = serde_json::Map::new();
    content_map.insert("rows".to_string(), serde_json::json!(result_rows));
    if !available_dimensions.is_empty() {
        content_map.insert(
            "available_dimensions".to_string(),
            serde_json::json!(available_dimensions),
        );
    }
    if !available_drilldown_dimensions.is_empty() {
        content_map.insert(
            "available_drilldown_dimensions".to_string(),
            serde_json::json!(available_drilldown_dimensions),
        );
    }
    if ranking_requested {
        content_map.insert(
            "ranking_summary".to_string(),
            serde_json::json!({
                "ordered_by": format!("{}({})", metrics[0].name, metrics[0].field),
                "direction": rank_direction.as_str(),
                "top_n": limit,
            }),
        );
    }

    let content = serde_json::Value::Object(content_map);
    let content_hash = canonical::hash_canonical_json(&content);

    let span_or_row_spec = serde_json::json!({
        "type": "db_aggregate",
        "view_id": spec.view_id,
        "filter_fingerprint": filter_fingerprint,
        "group_by": group_by,
        "time_granularity": time_granularity.map(TimeGranularity::label),
        "top_n": top_n,
        "rank_direction": ranking_requested.then_some(rank_direction.as_str()),
        "drilldown_dimension": drilldown_dimension,
        "metrics": metrics
            .iter()
            .map(|m| serde_json::json!({"name": m.name.as_str(), "field": m.field.as_str()}))
            .collect::<Vec<_>>(),
    });

    let version_id = content_hash.clone();
    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "pg_safeview",
        "object_id": spec.view_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(pecr_contracts::EvidenceUnit {
        source_system: "pg_safeview".to_string(),
        object_id: spec.view_id.to_string(),
        version_id,
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
        content: Some(content),
        content_hash,
        retrieved_at: as_of_time.to_string(),
        as_of_time: as_of_time.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

pub(super) async fn compare_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    as_of_time: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, ApiError> {
    let mut evidence = aggregate_from_pg_safeview(
        pool,
        config,
        tenant_id,
        policy_snapshot_id,
        policy_snapshot_hash,
        as_of_time,
        params,
    )
    .await?;

    let comparison_mode = if evidence
        .span_or_row_spec
        .get("time_granularity")
        .and_then(|value| value.as_str())
        .is_some()
    {
        "trend"
    } else if evidence
        .span_or_row_spec
        .get("group_by")
        .and_then(|value| value.as_array())
        .is_some_and(|fields| !fields.is_empty())
    {
        "group_compare"
    } else {
        "single_metric"
    };

    if let Some(spec) = evidence.span_or_row_spec.as_object_mut() {
        spec.insert(
            "comparison_mode".to_string(),
            serde_json::json!(comparison_mode),
        );
    }

    let comparison_summary = evidence
        .content
        .as_ref()
        .and_then(|content| content.get("rows"))
        .and_then(|value| value.as_array())
        .and_then(|rows| build_compare_summary(rows));

    if let Some(summary) = comparison_summary
        && let Some(content) = evidence.content.as_mut()
        && let Some(map) = content.as_object_mut()
    {
        map.insert("comparison_summary".to_string(), summary);
    }

    refresh_json_evidence_identity(&mut evidence);
    Ok(evidence)
}

pub(super) async fn discover_dimensions_from_pg_safeview(
    pool: &PgPool,
    config: &GatewayConfig,
    tenant_id: &str,
    policy_snapshot_id: &str,
    policy_snapshot_hash: &str,
    as_of_time: &str,
    params: &serde_json::Value,
) -> Result<pecr_contracts::EvidenceUnit, ApiError> {
    let view_id = parse_safeview_string(params.get("view_id"), "view_id")?;
    let spec = safeview_spec(&view_id).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PARAMS",
            "view_id not allowlisted".to_string(),
            TerminalMode::InsufficientEvidence,
            false,
        )
    })?;

    let filters = parse_safeview_filter_spec(params, spec)?;
    let default_filter = serde_json::json!({});
    let filter_value = params.get("filter_spec").unwrap_or(&default_filter);
    let filter_fingerprint = canonical::hash_canonical_json(filter_value);
    let max_values_per_dimension = params
        .get("max_values_per_dimension")
        .and_then(|value| value.as_u64())
        .map(|value| value.clamp(1, 10) as usize)
        .unwrap_or(3);

    let timeout_str = format!("{}ms", config.pg_safeview_query_timeout_ms);
    let mut tx = pool.begin().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(&timeout_str)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    sqlx::query("SELECT set_config('pecr.tenant_id', $1, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let mut counts_by_dimension = BTreeMap::<String, Vec<(String, i64)>>::new();
    for field in spec.allowlisted_group_by_fields {
        let mut sql = format!(
            "SELECT {field}::text as dimension_value, COUNT({count_field})::bigint as metric_value FROM {view}",
            field = field,
            count_field = spec.allowlisted_metrics[0].field,
            view = spec.view_id,
        );
        if !filters.is_empty() {
            sql.push_str(" WHERE ");
            for (idx, (filter_field, _)) in filters.iter().enumerate() {
                if idx != 0 {
                    sql.push_str(" AND ");
                }
                sql.push_str(filter_field);
                sql.push_str(" = $");
                sql.push_str(&(idx + 1).to_string());
            }
        }
        sql.push_str(" GROUP BY ");
        sql.push_str(field);
        sql.push_str(" ORDER BY metric_value DESC, dimension_value ASC LIMIT ");
        sql.push_str(&max_values_per_dimension.to_string());

        let mut query = sqlx::query(&sql);
        for (_, value) in &filters {
            query = query.bind(value.as_str());
        }

        let rows = query.fetch_all(&mut *tx).await.map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_UNAVAILABLE",
                "database query failed".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let value: Option<String> = row.try_get("dimension_value").map_err(|_| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "safe view schema mismatch".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;
            let count: i64 = row.try_get("metric_value").map_err(|_| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "safe view schema mismatch".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;
            if let Some(value) = value
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            {
                values.push((value, count));
            }
        }
        counts_by_dimension.insert(field.to_string(), values);
    }

    tx.commit().await.map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "database unavailable".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    let discovery = build_dimension_discovery_result(spec, &filters, &counts_by_dimension);
    let content = serde_json::to_value(&discovery).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "failed to serialize dimension discovery result".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    let content_hash = canonical::hash_canonical_json(&content);
    let span_or_row_spec = serde_json::json!({
        "type": "db_dimension_discovery",
        "view_id": spec.view_id,
        "filter_fingerprint": filter_fingerprint,
        "max_values_per_dimension": max_values_per_dimension,
    });
    let version_id = content_hash.clone();
    let transform_chain: Vec<pecr_contracts::TransformStep> = Vec::new();
    let identity = serde_json::json!({
        "source_system": "pg_safeview",
        "object_id": spec.view_id,
        "version_id": version_id.clone(),
        "span_or_row_spec": span_or_row_spec.clone(),
        "content_hash": content_hash.clone(),
        "as_of_time": as_of_time,
        "policy_snapshot_hash": policy_snapshot_hash,
        "transform_chain": transform_chain,
    });
    let evidence_unit_id = canonical::hash_canonical_json(&identity);

    Ok(pecr_contracts::EvidenceUnit {
        source_system: "pg_safeview".to_string(),
        object_id: spec.view_id.to_string(),
        version_id,
        span_or_row_spec,
        content_type: pecr_contracts::EvidenceContentType::ApplicationJson,
        content: Some(content),
        content_hash,
        retrieved_at: as_of_time.to_string(),
        as_of_time: as_of_time.to_string(),
        policy_snapshot_id: policy_snapshot_id.to_string(),
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
        transform_chain: Vec::new(),
        evidence_unit_id,
    })
}

fn decorate_aggregate_rows(
    rows: &mut [serde_json::Value],
    base_filters: &[FilterEq],
    include_rank: bool,
    drilldown_dimension: Option<&str>,
) {
    for (index, row) in rows.iter_mut().enumerate() {
        let Some(row_map) = row.as_object_mut() else {
            continue;
        };

        let group_map = row_map.get("group").and_then(|value| value.as_object());
        let mut drilldown_filter_spec = serde_json::Map::new();
        for (field, value) in base_filters {
            drilldown_filter_spec.insert(field.clone(), serde_json::json!(value));
        }
        if let Some(group_map) = group_map {
            for (field, value) in group_map {
                if field == "time_bucket" {
                    continue;
                }
                if let Some(text) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                {
                    drilldown_filter_spec.insert(field.clone(), serde_json::json!(text));
                }
            }
        }

        if include_rank {
            row_map.insert("rank".to_string(), serde_json::json!(index + 1));
        }
        if let Some(dimension) = drilldown_dimension
            && !drilldown_filter_spec.is_empty()
        {
            row_map.insert(
                "drilldown".to_string(),
                serde_json::to_value(StructuredDrilldownHint {
                    dimension: dimension.to_string(),
                    filter_spec: serde_json::Value::Object(drilldown_filter_spec),
                })
                .unwrap_or_else(|_| serde_json::json!({})),
            );
        }
    }
}

fn build_dimension_discovery_result(
    spec: SafeViewSpec,
    filters: &[FilterEq],
    counts_by_dimension: &BTreeMap<String, Vec<(String, i64)>>,
) -> StructuredDimensionDiscoveryResult {
    let available_dimensions = spec
        .allowlisted_group_by_fields
        .iter()
        .map(|field| field.to_string())
        .collect::<Vec<_>>();
    let metrics = spec
        .allowlisted_metrics
        .iter()
        .map(|metric| StructuredMetricDescriptor {
            name: metric.name.to_string(),
            field: metric.field.to_string(),
        })
        .collect::<Vec<_>>();
    let dimensions = available_dimensions
        .iter()
        .map(|field| StructuredDimensionDescriptor {
            field: field.clone(),
            top_values: counts_by_dimension
                .get(field)
                .into_iter()
                .flatten()
                .map(|(value, count)| StructuredDimensionValueCount {
                    value: value.clone(),
                    count: *count,
                })
                .collect(),
            drilldown_supported: available_dimensions.len() > 1,
        })
        .collect::<Vec<_>>();

    StructuredDimensionDiscoveryResult {
        view_id: spec.view_id.to_string(),
        available_dimensions,
        metrics,
        dimensions,
        filters_applied: (!filters.is_empty()).then(|| {
            serde_json::Value::Object(
                filters
                    .iter()
                    .map(|(field, value)| (field.clone(), serde_json::json!(value)))
                    .collect(),
            )
        }),
    }
}

fn build_compare_summary(rows: &[serde_json::Value]) -> Option<serde_json::Value> {
    if rows.is_empty() {
        return None;
    }

    if rows.iter().all(|row| {
        row.get("group")
            .and_then(|value| value.get("time_bucket"))
            .and_then(|value| value.as_str())
            .is_some()
    }) {
        return build_trend_compare_summary(rows);
    }

    build_group_compare_summary(rows).or_else(|| build_single_metric_summary(rows))
}

fn build_trend_compare_summary(rows: &[serde_json::Value]) -> Option<serde_json::Value> {
    let mut points = rows
        .iter()
        .filter_map(|row| {
            let bucket = row
                .get("group")
                .and_then(|value| value.get("time_bucket"))
                .and_then(|value| value.as_str())?;
            let metric = first_metric(row)?;
            Some((bucket.to_string(), metric))
        })
        .collect::<Vec<_>>();
    if points.is_empty() {
        return None;
    }

    points.sort_by(|left, right| left.0.cmp(&right.0));
    let first = points.first()?;
    let last = points.last()?;
    let direction = if last.1.value > first.1.value {
        "increased"
    } else if last.1.value < first.1.value {
        "decreased"
    } else {
        "held steady"
    };
    let summary = if direction == "held steady" {
        format!(
            "{} stayed at {} across {} time buckets",
            first.1.label,
            first.1.value,
            points.len()
        )
    } else {
        format!(
            "{} {} from {} to {} across {} time buckets",
            first.1.label,
            direction,
            first.1.value,
            last.1.value,
            points.len()
        )
    };

    let highlights = points
        .into_iter()
        .take(3)
        .map(|(bucket, metric)| format!("{} {}", bucket, metric.render()))
        .collect::<Vec<_>>();

    Some(serde_json::json!({
        "kind": "trend",
        "summary": summary,
        "highlights": highlights,
    }))
}

fn build_group_compare_summary(rows: &[serde_json::Value]) -> Option<serde_json::Value> {
    let mut groups = rows
        .iter()
        .filter_map(|row| {
            let metric = first_metric(row)?;
            let label = render_group_label(row.get("group")?)?;
            Some((label, metric))
        })
        .collect::<Vec<_>>();
    if groups.is_empty() {
        return None;
    }

    groups.sort_by(|left, right| {
        right
            .1
            .value
            .cmp(&left.1.value)
            .then_with(|| left.0.cmp(&right.0))
    });
    let highest = groups.first()?;
    let lowest = groups.last()?;
    let summary = if highest.0 == lowest.0 {
        format!(
            "{} for {} is {}",
            highest.1.label, highest.0, highest.1.value
        )
    } else {
        format!(
            "{} is highest for {} ({}) and lowest for {} ({})",
            highest.1.label, highest.0, highest.1.value, lowest.0, lowest.1.value
        )
    };

    let highlights = groups
        .into_iter()
        .take(3)
        .map(|(label, metric)| format!("{} {}", label, metric.render()))
        .collect::<Vec<_>>();

    Some(serde_json::json!({
        "kind": "group_compare",
        "summary": summary,
        "highlights": highlights,
    }))
}

fn build_single_metric_summary(rows: &[serde_json::Value]) -> Option<serde_json::Value> {
    let metric = rows.iter().find_map(first_metric)?;
    Some(serde_json::json!({
        "kind": "single_metric",
        "summary": format!("{} is {}", metric.label, metric.value),
        "highlights": [metric.render()],
    }))
}

#[derive(Clone)]
struct CompareMetric {
    label: String,
    value: i64,
}

impl CompareMetric {
    fn render(&self) -> String {
        format!("{}={}", self.label, self.value)
    }
}

fn first_metric(row: &serde_json::Value) -> Option<CompareMetric> {
    let metric = row.get("metrics")?.as_array()?.first()?.as_object()?;
    let name = metric.get("name")?.as_str()?.trim();
    let field = metric.get("field")?.as_str()?.trim();
    let value = metric.get("value")?.as_i64()?;
    Some(CompareMetric {
        label: format!("{}({})", name, field),
        value,
    })
}

fn render_group_label(group: &serde_json::Value) -> Option<String> {
    let group = group.as_object()?;
    let mut parts = group
        .iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(text) if !text.trim().is_empty() => {
                Some(format!("{}={}", key, text.trim()))
            }
            serde_json::Value::Number(number) => Some(format!("{}={}", key, number)),
            serde_json::Value::Bool(value) => Some(format!("{}={}", key, value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    parts.sort();
    (!parts.is_empty()).then(|| parts.join(", "))
}

fn refresh_json_evidence_identity(evidence: &mut pecr_contracts::EvidenceUnit) {
    let Some(content) = evidence.content.as_ref() else {
        return;
    };

    let content_hash = canonical::hash_canonical_json(content);
    evidence.content_hash = content_hash.clone();
    evidence.version_id = content_hash.clone();

    let identity = serde_json::json!({
        "source_system": evidence.source_system.clone(),
        "object_id": evidence.object_id.clone(),
        "version_id": evidence.version_id.clone(),
        "span_or_row_spec": evidence.span_or_row_spec.clone(),
        "content_hash": evidence.content_hash.clone(),
        "as_of_time": evidence.as_of_time.clone(),
        "policy_snapshot_hash": evidence.policy_snapshot_hash.clone(),
        "transform_chain": evidence.transform_chain.clone(),
    });
    evidence.evidence_unit_id = canonical::hash_canonical_json(&identity);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fs_search_request_normalizes_defaults() {
        let request = parse_fs_search_request(&serde_json::json!({
            "query": "  refund   policy ",
            "object_prefix": "\\public\\support\\",
            "match_mode": "ANY"
        }))
        .expect("search request should parse");

        assert_eq!(request.query, "refund policy");
        assert_eq!(
            request.terms,
            vec!["refund".to_string(), "policy".to_string()]
        );
        assert_eq!(request.object_prefix, Some("public/support".to_string()));
        assert_eq!(request.limit, 10);
        assert_eq!(request.match_mode, SearchMatchMode::Any);
    }

    #[tokio::test]
    async fn search_from_fs_returns_ranked_refs_with_span_metadata() {
        let temp_dir = std::env::temp_dir().join(format!(
            "pecr-search-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time should move forward")
                .as_nanos()
        ));
        tokio::fs::create_dir_all(temp_dir.join("public"))
            .await
            .expect("temp dir should be created");
        tokio::fs::write(
            temp_dir.join("public").join("support_policy.txt"),
            "General overview\nRefunds are available for annual plans within 30 days.\nContact support.\n",
        )
        .await
        .expect("support policy fixture should be written");
        tokio::fs::write(
            temp_dir.join("public").join("notes.txt"),
            "General overview only.\n",
        )
        .await
        .expect("notes fixture should be written");

        let cache = Arc::new(RwLock::new(FsSearchIndexCache::new(Duration::from_secs(
            60,
        ))));
        let policy_snapshot_hash = "a".repeat(64);
        let refs = search_from_fs(
            &cache,
            temp_dir.to_str().expect("temp path must be utf-8"),
            "1970-01-01T00:00:00Z",
            policy_snapshot_hash.as_str(),
            &serde_json::json!({
                "query": "refund policy",
                "object_prefix": "public",
                "match_mode": "any"
            }),
        )
        .await
        .expect("search should succeed");

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].object_id, "public/support_policy.txt");
        assert_eq!(refs[0].line_start, Some(2));
        assert_eq!(refs[0].line_end, Some(2));
        assert!(refs[0].start_byte.is_some());
        assert!(refs[0].end_byte.is_some());
        assert!(
            refs[0]
                .match_preview
                .as_deref()
                .expect("preview should be present")
                .contains("Refunds are available")
        );
        assert!(refs[0].match_score.unwrap_or_default() > 0);

        let _ = tokio::fs::remove_dir_all(temp_dir).await;
    }

    #[test]
    fn build_compare_summary_surfaces_group_highlights() {
        let summary = build_compare_summary(&[
            serde_json::json!({
                "group": { "plan_tier": "starter" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
            }),
            serde_json::json!({
                "group": { "plan_tier": "premium" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 4 }]
            }),
        ])
        .expect("group compare summary should exist");

        assert_eq!(summary["kind"], serde_json::json!("group_compare"));
        assert!(
            summary["summary"]
                .as_str()
                .is_some_and(|text| text.contains("highest for plan_tier=starter"))
        );
    }

    #[test]
    fn build_compare_summary_surfaces_trend_direction() {
        let summary = build_compare_summary(&[
            serde_json::json!({
                "group": { "time_bucket": "2026-03-01" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 12 }]
            }),
            serde_json::json!({
                "group": { "time_bucket": "2026-03-02" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 15 }]
            }),
        ])
        .expect("trend compare summary should exist");

        assert_eq!(summary["kind"], serde_json::json!("trend"));
        assert!(
            summary["summary"]
                .as_str()
                .is_some_and(|text| text.contains("increased from 12 to 15"))
        );
    }

    #[test]
    fn decorate_aggregate_rows_adds_rank_and_drilldown_hint() {
        let mut rows = vec![
            serde_json::json!({
                "group": { "plan_tier": "starter" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
            }),
            serde_json::json!({
                "group": { "plan_tier": "premium" },
                "metrics": [{ "name": "count", "field": "customer_id", "value": 4 }]
            }),
        ];

        decorate_aggregate_rows(
            &mut rows,
            &[("status".to_string(), "active".to_string())],
            true,
            Some("status"),
        );

        assert_eq!(rows[0]["rank"], serde_json::json!(1));
        assert_eq!(rows[1]["rank"], serde_json::json!(2));
        assert_eq!(
            rows[0]["drilldown"]["dimension"],
            serde_json::json!("status")
        );
        assert_eq!(
            rows[0]["drilldown"]["filter_spec"],
            serde_json::json!({
                "plan_tier": "starter",
                "status": "active"
            })
        );
    }

    #[test]
    fn build_dimension_discovery_result_surfaces_top_values_and_metrics() {
        let spec = safeview_spec("safe_customer_view_public")
            .expect("safe_customer_view_public must be allowlisted");
        let discovery = build_dimension_discovery_result(
            spec,
            &[("status".to_string(), "active".to_string())],
            &BTreeMap::from([
                (
                    "plan_tier".to_string(),
                    vec![("starter".to_string(), 9), ("premium".to_string(), 4)],
                ),
                (
                    "status".to_string(),
                    vec![("active".to_string(), 10), ("inactive".to_string(), 3)],
                ),
            ]),
        );

        assert_eq!(discovery.view_id, "safe_customer_view_public");
        assert_eq!(
            discovery.available_dimensions,
            vec!["status".to_string(), "plan_tier".to_string()]
        );
        assert_eq!(discovery.metrics.len(), 1);
        assert_eq!(discovery.metrics[0].name, "count");
        assert_eq!(discovery.dimensions.len(), 2);
        assert_eq!(discovery.dimensions[0].field, "status");
        assert_eq!(discovery.dimensions[0].top_values[0].value, "active");
        assert!(discovery.dimensions[0].drilldown_supported);
        assert_eq!(
            discovery.filters_applied,
            Some(serde_json::json!({ "status": "active" }))
        );
    }

    #[test]
    fn fs_version_cache_orders_versions_by_latest_observed_as_of_time() {
        let mut cache = FsVersionCache::new(1024, 4);
        cache.insert("public/support_policy.txt", "older", b"older".to_vec());
        cache.observe_version("public/support_policy.txt", "2026-03-01T00:00:00Z", "older");
        cache.insert("public/support_policy.txt", "latest", b"latest".to_vec());
        cache.observe_version(
            "public/support_policy.txt",
            "2026-03-02T00:00:00Z",
            "latest",
        );

        assert_eq!(
            cache.ordered_versions("public/support_policy.txt"),
            vec![
                ("latest".to_string(), "2026-03-02T00:00:00Z".to_string()),
                ("older".to_string(), "2026-03-01T00:00:00Z".to_string())
            ]
        );
    }
}
