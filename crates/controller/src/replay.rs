use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, ClaimMap, ClaimStatus, EngineMode, ReplayBundle, ReplayBundleMetadata,
    ReplayEvaluationResult, ReplayEvaluationSubmission, ReplayRunScore, RunQualityScorecard,
    TerminalMode,
};
use serde::de::DeserializeOwned;
use ulid::Ulid;

use crate::config::ControllerEngine;

const REPLAY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct PersistedRun {
    pub trace_id: String,
    pub request_id: String,
    pub principal_id: String,
    pub engine_mode: ControllerEngine,
    pub query: String,
    pub budget: Budget,
    pub session_id: String,
    pub policy_snapshot_id: String,
    pub loop_terminal_mode: TerminalMode,
    pub loop_response_text: Option<String>,
    pub terminal_mode: TerminalMode,
    pub response_text: String,
    pub claim_map: ClaimMap,
    pub operator_calls_used: u32,
    pub bytes_used: u64,
    pub depth_used: u32,
    pub evidence_ref_count: u32,
    pub evidence_unit_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayStore {
    root_dir: PathBuf,
    retention_days: u64,
}

impl ReplayStore {
    pub fn new(root_dir: PathBuf, retention_days: u64) -> io::Result<Self> {
        let store = Self {
            root_dir,
            retention_days,
        };
        fs::create_dir_all(store.replays_dir())?;
        fs::create_dir_all(store.evaluations_dir())?;
        Ok(store)
    }

    pub fn persist_run(&self, run: PersistedRun) -> io::Result<ReplayBundleMetadata> {
        self.cleanup_expired()?;

        let run_id = format!("{}-{}", run.trace_id, Ulid::new());
        let principal_id_hash = hash_principal_id(run.principal_id.as_str());
        let quality_score = compute_quality_score(
            run.terminal_mode,
            &run.claim_map,
            run.evidence_unit_ids.len(),
        );
        let metadata = ReplayBundleMetadata {
            schema_version: REPLAY_SCHEMA_VERSION,
            run_id: run_id.clone(),
            trace_id: run.trace_id,
            request_id: run.request_id,
            principal_id_hash,
            engine_mode: controller_engine_to_contract(run.engine_mode),
            recorded_at_unix_ms: now_unix_ms(),
            terminal_mode: run.terminal_mode,
            quality_score,
            bundle_hash: String::new(),
        };

        let mut bundle = ReplayBundle {
            metadata,
            query: run.query,
            budget: run.budget,
            session_id: run.session_id,
            policy_snapshot_id: run.policy_snapshot_id,
            loop_terminal_mode: run.loop_terminal_mode,
            loop_response_text: run.loop_response_text,
            response_text: run.response_text,
            claim_map: run.claim_map,
            operator_calls_used: run.operator_calls_used,
            bytes_used: run.bytes_used,
            depth_used: run.depth_used,
            evidence_ref_count: run.evidence_ref_count,
            evidence_unit_ids: run.evidence_unit_ids,
        };

        bundle.metadata.bundle_hash = bundle_hash(&bundle)?;
        let path = self.replays_dir().join(format!("{}.json", run_id));
        write_json_atomic(&path, &bundle)?;

        Ok(bundle.metadata)
    }

    pub fn list_replay_metadata(
        &self,
        principal_id_hash: &str,
        limit: usize,
        engine_mode: Option<EngineMode>,
    ) -> io::Result<Vec<ReplayBundleMetadata>> {
        let mut bundles = self.load_bundles_for_principal(principal_id_hash, engine_mode)?;
        bundles.sort_by_key(|bundle| std::cmp::Reverse(bundle.metadata.recorded_at_unix_ms));

        Ok(bundles
            .into_iter()
            .take(limit)
            .map(|bundle| bundle.metadata)
            .collect())
    }

    pub fn load_replay(
        &self,
        principal_id_hash: &str,
        run_id: &str,
    ) -> io::Result<Option<ReplayBundle>> {
        if !is_safe_id(run_id) {
            return Ok(None);
        }

        let path = self.replays_dir().join(format!("{}.json", run_id));
        if !path.exists() {
            return Ok(None);
        }
        let bundle = read_json::<ReplayBundle>(&path)?;
        if !has_valid_bundle_hash(&bundle)? {
            return Ok(None);
        }
        if bundle.metadata.principal_id_hash != principal_id_hash {
            return Ok(None);
        }
        Ok(Some(bundle))
    }

    pub fn submit_evaluation(
        &self,
        principal_id_hash: &str,
        mut submission: ReplayEvaluationSubmission,
        max_runs: usize,
    ) -> io::Result<ReplayEvaluationResult> {
        let evaluation_name = submission.evaluation_name.trim();
        if evaluation_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evaluation_name must be non-empty",
            ));
        }
        submission.evaluation_name = evaluation_name.to_string();
        let min_quality_score = submission
            .min_quality_score
            .unwrap_or(0.0)
            .clamp(0.0, 100.0);
        let max_source_unavailable_rate = submission
            .max_source_unavailable_rate
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);

        let mut missing_replay_ids = Vec::new();
        let mut selected_bundles = Vec::new();
        if submission.replay_ids.is_empty() {
            let mut bundles =
                self.load_bundles_for_principal(principal_id_hash, submission.engine_mode)?;
            bundles.sort_by_key(|bundle| std::cmp::Reverse(bundle.metadata.recorded_at_unix_ms));
            selected_bundles.extend(bundles.into_iter().take(max_runs));
        } else {
            for replay_id in &submission.replay_ids {
                match self.load_replay(principal_id_hash, replay_id)? {
                    Some(bundle) => {
                        if submission
                            .engine_mode
                            .is_none_or(|mode| bundle.metadata.engine_mode == mode)
                        {
                            selected_bundles.push(bundle);
                        }
                    }
                    None => missing_replay_ids.push(replay_id.clone()),
                }
            }
        }

        let run_results = selected_bundles
            .iter()
            .map(|bundle| ReplayRunScore {
                run_id: bundle.metadata.run_id.clone(),
                trace_id: bundle.metadata.trace_id.clone(),
                engine_mode: bundle.metadata.engine_mode,
                terminal_mode: bundle.metadata.terminal_mode,
                quality_score: bundle.metadata.quality_score,
                coverage_observed: bundle.claim_map.coverage_observed.clamp(0.0, 1.0),
            })
            .collect::<Vec<_>>();
        let scorecards = build_scorecards(&run_results);

        let source_unavailable_rate = if run_results.is_empty() {
            0.0
        } else {
            run_results
                .iter()
                .filter(|run| run.terminal_mode == TerminalMode::SourceUnavailable)
                .count() as f64
                / run_results.len() as f64
        };

        let overall_pass = run_results
            .iter()
            .all(|run| run.quality_score >= min_quality_score)
            && source_unavailable_rate <= max_source_unavailable_rate
            && missing_replay_ids.is_empty();

        let result = ReplayEvaluationResult {
            evaluation_id: Ulid::new().to_string(),
            evaluation_name: submission.evaluation_name,
            principal_id_hash: principal_id_hash.to_string(),
            created_at_unix_ms: now_unix_ms(),
            replay_ids: run_results.iter().map(|run| run.run_id.clone()).collect(),
            missing_replay_ids,
            run_results,
            scorecards,
            overall_pass,
        };

        let path = self
            .evaluations_dir()
            .join(format!("{}.json", result.evaluation_id));
        write_json_atomic(&path, &result)?;
        Ok(result)
    }

    pub fn load_evaluation(
        &self,
        principal_id_hash: &str,
        evaluation_id: &str,
    ) -> io::Result<Option<ReplayEvaluationResult>> {
        if !is_safe_id(evaluation_id) {
            return Ok(None);
        }
        let path = self
            .evaluations_dir()
            .join(format!("{}.json", evaluation_id));
        if !path.exists() {
            return Ok(None);
        }

        let result = read_json::<ReplayEvaluationResult>(&path)?;
        if result.principal_id_hash != principal_id_hash {
            return Ok(None);
        }
        Ok(Some(result))
    }

    pub fn scorecards_for_principal(
        &self,
        principal_id_hash: &str,
        limit: usize,
        engine_mode: Option<EngineMode>,
    ) -> io::Result<Vec<RunQualityScorecard>> {
        let mut bundles = self.load_bundles_for_principal(principal_id_hash, engine_mode)?;
        bundles.sort_by_key(|bundle| std::cmp::Reverse(bundle.metadata.recorded_at_unix_ms));
        let runs = bundles
            .into_iter()
            .take(limit)
            .map(|bundle| ReplayRunScore {
                run_id: bundle.metadata.run_id,
                trace_id: bundle.metadata.trace_id,
                engine_mode: bundle.metadata.engine_mode,
                terminal_mode: bundle.metadata.terminal_mode,
                quality_score: bundle.metadata.quality_score,
                coverage_observed: bundle.claim_map.coverage_observed.clamp(0.0, 1.0),
            })
            .collect::<Vec<_>>();

        Ok(build_scorecards(&runs))
    }

    pub fn cleanup_expired(&self) -> io::Result<usize> {
        if self.retention_days == 0 {
            return Ok(0);
        }

        let max_age = Duration::from_secs(self.retention_days.saturating_mul(24 * 60 * 60));
        let mut removed = 0usize;
        removed += prune_old_json_files(self.replays_dir().as_path(), max_age)?;
        removed += prune_old_json_files(self.evaluations_dir().as_path(), max_age)?;
        Ok(removed)
    }

    fn load_bundles_for_principal(
        &self,
        principal_id_hash: &str,
        engine_mode: Option<EngineMode>,
    ) -> io::Result<Vec<ReplayBundle>> {
        let mut bundles = Vec::new();
        for entry in fs::read_dir(self.replays_dir())? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bundle = match read_json::<ReplayBundle>(&path) {
                Ok(bundle) => bundle,
                Err(_) => continue,
            };
            if !has_valid_bundle_hash(&bundle)? {
                continue;
            }
            if bundle.metadata.principal_id_hash != principal_id_hash {
                continue;
            }
            if engine_mode.is_some_and(|mode| bundle.metadata.engine_mode != mode) {
                continue;
            }
            bundles.push(bundle);
        }
        Ok(bundles)
    }

    fn replays_dir(&self) -> PathBuf {
        self.root_dir.join("replays")
    }

    fn evaluations_dir(&self) -> PathBuf {
        self.root_dir.join("evaluations")
    }
}

pub fn hash_principal_id(principal_id: &str) -> String {
    canonical::hash_canonical_json(&serde_json::json!({ "principal_id": principal_id }))
}

pub fn controller_engine_to_contract(engine: ControllerEngine) -> EngineMode {
    match engine {
        ControllerEngine::Baseline => EngineMode::Baseline,
        ControllerEngine::Rlm => EngineMode::Rlm,
    }
}

pub fn compute_quality_score(
    terminal_mode: TerminalMode,
    claim_map: &ClaimMap,
    evidence_unit_count: usize,
) -> f64 {
    let terminal_component = match terminal_mode {
        TerminalMode::Supported => 1.0,
        TerminalMode::InsufficientEvidence => 0.72,
        TerminalMode::InsufficientPermission => 0.78,
        TerminalMode::SourceUnavailable => 0.2,
    };
    let coverage_component = claim_map.coverage_observed.clamp(0.0, 1.0);
    let supported_claims = claim_map
        .claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Supported)
        .count();
    let supported_with_evidence = claim_map
        .claims
        .iter()
        .filter(|claim| {
            claim.status == ClaimStatus::Supported && !claim.evidence_unit_ids.is_empty()
        })
        .count();
    let support_component = if supported_claims == 0 {
        1.0
    } else {
        supported_with_evidence as f64 / supported_claims as f64
    };
    let evidence_component = if supported_claims == 0 {
        if evidence_unit_count == 0 { 0.8 } else { 1.0 }
    } else {
        (evidence_unit_count as f64 / supported_claims as f64).min(1.0)
    };

    round_2dp(
        (terminal_component * 0.40
            + coverage_component * 0.35
            + support_component * 0.15
            + evidence_component * 0.10)
            * 100.0,
    )
}

fn build_scorecards(run_results: &[ReplayRunScore]) -> Vec<RunQualityScorecard> {
    let mut grouped = BTreeMap::<EngineMode, Vec<&ReplayRunScore>>::new();
    for run in run_results {
        grouped.entry(run.engine_mode).or_default().push(run);
    }

    grouped
        .into_iter()
        .map(|(engine_mode, runs)| {
            let run_count = runs.len() as u64;
            let avg_quality_score =
                runs.iter().map(|run| run.quality_score).sum::<f64>() / run_count as f64;
            let min_quality_score = runs
                .iter()
                .map(|run| run.quality_score)
                .fold(f64::INFINITY, f64::min);
            let max_quality_score = runs
                .iter()
                .map(|run| run.quality_score)
                .fold(f64::NEG_INFINITY, f64::max);
            let supported_rate = runs
                .iter()
                .filter(|run| run.terminal_mode == TerminalMode::Supported)
                .count() as f64
                / run_count as f64;
            let source_unavailable_rate = runs
                .iter()
                .filter(|run| run.terminal_mode == TerminalMode::SourceUnavailable)
                .count() as f64
                / run_count as f64;
            let avg_coverage_observed =
                runs.iter().map(|run| run.coverage_observed).sum::<f64>() / run_count as f64;

            RunQualityScorecard {
                engine_mode,
                run_count,
                average_quality_score: round_2dp(avg_quality_score),
                minimum_quality_score: round_2dp(min_quality_score),
                maximum_quality_score: round_2dp(max_quality_score),
                supported_rate: round_4dp(supported_rate),
                source_unavailable_rate: round_4dp(source_unavailable_rate),
                average_coverage_observed: round_4dp(avg_coverage_observed),
            }
        })
        .collect()
}

fn bundle_hash(bundle: &ReplayBundle) -> io::Result<String> {
    let mut value = serde_json::to_value(bundle).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to convert replay bundle to value: {}", err),
        )
    })?;

    if let Some(metadata) = value.get_mut("metadata")
        && let Some(hash) = metadata.get_mut("bundle_hash")
    {
        *hash = serde_json::Value::String(String::new());
    }

    Ok(canonical::hash_canonical_json(&value))
}

fn has_valid_bundle_hash(bundle: &ReplayBundle) -> io::Result<bool> {
    Ok(bundle_hash(bundle)? == bundle.metadata.bundle_hash)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice::<T>(&bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {}: {}", path.display(), err),
        )
    })
}

fn write_json_atomic(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let payload = serde_json::to_vec_pretty(value).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize {}: {}", path.display(), err),
        )
    })?;
    let temp_name = format!(
        "{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("tmp"),
        Ulid::new()
    );
    let temp_path = path.with_file_name(temp_name);
    fs::write(&temp_path, payload)?;
    if fs::rename(&temp_path, path).is_err() {
        let _ = fs::remove_file(path);
        fs::rename(&temp_path, path)?;
    }
    Ok(())
}

fn prune_old_json_files(dir: &Path, max_age: Duration) -> io::Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }

    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let modified = match entry.metadata().and_then(|meta| meta.modified()) {
            Ok(modified) => modified,
            Err(_) => continue,
        };
        let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
        if age > max_age && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }

    Ok(removed)
}

fn is_safe_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 256
        && raw
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn round_2dp(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn round_4dp(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    use pecr_contracts::{Claim, ClaimStatus};
    use std::fs;

    fn sample_claim_map(terminal_mode: TerminalMode, supported: bool) -> ClaimMap {
        let claims = if supported {
            vec![Claim {
                claim_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                claim_text: "supported claim".to_string(),
                status: ClaimStatus::Supported,
                evidence_unit_ids: vec![
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                ],
            }]
        } else {
            vec![Claim {
                claim_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
                claim_text: "unknown claim".to_string(),
                status: ClaimStatus::Unknown,
                evidence_unit_ids: Vec::new(),
            }]
        };

        ClaimMap {
            claim_map_id: Ulid::new().to_string(),
            terminal_mode,
            claims,
            coverage_threshold: 0.95,
            coverage_observed: if supported { 1.0 } else { 0.75 },
            notes: None,
        }
    }

    fn sample_budget() -> Budget {
        Budget {
            max_operator_calls: 10,
            max_bytes: 1024,
            max_wallclock_ms: 1000,
            max_recursion_depth: 3,
            max_parallelism: Some(1),
        }
    }

    fn temp_store_dir() -> PathBuf {
        std::env::temp_dir().join(format!("pecr-replay-test-{}", Ulid::new()))
    }

    #[test]
    fn replay_store_persists_and_scopes_bundles_to_principal_hash() {
        let root = temp_store_dir();
        let store = ReplayStore::new(root.clone(), 30).expect("store should initialize");
        let meta = store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req1".to_string(),
                principal_id: "alice".to_string(),
                engine_mode: ControllerEngine::Baseline,
                query: "q".to_string(),
                budget: sample_budget(),
                session_id: "session".to_string(),
                policy_snapshot_id: "policy".to_string(),
                loop_terminal_mode: TerminalMode::InsufficientEvidence,
                loop_response_text: Some("UNKNOWN: missing evidence".to_string()),
                terminal_mode: TerminalMode::InsufficientEvidence,
                response_text: "UNKNOWN: missing evidence".to_string(),
                claim_map: sample_claim_map(TerminalMode::InsufficientEvidence, false),
                operator_calls_used: 2,
                bytes_used: 120,
                depth_used: 2,
                evidence_ref_count: 1,
                evidence_unit_ids: Vec::new(),
            })
            .expect("persist should succeed");

        let alice = hash_principal_id("alice");
        let bob = hash_principal_id("bob");
        let listed = store
            .list_replay_metadata(&alice, 10, None)
            .expect("list should succeed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].run_id, meta.run_id);

        let bundle = store
            .load_replay(&alice, &meta.run_id)
            .expect("load should succeed")
            .expect("bundle should exist");
        assert_eq!(bundle.query, "q");
        assert_eq!(bundle.metadata.principal_id_hash, alice);
        assert!(
            store
                .load_replay(&bob, &meta.run_id)
                .expect("load should succeed")
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_store_builds_scorecards_by_engine_mode() {
        let root = temp_store_dir();
        let store = ReplayStore::new(root.clone(), 30).expect("store should initialize");
        let principal = "engine-test";
        let principal_hash = hash_principal_id(principal);

        store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-baseline".to_string(),
                principal_id: principal.to_string(),
                engine_mode: ControllerEngine::Baseline,
                query: "q1".to_string(),
                budget: sample_budget(),
                session_id: "session1".to_string(),
                policy_snapshot_id: "policy1".to_string(),
                loop_terminal_mode: TerminalMode::Supported,
                loop_response_text: Some("SUPPORTED".to_string()),
                terminal_mode: TerminalMode::Supported,
                response_text: "SUPPORTED".to_string(),
                claim_map: sample_claim_map(TerminalMode::Supported, true),
                operator_calls_used: 1,
                bytes_used: 10,
                depth_used: 1,
                evidence_ref_count: 1,
                evidence_unit_ids: vec![
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                ],
            })
            .expect("persist baseline should succeed");

        store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-rlm".to_string(),
                principal_id: principal.to_string(),
                engine_mode: ControllerEngine::Rlm,
                query: "q2".to_string(),
                budget: sample_budget(),
                session_id: "session2".to_string(),
                policy_snapshot_id: "policy2".to_string(),
                loop_terminal_mode: TerminalMode::SourceUnavailable,
                loop_response_text: Some("UNKNOWN: source unavailable".to_string()),
                terminal_mode: TerminalMode::SourceUnavailable,
                response_text: "UNKNOWN: source unavailable".to_string(),
                claim_map: sample_claim_map(TerminalMode::SourceUnavailable, false),
                operator_calls_used: 1,
                bytes_used: 10,
                depth_used: 1,
                evidence_ref_count: 0,
                evidence_unit_ids: Vec::new(),
            })
            .expect("persist rlm should succeed");

        let scorecards = store
            .scorecards_for_principal(&principal_hash, 10, None)
            .expect("scorecards should succeed");
        assert_eq!(scorecards.len(), 2);

        let baseline = scorecards
            .iter()
            .find(|scorecard| scorecard.engine_mode == EngineMode::Baseline)
            .expect("baseline scorecard must exist");
        let rlm = scorecards
            .iter()
            .find(|scorecard| scorecard.engine_mode == EngineMode::Rlm)
            .expect("rlm scorecard must exist");
        assert!(baseline.average_quality_score > rlm.average_quality_score);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_store_evaluation_records_missing_ids_and_threshold_failures() {
        let root = temp_store_dir();
        let store = ReplayStore::new(root.clone(), 30).expect("store should initialize");
        let principal = "eval-user";
        let principal_hash = hash_principal_id(principal);

        let replay = store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-eval".to_string(),
                principal_id: principal.to_string(),
                engine_mode: ControllerEngine::Baseline,
                query: "q".to_string(),
                budget: sample_budget(),
                session_id: "session".to_string(),
                policy_snapshot_id: "policy".to_string(),
                loop_terminal_mode: TerminalMode::Supported,
                loop_response_text: Some("SUPPORTED".to_string()),
                terminal_mode: TerminalMode::Supported,
                response_text: "SUPPORTED".to_string(),
                claim_map: sample_claim_map(TerminalMode::Supported, true),
                operator_calls_used: 1,
                bytes_used: 10,
                depth_used: 1,
                evidence_ref_count: 1,
                evidence_unit_ids: vec![
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                ],
            })
            .expect("persist run should succeed");

        let result = store
            .submit_evaluation(
                &principal_hash,
                ReplayEvaluationSubmission {
                    evaluation_name: "strict-check".to_string(),
                    replay_ids: vec![replay.run_id, "missing-run-id".to_string()],
                    engine_mode: None,
                    min_quality_score: Some(99.9),
                    max_source_unavailable_rate: Some(0.0),
                },
                50,
            )
            .expect("evaluation should succeed");

        assert!(!result.missing_replay_ids.is_empty());
        assert!(!result.overall_pass);

        let loaded = store
            .load_evaluation(&principal_hash, &result.evaluation_id)
            .expect("load evaluation should succeed")
            .expect("evaluation should exist");
        assert_eq!(loaded.evaluation_name, "strict-check");

        let _ = fs::remove_dir_all(root);
    }
}
