use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use pecr_contracts::canonical;
use pecr_contracts::{
    Budget, ClaimMap, ClaimStatus, ClientResponseKind, EngineComparisonSummary, EngineMode,
    ReplayBundle, ReplayBundleMetadata, ReplayEvaluationResult, ReplayEvaluationSubmission,
    ReplayPlannerTrace, ReplayRunScore, RunQualityScorecard, TerminalMode,
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
    pub planner_traces: Vec<ReplayPlannerTrace>,
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
            planner_traces: run.planner_traces,
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
                citation_quality: compute_citation_quality(&bundle.claim_map),
                response_kind: compute_response_kind(
                    bundle.metadata.terminal_mode,
                    &bundle.response_text,
                    &bundle.claim_map,
                ),
            })
            .collect::<Vec<_>>();
        let scorecards = build_scorecards(&run_results);
        let engine_comparisons = build_engine_comparisons(&selected_bundles);

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
            engine_comparisons,
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
                citation_quality: compute_citation_quality(&bundle.claim_map),
                response_kind: compute_response_kind(
                    bundle.metadata.terminal_mode,
                    &bundle.response_text,
                    &bundle.claim_map,
                ),
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

    pub fn readiness_check(&self) -> io::Result<()> {
        fs::create_dir_all(self.replays_dir())?;
        fs::create_dir_all(self.evaluations_dir())?;

        let probe_path = self.root_dir.join(format!(".probe-{}", Ulid::new()));
        fs::write(&probe_path, b"ok")?;
        fs::remove_file(probe_path)?;
        Ok(())
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
        ControllerEngine::BeamPlanner => EngineMode::BeamPlanner,
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
    let citation_component = compute_citation_quality(claim_map);
    let corroboration_component = compute_corroboration_quality(claim_map);

    round_2dp(
        (terminal_component * 0.35
            + coverage_component * 0.24
            + support_component * 0.15
            + evidence_component * 0.10
            + citation_component * 0.13
            + corroboration_component * 0.03)
            * 100.0,
    )
}

fn compute_citation_quality(claim_map: &ClaimMap) -> f64 {
    let supported_claims = claim_map
        .claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Supported)
        .collect::<Vec<_>>();

    if supported_claims.is_empty() {
        return if claim_map.terminal_mode == TerminalMode::Supported {
            0.0
        } else {
            1.0
        };
    }

    let citation_coverage = supported_claims
        .iter()
        .filter(|claim| !claim.evidence_unit_ids.is_empty())
        .count() as f64
        / supported_claims.len() as f64;
    let snippet_coverage = supported_claims
        .iter()
        .filter(|claim| !claim.evidence_snippets.is_empty())
        .count() as f64
        / supported_claims.len() as f64;
    let snippet_alignment = supported_claims
        .iter()
        .map(|claim| {
            if claim.evidence_snippets.is_empty() {
                return 0.0;
            }
            let evidence_ids = claim
                .evidence_unit_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<BTreeSet<_>>();
            let aligned = claim
                .evidence_snippets
                .iter()
                .filter(|snippet| evidence_ids.contains(snippet.evidence_unit_id.as_str()))
                .count();
            aligned as f64 / claim.evidence_snippets.len() as f64
        })
        .sum::<f64>()
        / supported_claims.len() as f64;

    round_4dp(citation_coverage * 0.45 + snippet_coverage * 0.35 + snippet_alignment * 0.20)
}

fn compute_corroboration_quality(claim_map: &ClaimMap) -> f64 {
    let supported_claims = claim_map
        .claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Supported)
        .collect::<Vec<_>>();

    if supported_claims.is_empty() {
        return if claim_map.terminal_mode == TerminalMode::Supported {
            0.0
        } else {
            1.0
        };
    }

    let corroborated_rate = supported_claims
        .iter()
        .filter(|claim| {
            claim
                .evidence_unit_ids
                .iter()
                .map(|id| id.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                >= 2
        })
        .count() as f64
        / supported_claims.len() as f64;

    round_4dp(0.5 + corroborated_rate * 0.5)
}

fn compute_response_kind(
    terminal_mode: TerminalMode,
    response_text: &str,
    claim_map: &ClaimMap,
) -> Option<ClientResponseKind> {
    if claim_map
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("Partial answer:"))
    {
        return Some(ClientResponseKind::PartialAnswer);
    }

    if terminal_mode == TerminalMode::InsufficientEvidence {
        let response_text = response_text.to_ascii_lowercase();
        if response_text.contains("underspecified")
            || response_text.contains("too broad")
            || response_text.contains("specify which document or policy")
            || response_text.contains("safe scopes for the current principal")
        {
            return Some(ClientResponseKind::Ambiguous);
        }
    }

    if terminal_mode == TerminalMode::InsufficientPermission {
        return Some(ClientResponseKind::Blocked);
    }
    if terminal_mode == TerminalMode::SourceUnavailable {
        return Some(ClientResponseKind::SourceDown);
    }

    None
}

#[derive(Debug, Clone, Default)]
struct QueryMetricsAggregate {
    run_count: u64,
    quality_score_sum: f64,
    supported_count: u64,
    source_unavailable_count: u64,
    coverage_observed_sum: f64,
    citation_quality_sum: f64,
}

impl QueryMetricsAggregate {
    fn observe_bundle(&mut self, bundle: &ReplayBundle) {
        self.run_count = self.run_count.saturating_add(1);
        self.quality_score_sum += bundle.metadata.quality_score;
        if bundle.metadata.terminal_mode == TerminalMode::Supported {
            self.supported_count = self.supported_count.saturating_add(1);
        }
        if bundle.metadata.terminal_mode == TerminalMode::SourceUnavailable {
            self.source_unavailable_count = self.source_unavailable_count.saturating_add(1);
        }
        self.coverage_observed_sum += bundle.claim_map.coverage_observed.clamp(0.0, 1.0);
        self.citation_quality_sum += compute_citation_quality(&bundle.claim_map);
    }

    fn average_quality_score(&self) -> f64 {
        self.quality_score_sum / self.run_count as f64
    }

    fn supported_rate(&self) -> f64 {
        self.supported_count as f64 / self.run_count as f64
    }

    fn source_unavailable_rate(&self) -> f64 {
        self.source_unavailable_count as f64 / self.run_count as f64
    }

    fn average_coverage_observed(&self) -> f64 {
        self.coverage_observed_sum / self.run_count as f64
    }

    fn average_citation_quality(&self) -> f64 {
        self.citation_quality_sum / self.run_count as f64
    }
}

fn normalized_query_key(query: &str) -> String {
    query
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn comparison_winner(
    primary: EngineMode,
    secondary: EngineMode,
    primary_wins: u64,
    secondary_wins: u64,
    average_quality_score_delta: f64,
    supported_rate_delta: f64,
    source_unavailable_rate_delta: f64,
    average_citation_quality_delta: f64,
) -> Option<EngineMode> {
    if primary_wins > secondary_wins {
        return Some(primary);
    }
    if secondary_wins > primary_wins {
        return Some(secondary);
    }
    if average_quality_score_delta.abs() >= 0.01 {
        return Some(if average_quality_score_delta.is_sign_positive() {
            primary
        } else {
            secondary
        });
    }
    if supported_rate_delta.abs() >= 0.0001 {
        return Some(if supported_rate_delta.is_sign_positive() {
            primary
        } else {
            secondary
        });
    }
    if source_unavailable_rate_delta.abs() >= 0.0001 {
        return Some(if source_unavailable_rate_delta.is_sign_negative() {
            primary
        } else {
            secondary
        });
    }
    if average_citation_quality_delta.abs() >= 0.0001 {
        return Some(if average_citation_quality_delta.is_sign_positive() {
            primary
        } else {
            secondary
        });
    }

    None
}

fn build_engine_comparisons(bundles: &[ReplayBundle]) -> Vec<EngineComparisonSummary> {
    let mut grouped = BTreeMap::<String, BTreeMap<EngineMode, QueryMetricsAggregate>>::new();
    for bundle in bundles {
        let query_key = normalized_query_key(&bundle.query);
        grouped
            .entry(query_key)
            .or_default()
            .entry(bundle.metadata.engine_mode)
            .or_default()
            .observe_bundle(bundle);
    }

    let engines = grouped
        .values()
        .flat_map(|by_engine| by_engine.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut comparisons = Vec::new();

    for (primary_index, primary_engine_mode) in engines.iter().enumerate() {
        for secondary_engine_mode in engines.iter().skip(primary_index + 1) {
            let mut paired_query_count = 0u64;
            let mut primary_wins = 0u64;
            let mut secondary_wins = 0u64;
            let mut ties = 0u64;
            let mut quality_delta_sum = 0.0;
            let mut supported_rate_delta_sum = 0.0;
            let mut source_unavailable_rate_delta_sum = 0.0;
            let mut coverage_delta_sum = 0.0;
            let mut citation_delta_sum = 0.0;

            for by_engine in grouped.values() {
                let (Some(primary), Some(secondary)) = (
                    by_engine.get(primary_engine_mode),
                    by_engine.get(secondary_engine_mode),
                ) else {
                    continue;
                };
                paired_query_count = paired_query_count.saturating_add(1);

                let quality_delta =
                    primary.average_quality_score() - secondary.average_quality_score();
                quality_delta_sum += quality_delta;
                supported_rate_delta_sum += primary.supported_rate() - secondary.supported_rate();
                source_unavailable_rate_delta_sum +=
                    primary.source_unavailable_rate() - secondary.source_unavailable_rate();
                coverage_delta_sum +=
                    primary.average_coverage_observed() - secondary.average_coverage_observed();
                citation_delta_sum +=
                    primary.average_citation_quality() - secondary.average_citation_quality();

                if quality_delta >= 0.01 {
                    primary_wins = primary_wins.saturating_add(1);
                } else if quality_delta <= -0.01 {
                    secondary_wins = secondary_wins.saturating_add(1);
                } else {
                    ties = ties.saturating_add(1);
                }
            }

            if paired_query_count == 0 {
                continue;
            }

            let paired_query_count_f64 = paired_query_count as f64;
            let average_quality_score_delta = round_2dp(quality_delta_sum / paired_query_count_f64);
            let supported_rate_delta = round_4dp(supported_rate_delta_sum / paired_query_count_f64);
            let source_unavailable_rate_delta =
                round_4dp(source_unavailable_rate_delta_sum / paired_query_count_f64);
            let average_coverage_observed_delta =
                round_4dp(coverage_delta_sum / paired_query_count_f64);
            let average_citation_quality_delta =
                round_4dp(citation_delta_sum / paired_query_count_f64);

            comparisons.push(EngineComparisonSummary {
                primary_engine_mode: *primary_engine_mode,
                secondary_engine_mode: *secondary_engine_mode,
                paired_query_count,
                average_quality_score_delta,
                supported_rate_delta,
                source_unavailable_rate_delta,
                average_coverage_observed_delta,
                average_citation_quality_delta,
                primary_win_rate: round_4dp(primary_wins as f64 / paired_query_count_f64),
                secondary_win_rate: round_4dp(secondary_wins as f64 / paired_query_count_f64),
                tie_rate: round_4dp(ties as f64 / paired_query_count_f64),
                more_helpful_engine_mode: comparison_winner(
                    *primary_engine_mode,
                    *secondary_engine_mode,
                    primary_wins,
                    secondary_wins,
                    average_quality_score_delta,
                    supported_rate_delta,
                    source_unavailable_rate_delta,
                    average_citation_quality_delta,
                ),
            });
        }
    }

    comparisons
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
            let ambiguity_rate = runs
                .iter()
                .filter(|run| run.response_kind == Some(ClientResponseKind::Ambiguous))
                .count() as f64
                / run_count as f64;
            let partial_answer_rate = runs
                .iter()
                .filter(|run| run.response_kind == Some(ClientResponseKind::PartialAnswer))
                .count() as f64
                / run_count as f64;
            let refusal_friction_rate = runs
                .iter()
                .filter(|run| {
                    run.terminal_mode != TerminalMode::Supported
                        && run.response_kind != Some(ClientResponseKind::Ambiguous)
                })
                .count() as f64
                / run_count as f64;
            let avg_coverage_observed =
                runs.iter().map(|run| run.coverage_observed).sum::<f64>() / run_count as f64;
            let avg_citation_quality =
                runs.iter().map(|run| run.citation_quality).sum::<f64>() / run_count as f64;

            RunQualityScorecard {
                engine_mode,
                run_count,
                average_quality_score: round_2dp(avg_quality_score),
                minimum_quality_score: round_2dp(min_quality_score),
                maximum_quality_score: round_2dp(max_quality_score),
                supported_rate: round_4dp(supported_rate),
                source_unavailable_rate: round_4dp(source_unavailable_rate),
                ambiguity_rate: round_4dp(ambiguity_rate),
                partial_answer_rate: round_4dp(partial_answer_rate),
                refusal_friction_rate: round_4dp(refusal_friction_rate),
                average_coverage_observed: round_4dp(avg_coverage_observed),
                average_citation_quality: round_4dp(avg_citation_quality),
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

    use pecr_contracts::{Claim, ClaimEvidenceSnippet, ClaimStatus};
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
                evidence_snippets: vec![ClaimEvidenceSnippet {
                    evidence_unit_id:
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    location: "fs_corpus/public/public_1.txt line 1".to_string(),
                    snippet: "supported claim".to_string(),
                }],
            }]
        } else {
            vec![Claim {
                claim_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
                claim_text: "unknown claim".to_string(),
                status: ClaimStatus::Unknown,
                evidence_unit_ids: Vec::new(),
                evidence_snippets: Vec::new(),
            }]
        };

        ClaimMap {
            claim_map_id: Ulid::new().to_string(),
            terminal_mode,
            claims,
            coverage_threshold: 0.95,
            coverage_observed: if supported { 1.0 } else { 0.75 },
            clarification_prompt: None,
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
                planner_traces: Vec::new(),
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
                planner_traces: Vec::new(),
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
                planner_traces: Vec::new(),
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
        assert_eq!(baseline.average_citation_quality, 1.0);
        assert_eq!(baseline.partial_answer_rate, 0.0);
        assert_eq!(baseline.refusal_friction_rate, 0.0);
        assert_eq!(rlm.refusal_friction_rate, 1.0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn compute_citation_quality_rewards_snippet_backed_supported_claims() {
        let supported = sample_claim_map(TerminalMode::Supported, true);
        let mut missing_snippets = supported.clone();
        missing_snippets.claims[0].evidence_snippets.clear();

        assert_eq!(compute_citation_quality(&supported), 1.0);
        assert!(compute_citation_quality(&missing_snippets) < 1.0);
    }

    #[test]
    fn compute_corroboration_quality_rewards_supported_claims_with_multiple_evidence_units() {
        let supported = sample_claim_map(TerminalMode::Supported, true);
        let mut corroborated = supported.clone();
        corroborated.claims[0]
            .evidence_unit_ids
            .push("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string());
        corroborated.claims[0]
            .evidence_snippets
            .push(ClaimEvidenceSnippet {
                evidence_unit_id:
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
                location: "fs_corpus/public/public_2.txt line 3".to_string(),
                snippet: "supported claim".to_string(),
            });

        assert_eq!(compute_corroboration_quality(&supported), 0.5);
        assert_eq!(compute_corroboration_quality(&corroborated), 1.0);
        assert!(
            compute_quality_score(
                TerminalMode::Supported,
                &corroborated,
                corroborated.claims[0].evidence_unit_ids.len()
            ) > compute_quality_score(
                TerminalMode::Supported,
                &supported,
                supported.claims[0].evidence_unit_ids.len()
            )
        );
    }

    #[test]
    fn compute_response_kind_detects_partial_and_ambiguous_replays() {
        let mut partial = sample_claim_map(TerminalMode::Supported, true);
        partial.notes = Some(
            "Partial answer: supported claims are grounded, but some requested details remain unresolved."
                .to_string(),
        );
        assert_eq!(
            compute_response_kind(
                TerminalMode::Supported,
                "SUPPORTED: annual plans may request refunds within 30 days.",
                &partial,
            ),
            Some(ClientResponseKind::PartialAnswer)
        );

        let ambiguous = sample_claim_map(TerminalMode::InsufficientEvidence, false);
        assert_eq!(
            compute_response_kind(
                TerminalMode::InsufficientEvidence,
                "UNKNOWN: the structured lookup is underspecified. Safe scopes for the current principal: customer rows in safe_customer_view_public. Available safe views: `safe_customer_view_public`. Useful filters or fields: `customer_id`, `status`, `plan_tier`.",
                &ambiguous,
            ),
            Some(ClientResponseKind::Ambiguous)
        );
    }

    #[test]
    fn build_scorecards_tracks_partial_and_ambiguity_rates() {
        let scorecards = build_scorecards(&[
            ReplayRunScore {
                run_id: "run-supported".to_string(),
                trace_id: "trace-supported".to_string(),
                engine_mode: EngineMode::Baseline,
                terminal_mode: TerminalMode::Supported,
                quality_score: 96.0,
                coverage_observed: 1.0,
                citation_quality: 1.0,
                response_kind: None,
            },
            ReplayRunScore {
                run_id: "run-partial".to_string(),
                trace_id: "trace-partial".to_string(),
                engine_mode: EngineMode::Baseline,
                terminal_mode: TerminalMode::Supported,
                quality_score: 91.0,
                coverage_observed: 1.0,
                citation_quality: 0.9,
                response_kind: Some(ClientResponseKind::PartialAnswer),
            },
            ReplayRunScore {
                run_id: "run-ambiguous".to_string(),
                trace_id: "trace-ambiguous".to_string(),
                engine_mode: EngineMode::Baseline,
                terminal_mode: TerminalMode::InsufficientEvidence,
                quality_score: 90.0,
                coverage_observed: 1.0,
                citation_quality: 1.0,
                response_kind: Some(ClientResponseKind::Ambiguous),
            },
        ]);

        assert_eq!(scorecards.len(), 1);
        let baseline = &scorecards[0];
        assert_eq!(baseline.partial_answer_rate, 0.3333);
        assert_eq!(baseline.ambiguity_rate, 0.3333);
        assert_eq!(baseline.refusal_friction_rate, 0.0);
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
                planner_traces: Vec::new(),
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

    #[test]
    fn replay_store_evaluation_reports_engine_comparisons_for_paired_queries() {
        let root = temp_store_dir();
        let store = ReplayStore::new(root.clone(), 30).expect("store should initialize");
        let principal = "compare-user";
        let principal_hash = hash_principal_id(principal);

        store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-baseline-compare".to_string(),
                principal_id: principal.to_string(),
                engine_mode: ControllerEngine::Baseline,
                query: "What is the customer status and plan tier?".to_string(),
                budget: sample_budget(),
                session_id: "session-baseline".to_string(),
                policy_snapshot_id: "policy-baseline".to_string(),
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
                planner_traces: Vec::new(),
            })
            .expect("persist baseline comparison run should succeed");

        store
            .persist_run(PersistedRun {
                trace_id: Ulid::new().to_string(),
                request_id: "req-rlm-compare".to_string(),
                principal_id: principal.to_string(),
                engine_mode: ControllerEngine::Rlm,
                query: "What is the customer status and plan tier?".to_string(),
                budget: sample_budget(),
                session_id: "session-rlm".to_string(),
                policy_snapshot_id: "policy-rlm".to_string(),
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
                planner_traces: Vec::new(),
            })
            .expect("persist rlm comparison run should succeed");

        let evaluation = store
            .submit_evaluation(
                &principal_hash,
                ReplayEvaluationSubmission {
                    evaluation_name: "engine-compare".to_string(),
                    replay_ids: Vec::new(),
                    engine_mode: None,
                    min_quality_score: Some(0.0),
                    max_source_unavailable_rate: Some(1.0),
                },
                50,
            )
            .expect("evaluation should succeed");

        assert_eq!(evaluation.engine_comparisons.len(), 1);
        let comparison = &evaluation.engine_comparisons[0];
        assert_eq!(comparison.primary_engine_mode, EngineMode::Baseline);
        assert_eq!(comparison.secondary_engine_mode, EngineMode::Rlm);
        assert_eq!(comparison.paired_query_count, 1);
        assert_eq!(
            comparison.more_helpful_engine_mode,
            Some(EngineMode::Baseline)
        );
        assert!(comparison.average_quality_score_delta > 0.0);
        assert!(comparison.primary_win_rate > comparison.secondary_win_rate);

        let _ = fs::remove_dir_all(root);
    }
}
