use std::collections::{BTreeMap, BTreeSet};

use pecr_contracts::canonical;
use pecr_contracts::{
    Claim, ClaimEvidenceSnippet, ClaimMap, ClaimStatus, ClarificationPrompt, EvidenceUnit,
    TerminalMode,
};
use ulid::Ulid;

use super::orchestration::{
    ambiguity_guidance_for_query, clarification_prompt_for_query, decompose_query_clauses,
    semantic_query_tokens,
};

pub(super) struct FinalizeOutput {
    pub(super) response_text: String,
    pub(super) claim_map: ClaimMap,
}

const MAX_FINALIZE_EVIDENCE_UNITS: usize = 4;

#[derive(Debug, Clone)]
struct SupportedClaimCandidate {
    claim_text: String,
    claim_key: String,
    evidence_unit_ids: Vec<String>,
    corroboration_source_keys: BTreeSet<String>,
    best_rank_score: i64,
}

pub(super) fn build_finalize_output(
    query: &str,
    loop_terminal_mode: TerminalMode,
    loop_response_text: Option<String>,
    evidence_units: &[EvidenceUnit],
) -> FinalizeOutput {
    let ranked_evidence_units = select_finalize_evidence_units(query, evidence_units);
    let supported_evidence_unit_ids = supported_evidence_unit_ids(&ranked_evidence_units);
    let supported_evidence_snippets = supported_evidence_snippets(query, &ranked_evidence_units);
    let trimmed_loop_response_text = loop_response_text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let evidence_matches_query = evidence_meaningfully_matches_query(query, &ranked_evidence_units);
    let loop_response_has_only_non_supported_claims =
        trimmed_loop_response_text.is_some_and(response_text_has_only_non_supported_claims);
    let effective_terminal_mode = match loop_terminal_mode {
        TerminalMode::InsufficientEvidence
            if evidence_matches_query && !supported_evidence_unit_ids.is_empty() =>
        {
            TerminalMode::Supported
        }
        TerminalMode::Supported
            if loop_response_has_only_non_supported_claims
                && (!evidence_matches_query || supported_evidence_unit_ids.is_empty()) =>
        {
            TerminalMode::InsufficientEvidence
        }
        _ => loop_terminal_mode,
    };
    let synthesize_supported_from_evidence = trimmed_loop_response_text.is_some_and(|text| {
        should_synthesize_supported_from_evidence(
            effective_terminal_mode,
            text,
            &supported_evidence_unit_ids,
            evidence_matches_query,
        )
    });

    if let Some(partial_output) = synthesize_partial_finalize_output(
        query,
        loop_terminal_mode,
        trimmed_loop_response_text,
        &ranked_evidence_units,
    ) {
        return partial_output;
    }

    if synthesize_supported_from_evidence
        && let Some(partial_output) = synthesize_partial_finalize_output(
            query,
            TerminalMode::InsufficientEvidence,
            trimmed_loop_response_text,
            &ranked_evidence_units,
        )
    {
        return partial_output;
    }

    let response_text = if synthesize_supported_from_evidence {
        synthesize_supported_response_text(query, &ranked_evidence_units)
            .unwrap_or_else(|| response_text_for_terminal_mode(effective_terminal_mode))
    } else {
        trimmed_loop_response_text
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if effective_terminal_mode == TerminalMode::Supported {
                    synthesize_supported_response_text(query, &ranked_evidence_units)
                        .unwrap_or_else(|| response_text_for_terminal_mode(effective_terminal_mode))
                } else if ranked_evidence_units.is_empty() {
                    ambiguity_guidance_for_query(query)
                        .unwrap_or_else(|| response_text_for_terminal_mode(effective_terminal_mode))
                } else {
                    response_text_for_terminal_mode(effective_terminal_mode)
                }
            })
    };

    let claim_map = if effective_terminal_mode == TerminalMode::Supported
        && (trimmed_loop_response_text.is_none() || synthesize_supported_from_evidence)
    {
        synthesize_supported_claim_map(query, &ranked_evidence_units).unwrap_or_else(|| {
            build_claim_map_with_supported_evidence(
                &response_text,
                effective_terminal_mode,
                &supported_evidence_unit_ids,
                &supported_evidence_snippets,
            )
        })
    } else {
        build_claim_map_with_supported_evidence(
            &response_text,
            effective_terminal_mode,
            &supported_evidence_unit_ids,
            &supported_evidence_snippets,
        )
    };
    let clarification_prompt =
        finalize_clarification_prompt(query, effective_terminal_mode, &ranked_evidence_units);
    let mut claim_map = claim_map;
    claim_map.clarification_prompt = clarification_prompt;

    FinalizeOutput {
        response_text,
        claim_map,
    }
}

fn finalize_clarification_prompt(
    query: &str,
    terminal_mode: TerminalMode,
    evidence_units: &[&EvidenceUnit],
) -> Option<ClarificationPrompt> {
    if terminal_mode != TerminalMode::InsufficientEvidence || !evidence_units.is_empty() {
        return None;
    }
    clarification_prompt_for_query(query)
}

fn synthesize_partial_finalize_output(
    query: &str,
    loop_terminal_mode: TerminalMode,
    loop_response_text: Option<&str>,
    evidence_units: &[&EvidenceUnit],
) -> Option<FinalizeOutput> {
    if loop_terminal_mode != TerminalMode::InsufficientEvidence
        || !evidence_meaningfully_matches_query(query, evidence_units)
    {
        return None;
    }

    let loop_response_text = loop_response_text?;
    let snippet_by_id = claim_evidence_snippet_by_id(query, evidence_units);
    let mut supported_claims = synthesize_multi_part_supported_claims(query, evidence_units)
        .unwrap_or_else(|| synthesize_supported_claims(query, evidence_units));
    if supported_claims.is_empty() {
        return None;
    }

    for claim in &mut supported_claims {
        claim.evidence_snippets = claim
            .evidence_unit_ids
            .iter()
            .filter_map(|evidence_unit_id| snippet_by_id.get(evidence_unit_id).cloned())
            .collect();
    }

    let unresolved_claims =
        synthesize_partial_unresolved_claims(query, loop_response_text, &supported_claims);
    if unresolved_claims.is_empty() {
        return None;
    }

    let mut claims = supported_claims;
    claims.extend(unresolved_claims);

    Some(FinalizeOutput {
        response_text: render_claims_response_text(&claims),
        claim_map: ClaimMap {
            claim_map_id: Ulid::new().to_string(),
            terminal_mode: TerminalMode::Supported,
            coverage_threshold: 0.95,
            coverage_observed: 1.0,
            claims,
            clarification_prompt: None,
            notes: Some(
                "Partial answer: supported claims are grounded, but some requested details remain unresolved."
                    .to_string(),
            ),
        },
    })
}

pub(super) fn response_text_for_terminal_mode(terminal_mode: TerminalMode) -> String {
    match terminal_mode {
        TerminalMode::InsufficientEvidence => {
            "UNKNOWN: insufficient evidence to answer the query.".to_string()
        }
        TerminalMode::InsufficientPermission => {
            "UNKNOWN: insufficient permission to access required evidence.".to_string()
        }
        TerminalMode::SourceUnavailable => {
            "UNKNOWN: required sources were unavailable within budget.".to_string()
        }
        TerminalMode::Supported => {
            "SUPPORTED: evidence-backed answer available for the request.".to_string()
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn build_claim_map(response_text: &str, terminal_mode: TerminalMode) -> ClaimMap {
    build_claim_map_with_supported_evidence(response_text, terminal_mode, &[], &[])
}

fn build_claim_map_with_supported_evidence(
    response_text: &str,
    terminal_mode: TerminalMode,
    supported_evidence_unit_ids: &[String],
    supported_evidence_snippets: &[ClaimEvidenceSnippet],
) -> ClaimMap {
    let supported_evidence_unit_ids = normalize_evidence_unit_ids(supported_evidence_unit_ids);
    let supported_evidence_snippets = normalize_claim_evidence_snippets(
        supported_evidence_snippets,
        &supported_evidence_unit_ids,
    );
    let claims = extract_atomic_claims(response_text)
        .into_iter()
        .map(|(status, claim_text)| {
            let (evidence_unit_ids, evidence_snippets) = if status == ClaimStatus::Supported {
                (
                    supported_evidence_unit_ids.clone(),
                    supported_evidence_snippets.clone(),
                )
            } else {
                (Vec::new(), Vec::new())
            };
            let claim_id = claim_id_for(&claim_text, status, &evidence_unit_ids);
            Claim {
                claim_id,
                claim_text,
                status,
                evidence_unit_ids,
                evidence_snippets,
            }
        })
        .collect::<Vec<_>>();

    let claims = if terminal_mode == TerminalMode::Supported
        && claims
            .iter()
            .all(|claim| claim.status != ClaimStatus::Supported)
        && !contains_explicit_claim_labels(response_text)
    {
        let claim_text = normalize_claim_text(response_text);
        if claim_text.is_empty() {
            claims
        } else {
            let claim_id = claim_id_for(
                &claim_text,
                ClaimStatus::Supported,
                &supported_evidence_unit_ids,
            );
            vec![Claim {
                claim_id,
                claim_text,
                status: ClaimStatus::Supported,
                evidence_unit_ids: supported_evidence_unit_ids.clone(),
                evidence_snippets: supported_evidence_snippets.clone(),
            }]
        }
    } else {
        claims
    };

    let supported_claims = claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported)
        .count();
    let covered_claims = claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported && !c.evidence_unit_ids.is_empty())
        .count();

    let coverage_observed = if supported_claims == 0 {
        1.0
    } else {
        covered_claims as f64 / supported_claims as f64
    };

    ClaimMap {
        claim_map_id: Ulid::new().to_string(),
        terminal_mode,
        claims,
        coverage_threshold: 0.95,
        coverage_observed,
        clarification_prompt: None,
        notes: None,
    }
}

pub(super) fn extract_atomic_claims(response_text: &str) -> Vec<(ClaimStatus, String)> {
    response_text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            if let Some(rest) = line.strip_prefix("SUPPORTED:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Supported, claim.to_string()));
            }

            if let Some(rest) = line.strip_prefix("ASSUMPTION:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Assumption, claim.to_string()));
            }

            if let Some(rest) = line.strip_prefix("UNKNOWN:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Unknown, claim.to_string()));
            }

            Some((ClaimStatus::Unknown, line.to_string()))
        })
        .collect()
}

fn claim_id_for(claim_text: &str, status: ClaimStatus, evidence_unit_ids: &[String]) -> String {
    let status_str = match status {
        ClaimStatus::Supported => "SUPPORTED",
        ClaimStatus::Assumption => "ASSUMPTION",
        ClaimStatus::Unknown => "UNKNOWN",
    };

    canonical::hash_canonical_json(&serde_json::json!({
        "claim_text": claim_text,
        "status": status_str,
        "evidence_unit_ids": evidence_unit_ids,
    }))
}

fn synthesize_supported_claim_map(
    query: &str,
    evidence_units: &[&EvidenceUnit],
) -> Option<ClaimMap> {
    let snippet_by_id = claim_evidence_snippet_by_id(query, evidence_units);
    let claims = synthesize_multi_part_supported_claims(query, evidence_units)
        .unwrap_or_else(|| synthesize_supported_claims(query, evidence_units));
    if claims.is_empty() {
        return None;
    }

    Some(ClaimMap {
        claim_map_id: Ulid::new().to_string(),
        terminal_mode: TerminalMode::Supported,
        coverage_threshold: 0.95,
        coverage_observed: 1.0,
        claims: claims
            .into_iter()
            .map(|mut claim| {
                claim.evidence_snippets = claim
                    .evidence_unit_ids
                    .iter()
                    .filter_map(|evidence_unit_id| snippet_by_id.get(evidence_unit_id).cloned())
                    .collect();
                claim
            })
            .collect(),
        clarification_prompt: None,
        notes: None,
    })
}

fn synthesize_supported_response_text(
    query: &str,
    evidence_units: &[&EvidenceUnit],
) -> Option<String> {
    let snippet_by_id = claim_evidence_snippet_by_id(query, evidence_units);
    let mut claims = synthesize_multi_part_supported_claims(query, evidence_units)
        .unwrap_or_else(|| synthesize_supported_claims(query, evidence_units));
    if claims.is_empty() {
        return None;
    }

    for claim in &mut claims {
        claim.evidence_snippets = claim
            .evidence_unit_ids
            .iter()
            .filter_map(|evidence_unit_id| snippet_by_id.get(evidence_unit_id).cloned())
            .collect();
    }

    Some(render_claims_response_text(&claims))
}

fn render_claims_response_text(claims: &[Claim]) -> String {
    claims
        .iter()
        .map(|claim| match claim.status {
            ClaimStatus::Supported => supported_claim_response_line(claim),
            ClaimStatus::Assumption => format!("ASSUMPTION: {}", claim.claim_text),
            ClaimStatus::Unknown => format!("UNKNOWN: {}", claim.claim_text),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn supported_claim_response_line(claim: &Claim) -> String {
    let claim_text = normalize_claim_text(&claim.claim_text);
    if claim_text.is_empty() {
        return "SUPPORTED: evidence-backed answer available.".to_string();
    }

    let (fallback_location, summary) = claim_text
        .split_once(": ")
        .map(|(location, summary)| (location.trim(), summary.trim()))
        .unwrap_or(("", claim_text.as_str()));
    let summary = punctuated_sentence(&humanize_supported_summary(summary));
    let source_locations = supported_claim_source_locations(claim, fallback_location);

    if source_locations.is_empty() {
        format!("SUPPORTED: {}", summary)
    } else if source_locations.len() == 1 {
        format!("SUPPORTED: {} Source: {}.", summary, source_locations[0])
    } else {
        format!(
            "SUPPORTED: {} Sources: {}.",
            summary,
            source_locations.join("; ")
        )
    }
}

fn supported_claim_source_locations(claim: &Claim, fallback_location: &str) -> Vec<String> {
    let mut locations = claim
        .evidence_snippets
        .iter()
        .map(|snippet| normalize_claim_text(&snippet.location))
        .filter(|location| !location.is_empty())
        .collect::<Vec<_>>();

    if locations.is_empty() && !fallback_location.trim().is_empty() {
        locations.push(normalize_claim_text(fallback_location));
    }

    locations.sort();
    locations.dedup();
    locations
}

fn punctuated_sentence(text: &str) -> String {
    let normalized = normalize_claim_text(text);
    if normalized.is_empty() {
        return normalized;
    }
    if normalized.ends_with(['.', '!', '?']) {
        normalized
    } else {
        format!("{}.", normalized)
    }
}

fn humanize_supported_summary(summary: &str) -> String {
    let normalized = normalize_claim_text(summary);
    if normalized.is_empty() || !normalized.contains('=') {
        return normalized;
    }

    normalized
        .split("; ")
        .map(humanize_supported_segment)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

fn humanize_supported_segment(segment: &str) -> String {
    segment
        .split_whitespace()
        .map(humanize_supported_token)
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" ,", ",")
}

fn humanize_supported_token(token: &str) -> String {
    let (trimmed_token, trailing_punctuation) = trim_trailing_clause_punctuation(token);
    let humanized = if let Some((left, right)) = trimmed_token.split_once('=') {
        format!(
            "{} is {}",
            humanize_supported_key(left),
            right.replace('_', " ")
        )
    } else {
        trimmed_token.replace('_', " ")
    };

    format!("{}{}", humanized, trailing_punctuation)
}

fn humanize_supported_key(key: &str) -> String {
    let normalized = key.replace('_', " ");
    if let Some((metric_name, field_name)) = normalized
        .split_once('(')
        .and_then(|(metric_name, rest)| rest.strip_suffix(')').map(|field| (metric_name, field)))
    {
        format!("{} of {}", metric_name.trim(), field_name.trim())
    } else {
        normalized
    }
}

fn trim_trailing_clause_punctuation(token: &str) -> (&str, &str) {
    if let Some(stripped) = token.strip_suffix(',') {
        (stripped, ",")
    } else {
        (token, "")
    }
}

fn synthesize_multi_part_supported_claims(
    query: &str,
    evidence_units: &[&EvidenceUnit],
) -> Option<Vec<Claim>> {
    let clauses = decompose_query_clauses(query);
    if clauses.len() <= 1 {
        return None;
    }

    let mut claims = Vec::new();
    let mut seen_claims = BTreeSet::new();

    for clause in clauses {
        let clause_units = select_finalize_evidence_unit_refs(clause.as_str(), evidence_units);
        let clause_claim = synthesize_supported_claims(clause.as_str(), &clause_units)
            .into_iter()
            .find(|claim| {
                let key = normalize_claim_text(&claim.claim_text).to_ascii_lowercase();
                !key.is_empty() && seen_claims.insert(key)
            });
        if let Some(claim) = clause_claim {
            claims.push(claim);
        }
    }

    (claims.len() >= 2).then_some(claims)
}

fn synthesize_supported_claims(query: &str, evidence_units: &[&EvidenceUnit]) -> Vec<Claim> {
    let mut grouped_candidates = BTreeMap::<String, SupportedClaimCandidate>::new();

    for unit in evidence_units {
        let evidence_unit_id = unit.evidence_unit_id.trim();
        if evidence_unit_id.is_empty() {
            continue;
        }

        let claim_text = describe_evidence_unit(query, unit);
        let claim_key = normalize_claim_text(&claim_text).to_ascii_lowercase();
        if claim_key.is_empty() {
            continue;
        }

        let corroboration_key = evidence_corroboration_key(query, unit);
        let rank_score = evidence_rank_score(query, unit);
        let candidate = grouped_candidates
            .entry(corroboration_key)
            .or_insert_with(|| SupportedClaimCandidate {
                claim_text: claim_text.clone(),
                claim_key: claim_key.clone(),
                evidence_unit_ids: Vec::new(),
                corroboration_source_keys: BTreeSet::new(),
                best_rank_score: rank_score,
            });

        if rank_score > candidate.best_rank_score
            || (rank_score == candidate.best_rank_score && claim_key < candidate.claim_key)
        {
            candidate.claim_text = claim_text.clone();
            candidate.claim_key = claim_key.clone();
            candidate.best_rank_score = rank_score;
        }

        candidate
            .corroboration_source_keys
            .insert(evidence_corroboration_source_key(unit));
        if !candidate
            .evidence_unit_ids
            .iter()
            .any(|existing| existing == evidence_unit_id)
        {
            candidate
                .evidence_unit_ids
                .push(evidence_unit_id.to_string());
        }
    }

    let mut candidates = grouped_candidates.into_values().collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .corroboration_source_keys
            .len()
            .cmp(&left.corroboration_source_keys.len())
            .then_with(|| right.best_rank_score.cmp(&left.best_rank_score))
            .then_with(|| left.claim_key.cmp(&right.claim_key))
    });

    let mut seen_claims = BTreeSet::new();
    let mut claims = Vec::new();
    for candidate in candidates {
        if !seen_claims.insert(candidate.claim_key.clone()) {
            continue;
        }

        let evidence_unit_ids = normalize_evidence_unit_ids(&candidate.evidence_unit_ids);
        let claim_id = claim_id_for(
            &candidate.claim_text,
            ClaimStatus::Supported,
            &evidence_unit_ids,
        );
        claims.push(Claim {
            claim_id,
            claim_text: candidate.claim_text,
            status: ClaimStatus::Supported,
            evidence_unit_ids,
            evidence_snippets: Vec::new(),
        });
    }

    claims
}

fn synthesize_partial_unresolved_claims(
    query: &str,
    loop_response_text: &str,
    supported_claims: &[Claim],
) -> Vec<Claim> {
    let supported_claim_keys = supported_claims
        .iter()
        .map(|claim| normalize_claim_text(&claim.claim_text).to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut seen_claims = supported_claim_keys.clone();

    let mut unresolved = extract_explicit_non_supported_claims(loop_response_text)
        .into_iter()
        .filter_map(|(status, claim_text)| {
            let claim_text = normalize_claim_text(&claim_text);
            let claim_key = claim_text.to_ascii_lowercase();
            if claim_text.is_empty() || !seen_claims.insert(claim_key) {
                return None;
            }

            let claim_id = claim_id_for(&claim_text, status, &[]);
            Some(Claim {
                claim_id,
                claim_text,
                status,
                evidence_unit_ids: Vec::new(),
                evidence_snippets: Vec::new(),
            })
        })
        .collect::<Vec<_>>();

    if unresolved.is_empty() {
        let claim_text = default_partial_unknown_claim(query);
        let claim_id = claim_id_for(&claim_text, ClaimStatus::Unknown, &[]);
        unresolved.push(Claim {
            claim_id,
            claim_text,
            status: ClaimStatus::Unknown,
            evidence_unit_ids: Vec::new(),
            evidence_snippets: Vec::new(),
        });
    }

    unresolved
}

fn extract_explicit_non_supported_claims(response_text: &str) -> Vec<(ClaimStatus, String)> {
    response_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            if let Some(rest) = line.strip_prefix("ASSUMPTION:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Assumption, claim.to_string()));
            }

            if let Some(rest) = line.strip_prefix("UNKNOWN:") {
                let claim = rest.trim();
                return (!claim.is_empty()).then_some((ClaimStatus::Unknown, claim.to_string()));
            }

            None
        })
        .collect()
}

fn select_finalize_evidence_units<'a>(
    query: &str,
    evidence_units: &'a [EvidenceUnit],
) -> Vec<&'a EvidenceUnit> {
    let corroboration_counts = evidence_corroboration_counts(query, evidence_units.iter());
    let mut ranked = evidence_units
        .iter()
        .map(|unit| {
            (
                corroboration_count_for_unit(query, unit, &corroboration_counts),
                evidence_rank_score(query, unit),
                finalize_evidence_key(unit),
                unit,
            )
        })
        .collect::<Vec<_>>();

    ranked.sort_by(
        |(corroboration_a, score_a, key_a, unit_a), (corroboration_b, score_b, key_b, unit_b)| {
            corroboration_b
                .cmp(corroboration_a)
                .then_with(|| score_b.cmp(score_a))
                .then_with(|| {
                    unit_a
                        .transform_chain
                        .len()
                        .cmp(&unit_b.transform_chain.len())
                })
                .then_with(|| key_a.cmp(key_b))
                .then_with(|| unit_a.evidence_unit_id.cmp(&unit_b.evidence_unit_id))
        },
    );

    let mut seen_keys = BTreeSet::new();
    let mut selected = Vec::new();
    for (_, _, key, unit) in ranked {
        if !seen_keys.insert(key) {
            continue;
        }
        selected.push(unit);
        if selected.len() >= MAX_FINALIZE_EVIDENCE_UNITS {
            break;
        }
    }

    selected
}

fn select_finalize_evidence_unit_refs<'a>(
    query: &str,
    evidence_units: &[&'a EvidenceUnit],
) -> Vec<&'a EvidenceUnit> {
    let corroboration_counts = evidence_corroboration_counts(query, evidence_units.iter().copied());
    let mut ranked = evidence_units
        .iter()
        .map(|unit| {
            (
                corroboration_count_for_unit(query, unit, &corroboration_counts),
                evidence_rank_score(query, unit),
                finalize_evidence_key(unit),
                *unit,
            )
        })
        .collect::<Vec<_>>();

    ranked.sort_by(
        |(corroboration_a, score_a, key_a, unit_a), (corroboration_b, score_b, key_b, unit_b)| {
            corroboration_b
                .cmp(corroboration_a)
                .then_with(|| score_b.cmp(score_a))
                .then_with(|| {
                    unit_a
                        .transform_chain
                        .len()
                        .cmp(&unit_b.transform_chain.len())
                })
                .then_with(|| key_a.cmp(key_b))
                .then_with(|| unit_a.evidence_unit_id.cmp(&unit_b.evidence_unit_id))
        },
    );

    let mut seen_keys = BTreeSet::new();
    let mut selected = Vec::new();
    for (_, _, key, unit) in ranked {
        if !seen_keys.insert(key) {
            continue;
        }
        selected.push(unit);
        if selected.len() >= MAX_FINALIZE_EVIDENCE_UNITS {
            break;
        }
    }

    selected
}

fn evidence_corroboration_counts<'a>(
    query: &str,
    evidence_units: impl IntoIterator<Item = &'a EvidenceUnit>,
) -> BTreeMap<String, usize> {
    let mut sources_by_key = BTreeMap::<String, BTreeSet<String>>::new();
    for unit in evidence_units {
        let corroboration_key = evidence_corroboration_key(query, unit);
        if corroboration_key.is_empty() {
            continue;
        }

        sources_by_key
            .entry(corroboration_key)
            .or_default()
            .insert(evidence_corroboration_source_key(unit));
    }

    sources_by_key
        .into_iter()
        .map(|(key, sources)| (key, sources.len()))
        .collect()
}

fn corroboration_count_for_unit(
    query: &str,
    unit: &EvidenceUnit,
    corroboration_counts: &BTreeMap<String, usize>,
) -> usize {
    let corroboration_key = evidence_corroboration_key(query, unit);
    corroboration_counts
        .get(&corroboration_key)
        .copied()
        .unwrap_or(1)
}

fn evidence_corroboration_key(query: &str, unit: &EvidenceUnit) -> String {
    unit.content
        .as_ref()
        .and_then(|content| summarize_content_for_query(content, query))
        .map(|summary| normalize_claim_text(&summary))
        .filter(|summary| !summary.is_empty())
        .unwrap_or_else(|| normalize_claim_text(&describe_evidence_unit(query, unit)))
        .to_ascii_lowercase()
}

fn evidence_corroboration_source_key(unit: &EvidenceUnit) -> String {
    canonical::hash_canonical_json(&serde_json::json!({
        "source_system": unit.source_system,
        "object_id": unit.object_id,
        "version_id": unit.version_id,
        "span_or_row_spec": unit.span_or_row_spec,
    }))
}

fn evidence_rank_score(query: &str, unit: &EvidenceUnit) -> i64 {
    let query_tokens = normalized_tokens(query);
    let candidate_text = format!(
        "{} {} {} {}",
        unit.source_system,
        unit.object_id,
        unit.version_id,
        unit.content
            .as_ref()
            .map(summarize_content)
            .unwrap_or_default()
    );
    let candidate_tokens = normalized_tokens(&candidate_text);
    let overlap = query_tokens
        .iter()
        .filter(|token| candidate_tokens.contains(*token))
        .count() as i64;

    let mut score = overlap * 10;
    if unit.content.is_some() {
        score += 6;
    }
    score += match unit.content_type {
        pecr_contracts::EvidenceContentType::TextPlain => 4,
        pecr_contracts::EvidenceContentType::ApplicationJson => 3,
    };
    score += match unit
        .span_or_row_spec
        .get("type")
        .and_then(|value| value.as_str())
    {
        Some("text_span") => 2,
        Some("row") => 1,
        _ => 0,
    };
    if unit.transform_chain.len() <= 1 {
        score += 2;
    }
    if !query_tokens.is_empty()
        && query_tokens
            .iter()
            .any(|token| unit.object_id.to_ascii_lowercase().contains(token))
    {
        score += 3;
    }

    score
}

fn finalize_evidence_key(unit: &EvidenceUnit) -> String {
    canonical::hash_canonical_json(&serde_json::json!({
        "source_system": unit.source_system,
        "object_id": unit.object_id,
        "version_id": unit.version_id,
        "span_or_row_spec": unit.span_or_row_spec,
        "content_type": match unit.content_type {
            pecr_contracts::EvidenceContentType::TextPlain => "text/plain",
            pecr_contracts::EvidenceContentType::ApplicationJson => "application/json",
        },
        "content_hash": unit.content_hash,
        "as_of_time": unit.as_of_time,
        "policy_snapshot_hash": unit.policy_snapshot_hash,
    }))
}

fn describe_evidence_unit(query: &str, unit: &EvidenceUnit) -> String {
    let location = evidence_location_label(unit);
    let summary = unit
        .content
        .as_ref()
        .and_then(|content| summarize_content_for_query(content, query))
        .filter(|text| !text.is_empty());

    match summary {
        Some(summary) => format!("{}: {}", location, summary),
        None => {
            let version = abbreviate(unit.version_id.as_str(), 12);
            format!(
                "Retrieved evidence from {} at version {}",
                location, version
            )
        }
    }
}

fn evidence_location_label(unit: &EvidenceUnit) -> String {
    let source = format!("{}/{}", unit.source_system, unit.object_id);
    match unit
        .span_or_row_spec
        .get("type")
        .and_then(|value| value.as_str())
    {
        Some("text_span") => match (
            unit.span_or_row_spec
                .get("line_start")
                .and_then(|value| value.as_u64()),
            unit.span_or_row_spec
                .get("line_end")
                .and_then(|value| value.as_u64()),
        ) {
            (Some(line_start), Some(line_end)) if line_start == line_end => {
                format!("{} line {}", source, line_start)
            }
            (Some(line_start), Some(line_end)) => {
                format!("{} lines {}-{}", source, line_start, line_end)
            }
            _ => source,
        },
        Some("row") => unit
            .span_or_row_spec
            .get("row_id")
            .and_then(|value| value.as_str())
            .map(|row_id| format!("{} row {}", source, row_id))
            .unwrap_or_else(|| format!("{} row", source)),
        Some("db_row") => unit
            .span_or_row_spec
            .get("primary_key")
            .and_then(|value| value.as_object())
            .map(|primary_key| {
                let mut parts = primary_key
                    .iter()
                    .filter_map(|(key, value)| {
                        scalar_value_summary(value).map(|summary| format!("{}={}", key, summary))
                    })
                    .collect::<Vec<_>>();
                parts.sort();
                if parts.is_empty() {
                    format!("{} row", source)
                } else {
                    format!("{} row {}", source, parts.join(", "))
                }
            })
            .unwrap_or_else(|| format!("{} row", source)),
        Some("db_aggregate") => format!("{} aggregate", source),
        _ => source,
    }
}

fn summarize_content_for_query(content: &serde_json::Value, query: &str) -> Option<String> {
    match content {
        serde_json::Value::String(text) => summarize_text_for_query(text, query),
        serde_json::Value::Object(map) => summarize_object_for_query(map, query),
        serde_json::Value::Array(values) => summarize_array_for_query(values),
        other => Some(summarize_content(other)),
    }
}

fn summarize_text_for_query(text: &str, query: &str) -> Option<String> {
    let normalized = normalize_claim_text(text);
    if normalized.is_empty() {
        return None;
    }

    let mut candidates = text
        .split(['\n', '.', '!', '?'])
        .map(normalize_claim_text)
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates.push(normalized);
    }

    let query_tokens = normalized_tokens(query);
    let mut best_index = 0usize;
    let mut best_score = i64::MIN;
    let mut best_len = usize::MAX;
    for (index, candidate) in candidates.iter().enumerate() {
        let score = token_overlap_score(&query_tokens, candidate);
        if score > best_score || (score == best_score && candidate.len() < best_len) {
            best_index = index;
            best_score = score;
            best_len = candidate.len();
        }
    }

    Some(abbreviate(&candidates[best_index], 120))
}

fn summarize_object_for_query(
    map: &serde_json::Map<String, serde_json::Value>,
    query: &str,
) -> Option<String> {
    if let Some(rows) = map.get("rows").and_then(|value| value.as_array())
        && let Some(summary) = summarize_aggregate_rows(rows, query)
    {
        return Some(summary);
    }

    let query_tokens = normalized_tokens(query);
    let mut entries = map
        .iter()
        .filter_map(|(key, value)| {
            let value_summary = scalar_value_summary(value)?;
            let summary = format!("{}={}", key, value_summary);
            let key_tokens = normalized_tokens(key);
            let mut score = token_overlap_score(&query_tokens, &summary);
            if query_tokens.contains(&key.to_ascii_lowercase()) {
                score += 2;
            }
            if !key_tokens.is_empty() && key_tokens.iter().all(|token| query_tokens.contains(token))
            {
                score += 2;
            }
            Some((score, key.as_str(), summary))
        })
        .collect::<Vec<_>>();

    if entries.is_empty() {
        return Some(summarize_content(&serde_json::Value::Object(map.clone())));
    }

    entries.sort_by(|(score_a, key_a, _), (score_b, key_b, _)| {
        score_b.cmp(score_a).then_with(|| key_a.cmp(key_b))
    });

    let has_query_match = entries.iter().any(|(score, _, _)| *score > 0);
    let summary_limit = if has_query_match { 2 } else { 3 };
    let summaries = entries
        .into_iter()
        .filter(|(score, _, _)| !has_query_match || *score > 0)
        .map(|(_, _, summary)| summary)
        .take(summary_limit)
        .collect::<Vec<_>>();

    if summaries.is_empty() {
        return Some(summarize_content(&serde_json::Value::Object(map.clone())));
    }

    Some(summaries.join("; "))
}

fn summarize_aggregate_rows(rows: &[serde_json::Value], query: &str) -> Option<String> {
    let query_tokens = normalized_tokens(query);
    let mut summaries = rows
        .iter()
        .filter_map(|row| summarize_aggregate_row(row, &query_tokens))
        .collect::<Vec<_>>();

    if summaries.is_empty() {
        return None;
    }

    summaries.sort_by(|(score_a, summary_a), (score_b, summary_b)| {
        score_b.cmp(score_a).then_with(|| summary_a.cmp(summary_b))
    });

    Some(
        summaries
            .into_iter()
            .map(|(_, summary)| summary)
            .take(3)
            .collect::<Vec<_>>()
            .join("; "),
    )
}

fn summarize_aggregate_row(
    row: &serde_json::Value,
    query_tokens: &BTreeSet<String>,
) -> Option<(i64, String)> {
    let row_map = row.as_object()?;
    let group = row_map.get("group")?.as_object()?;
    let metrics = row_map.get("metrics")?.as_array()?;

    let mut group_parts = group
        .iter()
        .filter_map(|(key, value)| {
            scalar_value_summary(value).map(|summary| format!("{}={}", key, summary))
        })
        .collect::<Vec<_>>();
    group_parts.sort();

    let mut metric_parts = metrics
        .iter()
        .filter_map(|metric| {
            let metric_map = metric.as_object()?;
            let name = metric_map.get("name")?.as_str()?.trim();
            let field = metric_map.get("field")?.as_str()?.trim();
            let value = metric_map.get("value")?;
            let value_summary = scalar_value_summary(value)?;
            Some(format!("{}({})={}", name, field, value_summary))
        })
        .collect::<Vec<_>>();
    metric_parts.sort();

    if group_parts.is_empty() && metric_parts.is_empty() {
        return None;
    }

    let summary = match (group_parts.is_empty(), metric_parts.is_empty()) {
        (false, false) => format!("{} {}", group_parts.join(", "), metric_parts.join(", ")),
        (false, true) => group_parts.join(", "),
        (true, false) => metric_parts.join(", "),
        (true, true) => return None,
    };

    Some((token_overlap_score(query_tokens, &summary), summary))
}

fn summarize_array_for_query(values: &[serde_json::Value]) -> Option<String> {
    let summaries = values
        .iter()
        .filter_map(scalar_value_summary)
        .take(3)
        .collect::<Vec<_>>();

    if summaries.is_empty() {
        return Some(summarize_content(&serde_json::Value::Array(
            values.to_vec(),
        )));
    }

    Some(format!("values [{}]", summaries.join(", ")))
}

fn scalar_value_summary(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => {
            let normalized = normalize_claim_text(text);
            (!normalized.is_empty()).then(|| abbreviate(&normalized, 48))
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn token_overlap_score(query_tokens: &BTreeSet<String>, candidate: &str) -> i64 {
    let candidate_tokens = normalized_tokens(candidate);
    query_tokens
        .iter()
        .filter(|token| {
            candidate_tokens
                .iter()
                .any(|candidate_token| tokens_match(token, candidate_token))
        })
        .count() as i64
}

fn tokens_match(left: &str, right: &str) -> bool {
    left == right
        || (left.len() >= 4 && right.starts_with(left))
        || (right.len() >= 4 && left.starts_with(right))
}

fn summarize_content(content: &serde_json::Value) -> String {
    match content {
        serde_json::Value::String(text) => abbreviate(&normalize_claim_text(text), 120),
        other => serde_json::to_string(other)
            .map(|value| abbreviate(&value, 120))
            .unwrap_or_else(|_| "structured content".to_string()),
    }
}

fn normalize_evidence_unit_ids(evidence_unit_ids: &[String]) -> Vec<String> {
    let mut ids = evidence_unit_ids
        .iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn supported_evidence_unit_ids(evidence_units: &[&EvidenceUnit]) -> Vec<String> {
    normalize_evidence_unit_ids(
        &evidence_units
            .iter()
            .map(|unit| unit.evidence_unit_id.clone())
            .collect::<Vec<_>>(),
    )
}

fn supported_evidence_snippets(
    query: &str,
    evidence_units: &[&EvidenceUnit],
) -> Vec<ClaimEvidenceSnippet> {
    normalize_claim_evidence_snippets(
        &evidence_units
            .iter()
            .filter_map(|unit| claim_evidence_snippet(query, unit))
            .collect::<Vec<_>>(),
        &supported_evidence_unit_ids(evidence_units),
    )
}

fn claim_evidence_snippet_by_id(
    query: &str,
    evidence_units: &[&EvidenceUnit],
) -> BTreeMap<String, ClaimEvidenceSnippet> {
    supported_evidence_snippets(query, evidence_units)
        .into_iter()
        .map(|snippet| (snippet.evidence_unit_id.clone(), snippet))
        .collect()
}

fn claim_evidence_snippet(query: &str, unit: &EvidenceUnit) -> Option<ClaimEvidenceSnippet> {
    let evidence_unit_id = unit.evidence_unit_id.trim();
    if evidence_unit_id.is_empty() {
        return None;
    }

    let snippet = unit
        .content
        .as_ref()
        .and_then(|content| summarize_content_for_query(content, query))
        .map(|summary| summary.trim().to_string())
        .filter(|summary| !summary.is_empty())?;

    Some(ClaimEvidenceSnippet {
        evidence_unit_id: evidence_unit_id.to_string(),
        location: evidence_location_label(unit),
        snippet: snippet.clone(),
    })
}

fn normalize_claim_evidence_snippets(
    snippets: &[ClaimEvidenceSnippet],
    supported_evidence_unit_ids: &[String],
) -> Vec<ClaimEvidenceSnippet> {
    let allowed_ids = supported_evidence_unit_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut normalized = Vec::new();
    let mut seen_ids = BTreeSet::new();

    for snippet in snippets {
        let evidence_unit_id = snippet.evidence_unit_id.trim();
        let location = snippet.location.trim();
        let body = snippet.snippet.trim();
        if evidence_unit_id.is_empty()
            || body.is_empty()
            || !allowed_ids.contains(evidence_unit_id)
            || !seen_ids.insert(evidence_unit_id.to_string())
        {
            continue;
        }

        normalized.push(ClaimEvidenceSnippet {
            evidence_unit_id: evidence_unit_id.to_string(),
            location: if location.is_empty() {
                "evidence".to_string()
            } else {
                location.to_string()
            },
            snippet: body.to_string(),
        });
    }

    normalized
}

fn normalize_claim_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_explicit_claim_labels(text: &str) -> bool {
    text.lines().map(str::trim).any(|line| {
        line.starts_with("SUPPORTED:")
            || line.starts_with("ASSUMPTION:")
            || line.starts_with("UNKNOWN:")
    })
}

fn response_text_has_only_non_supported_claims(response_text: &str) -> bool {
    contains_explicit_claim_labels(response_text)
        && extract_atomic_claims(response_text)
            .into_iter()
            .all(|(status, _)| status != ClaimStatus::Supported)
}

fn evidence_meaningfully_matches_query(query: &str, evidence_units: &[&EvidenceUnit]) -> bool {
    let query_tokens = semantic_query_tokens(query)
        .into_iter()
        .collect::<BTreeSet<_>>();
    if query_tokens.is_empty() {
        return false;
    }

    evidence_units
        .iter()
        .any(|unit| token_overlap_score(&query_tokens, &describe_evidence_unit(query, unit)) > 0)
}

fn should_synthesize_supported_from_evidence(
    terminal_mode: TerminalMode,
    response_text: &str,
    supported_evidence_unit_ids: &[String],
    evidence_matches_query: bool,
) -> bool {
    terminal_mode == TerminalMode::Supported
        && evidence_matches_query
        && !supported_evidence_unit_ids.is_empty()
        && contains_explicit_claim_labels(response_text)
        && extract_atomic_claims(response_text)
            .into_iter()
            .all(|(status, _)| status != ClaimStatus::Supported)
}

fn default_partial_unknown_claim(query: &str) -> String {
    let query = normalize_claim_text(query);
    if query.is_empty() {
        "Additional requested details could not be fully supported by the available evidence."
            .to_string()
    } else {
        format!(
            "Additional requested details for the request could not be fully supported by the available evidence: {}",
            abbreviate(&query, 96)
        )
    }
}

fn normalized_tokens(text: &str) -> BTreeSet<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .collect()
}

fn abbreviate(text: &str, max_chars: usize) -> String {
    let text = text.trim();
    let mut chars = text.chars();
    let abbreviated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", abbreviated)
    } else {
        abbreviated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pecr_contracts::{EvidenceContentType, TransformStep};

    fn sample_evidence_unit(
        evidence_unit_id: &str,
        content: serde_json::Value,
        content_type: EvidenceContentType,
    ) -> EvidenceUnit {
        let content_hash = canonical::hash_canonical_json(&content);
        let span_or_row_spec = match content_type {
            EvidenceContentType::TextPlain => serde_json::json!({
                "type": "text_span",
                "line_start": 1,
                "line_end": 1
            }),
            EvidenceContentType::ApplicationJson => serde_json::json!({
                "type": "row",
                "row_id": "row-1"
            }),
        };
        EvidenceUnit {
            source_system: "fs_corpus".to_string(),
            object_id: "public/public_1.txt".to_string(),
            version_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            span_or_row_spec,
            content_type,
            content: Some(content),
            content_hash,
            retrieved_at: "1970-01-01T00:00:00Z".to_string(),
            as_of_time: "1970-01-01T00:00:00Z".to_string(),
            policy_snapshot_id: "policy".to_string(),
            policy_snapshot_hash:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            transform_chain: vec![TransformStep {
                transform_type: "identity".to_string(),
                transform_hash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_string(),
                params: None,
            }],
            evidence_unit_id: evidence_unit_id.to_string(),
        }
    }

    #[test]
    fn build_finalize_output_synthesizes_supported_claims_from_evidence() {
        let evidence_units = vec![sample_evidence_unit(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            serde_json::Value::String("unit-test text".to_string()),
            EvidenceContentType::TextPlain,
        )];

        let out = build_finalize_output(
            "unit-test",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.terminal_mode, TerminalMode::Supported);
        assert_eq!(out.claim_map.coverage_observed, 1.0);
        assert_eq!(out.claim_map.claims.len(), 1);
        assert_eq!(out.claim_map.claims[0].status, ClaimStatus::Supported);
        assert_eq!(
            out.claim_map.claims[0].evidence_unit_ids,
            vec!["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()]
        );
        assert_eq!(out.claim_map.claims[0].evidence_snippets.len(), 1);
        assert_eq!(
            out.claim_map.claims[0].evidence_snippets[0].location,
            "fs_corpus/public/public_1.txt line 1"
        );
        assert!(
            out.claim_map.claims[0].evidence_snippets[0]
                .snippet
                .contains("unit-test text")
        );
        assert!(out.response_text.starts_with("SUPPORTED:"));
        assert!(out.response_text.contains("unit-test text"));
    }

    #[test]
    fn build_finalize_output_renders_supported_response_text_with_source_suffix() {
        let evidence_units = vec![sample_evidence_unit(
            "0101010101010101010101010101010101010101010101010101010101010101",
            serde_json::json!({
                "status": "active",
                "plan_tier": "starter"
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "What is the customer status and plan tier?",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert!(
            out.response_text
                .contains("SUPPORTED: status is active; plan tier is starter.")
        );
        assert!(
            out.response_text
                .contains("Source: fs_corpus/public/public_1.txt row row-1.")
        );
    }

    #[test]
    fn build_finalize_output_deduplicates_semantically_equivalent_evidence() {
        let first = sample_evidence_unit(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            serde_json::Value::String("same text".to_string()),
            EvidenceContentType::TextPlain,
        );
        let mut duplicate = first.clone();
        duplicate.evidence_unit_id =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

        let out = build_finalize_output(
            "same text",
            TerminalMode::InsufficientEvidence,
            None,
            &[first, duplicate],
        );

        assert_eq!(out.claim_map.claims.len(), 1);
        assert_eq!(
            out.claim_map.claims[0].evidence_unit_ids,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
        );
    }

    #[test]
    fn build_finalize_output_merges_corroborating_evidence_units_into_one_claim() {
        let first = sample_evidence_unit(
            "abababababababababababababababababababababababababababababababab",
            serde_json::Value::String(
                "Refunds are available for annual plans within 30 days.".to_string(),
            ),
            EvidenceContentType::TextPlain,
        );
        let mut second = sample_evidence_unit(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            serde_json::Value::String(
                "Refunds are available for annual plans within 30 days.".to_string(),
            ),
            EvidenceContentType::TextPlain,
        );
        second.object_id = "public/refund_faq.txt".to_string();
        second.span_or_row_spec = serde_json::json!({
            "type": "text_span",
            "line_start": 3,
            "line_end": 3
        });

        let out = build_finalize_output(
            "Show the source text for annual refund terms",
            TerminalMode::InsufficientEvidence,
            None,
            &[first, second],
        );

        assert_eq!(out.claim_map.claims.len(), 1);
        assert_eq!(out.claim_map.claims[0].evidence_unit_ids.len(), 2);
        assert_eq!(out.claim_map.claims[0].evidence_snippets.len(), 2);
        assert!(
            out.claim_map.claims[0]
                .claim_text
                .contains("Refunds are available for annual plans within 30 days")
        );
    }

    #[test]
    fn build_finalize_output_prefers_query_matching_evidence_and_trims_tail() {
        let evidence_units = vec![
            sample_evidence_unit(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                serde_json::Value::String("billing address on file".to_string()),
                EvidenceContentType::TextPlain,
            ),
            sample_evidence_unit(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                serde_json::json!({"status": "active", "plan_tier": "starter"}),
                EvidenceContentType::ApplicationJson,
            ),
            sample_evidence_unit(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                serde_json::Value::String("generic support paragraph".to_string()),
                EvidenceContentType::TextPlain,
            ),
            sample_evidence_unit(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                serde_json::Value::String("another generic support paragraph".to_string()),
                EvidenceContentType::TextPlain,
            ),
            sample_evidence_unit(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                serde_json::Value::String("yet another generic support paragraph".to_string()),
                EvidenceContentType::TextPlain,
            ),
        ];

        let out = build_finalize_output(
            "What is the customer status?",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.claims.len(), 4);
        assert!(out.claim_map.claims[0].claim_text.contains("status"));
        assert!(
            out.claim_map
                .claims
                .iter()
                .all(|claim| !claim.claim_text.is_empty())
        );
    }

    #[test]
    fn build_finalize_output_synthesizes_query_focused_json_claims() {
        let evidence_units = vec![sample_evidence_unit(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            serde_json::json!({
                "customer_name": "Ada",
                "plan_tier": "starter",
                "status": "active"
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "What is the customer status?",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.claims.len(), 1);
        assert!(out.claim_map.claims[0].claim_text.contains("status=active"));
        assert!(out.claim_map.claims[0].claim_text.contains("row row-1"));
    }

    #[test]
    fn build_finalize_output_prefers_matching_text_sentence() {
        let evidence_units = vec![sample_evidence_unit(
            "9999999999999999999999999999999999999999999999999999999999999999",
            serde_json::Value::String(
                "General availability overview. Refunds are available for annual plans within 30 days. Contact support for exceptions.".to_string(),
            ),
            EvidenceContentType::TextPlain,
        )];

        let out = build_finalize_output(
            "What is the refund policy?",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.claims.len(), 1);
        assert!(
            out.claim_map.claims[0]
                .claim_text
                .contains("Refunds are available for annual plans within 30 days")
        );
        assert!(
            !out.claim_map.claims[0]
                .claim_text
                .contains("General availability overview")
        );
    }

    #[test]
    fn build_finalize_output_summarizes_aggregate_rows_for_compare_queries() {
        let evidence_units = vec![sample_evidence_unit(
            "1212121212121212121212121212121212121212121212121212121212121212",
            serde_json::json!({
                "rows": [
                    {
                        "group": { "plan_tier": "starter" },
                        "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
                    },
                    {
                        "group": { "plan_tier": "premium" },
                        "metrics": [{ "name": "count", "field": "customer_id", "value": 4 }]
                    }
                ]
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "Compare customer counts by plan tier",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.claims.len(), 1);
        assert!(
            out.claim_map.claims[0]
                .claim_text
                .contains("plan_tier=starter")
        );
        assert!(
            out.claim_map.claims[0]
                .claim_text
                .contains("count(customer_id)=9")
        );
    }

    #[test]
    fn build_finalize_output_recombines_multi_part_query_clauses() {
        let evidence_units = vec![
            sample_evidence_unit(
                "1313131313131313131313131313131313131313131313131313131313131313",
                serde_json::json!({
                    "rows": [
                        {
                            "group": { "plan_tier": "starter" },
                            "metrics": [{ "name": "count", "field": "customer_id", "value": 9 }]
                        },
                        {
                            "group": { "plan_tier": "premium" },
                            "metrics": [{ "name": "count", "field": "customer_id", "value": 4 }]
                        }
                    ]
                }),
                EvidenceContentType::ApplicationJson,
            ),
            sample_evidence_unit(
                "1414141414141414141414141414141414141414141414141414141414141414",
                serde_json::Value::String(
                    "Billing terms require annual prepayment. Contact support for renewal questions."
                        .to_string(),
                ),
                EvidenceContentType::TextPlain,
            ),
        ];

        let out = build_finalize_output(
            "Compare customer counts by plan tier and show the source text for the billing terms policy",
            TerminalMode::InsufficientEvidence,
            None,
            &evidence_units,
        );

        assert_eq!(out.claim_map.claims.len(), 2);
        assert!(
            out.claim_map.claims.iter().any(|claim| {
                claim.claim_text.contains("plan_tier=starter")
                    && claim.claim_text.contains("count(customer_id)=9")
            }),
            "one claim should summarize the comparison result: {:?}",
            out.claim_map.claims
        );
        assert!(
            out.claim_map.claims.iter().any(|claim| claim
                .claim_text
                .contains("Billing terms require annual prepayment")),
            "one claim should preserve the supporting source text: {:?}",
            out.claim_map.claims
        );
        assert_eq!(out.response_text.lines().count(), 2);
    }

    #[test]
    fn build_claim_map_supports_supported_labels_with_evidence_ids() {
        let claim_map = build_claim_map_with_supported_evidence(
            "SUPPORTED: answer line\nUNKNOWN: fallback line",
            TerminalMode::Supported,
            &["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
            &[ClaimEvidenceSnippet {
                evidence_unit_id:
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                location: "fs_corpus/public/public_1.txt line 1".to_string(),
                snippet: "answer evidence".to_string(),
            }],
        );

        assert_eq!(claim_map.claims.len(), 2);
        assert_eq!(claim_map.claims[0].status, ClaimStatus::Supported);
        assert_eq!(
            claim_map.claims[0].evidence_unit_ids,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()]
        );
        assert_eq!(claim_map.claims[0].evidence_snippets.len(), 1);
        assert_eq!(
            claim_map.claims[0].evidence_snippets[0].snippet,
            "answer evidence"
        );
        assert_eq!(claim_map.claims[1].status, ClaimStatus::Unknown);
        assert!(claim_map.claims[1].evidence_unit_ids.is_empty());
        assert!(claim_map.claims[1].evidence_snippets.is_empty());
    }

    #[test]
    fn build_claim_map_promotes_freeform_supported_text() {
        let claim_map = build_claim_map_with_supported_evidence(
            "This answer is backed by evidence.",
            TerminalMode::Supported,
            &["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
            &[ClaimEvidenceSnippet {
                evidence_unit_id:
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
                location: "fs_corpus/public/public_1.txt line 1".to_string(),
                snippet: "backing evidence".to_string(),
            }],
        );

        assert_eq!(claim_map.claims.len(), 1);
        assert_eq!(claim_map.claims[0].status, ClaimStatus::Supported);
        assert_eq!(
            claim_map.claims[0].claim_text,
            "This answer is backed by evidence."
        );
        assert_eq!(claim_map.claims[0].evidence_snippets.len(), 1);
        assert_eq!(claim_map.coverage_observed, 1.0);
    }

    #[test]
    fn build_claim_map_preserves_explicit_unknown_claims() {
        let claim_map = build_claim_map_with_supported_evidence(
            "UNKNOWN: still unresolved",
            TerminalMode::Supported,
            &["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
            &[ClaimEvidenceSnippet {
                evidence_unit_id:
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
                location: "fs_corpus/public/public_1.txt line 1".to_string(),
                snippet: "backing evidence".to_string(),
            }],
        );

        assert_eq!(claim_map.claims.len(), 1);
        assert_eq!(claim_map.claims[0].status, ClaimStatus::Unknown);
        assert!(claim_map.claims[0].evidence_unit_ids.is_empty());
        assert!(claim_map.claims[0].evidence_snippets.is_empty());
    }

    #[test]
    fn build_finalize_output_emits_partial_answer_when_unresolved_claims_remain() {
        let evidence_units = vec![sample_evidence_unit(
            "abababababababababababababababababababababababababababababababab",
            serde_json::json!({
                "customer_name": "Ada",
                "status": "active"
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "What is the customer status and plan tier?",
            TerminalMode::InsufficientEvidence,
            Some(
                "UNKNOWN: the plan tier could not be confirmed from the retrieved evidence."
                    .to_string(),
            ),
            &evidence_units,
        );

        assert_eq!(out.claim_map.terminal_mode, TerminalMode::Supported);
        assert_eq!(
            out.claim_map.notes.as_deref(),
            Some(
                "Partial answer: supported claims are grounded, but some requested details remain unresolved."
            )
        );
        assert_eq!(out.claim_map.claims.len(), 2);
        assert_eq!(out.claim_map.claims[0].status, ClaimStatus::Supported);
        assert_eq!(out.claim_map.claims[1].status, ClaimStatus::Unknown);
        assert_eq!(
            out.claim_map.claims[1].claim_text,
            "the plan tier could not be confirmed from the retrieved evidence."
        );
        assert!(out.claim_map.claims[0].claim_text.contains("status=active"));
        assert!(
            out.response_text.contains("SUPPORTED:")
                && out
                    .response_text
                    .contains("UNKNOWN: the plan tier could not be confirmed")
        );
    }

    #[test]
    fn build_finalize_output_adds_generic_partial_unknown_claim_for_freeform_loop_text() {
        let evidence_units = vec![sample_evidence_unit(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            serde_json::Value::String("Refunds are available within 30 days.".to_string()),
            EvidenceContentType::TextPlain,
        )];

        let out = build_finalize_output(
            "What is the refund policy and billing contact?",
            TerminalMode::InsufficientEvidence,
            Some("I could only confirm part of the request.".to_string()),
            &evidence_units,
        );

        assert_eq!(out.claim_map.terminal_mode, TerminalMode::Supported);
        assert_eq!(out.claim_map.claims.len(), 2);
        assert_eq!(out.claim_map.claims[0].status, ClaimStatus::Supported);
        assert_eq!(out.claim_map.claims[1].status, ClaimStatus::Unknown);
        assert!(
            out.claim_map.claims[1].claim_text.contains(
                "Additional requested details for the request could not be fully supported"
            )
        );
        assert!(
            out.response_text
                .contains("UNKNOWN: Additional requested details")
        );
    }

    #[test]
    fn build_finalize_output_recovers_supported_claims_from_unknown_loop_text() {
        let evidence_units = vec![sample_evidence_unit(
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            serde_json::json!({
                "status": "active",
                "plan_tier": "starter"
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "What is the customer status and plan tier?",
            TerminalMode::Supported,
            Some("UNKNOWN: insufficient evidence to answer the query.".to_string()),
            &evidence_units,
        );

        assert_eq!(out.claim_map.terminal_mode, TerminalMode::Supported);
        assert!(
            out.claim_map.claims.iter().any(|claim| {
                claim.status == ClaimStatus::Supported && !claim.evidence_unit_ids.is_empty()
            }),
            "supported evidence-backed claims should be synthesized from the retrieved evidence"
        );
        assert!(out.response_text.contains("SUPPORTED:"));
    }

    #[test]
    fn build_finalize_output_demotes_placeholder_supported_mode_without_query_match() {
        let evidence_units = vec![sample_evidence_unit(
            "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
            serde_json::json!({
                "status": "active",
                "plan_tier": "starter"
            }),
            EvidenceContentType::ApplicationJson,
        )];

        let out = build_finalize_output(
            "smoke",
            TerminalMode::Supported,
            Some("UNKNOWN: insufficient evidence to answer the query.".to_string()),
            &evidence_units,
        );

        assert_eq!(
            out.claim_map.terminal_mode,
            TerminalMode::InsufficientEvidence
        );
        assert_eq!(
            out.response_text,
            "UNKNOWN: insufficient evidence to answer the query."
        );
        assert!(
            out.claim_map
                .claims
                .iter()
                .all(|claim| claim.status != ClaimStatus::Supported)
        );
    }

    #[test]
    fn build_finalize_output_uses_ambiguity_guidance_for_broad_query_without_evidence() {
        let out = build_finalize_output("customer", TerminalMode::InsufficientEvidence, None, &[]);

        assert_eq!(
            out.claim_map.terminal_mode,
            TerminalMode::InsufficientEvidence
        );
        assert_eq!(out.claim_map.claims.len(), 1);
        assert_eq!(out.claim_map.claims[0].status, ClaimStatus::Unknown);
        assert!(
            out.response_text
                .contains("Which field or filter should I use for the customer lookup")
        );
        assert!(out.response_text.contains("customer status"));
        assert_eq!(
            out.claim_map
                .clarification_prompt
                .as_ref()
                .map(|prompt| prompt.question.as_str()),
            Some("Which field or filter should I use for the customer lookup")
        );
    }

    #[test]
    fn extract_atomic_claims_respects_supported_unknown_and_assumption_labels() {
        let input = "\nSUPPORTED: first claim\nUNKNOWN: second claim\nASSUMPTION: third claim\n";
        let claims = extract_atomic_claims(input);

        assert_eq!(claims.len(), 3);
        assert_eq!(claims[0].0, ClaimStatus::Supported);
        assert_eq!(claims[0].1, "first claim");
        assert_eq!(claims[1].0, ClaimStatus::Unknown);
        assert_eq!(claims[1].1, "second claim");
        assert_eq!(claims[2].0, ClaimStatus::Assumption);
        assert_eq!(claims[2].1, "third claim");
    }
}
