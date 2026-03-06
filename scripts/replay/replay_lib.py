#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TERMINAL_MODE_SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
PLANNER_MODE_BEAM_SHADOW = "beam_planner_shadow"
PLANNER_MODE_BEAM_EXECUTION = "beam_planner"


def _planner_mode_for_source(planner_source: str | None) -> str | None:
    if planner_source == "rust_owned":
        return "baseline"
    if planner_source == "rlm_bridge":
        return "rlm"
    if planner_source == "beam_planner" or planner_source == "beam_recovery":
        return PLANNER_MODE_BEAM_EXECUTION
    if planner_source == "beam_shadow":
        return PLANNER_MODE_BEAM_SHADOW
    return None


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def replay_paths(store_dir: Path) -> list[Path]:
    replay_dir = store_dir / "replays"
    if not replay_dir.exists():
        return []
    return sorted(path for path in replay_dir.glob("*.json") if path.is_file())


def load_replay_bundles(
    store_dir: Path,
    *,
    engine_mode: str | None = None,
    replay_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    bundles: list[dict[str, Any]] = []
    for path in replay_paths(store_dir):
        bundle = load_json(path)
        metadata = bundle.get("metadata", {})
        run_id = metadata.get("run_id")
        if replay_ids and run_id not in replay_ids:
            continue
        if engine_mode and metadata.get("engine_mode") != engine_mode:
            continue
        bundles.append(bundle)

    bundles.sort(
        key=lambda bundle: int(bundle.get("metadata", {}).get("recorded_at_unix_ms", 0)),
        reverse=True,
    )
    return bundles


def reconstruct_outcome(bundle: dict[str, Any]) -> dict[str, Any]:
    metadata = bundle.get("metadata", {})
    return {
        "terminal_mode": metadata.get("terminal_mode"),
        "trace_id": metadata.get("trace_id"),
        "claim_map": bundle.get("claim_map"),
        "response_text": bundle.get("response_text"),
    }


def source_unavailable_rate(bundles: list[dict[str, Any]]) -> float:
    if not bundles:
        return 0.0
    source_unavailable = 0
    for bundle in bundles:
        terminal_mode = bundle.get("metadata", {}).get("terminal_mode")
        if terminal_mode == TERMINAL_MODE_SOURCE_UNAVAILABLE:
            source_unavailable += 1
    return source_unavailable / len(bundles)


def citation_quality(claim_map: dict[str, Any]) -> float:
    claims = claim_map.get("claims", [])
    supported_claims = [claim for claim in claims if claim.get("status") == "SUPPORTED"]
    terminal_mode = claim_map.get("terminal_mode")

    if not supported_claims:
        return 0.0 if terminal_mode == "SUPPORTED" else 1.0

    citation_coverage = sum(
        1 for claim in supported_claims if claim.get("evidence_unit_ids")
    ) / len(supported_claims)
    snippet_coverage = sum(
        1 for claim in supported_claims if claim.get("evidence_snippets")
    ) / len(supported_claims)

    snippet_alignment = 0.0
    for claim in supported_claims:
        snippets = claim.get("evidence_snippets") or []
        if not snippets:
            continue
        evidence_ids = set(claim.get("evidence_unit_ids") or [])
        aligned = sum(
            1
            for snippet in snippets
            if snippet.get("evidence_unit_id") in evidence_ids
        )
        snippet_alignment += aligned / len(snippets)
    snippet_alignment /= len(supported_claims)

    return round(
        citation_coverage * 0.45 + snippet_coverage * 0.35 + snippet_alignment * 0.20, 4
    )


def response_kind(bundle: dict[str, Any]) -> str | None:
    claim_map = bundle.get("claim_map", {})
    notes = str(claim_map.get("notes") or "")
    if "Partial answer:" in notes:
        return "partial_answer"

    terminal_mode = bundle.get("metadata", {}).get("terminal_mode")
    response_text = str(bundle.get("response_text") or "").lower()
    if terminal_mode == "INSUFFICIENT_EVIDENCE" and (
        "underspecified" in response_text
        or "too broad" in response_text
        or "specify which document or policy" in response_text
        or "safe scopes for the current principal" in response_text
    ):
        return "ambiguous"
    if terminal_mode == "INSUFFICIENT_PERMISSION":
        return "blocked"
    if terminal_mode == TERMINAL_MODE_SOURCE_UNAVAILABLE:
        return "source_down"

    return None


def max_supported_claim_evidence_units(bundle: dict[str, Any]) -> int:
    claim_map = bundle.get("claim_map", {})
    claims = claim_map.get("claims", [])
    max_units = 0
    for claim in claims:
        if claim.get("status") != "SUPPORTED":
            continue
        evidence_ids = {
            str(evidence_id).strip()
            for evidence_id in (claim.get("evidence_unit_ids") or [])
            if str(evidence_id).strip()
        }
        max_units = max(max_units, len(evidence_ids))
    return max_units


def _benchmark_index(benchmark_manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not benchmark_manifest:
        return {}
    return {
        scenario["run_id"]: scenario
        for scenario in benchmark_manifest.get("scenarios", [])
        if scenario.get("run_id")
    }


def _benchmark_query_index(benchmark_manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not benchmark_manifest:
        return {}
    return {
        " ".join(str(scenario.get("query", "")).lower().split()): scenario
        for scenario in benchmark_manifest.get("scenarios", [])
        if scenario.get("query")
    }


def _normalized_query_key(query: str) -> str:
    return " ".join(query.lower().split())


def _paired_group_key(
    bundle: dict[str, Any],
    benchmark_index: dict[str, dict[str, Any]],
    benchmark_query_index: dict[str, dict[str, Any]],
) -> str:
    metadata = bundle.get("metadata", {})
    run_id = metadata.get("run_id")
    if run_id in benchmark_index:
        return f"scenario:{benchmark_index[run_id]['scenario_id']}"

    query = bundle.get("query")
    if isinstance(query, str) and query.strip():
        normalized = _normalized_query_key(query)
        if normalized in benchmark_query_index:
            return f"scenario:{benchmark_query_index[normalized]['scenario_id']}"
        return f"query:{normalized}"

    return f"run:{run_id}"


def benchmark_pass(bundle: dict[str, Any], scenario: dict[str, Any]) -> bool:
    if bundle.get("metadata", {}).get("terminal_mode") != scenario.get(
        "expected_terminal_mode"
    ):
        return False
    if float(bundle.get("metadata", {}).get("quality_score", 0.0)) < float(
        scenario.get("minimum_quality_score", 0.0)
    ):
        return False
    expected_response_kind = scenario.get("expected_response_kind")
    if expected_response_kind is not None and response_kind(bundle) != expected_response_kind:
        return False

    response_text = str(bundle.get("response_text") or "")
    for substring in scenario.get("expected_response_substrings", []):
        if substring not in response_text:
            return False

    notes = str(bundle.get("claim_map", {}).get("notes") or "")
    for substring in scenario.get("expected_note_substrings", []):
        if substring not in notes:
            return False

    minimum_supported_claim_evidence_units = int(
        scenario.get("minimum_supported_claim_evidence_units", 0)
    )
    if minimum_supported_claim_evidence_units > 0 and (
        max_supported_claim_evidence_units(bundle)
        < minimum_supported_claim_evidence_units
    ):
        return False

    return True


def _planner_step_key(step: dict[str, Any]) -> str:
    kind = step.get("kind")
    if kind == "operator":
        return str(step.get("op_name") or "operator")
    if kind == "search_ref_fetch_span":
        return "search_ref_fetch_span"
    return str(kind or "unknown")


def planner_step_signature(steps: list[dict[str, Any]]) -> list[str]:
    return [_planner_step_key(step) for step in steps if isinstance(step, dict)]


def _scenario_for_bundle(
    bundle: dict[str, Any],
    benchmark_index: dict[str, dict[str, Any]],
    benchmark_query_index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    metadata = bundle.get("metadata", {})
    run_id = metadata.get("run_id")
    if run_id in benchmark_index:
        return benchmark_index[run_id]

    query = bundle.get("query")
    if isinstance(query, str) and query.strip():
        return benchmark_query_index.get(_normalized_query_key(query))

    return None


def planner_expected_paths(scenario: dict[str, Any] | None) -> list[list[str]]:
    if not scenario:
        return []
    paths = scenario.get("expected_planner_prefixes")
    if not paths:
        paths = scenario.get("expected_planner_paths") or []
    normalized: list[list[str]] = []
    for path in paths:
        if isinstance(path, list) and all(isinstance(step, str) and step.strip() for step in path):
            normalized.append([step.strip() for step in path])
    return normalized


def planner_benchmark_pass(
    planner_trace: dict[str, Any],
    scenario: dict[str, Any] | None,
) -> bool | None:
    expected_paths = planner_expected_paths(scenario)
    if not expected_paths:
        return None

    actual_path = planner_step_signature(planner_trace.get("output_steps") or [])
    for expected_path in expected_paths:
        if len(actual_path) < len(expected_path):
            continue
        if actual_path[: len(expected_path)] == expected_path:
            return True
    return False


def planner_rows(
    bundles: list[dict[str, Any]],
    benchmark_manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    benchmark_index = _benchmark_index(benchmark_manifest)
    benchmark_query_index = _benchmark_query_index(benchmark_manifest)
    latest_rows: dict[tuple[str, str], dict[str, Any]] = {}

    for bundle in bundles:
        scenario = _scenario_for_bundle(bundle, benchmark_index, benchmark_query_index)
        group_key = _paired_group_key(bundle, benchmark_index, benchmark_query_index)
        recorded_at = int(bundle.get("metadata", {}).get("recorded_at_unix_ms", 0))
        run_id = bundle.get("metadata", {}).get("run_id")
        for planner_trace in bundle.get("planner_traces") or []:
            decision_summary = planner_trace.get("decision_summary") or {}
            planner_source = decision_summary.get("planner_source")
            planner_mode = _planner_mode_for_source(planner_source)
            if planner_mode is None:
                continue

            row = {
                "scenario_id": None if scenario is None else scenario.get("scenario_id"),
                "title": None if scenario is None else scenario.get("title"),
                "query": bundle.get("query"),
                "run_id": run_id,
                "group_key": group_key,
                "planner_mode": planner_mode,
                "planner_source": planner_source,
                "planner_selected_for_execution": bool(
                    decision_summary.get("selected_for_execution")
                ),
                "planner_used_fallback_plan": bool(
                    decision_summary.get("used_fallback_plan")
                ),
                "planner_stop_reason": decision_summary.get("stop_reason"),
                "planner_summary": decision_summary.get("planner_summary"),
                "planner_expected_usefulness_score": decision_summary.get(
                    "expected_usefulness_score"
                ),
                "planner_expected_usefulness_reasons": decision_summary.get(
                    "expected_usefulness_reasons"
                )
                or [],
                "planner_selection_rationale": decision_summary.get(
                    "selection_rationale"
                ),
                "actual_planner_path": planner_step_signature(
                    planner_trace.get("output_steps") or []
                ),
                "expected_planner_paths": planner_expected_paths(scenario),
                "planner_benchmark_pass": planner_benchmark_pass(planner_trace, scenario),
                "_recorded_at_unix_ms": recorded_at,
            }
            key = (group_key, planner_mode)
            current = latest_rows.get(key)
            if current is None or recorded_at >= current["_recorded_at_unix_ms"]:
                latest_rows[key] = row

    rows = sorted(
        latest_rows.values(),
        key=lambda row: (str(row.get("scenario_id") or row.get("group_key")), row["planner_mode"]),
    )
    for row in rows:
        row.pop("_recorded_at_unix_ms", None)
    return rows


def compute_planner_scorecards(
    bundles: list[dict[str, Any]],
    benchmark_manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rows = planner_rows(bundles, benchmark_manifest)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["planner_mode"], []).append(row)

    scenario_total = len((benchmark_manifest or {}).get("scenarios", []))
    scorecards: list[dict[str, Any]] = []
    for planner_mode in sorted(grouped.keys()):
        mode_rows = grouped[planner_mode]
        benchmark_rows = [
            row for row in mode_rows if row.get("planner_benchmark_pass") is not None
        ]
        benchmark_passes = sum(
            1 for row in benchmark_rows if bool(row.get("planner_benchmark_pass"))
        )
        scorecards.append(
            {
                "planner_mode": planner_mode,
                "scenario_count": len(mode_rows),
                "scenario_coverage_rate": round(
                    0.0 if scenario_total == 0 else len(mode_rows) / scenario_total, 4
                ),
                "benchmark_pass_rate": round(
                    0.0
                    if not benchmark_rows
                    else benchmark_passes / len(benchmark_rows),
                    4,
                ),
                "fallback_rate": round(
                    sum(
                        1
                        for row in mode_rows
                        if bool(row.get("planner_used_fallback_plan"))
                    )
                    / len(mode_rows),
                    4,
                ),
                "selected_for_execution_rate": round(
                    sum(
                        1
                        for row in mode_rows
                        if bool(row.get("planner_selected_for_execution"))
                    )
                    / len(mode_rows),
                    4,
                ),
                "average_expected_usefulness_score": round(
                    sum(float(row.get("planner_expected_usefulness_score") or 0.0) for row in mode_rows)
                    / len(mode_rows),
                    4,
                ),
            }
        )

    return scorecards


def compute_planner_comparisons(
    bundles: list[dict[str, Any]],
    benchmark_manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    rows = planner_rows(bundles, benchmark_manifest)
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["group_key"], {})[row["planner_mode"]] = row

    planner_modes = sorted(
        {planner_mode for planner_rows_by_mode in grouped.values() for planner_mode in planner_rows_by_mode}
    )
    comparisons: list[dict[str, Any]] = []
    for primary_index, primary_mode in enumerate(planner_modes):
        for secondary_mode in planner_modes[primary_index + 1 :]:
            paired_scenario_count = 0
            primary_wins = 0
            secondary_wins = 0
            ties = 0
            benchmark_pass_delta_sum = 0.0
            fallback_rate_delta_sum = 0.0
            expected_usefulness_delta_sum = 0.0

            for rows_by_mode in grouped.values():
                primary = rows_by_mode.get(primary_mode)
                secondary = rows_by_mode.get(secondary_mode)
                if not primary or not secondary:
                    continue
                primary_pass = primary.get("planner_benchmark_pass")
                secondary_pass = secondary.get("planner_benchmark_pass")
                if primary_pass is None or secondary_pass is None:
                    continue

                paired_scenario_count += 1
                primary_pass_value = 1.0 if primary_pass else 0.0
                secondary_pass_value = 1.0 if secondary_pass else 0.0
                benchmark_pass_delta = primary_pass_value - secondary_pass_value
                benchmark_pass_delta_sum += benchmark_pass_delta
                primary_fallback = 1.0 if primary.get("planner_used_fallback_plan") else 0.0
                secondary_fallback = 1.0 if secondary.get("planner_used_fallback_plan") else 0.0
                fallback_rate_delta_sum += primary_fallback - secondary_fallback
                primary_score = float(primary.get("planner_expected_usefulness_score") or 0.0)
                secondary_score = float(
                    secondary.get("planner_expected_usefulness_score") or 0.0
                )
                expected_usefulness_delta = primary_score - secondary_score
                expected_usefulness_delta_sum += expected_usefulness_delta

                if benchmark_pass_delta > 0.0:
                    primary_wins += 1
                elif benchmark_pass_delta < 0.0:
                    secondary_wins += 1
                elif primary_fallback < secondary_fallback:
                    primary_wins += 1
                elif primary_fallback > secondary_fallback:
                    secondary_wins += 1
                elif expected_usefulness_delta > 0.0:
                    primary_wins += 1
                elif expected_usefulness_delta < 0.0:
                    secondary_wins += 1
                else:
                    ties += 1

            if paired_scenario_count == 0:
                continue

            more_helpful_planner_mode = None
            if primary_wins > secondary_wins:
                more_helpful_planner_mode = primary_mode
            elif secondary_wins > primary_wins:
                more_helpful_planner_mode = secondary_mode

            comparisons.append(
                {
                    "primary_planner_mode": primary_mode,
                    "secondary_planner_mode": secondary_mode,
                    "paired_scenario_count": paired_scenario_count,
                    "benchmark_pass_rate_delta": round(
                        benchmark_pass_delta_sum / paired_scenario_count, 4
                    ),
                    "fallback_rate_delta": round(
                        fallback_rate_delta_sum / paired_scenario_count, 4
                    ),
                    "average_expected_usefulness_delta": round(
                        expected_usefulness_delta_sum / paired_scenario_count, 4
                    ),
                    "primary_win_rate": round(primary_wins / paired_scenario_count, 4),
                    "secondary_win_rate": round(secondary_wins / paired_scenario_count, 4),
                    "tie_rate": round(ties / paired_scenario_count, 4),
                    "more_helpful_planner_mode": more_helpful_planner_mode,
                }
            )

    return comparisons


def compute_engine_comparisons(
    bundles: list[dict[str, Any]],
    benchmark_manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    benchmark_index = _benchmark_index(benchmark_manifest)
    benchmark_query_index = _benchmark_query_index(benchmark_manifest)
    grouped: dict[str, dict[str, dict[str, float]]] = {}
    for bundle in bundles:
        engine_mode = bundle.get("metadata", {}).get("engine_mode", "unknown")
        group_key = _paired_group_key(bundle, benchmark_index, benchmark_query_index)
        grouped.setdefault(group_key, {})
        metrics = grouped[group_key].setdefault(
            engine_mode,
            {
                "run_count": 0.0,
                "quality_score_sum": 0.0,
                "supported_count": 0.0,
                "source_unavailable_count": 0.0,
                "coverage_observed_sum": 0.0,
                "citation_quality_sum": 0.0,
            },
        )
        metrics["run_count"] += 1.0
        metrics["quality_score_sum"] += float(
            bundle.get("metadata", {}).get("quality_score", 0.0)
        )
        if bundle.get("metadata", {}).get("terminal_mode") == "SUPPORTED":
            metrics["supported_count"] += 1.0
        if bundle.get("metadata", {}).get("terminal_mode") == TERMINAL_MODE_SOURCE_UNAVAILABLE:
            metrics["source_unavailable_count"] += 1.0
        metrics["coverage_observed_sum"] += float(
            bundle.get("claim_map", {}).get("coverage_observed", 0.0)
        )
        metrics["citation_quality_sum"] += citation_quality(bundle.get("claim_map", {}))

    engines = sorted(
        {
            engine_mode
            for grouped_metrics in grouped.values()
            for engine_mode in grouped_metrics.keys()
        }
    )
    comparisons: list[dict[str, Any]] = []
    for primary_index, primary_engine in enumerate(engines):
        for secondary_engine in engines[primary_index + 1 :]:
            paired_query_count = 0
            primary_wins = 0
            secondary_wins = 0
            ties = 0
            quality_delta_sum = 0.0
            supported_rate_delta_sum = 0.0
            source_unavailable_rate_delta_sum = 0.0
            coverage_delta_sum = 0.0
            citation_delta_sum = 0.0

            for grouped_metrics in grouped.values():
                primary = grouped_metrics.get(primary_engine)
                secondary = grouped_metrics.get(secondary_engine)
                if not primary or not secondary:
                    continue

                paired_query_count += 1
                primary_quality = primary["quality_score_sum"] / primary["run_count"]
                secondary_quality = secondary["quality_score_sum"] / secondary["run_count"]
                quality_delta = primary_quality - secondary_quality
                quality_delta_sum += quality_delta
                supported_rate_delta_sum += (
                    primary["supported_count"] / primary["run_count"]
                    - secondary["supported_count"] / secondary["run_count"]
                )
                source_unavailable_rate_delta_sum += (
                    primary["source_unavailable_count"] / primary["run_count"]
                    - secondary["source_unavailable_count"] / secondary["run_count"]
                )
                coverage_delta_sum += (
                    primary["coverage_observed_sum"] / primary["run_count"]
                    - secondary["coverage_observed_sum"] / secondary["run_count"]
                )
                citation_delta_sum += (
                    primary["citation_quality_sum"] / primary["run_count"]
                    - secondary["citation_quality_sum"] / secondary["run_count"]
                )

                if quality_delta >= 0.01:
                    primary_wins += 1
                elif quality_delta <= -0.01:
                    secondary_wins += 1
                else:
                    ties += 1

            if paired_query_count == 0:
                continue

            average_quality_score_delta = round(quality_delta_sum / paired_query_count, 2)
            supported_rate_delta = round(supported_rate_delta_sum / paired_query_count, 4)
            source_unavailable_rate_delta = round(
                source_unavailable_rate_delta_sum / paired_query_count, 4
            )
            average_coverage_observed_delta = round(coverage_delta_sum / paired_query_count, 4)
            average_citation_quality_delta = round(citation_delta_sum / paired_query_count, 4)

            more_helpful_engine_mode = None
            if primary_wins > secondary_wins:
                more_helpful_engine_mode = primary_engine
            elif secondary_wins > primary_wins:
                more_helpful_engine_mode = secondary_engine
            elif abs(average_quality_score_delta) >= 0.01:
                more_helpful_engine_mode = (
                    primary_engine if average_quality_score_delta > 0 else secondary_engine
                )
            elif abs(supported_rate_delta) >= 0.0001:
                more_helpful_engine_mode = (
                    primary_engine if supported_rate_delta > 0 else secondary_engine
                )
            elif abs(source_unavailable_rate_delta) >= 0.0001:
                more_helpful_engine_mode = (
                    primary_engine
                    if source_unavailable_rate_delta < 0
                    else secondary_engine
                )
            elif abs(average_citation_quality_delta) >= 0.0001:
                more_helpful_engine_mode = (
                    primary_engine
                    if average_citation_quality_delta > 0
                    else secondary_engine
                )

            comparisons.append(
                {
                    "primary_engine_mode": primary_engine,
                    "secondary_engine_mode": secondary_engine,
                    "paired_query_count": paired_query_count,
                    "average_quality_score_delta": average_quality_score_delta,
                    "supported_rate_delta": supported_rate_delta,
                    "source_unavailable_rate_delta": source_unavailable_rate_delta,
                    "average_coverage_observed_delta": average_coverage_observed_delta,
                    "average_citation_quality_delta": average_citation_quality_delta,
                    "primary_win_rate": round(primary_wins / paired_query_count, 4),
                    "secondary_win_rate": round(secondary_wins / paired_query_count, 4),
                    "tie_rate": round(ties / paired_query_count, 4),
                    "more_helpful_engine_mode": more_helpful_engine_mode,
                }
            )

    return comparisons


def compute_scorecards(
    bundles: list[dict[str, Any]], benchmark_manifest: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for bundle in bundles:
        engine_mode = bundle.get("metadata", {}).get("engine_mode", "unknown")
        grouped.setdefault(engine_mode, []).append(bundle)

    benchmark_index = _benchmark_index(benchmark_manifest)
    scorecards: list[dict[str, Any]] = []
    for engine_mode in sorted(grouped.keys()):
        rows = grouped[engine_mode]
        run_count = len(rows)
        quality_scores = [
            float(row.get("metadata", {}).get("quality_score", 0.0)) for row in rows
        ]
        coverage = [float(row.get("claim_map", {}).get("coverage_observed", 0.0)) for row in rows]
        citation_scores = [citation_quality(row.get("claim_map", {})) for row in rows]
        response_kinds = [response_kind(row) for row in rows]

        supported = 0
        source_unavailable = 0
        for row in rows:
            terminal_mode = row.get("metadata", {}).get("terminal_mode")
            if terminal_mode == "SUPPORTED":
                supported += 1
            if terminal_mode == TERMINAL_MODE_SOURCE_UNAVAILABLE:
                source_unavailable += 1

        benchmark_rows = [
            row
            for row in rows
            if row.get("metadata", {}).get("run_id") in benchmark_index
        ]
        benchmark_passes = 0
        for row in benchmark_rows:
            scenario = benchmark_index[row.get("metadata", {}).get("run_id")]
            if benchmark_pass(row, scenario):
                benchmark_passes += 1

        ambiguity_rate = sum(1 for kind in response_kinds if kind == "ambiguous") / run_count
        partial_answer_rate = (
            sum(1 for kind in response_kinds if kind == "partial_answer") / run_count
        )
        refusal_friction_rate = (
            sum(
                1
                for row, kind in zip(rows, response_kinds)
                if row.get("metadata", {}).get("terminal_mode") != "SUPPORTED"
                and kind != "ambiguous"
            )
            / run_count
        )

        scorecards.append(
            {
                "engine_mode": engine_mode,
                "run_count": run_count,
                "average_quality_score": round(sum(quality_scores) / run_count, 2),
                "minimum_quality_score": round(min(quality_scores), 2),
                "maximum_quality_score": round(max(quality_scores), 2),
                "supported_rate": round(supported / run_count, 4),
                "source_unavailable_rate": round(source_unavailable / run_count, 4),
                "ambiguity_rate": round(ambiguity_rate, 4),
                "partial_answer_rate": round(partial_answer_rate, 4),
                "refusal_friction_rate": round(refusal_friction_rate, 4),
                "average_coverage_observed": round(sum(coverage) / run_count, 4),
                "average_citation_quality": round(sum(citation_scores) / run_count, 4),
                "benchmark_coverage_rate": round(len(benchmark_rows) / run_count, 4),
                "benchmark_pass_rate": round(
                    0.0 if not benchmark_rows else benchmark_passes / len(benchmark_rows), 4
                ),
            }
        )

    return scorecards
