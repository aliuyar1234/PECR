#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from replay_lib import (
    compute_engine_comparisons,
    compute_planner_comparisons,
    compute_planner_scorecards,
    compute_scorecards,
    load_json,
    load_replay_bundles,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORE = ROOT / "target" / "replay"
DEFAULT_BENCHMARK_MANIFEST = ROOT / "fixtures" / "replay" / "useful_tasks" / "benchmark_manifest.json"


def build_report(
    store: Path,
    benchmark_manifest_path: Path,
    evaluation_name: str,
    engine_mode: str | None,
) -> dict[str, Any]:
    benchmark_manifest = load_json(benchmark_manifest_path)
    bundles = load_replay_bundles(store, engine_mode=engine_mode)
    scorecards = compute_scorecards(bundles, benchmark_manifest)
    comparisons = compute_engine_comparisons(bundles, benchmark_manifest)
    planner_scorecards = compute_planner_scorecards(bundles, benchmark_manifest)
    planner_comparisons = compute_planner_comparisons(bundles, benchmark_manifest)
    return {
        "evaluation_name": evaluation_name,
        "generated_at_unix_ms": int(time.time() * 1000),
        "engine_mode": engine_mode,
        "run_count": len(bundles),
        "benchmark_name": benchmark_manifest.get("benchmark_name"),
        "scenario_count": len(benchmark_manifest.get("scenarios", [])),
        "scorecards": scorecards,
        "engine_comparisons": comparisons,
        "planner_scorecards": planner_scorecards,
        "planner_comparisons": planner_comparisons,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['evaluation_name']}",
        "",
        f"- Generated at: `{report['generated_at_unix_ms']}`",
        f"- Benchmark: `{report['benchmark_name']}`",
        f"- Scenario count: `{report['scenario_count']}`",
        f"- Replay count: `{report['run_count']}`",
    ]
    if report.get("engine_mode"):
        lines.append(f"- Engine filter: `{report['engine_mode']}`")

    lines.extend(
        [
            "",
            "## Scorecards",
            "",
            "| Engine | Runs | Benchmark pass | Supported | Ambiguous | Partial answer | Refusal friction |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for scorecard in report.get("scorecards", []):
        lines.append(
            "| {engine} | {runs} | {benchmark:.4f} | {supported:.4f} | {ambiguous:.4f} | {partial:.4f} | {friction:.4f} |".format(
                engine=scorecard.get("engine_mode"),
                runs=scorecard.get("run_count"),
                benchmark=scorecard.get("benchmark_pass_rate", 0.0),
                supported=scorecard.get("supported_rate", 0.0),
                ambiguous=scorecard.get("ambiguity_rate", 0.0),
                partial=scorecard.get("partial_answer_rate", 0.0),
                friction=scorecard.get("refusal_friction_rate", 0.0),
            )
        )

    if report.get("planner_scorecards"):
        lines.extend(
            [
                "",
                "## Planner Scorecards",
                "",
                "| Planner mode | Scenarios | Coverage | Planner benchmark pass | Fallback | Selected for execution |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for scorecard in report["planner_scorecards"]:
            lines.append(
                "| {planner_mode} | {scenario_count} | {coverage:.4f} | {benchmark:.4f} | {fallback:.4f} | {selected:.4f} |".format(
                    planner_mode=scorecard.get("planner_mode"),
                    scenario_count=scorecard.get("scenario_count"),
                    coverage=scorecard.get("scenario_coverage_rate", 0.0),
                    benchmark=scorecard.get("benchmark_pass_rate", 0.0),
                    fallback=scorecard.get("fallback_rate", 0.0),
                    selected=scorecard.get("selected_for_execution_rate", 0.0),
                )
            )

    if report.get("engine_comparisons"):
        lines.extend(
            [
                "",
                "## Engine Comparisons",
                "",
                "| Primary | Secondary | Paired queries | Quality delta | More helpful |",
                "|---|---|---:|---:|---|",
            ]
        )
        for comparison in report["engine_comparisons"]:
            lines.append(
                "| {primary} | {secondary} | {pairs} | {delta:.2f} | {winner} |".format(
                    primary=comparison.get("primary_engine_mode"),
                    secondary=comparison.get("secondary_engine_mode"),
                    pairs=comparison.get("paired_query_count"),
                    delta=comparison.get("average_quality_score_delta", 0.0),
                    winner=comparison.get("more_helpful_engine_mode") or "tie",
                )
            )

    if report.get("planner_comparisons"):
        lines.extend(
            [
                "",
                "## Planner Comparisons",
                "",
                "| Primary | Secondary | Paired scenarios | Planner benchmark delta | More helpful |",
                "|---|---|---:|---:|---|",
            ]
        )
        for comparison in report["planner_comparisons"]:
            lines.append(
                "| {primary} | {secondary} | {pairs} | {delta:.4f} | {winner} |".format(
                    primary=comparison.get("primary_planner_mode"),
                    secondary=comparison.get("secondary_planner_mode"),
                    pairs=comparison.get("paired_scenario_count"),
                    delta=comparison.get("benchmark_pass_rate_delta", 0.0),
                    winner=comparison.get("more_helpful_planner_mode") or "tie",
                )
            )

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate nightly usefulness report artifacts.")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE)
    parser.add_argument(
        "--benchmark-manifest",
        type=Path,
        default=DEFAULT_BENCHMARK_MANIFEST,
    )
    parser.add_argument("--evaluation-name", required=True)
    parser.add_argument("--engine-mode", choices=["baseline", "beam_planner", "rlm"])
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-md", type=Path)
    args = parser.parse_args(argv)

    report = build_report(
        store=args.store,
        benchmark_manifest_path=args.benchmark_manifest,
        evaluation_name=args.evaluation_name,
        engine_mode=args.engine_mode,
    )

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(render_markdown(report), encoding="utf-8")
    elif not args.output_json:
        print(render_markdown(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
