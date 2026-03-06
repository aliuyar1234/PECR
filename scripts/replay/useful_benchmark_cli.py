#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORE = ROOT / "fixtures" / "replay" / "useful_tasks"

from replay_lib import (  # noqa: E402
    compute_planner_comparisons,
    compute_planner_scorecards,
    load_json,
    load_replay_bundles,
    max_supported_claim_evidence_units,
    planner_rows,
)


def load_manifest(store_dir: Path) -> dict[str, Any]:
    return load_json(store_dir / "benchmark_manifest.json")


def observed_response_kind(replay: dict[str, Any]) -> str | None:
    claim_map = replay.get("claim_map", {})
    notes = str(claim_map.get("notes") or "")
    if "Partial answer:" in notes:
        return "partial_answer"

    terminal_mode = replay.get("metadata", {}).get("terminal_mode")
    response_text = str(replay.get("response_text") or "").lower()
    if terminal_mode == "INSUFFICIENT_EVIDENCE" and (
        "underspecified" in response_text
        or "too broad" in response_text
        or "specify which document or policy" in response_text
        or "safe scopes for the current principal" in response_text
    ):
        return "ambiguous"

    return None


def scenario_rows(store_dir: Path) -> list[dict[str, Any]]:
    manifest = load_manifest(store_dir)
    rows = []
    for scenario in manifest.get("scenarios", []):
        replay_path = store_dir / scenario["replay_path"]
        replay = load_json(replay_path)
        metadata = replay.get("metadata", {})
        rows.append(
            {
                "scenario_id": scenario["scenario_id"],
                "title": scenario["title"],
                "category": scenario["category"],
                "job": scenario["job"],
                "query": scenario["query"],
                "run_id": scenario["run_id"],
                "replay_path": scenario["replay_path"],
                "expected_terminal_mode": scenario["expected_terminal_mode"],
                "expected_response_kind": scenario.get("expected_response_kind"),
                "minimum_quality_score": scenario["minimum_quality_score"],
                "minimum_supported_claim_evidence_units": scenario.get(
                    "minimum_supported_claim_evidence_units"
                ),
                "actual_terminal_mode": metadata.get("terminal_mode"),
                "actual_response_kind": observed_response_kind(replay),
                "actual_quality_score": metadata.get("quality_score"),
                "actual_max_supported_claim_evidence_units": max_supported_claim_evidence_units(
                    replay
                ),
            }
        )
    return rows


def validate_manifest(store_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(store_dir)
    scenarios = manifest.get("scenarios", [])
    errors: list[str] = []
    categories: dict[str, int] = {}

    for scenario in scenarios:
        categories[scenario["category"]] = categories.get(scenario["category"], 0) + 1
        replay_path = store_dir / scenario["replay_path"]
        if not replay_path.exists():
            errors.append(f"missing replay fixture: {scenario['replay_path']}")
            continue

        replay = load_json(replay_path)
        metadata = replay.get("metadata", {})
        if metadata.get("run_id") != scenario["run_id"]:
            errors.append(
                f"{scenario['scenario_id']}: run_id mismatch ({metadata.get('run_id')} != {scenario['run_id']})"
            )
        if replay.get("query") != scenario["query"]:
            errors.append(f"{scenario['scenario_id']}: query mismatch")
        if metadata.get("terminal_mode") != scenario["expected_terminal_mode"]:
            errors.append(
                f"{scenario['scenario_id']}: terminal_mode mismatch ({metadata.get('terminal_mode')} != {scenario['expected_terminal_mode']})"
            )
        expected_response_kind = scenario.get("expected_response_kind")
        if expected_response_kind is not None:
            actual_response_kind = observed_response_kind(replay)
            if actual_response_kind != expected_response_kind:
                errors.append(
                    f"{scenario['scenario_id']}: response_kind mismatch ({actual_response_kind} != {expected_response_kind})"
                )

        quality_score = float(metadata.get("quality_score", 0.0))
        if quality_score < float(scenario["minimum_quality_score"]):
            errors.append(
                f"{scenario['scenario_id']}: quality_score {quality_score} < {scenario['minimum_quality_score']}"
            )
        response_text = str(replay.get("response_text") or "")
        if not response_text:
            errors.append(f"{scenario['scenario_id']}: response_text missing")
        for substring in scenario.get("expected_response_substrings", []):
            if substring not in response_text:
                errors.append(
                    f"{scenario['scenario_id']}: response_text missing substring {substring!r}"
                )
        notes = str(replay.get("claim_map", {}).get("notes") or "")
        for substring in scenario.get("expected_note_substrings", []):
            if substring not in notes:
                errors.append(
                    f"{scenario['scenario_id']}: claim_map.notes missing substring {substring!r}"
                )
        minimum_supported_claim_evidence_units = int(
            scenario.get("minimum_supported_claim_evidence_units", 0)
        )
        if minimum_supported_claim_evidence_units > 0:
            actual_max_supported_claim_evidence_units = max_supported_claim_evidence_units(
                replay
            )
            if (
                actual_max_supported_claim_evidence_units
                < minimum_supported_claim_evidence_units
            ):
                errors.append(
                    f"{scenario['scenario_id']}: max supported claim evidence units "
                    f"{actual_max_supported_claim_evidence_units} < "
                    f"{minimum_supported_claim_evidence_units}"
                )

    return {
        "benchmark_name": manifest.get("benchmark_name"),
        "scenario_count": len(scenarios),
        "categories": categories,
        "errors": errors,
        "ok": not errors,
    }


def compare_planners(store_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(store_dir)
    bundles = load_replay_bundles(store_dir)
    rows = planner_rows(bundles, manifest)
    return {
        "benchmark_name": manifest.get("benchmark_name"),
        "planner_rows": rows,
        "planner_scorecards": compute_planner_scorecards(bundles, manifest),
        "planner_comparisons": compute_planner_comparisons(bundles, manifest),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect PECR useful-answer benchmark fixtures.")
    parser.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE,
        help="benchmark store directory (default: fixtures/replay/useful_tasks)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="list benchmark scenarios as JSON")
    subparsers.add_parser("validate", help="validate manifest-to-replay alignment")
    subparsers.add_parser(
        "planner-compare",
        help="compare baseline, rlm, and beam shadow planner traces against benchmark expectations",
    )
    args = parser.parse_args(argv)

    if args.command == "list":
        payload = {
            "benchmark_name": load_manifest(args.store).get("benchmark_name"),
            "scenarios": scenario_rows(args.store),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "planner-compare":
        payload = compare_planners(args.store)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    payload = validate_manifest(args.store)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
