#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from replay_lib import (
    benchmark_pass,
    citation_quality,
    compute_engine_comparisons,
    compute_planner_comparisons,
    compute_planner_scorecards,
    compute_scorecards,
    load_json,
    load_replay_bundles,
    planner_rows,
    reconstruct_outcome,
    response_kind,
    source_unavailable_rate,
)


def principal_hash(principal_id: str) -> str:
    payload = json.dumps({"principal_id": principal_id}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def load_benchmark_manifest_if_present(store: Path) -> dict[str, Any] | None:
    manifest_path = store / "benchmark_manifest.json"
    if not manifest_path.exists():
        return None
    return load_json(manifest_path)


def cmd_list(args: argparse.Namespace) -> int:
    bundles = load_replay_bundles(Path(args.store), engine_mode=args.engine_mode)
    if args.limit is not None:
        bundles = bundles[: args.limit]
    metadata = [bundle.get("metadata", {}) for bundle in bundles]
    print_json({"replays": metadata})
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    bundles = load_replay_bundles(Path(args.store), replay_ids={args.run_id})
    if not bundles:
        raise SystemExit(f"replay run not found: {args.run_id}")
    print_json(reconstruct_outcome(bundles[0]))
    return 0


def cmd_scorecards(args: argparse.Namespace) -> int:
    store = Path(args.store)
    bundles = load_replay_bundles(store, engine_mode=args.engine_mode)
    if args.limit is not None:
        bundles = bundles[: args.limit]
    print_json(
        {
            "scorecards": compute_scorecards(
                bundles, load_benchmark_manifest_if_present(store)
            ),
            "engine_comparisons": compute_engine_comparisons(
                bundles, load_benchmark_manifest_if_present(store)
            ),
            "planner_scorecards": compute_planner_scorecards(
                bundles, load_benchmark_manifest_if_present(store)
            ),
            "planner_comparisons": compute_planner_comparisons(
                bundles, load_benchmark_manifest_if_present(store)
            ),
        }
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    requested_ids = set(args.run_ids or [])
    store = Path(args.store)
    benchmark_manifest = load_benchmark_manifest_if_present(store)
    benchmark_index = {
        scenario["run_id"]: scenario
        for scenario in (benchmark_manifest or {}).get("scenarios", [])
        if scenario.get("run_id")
    }
    bundles = load_replay_bundles(store, engine_mode=args.engine_mode, replay_ids=requested_ids or None)
    if args.limit is not None:
        bundles = bundles[: args.limit]

    found_ids = {
        bundle.get("metadata", {}).get("run_id")
        for bundle in bundles
        if bundle.get("metadata", {}).get("run_id")
    }
    missing = sorted(requested_ids - found_ids) if requested_ids else []

    min_quality_score = float(args.min_quality_score)
    max_source_unavailable = float(args.max_source_unavailable_rate)
    failed_quality = [
        bundle.get("metadata", {}).get("run_id")
        for bundle in bundles
        if float(bundle.get("metadata", {}).get("quality_score", 0.0)) < min_quality_score
    ]
    su_rate = source_unavailable_rate(bundles)
    overall_pass = not failed_quality and not missing and su_rate <= max_source_unavailable

    evaluation = {
        "evaluation_id": str(uuid.uuid4()),
        "evaluation_name": args.name,
        "principal_id_hash": principal_hash(args.principal_id),
        "created_at_unix_ms": int(time.time() * 1000),
        "replay_ids": [bundle.get("metadata", {}).get("run_id") for bundle in bundles],
        "missing_replay_ids": missing,
        "run_results": [
            {
                "run_id": bundle.get("metadata", {}).get("run_id"),
                "trace_id": bundle.get("metadata", {}).get("trace_id"),
                "engine_mode": bundle.get("metadata", {}).get("engine_mode"),
                "terminal_mode": bundle.get("metadata", {}).get("terminal_mode"),
                "quality_score": bundle.get("metadata", {}).get("quality_score"),
                "coverage_observed": bundle.get("claim_map", {}).get("coverage_observed"),
                "citation_quality": citation_quality(bundle.get("claim_map", {})),
                "response_kind": response_kind(bundle),
                "benchmark_scenario_id": benchmark_index.get(
                    bundle.get("metadata", {}).get("run_id"), {}
                ).get("scenario_id"),
                "benchmark_pass": (
                    None
                    if bundle.get("metadata", {}).get("run_id") not in benchmark_index
                    else benchmark_pass(
                        bundle,
                        benchmark_index[bundle.get("metadata", {}).get("run_id")],
                    )
                ),
            }
            for bundle in bundles
        ],
        "scorecards": compute_scorecards(bundles, benchmark_manifest),
        "engine_comparisons": compute_engine_comparisons(bundles, benchmark_manifest),
        "planner_rows": planner_rows(bundles, benchmark_manifest),
        "planner_scorecards": compute_planner_scorecards(bundles, benchmark_manifest),
        "planner_comparisons": compute_planner_comparisons(bundles, benchmark_manifest),
        "overall_pass": overall_pass,
    }
    print_json(evaluation)

    if args.persist:
        evaluations_dir = Path(args.store) / "evaluations"
        evaluations_dir.mkdir(parents=True, exist_ok=True)
        path = evaluations_dir / f"{evaluation['evaluation_id']}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(evaluation, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"saved evaluation: {path}", file=sys.stderr)

    return 0 if overall_pass else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local replay/eval developer commands for persisted controller bundles."
    )
    parser.add_argument("--store", default="target/replay", help="Replay store root directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List replay metadata")
    p_list.add_argument("--engine-mode", choices=["baseline", "beam_planner", "rlm"])
    p_list.add_argument("--limit", type=int)
    p_list.set_defaults(func=cmd_list)

    p_replay = sub.add_parser("replay", help="Reconstruct run outcome from a replay bundle")
    p_replay.add_argument("--run-id", required=True)
    p_replay.set_defaults(func=cmd_replay)

    p_scorecards = sub.add_parser("scorecards", help="Compute run quality scorecards by engine mode")
    p_scorecards.add_argument("--engine-mode", choices=["baseline", "beam_planner", "rlm"])
    p_scorecards.add_argument("--limit", type=int)
    p_scorecards.set_defaults(func=cmd_scorecards)

    p_eval = sub.add_parser("evaluate", help="Submit a local replay evaluation")
    p_eval.add_argument("--name", required=True, help="Evaluation name")
    p_eval.add_argument("--principal-id", default="dev")
    p_eval.add_argument("--run-id", dest="run_ids", action="append")
    p_eval.add_argument("--engine-mode", choices=["baseline", "beam_planner", "rlm"])
    p_eval.add_argument("--limit", type=int)
    p_eval.add_argument("--min-quality-score", type=float, default=0.0)
    p_eval.add_argument("--max-source-unavailable-rate", type=float, default=1.0)
    p_eval.add_argument("--persist", action="store_true")
    p_eval.set_defaults(func=cmd_evaluate)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
