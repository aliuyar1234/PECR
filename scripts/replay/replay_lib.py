#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


TERMINAL_MODE_SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


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


def compute_scorecards(bundles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for bundle in bundles:
        engine_mode = bundle.get("metadata", {}).get("engine_mode", "unknown")
        grouped.setdefault(engine_mode, []).append(bundle)

    scorecards: list[dict[str, Any]] = []
    for engine_mode in sorted(grouped.keys()):
        rows = grouped[engine_mode]
        run_count = len(rows)
        quality_scores = [
            float(row.get("metadata", {}).get("quality_score", 0.0)) for row in rows
        ]
        coverage = [float(row.get("claim_map", {}).get("coverage_observed", 0.0)) for row in rows]

        supported = 0
        source_unavailable = 0
        for row in rows:
            terminal_mode = row.get("metadata", {}).get("terminal_mode")
            if terminal_mode == "SUPPORTED":
                supported += 1
            if terminal_mode == TERMINAL_MODE_SOURCE_UNAVAILABLE:
                source_unavailable += 1

        scorecards.append(
            {
                "engine_mode": engine_mode,
                "run_count": run_count,
                "average_quality_score": round(sum(quality_scores) / run_count, 2),
                "minimum_quality_score": round(min(quality_scores), 2),
                "maximum_quality_score": round(max(quality_scores), 2),
                "supported_rate": round(supported / run_count, 4),
                "source_unavailable_rate": round(source_unavailable / run_count, 4),
                "average_coverage_observed": round(sum(coverage) / run_count, 4),
            }
        )

    return scorecards
