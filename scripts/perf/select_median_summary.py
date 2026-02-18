#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


def parse_metric(raw: str) -> tuple[str, str]:
    if ":" not in raw:
        raise SystemExit(f"invalid --metric {raw!r}; expected metric:key form")
    metric, key = raw.split(":", 1)
    metric = metric.strip()
    key = key.strip()
    if not metric or not key:
        raise SystemExit(f"invalid --metric {raw!r}; expected non-empty metric and key")
    return metric, key


def load_metric(path: Path, metric: str, key: str) -> float:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing summary file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid json in {path}: {exc}")

    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise SystemExit(f"{path}: missing metrics object")
    values = metrics.get(metric)
    if not isinstance(values, dict):
        raise SystemExit(f"{path}: missing metric {metric!r}")
    value = values.get(key)
    if not isinstance(value, (int, float)):
        raise SystemExit(f"{path}: missing numeric key {key!r} in metric {metric!r}")
    return float(value)


def select_median_candidate(candidates: list[tuple[Path, float]]) -> tuple[Path, float]:
    sorted_candidates = sorted(candidates, key=lambda item: item[1])
    values = [item[1] for item in sorted_candidates]
    middle = len(values) // 2
    if len(values) % 2 == 1:
        return sorted_candidates[middle]

    median_value = (values[middle - 1] + values[middle]) / 2.0
    selected = min(sorted_candidates, key=lambda item: (abs(item[1] - median_value), item[1], item[0].name))
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Select median k6 summary from multiple runs.")
    parser.add_argument(
        "--metric",
        default="http_req_duration:p(95)",
        help="Metric and key used for median selection (default: %(default)s).",
    )
    parser.add_argument("--output", required=True, help="Output summary path.")
    parser.add_argument(
        "--metadata-json",
        default="",
        help="Optional metadata artifact path describing candidate metrics and selected run.",
    )
    parser.add_argument("inputs", nargs="+", help="Input k6 summary JSON paths.")
    args = parser.parse_args()

    if len(args.inputs) < 1:
        raise SystemExit("at least one input summary is required")

    metric, key = parse_metric(args.metric)

    candidates: list[tuple[Path, float]] = []
    for raw in args.inputs:
        path = Path(raw)
        value = load_metric(path, metric, key)
        candidates.append((path, value))

    selected_path, selected_value = select_median_candidate(candidates)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(selected_path, output_path)

    metadata = {
        "metric": metric,
        "key": key,
        "selected_path": str(selected_path),
        "selected_value": selected_value,
        "output_path": str(output_path),
        "candidates": [{"path": str(path), "value": value} for path, value in candidates],
        "strategy": "median-by-metric",
    }

    if args.metadata_json.strip():
        metadata_path = Path(args.metadata_json)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(
        f"selected median summary: {selected_path} "
        f"({metric}:{key}={selected_value:.6f}) -> {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

