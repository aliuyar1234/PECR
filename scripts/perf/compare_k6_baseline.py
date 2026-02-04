#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing file: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"invalid JSON in {path}: {e}")


def get_metric_value(summary: dict, metric: str, key: str) -> float:
    metrics = summary.get("metrics")
    if not isinstance(metrics, dict):
        raise SystemExit("k6 summary JSON missing metrics object")

    m = metrics.get(metric)
    if not isinstance(m, dict):
        raise SystemExit(f"k6 summary JSON missing metric {metric!r}")

    v = m.get(key)
    if isinstance(v, (int, float)):
        return float(v)

    available = ", ".join(sorted(m.keys()))
    raise SystemExit(
        f"k6 summary metric {metric!r} missing key {key!r}. "
        f"Available: {available}. "
        "Hint: ensure k6 runs with --summary-trend-stats including p(99)."
    )


def parse_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")


def allowed_ms(baseline_ms: float, factor: float, abs_ms: float) -> float:
    return max(baseline_ms * factor, baseline_ms + abs_ms)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare k6 summary metrics to baseline.")
    parser.add_argument(
        "--baseline",
        default="perf/baselines/suite7_baseline.summary.json",
        help="Baseline k6 --summary-export JSON path (default: %(default)s)",
    )
    parser.add_argument(
        "--current",
        default="target/perf/suite7_baseline.summary.json",
        help="Current k6 --summary-export JSON path (default: %(default)s)",
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    current_path = Path(args.current)

    baseline = load_json(baseline_path)
    current = load_json(current_path)

    p95_factor = parse_float_env("PECR_PERF_REGRESSION_P95_FACTOR", 3.0)
    p99_factor = parse_float_env("PECR_PERF_REGRESSION_P99_FACTOR", 3.0)
    abs_ms = parse_float_env("PECR_PERF_REGRESSION_ABS_MS", 1000.0)

    metric = "http_req_duration"
    base_p95 = get_metric_value(baseline, metric, "p(95)")
    base_p99 = get_metric_value(baseline, metric, "p(99)")
    cur_p95 = get_metric_value(current, metric, "p(95)")
    cur_p99 = get_metric_value(current, metric, "p(99)")

    allow_p95 = allowed_ms(base_p95, p95_factor, abs_ms)
    allow_p99 = allowed_ms(base_p99, p99_factor, abs_ms)

    ok_p95 = cur_p95 <= allow_p95
    ok_p99 = cur_p99 <= allow_p99

    print(f"baseline: p95={base_p95:.3f}ms p99={base_p99:.3f}ms ({baseline_path})")
    print(f"current:  p95={cur_p95:.3f}ms p99={cur_p99:.3f}ms ({current_path})")
    print(
        f"tolerance: p95<=max(baseline*{p95_factor}, baseline+{abs_ms}ms) => {allow_p95:.3f}ms; "
        f"p99<=max(baseline*{p99_factor}, baseline+{abs_ms}ms) => {allow_p99:.3f}ms"
    )

    if ok_p95 and ok_p99:
        print("perf regression gate: PASS")
        return 0

    print("perf regression gate: FAIL")
    if not ok_p95:
        print(f"- p95 regressed: {cur_p95:.3f}ms > {allow_p95:.3f}ms")
    if not ok_p99:
        print(f"- p99 regressed: {cur_p99:.3f}ms > {allow_p99:.3f}ms")

    print(
        "If this regression is acceptable, update the baseline and record an explicit decision "
        "with mitigation (see SSOT CONSTITUTION exception process)."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

