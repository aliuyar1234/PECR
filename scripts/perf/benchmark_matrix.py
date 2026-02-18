#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}")


def parse_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")


def get_metric_value(summary: dict, metric: str, key: str) -> float:
    metrics = summary.get("metrics")
    if not isinstance(metrics, dict):
        raise SystemExit("k6 summary JSON missing metrics object")
    metric_values = metrics.get(metric)
    if not isinstance(metric_values, dict):
        raise SystemExit(f"k6 summary JSON missing metric {metric!r}")
    value = metric_values.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    raise SystemExit(f"k6 summary metric {metric!r} missing key {key!r}")


def get_optional_metric_value(summary: dict, metric: str, key: str) -> float | None:
    metrics = summary.get("metrics")
    if not isinstance(metrics, dict):
        return None
    metric_values = metrics.get(metric)
    if not isinstance(metric_values, dict):
        return None
    value = metric_values.get(key)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def allowed_ms(baseline_ms: float, factor: float, abs_ms: float) -> float:
    return max(baseline_ms * factor, baseline_ms + abs_ms)


def parse_candidate(raw: str) -> tuple[str, Path]:
    if "=" not in raw:
        raise SystemExit(f"invalid --candidate {raw!r}; expected label=path")
    label, path = raw.split("=", 1)
    label = label.strip()
    path = path.strip()
    if not label or not path:
        raise SystemExit(f"invalid --candidate {raw!r}; expected non-empty label and path")
    return label, Path(path)


def fmt_ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def pct_delta(current: float | None, baseline: float | None) -> float | None:
    if current is None or baseline is None:
        return None
    if abs(baseline) < 1e-12:
        return None
    return ((current - baseline) / baseline) * 100.0


def fmt_delta(value: float | None, *, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    return f"{value:+.2f}{suffix}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build baseline-vs-candidate benchmark matrix.")
    parser.add_argument(
        "--baseline",
        default="perf/baselines/suite7_baseline.summary.json",
        help="Reference baseline k6 summary JSON.",
    )
    parser.add_argument(
        "--candidate",
        action="append",
        required=True,
        help="Candidate summary in label=path form. Pass multiple times.",
    )
    parser.add_argument(
        "--output-json",
        default="target/perf/benchmark_matrix.json",
        help="Output JSON artifact path.",
    )
    parser.add_argument(
        "--output-md",
        default="target/perf/benchmark_matrix.md",
        help="Output markdown artifact path.",
    )
    parser.add_argument(
        "--append-step-summary",
        default="",
        help="Optional GitHub step summary file to append the markdown matrix.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero when any candidate fails latency/throughput gates.",
    )
    args = parser.parse_args()

    baseline = load_json(Path(args.baseline))
    base_p95 = get_metric_value(baseline, "http_req_duration", "p(95)")
    base_p99 = get_metric_value(baseline, "http_req_duration", "p(99)")
    base_rate = get_optional_metric_value(baseline, "http_reqs", "rate")

    p95_factor = parse_float_env("PECR_PERF_REGRESSION_P95_FACTOR", 1.8)
    p99_factor = parse_float_env("PECR_PERF_REGRESSION_P99_FACTOR", 1.8)
    abs_ms = parse_float_env("PECR_PERF_REGRESSION_ABS_MS", 400.0)
    min_rate_factor = parse_float_env("PECR_PERF_MIN_RATE_FACTOR", 0.85)
    rate_abs_drop = parse_float_env("PECR_PERF_RATE_ABS_DROP", 5.0)

    allow_p95 = allowed_ms(base_p95, p95_factor, abs_ms)
    allow_p99 = allowed_ms(base_p99, p99_factor, abs_ms)
    min_rate = None
    if base_rate is not None:
        min_rate = max(base_rate * min_rate_factor, base_rate - rate_abs_drop)

    rows: list[dict] = []
    failed = False

    for raw_candidate in args.candidate:
        label, path = parse_candidate(raw_candidate)
        row: dict[str, object] = {
            "label": label,
            "path": str(path),
            "status": "PASS",
            "missing": False,
            "checks": {},
        }
        if not path.exists():
            row["status"] = "MISSING"
            row["missing"] = True
            row["checks"] = {
                "p95_ok": False,
                "p99_ok": False,
                "rate_ok": False if min_rate is not None else True,
            }
            row["metrics"] = {"p95_ms": None, "p99_ms": None, "rate": None}
            rows.append(row)
            failed = True
            continue

        current = load_json(path)
        cur_p95 = get_metric_value(current, "http_req_duration", "p(95)")
        cur_p99 = get_metric_value(current, "http_req_duration", "p(99)")
        cur_rate = get_optional_metric_value(current, "http_reqs", "rate")

        p95_ok = cur_p95 <= allow_p95
        p99_ok = cur_p99 <= allow_p99
        if min_rate is None or cur_rate is None:
            rate_ok = True
        else:
            rate_ok = cur_rate >= min_rate

        status = "PASS" if (p95_ok and p99_ok and rate_ok) else "FAIL"
        row["status"] = status
        row["checks"] = {"p95_ok": p95_ok, "p99_ok": p99_ok, "rate_ok": rate_ok}
        row["metrics"] = {"p95_ms": cur_p95, "p99_ms": cur_p99, "rate": cur_rate}
        row["deltas"] = {
            "p95_ms": cur_p95 - base_p95,
            "p99_ms": cur_p99 - base_p99,
            "rate": None if (cur_rate is None or base_rate is None) else cur_rate - base_rate,
            "p95_pct": pct_delta(cur_p95, base_p95),
            "p99_pct": pct_delta(cur_p99, base_p99),
            "rate_pct": pct_delta(cur_rate, base_rate),
        }
        rows.append(row)
        if status != "PASS":
            failed = True

    matrix = {
        "baseline_file": args.baseline,
        "baseline_metrics": {"p95_ms": base_p95, "p99_ms": base_p99, "rate": base_rate},
        "thresholds": {
            "allow_p95_ms": allow_p95,
            "allow_p99_ms": allow_p99,
            "min_rate": min_rate,
            "p95_factor": p95_factor,
            "p99_factor": p99_factor,
            "abs_ms": abs_ms,
            "min_rate_factor": min_rate_factor,
            "rate_abs_drop": rate_abs_drop,
        },
        "rows": rows,
    }

    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")

    md_lines = [
        "### Baseline vs RLM Benchmark Matrix",
        "",
        f"- Baseline file: `{args.baseline}`",
        f"- Thresholds: `p95<={allow_p95:.3f}ms`, `p99<={allow_p99:.3f}ms`"
        + (f", `rate>={min_rate:.3f} req/s`" if min_rate is not None else ""),
        "",
        "| Scenario | Summary | p95 (ms) | p99 (ms) | Rate (req/s) | p95 delta | p99 delta | Rate delta | Gate |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]

    for row in rows:
        metrics = row.get("metrics", {})
        deltas = row.get("deltas", {})
        p95_ms = metrics.get("p95_ms") if isinstance(metrics, dict) else None
        p99_ms = metrics.get("p99_ms") if isinstance(metrics, dict) else None
        rate = metrics.get("rate") if isinstance(metrics, dict) else None
        p95_pct = deltas.get("p95_pct") if isinstance(deltas, dict) else None
        p99_pct = deltas.get("p99_pct") if isinstance(deltas, dict) else None
        rate_pct = deltas.get("rate_pct") if isinstance(deltas, dict) else None
        md_lines.append(
            "| "
            f"{row['label']} | `{row['path']}` | "
            f"{fmt_ms(p95_ms)} | {fmt_ms(p99_ms)} | {fmt_rate(rate)} | "
            f"{fmt_delta(p95_pct, suffix='%')} | {fmt_delta(p99_pct, suffix='%')} | {fmt_delta(rate_pct, suffix='%')} | "
            f"{row['status']} |"
        )

    md_lines.append("")
    if failed:
        md_lines.append("- Result: at least one scenario failed/missing against regression thresholds.")
    else:
        md_lines.append("- Result: all scenarios passed regression thresholds.")

    markdown = "\n".join(md_lines) + "\n"
    output_md = Path(args.output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(markdown, encoding="utf-8")

    print(markdown, end="")

    if args.append_step_summary.strip():
        summary_path = Path(args.append_step_summary)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(markdown)

    if args.strict and failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
