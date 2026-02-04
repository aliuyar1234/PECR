#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Sample:
    name: str
    labels: dict[str, str]
    value: float


LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\\\.|[^"\\\\])*)"')


def unescape_label_value(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\" or i + 1 >= len(raw):
            out.append(ch)
            i += 1
            continue

        nxt = raw[i + 1]
        if nxt == "n":
            out.append("\n")
        elif nxt == "\\":
            out.append("\\")
        elif nxt == '"':
            out.append('"')
        else:
            out.append(nxt)
        i += 2
    return "".join(out)


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"missing file: {path}")


def parse_prometheus_text(text: str) -> list[Sample]:
    samples: list[Sample] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        metric = parts[0]
        value_raw = parts[1]
        try:
            value = float(value_raw)
        except ValueError:
            continue

        if "{" in metric and metric.endswith("}"):
            name, labels_raw = metric.split("{", 1)
            labels_raw = labels_raw[:-1]  # trim trailing "}"
            labels: dict[str, str] = {}
            for m in LABEL_RE.finditer(labels_raw):
                labels[m.group(1)] = unescape_label_value(m.group(2))
            samples.append(Sample(name=name, labels=labels, value=value))
        else:
            samples.append(Sample(name=metric, labels={}, value=value))
    return samples


def sum_metric(
    samples: list[Sample],
    name: str,
    labels: dict[str, str],
    *,
    required: bool = True,
) -> float:
    total = 0.0
    found = False
    for s in samples:
        if s.name != name:
            continue
        if all(s.labels.get(k) == v for k, v in labels.items()):
            total += s.value
            found = True

    if not found:
        if not required:
            return 0.0

        label_str = ",".join([f'{k}={v!r}' for k, v in sorted(labels.items())])
        raise SystemExit(f"missing metric sample: {name} {{{label_str}}}")
    return total


def non_negative_delta(before: float, after: float, what: str) -> float:
    delta = after - before
    if delta < -1e-9:
        raise SystemExit(f"counter went backwards for {what}: before={before} after={after}")
    return max(0.0, delta)


def rate(numerator: float, denominator: float) -> float:
    return numerator / max(1.0, denominator)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute BVR/SER from Prometheus /metrics snapshots (before/after)."
    )
    parser.add_argument("--gateway-before", required=True, help="Gateway metrics snapshot (before).")
    parser.add_argument("--gateway-after", required=True, help="Gateway metrics snapshot (after).")
    parser.add_argument(
        "--controller-before", required=True, help="Controller metrics snapshot (before)."
    )
    parser.add_argument("--controller-after", required=True, help="Controller metrics snapshot (after).")
    parser.add_argument(
        "--bvr-threshold",
        type=float,
        default=0.01,
        help="Budget violation rate threshold (default: %(default)s).",
    )
    parser.add_argument(
        "--ser-threshold",
        type=float,
        default=0.01,
        help="Staleness error rate threshold (default: %(default)s).",
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="Optional JSON output path (written if provided).",
    )
    args = parser.parse_args()

    gw_before_path = Path(args.gateway_before)
    gw_after_path = Path(args.gateway_after)
    ctl_before_path = Path(args.controller_before)
    ctl_after_path = Path(args.controller_after)

    gw_before = parse_prometheus_text(load_text(gw_before_path))
    gw_after = parse_prometheus_text(load_text(gw_after_path))
    ctl_before = parse_prometheus_text(load_text(ctl_before_path))
    ctl_after = parse_prometheus_text(load_text(ctl_after_path))

    finalize_labels = {"route": "/v1/finalize", "method": "POST", "status": "200"}
    finalize_before = sum_metric(
        gw_before, "pecr_gateway_http_requests_total", finalize_labels, required=False
    )
    finalize_after = sum_metric(
        gw_after, "pecr_gateway_http_requests_total", finalize_labels, required=False
    )
    finalize_delta = non_negative_delta(finalize_before, finalize_after, "finalize_total")
    if finalize_delta < 1.0:
        raise SystemExit(
            "no finalize traffic observed (finalize_total_delta=0); cannot compute BVR/SER"
        )

    gw_budget_before = sum_metric(gw_before, "pecr_gateway_budget_violations_total", {})
    gw_budget_after = sum_metric(gw_after, "pecr_gateway_budget_violations_total", {})
    gw_budget_delta = non_negative_delta(gw_budget_before, gw_budget_after, "gateway_budget_violations")

    ctl_budget_before = sum_metric(ctl_before, "pecr_controller_budget_violations_total", {})
    ctl_budget_after = sum_metric(ctl_after, "pecr_controller_budget_violations_total", {})
    ctl_budget_delta = non_negative_delta(
        ctl_budget_before, ctl_budget_after, "controller_budget_violations"
    )

    gw_stale_before = sum_metric(gw_before, "pecr_gateway_staleness_errors_total", {})
    gw_stale_after = sum_metric(gw_after, "pecr_gateway_staleness_errors_total", {})
    gw_stale_delta = non_negative_delta(gw_stale_before, gw_stale_after, "gateway_staleness_errors")

    budget_delta = gw_budget_delta + ctl_budget_delta
    bvr = rate(budget_delta, finalize_delta)
    ser = rate(gw_stale_delta, finalize_delta)

    summary = {
        "finalize_total_delta": finalize_delta,
        "budget_violations_delta": {
            "gateway": gw_budget_delta,
            "controller": ctl_budget_delta,
            "total": budget_delta,
        },
        "staleness_errors_delta": {"gateway": gw_stale_delta},
        "rates": {"bvr": bvr, "ser": ser},
        "thresholds": {"bvr": float(args.bvr_threshold), "ser": float(args.ser_threshold)},
    }

    if args.output_json.strip():
        Path(args.output_json).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(f"finalize_total_delta: {finalize_delta:.0f}")
    print(
        "budget_violations_delta: "
        f"gateway={gw_budget_delta:.0f} controller={ctl_budget_delta:.0f} total={budget_delta:.0f}"
    )
    print(f"staleness_errors_delta: gateway={gw_stale_delta:.0f}")
    print(f"BVR={bvr:.6f} (threshold {args.bvr_threshold})")
    print(f"SER={ser:.6f} (threshold {args.ser_threshold})")

    ok_bvr = bvr <= args.bvr_threshold
    ok_ser = ser <= args.ser_threshold

    if ok_bvr and ok_ser:
        print("metrics gates: PASS")
        return 0

    print("metrics gates: FAIL")
    if not ok_bvr:
        print(f"- BVR exceeded: {bvr:.6f} > {args.bvr_threshold}")
    if not ok_ser:
        print(f"- SER exceeded: {ser:.6f} > {args.ser_threshold}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
