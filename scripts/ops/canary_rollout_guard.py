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
        raise SystemExit(f"{name} must be numeric, got {raw!r}")


def parse_bool(raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise SystemExit(f"invalid boolean value: {raw!r}")


def gh_escape(message: str) -> str:
    return (
        message.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
    )


def emit_gh_annotation(level: str, title: str, message: str) -> None:
    print(f"::{level} title={gh_escape(title)}::{gh_escape(message)}")


def read_summary_metrics(summary: dict) -> tuple[float, float]:
    metrics = summary.get("metrics")
    if not isinstance(metrics, dict):
        raise SystemExit("summary JSON missing metrics object")
    duration = metrics.get("http_req_duration")
    if not isinstance(duration, dict):
        raise SystemExit("summary JSON missing metrics.http_req_duration")

    p95 = duration.get("p(95)")
    p99 = duration.get("p(99)")
    if not isinstance(p95, (int, float)) or not isinstance(p99, (int, float)):
        raise SystemExit("summary JSON missing p(95)/p(99) in metrics.http_req_duration")
    return float(p95), float(p99)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate canary rollout SLO signals and emit next auto-fallback action "
            "according to docs/standards/ROLLOUT_CONTROL_PLANE_CONTRACT.md."
        )
    )
    parser.add_argument("--summary", required=True, help="k6 summary JSON for canary cohort.")
    parser.add_argument(
        "--metrics-gates",
        required=True,
        help="BVR/SER JSON artifact from scripts/perf/check_bvr_ser.py.",
    )
    parser.add_argument("--engine", default="rlm", help="Current engine mode.")
    parser.add_argument(
        "--adaptive-enabled",
        default="true",
        help="Current adaptive parallelism flag (true/false).",
    )
    parser.add_argument(
        "--batch-enabled",
        default="true",
        help="Current batch mode flag (true/false).",
    )
    parser.add_argument(
        "--max-p95-ms",
        type=float,
        default=parse_float_env("PECR_CANARY_P95_BUDGET_MS", 1200.0),
        help="Canary p95 SLO budget in ms.",
    )
    parser.add_argument(
        "--max-p99-ms",
        type=float,
        default=parse_float_env("PECR_CANARY_P99_BUDGET_MS", 1500.0),
        help="Canary p99 SLO budget in ms.",
    )
    parser.add_argument(
        "--source-unavailable-rate",
        type=float,
        default=None,
        help="Observed SOURCE_UNAVAILABLE rate (optional).",
    )
    parser.add_argument(
        "--max-source-unavailable-rate",
        type=float,
        default=parse_float_env("PECR_CANARY_SOURCE_UNAVAILABLE_MAX_RATE", 0.05),
        help="Maximum allowed SOURCE_UNAVAILABLE rate when --source-unavailable-rate is provided.",
    )
    parser.add_argument("--output-json", default="", help="Optional JSON artifact path.")
    parser.add_argument("--output-md", default="", help="Optional markdown artifact path.")
    parser.add_argument("--output-env", default="", help="Optional fallback env patch path.")
    parser.add_argument(
        "--github-annotations",
        action="store_true",
        help="Emit GitHub annotations (also auto-enabled on GitHub Actions).",
    )
    parser.add_argument(
        "--fail-on-fallback",
        action="store_true",
        help="Exit non-zero when fallback is required.",
    )
    args = parser.parse_args()

    summary = load_json(Path(args.summary))
    metrics_gates = load_json(Path(args.metrics_gates))

    p95, p99 = read_summary_metrics(summary)
    rates = metrics_gates.get("rates", {})
    thresholds = metrics_gates.get("thresholds", {})
    if not isinstance(rates, dict) or not isinstance(thresholds, dict):
        raise SystemExit("metrics gates JSON missing rates/thresholds")

    bvr = rates.get("bvr")
    ser = rates.get("ser")
    bvr_threshold = thresholds.get("bvr")
    ser_threshold = thresholds.get("ser")
    if not isinstance(bvr, (int, float)) or not isinstance(ser, (int, float)):
        raise SystemExit("metrics gates JSON missing numeric rates.bvr/rates.ser")
    if not isinstance(bvr_threshold, (int, float)) or not isinstance(ser_threshold, (int, float)):
        raise SystemExit("metrics gates JSON missing numeric thresholds.bvr/thresholds.ser")

    adaptive_enabled = parse_bool(args.adaptive_enabled)
    batch_enabled = parse_bool(args.batch_enabled)
    engine = args.engine.strip().lower() or "baseline"

    triggers: list[dict[str, object]] = []
    if p95 > args.max_p95_ms:
        triggers.append(
            {
                "id": "latency_p95",
                "message": f"p95 {p95:.3f}ms exceeds SLO {args.max_p95_ms:.3f}ms",
            }
        )
    if p99 > args.max_p99_ms:
        triggers.append(
            {
                "id": "latency_p99",
                "message": f"p99 {p99:.3f}ms exceeds SLO {args.max_p99_ms:.3f}ms",
            }
        )
    if float(bvr) > float(bvr_threshold):
        triggers.append(
            {
                "id": "budget_violation_rate",
                "message": f"BVR {float(bvr):.6f} exceeds threshold {float(bvr_threshold):.6f}",
            }
        )
    if float(ser) > float(ser_threshold):
        triggers.append(
            {
                "id": "staleness_error_rate",
                "message": f"SER {float(ser):.6f} exceeds threshold {float(ser_threshold):.6f}",
            }
        )

    if args.source_unavailable_rate is not None:
        if args.source_unavailable_rate > args.max_source_unavailable_rate:
            triggers.append(
                {
                    "id": "source_unavailable_rate",
                    "message": (
                        f"SOURCE_UNAVAILABLE rate {args.source_unavailable_rate:.6f} "
                        f"exceeds threshold {args.max_source_unavailable_rate:.6f}"
                    ),
                }
            )

    fallback_action = {"step": "none", "env_updates": {}, "reason": "canary healthy"}
    if triggers:
        if adaptive_enabled:
            fallback_action = {
                "step": "disable_adaptive_parallelism",
                "env_updates": {"PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED": "false"},
                "reason": "First fallback stage in contract order.",
            }
        elif batch_enabled:
            fallback_action = {
                "step": "disable_batch_mode",
                "env_updates": {"PECR_CONTROLLER_BATCH_MODE_ENABLED": "false"},
                "reason": "Second fallback stage in contract order.",
            }
        elif engine != "baseline":
            fallback_action = {
                "step": "switch_engine_to_baseline",
                "env_updates": {"PECR_CONTROLLER_ENGINE": "baseline"},
                "reason": "Final fallback stage in contract order.",
            }
        else:
            fallback_action = {
                "step": "already_at_safest_mode",
                "env_updates": {},
                "reason": "All fallback stages already applied; escalate incident.",
            }

    status = "healthy" if not triggers else "fallback_required"
    report = {
        "status": status,
        "engine": engine,
        "current_state": {
            "adaptive_parallelism_enabled": adaptive_enabled,
            "batch_mode_enabled": batch_enabled,
        },
        "signals": {
            "p95_ms": p95,
            "p99_ms": p99,
            "bvr": float(bvr),
            "ser": float(ser),
            "source_unavailable_rate": args.source_unavailable_rate,
        },
        "thresholds": {
            "max_p95_ms": args.max_p95_ms,
            "max_p99_ms": args.max_p99_ms,
            "bvr": float(bvr_threshold),
            "ser": float(ser_threshold),
            "max_source_unavailable_rate": args.max_source_unavailable_rate,
        },
        "triggers": triggers,
        "recommended_fallback": fallback_action,
    }

    annotations_enabled = args.github_annotations or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    if status == "healthy":
        print("canary guard: PASS")
        print(f"- engine: {engine}")
        print(f"- p95={p95:.3f}ms (budget {args.max_p95_ms:.3f}ms)")
        print(f"- p99={p99:.3f}ms (budget {args.max_p99_ms:.3f}ms)")
        print(f"- BVR={float(bvr):.6f} (threshold {float(bvr_threshold):.6f})")
        print(f"- SER={float(ser):.6f} (threshold {float(ser_threshold):.6f})")
        if annotations_enabled:
            emit_gh_annotation(
                "notice",
                "Canary guard passed",
                f"Engine {engine} canary is healthy; no fallback action required.",
            )
    else:
        print("canary guard: FALLBACK REQUIRED")
        for trigger in triggers:
            print(f"- {trigger['message']}")
        print(
            f"- recommended step: {fallback_action['step']} "
            f"({fallback_action['reason']})"
        )
        if fallback_action["env_updates"]:
            print("- env updates:")
            for key, value in fallback_action["env_updates"].items():
                print(f"  - {key}={value}")
        if annotations_enabled:
            trigger_summary = "; ".join(str(item["message"]) for item in triggers)
            emit_gh_annotation(
                "error",
                "Canary fallback required",
                (
                    f"Signals breached canary policy ({trigger_summary}). "
                    f"Next action: {fallback_action['step']}."
                ),
            )

    if args.output_json.strip():
        output_json = Path(args.output_json)
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.output_env.strip():
        output_env = Path(args.output_env)
        output_env.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"# generated by scripts/ops/canary_rollout_guard.py ({fallback_action['step']})"]
        for key, value in fallback_action["env_updates"].items():
            lines.append(f"{key}={value}")
        output_env.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if args.output_md.strip():
        output_md = Path(args.output_md)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        md_lines = [
            "### Canary Rollout Guard",
            "",
            f"- Status: **{status}**",
            f"- Engine: `{engine}`",
            f"- p95: `{p95:.3f}ms` (budget `{args.max_p95_ms:.3f}ms`)",
            f"- p99: `{p99:.3f}ms` (budget `{args.max_p99_ms:.3f}ms`)",
            f"- BVR: `{float(bvr):.6f}` (threshold `{float(bvr_threshold):.6f}`)",
            f"- SER: `{float(ser):.6f}` (threshold `{float(ser_threshold):.6f}`)",
            "",
            "#### Triggers",
        ]
        if triggers:
            for trigger in triggers:
                md_lines.append(f"- {trigger['message']}")
        else:
            md_lines.append("- None")
        md_lines.extend(
            [
                "",
                "#### Recommended Fallback",
                f"- Step: `{fallback_action['step']}`",
                f"- Reason: {fallback_action['reason']}",
            ]
        )
        if fallback_action["env_updates"]:
            md_lines.append("- Env updates:")
            for key, value in fallback_action["env_updates"].items():
                md_lines.append(f"  - `{key}={value}`")
        output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if status == "fallback_required" and args.fail_on_fallback:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
