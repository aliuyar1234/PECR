#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_runs(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing runs file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc

    if not isinstance(payload, list):
        raise SystemExit(f"expected {path} to contain a JSON list of workflow runs")

    normalized: list[dict[str, Any]] = []
    for entry in payload:
        if isinstance(entry, dict):
            normalized.append(entry)
    return normalized


def run_sort_key(run: dict[str, Any]) -> tuple[str, int]:
    created_at = str(run.get("createdAt", ""))
    database_id = run.get("databaseId", 0)
    if not isinstance(database_id, int):
        database_id = 0
    return (created_at, database_id)


def filter_runs(
    runs: list[dict[str, Any]],
    *,
    workflow_name: str,
    branch: str | None,
    head_sha: str | None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for run in runs:
        if run.get("workflowName") != workflow_name:
            continue
        if branch and run.get("headBranch") != branch:
            continue
        if head_sha and run.get("headSha") != head_sha:
            continue
        filtered.append(run)
    filtered.sort(key=run_sort_key, reverse=True)
    return filtered


def compute_success_streak(runs: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
    streak = 0
    considered: list[dict[str, Any]] = []
    for run in runs:
        considered.append(run)
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            break
        streak += 1
    return streak, considered


def build_report(
    runs: list[dict[str, Any]],
    *,
    workflow_name: str,
    branch: str | None,
    head_sha: str | None,
    required_successes: int,
) -> dict[str, Any]:
    matching_runs = filter_runs(runs, workflow_name=workflow_name, branch=branch, head_sha=head_sha)
    successful_streak, considered_runs = compute_success_streak(matching_runs)
    ready = successful_streak >= required_successes
    return {
        "status": "ready" if ready else "not_ready",
        "workflow_name": workflow_name,
        "branch": branch,
        "head_sha": head_sha,
        "required_successes": required_successes,
        "matching_run_count": len(matching_runs),
        "successful_streak": successful_streak,
        "considered_runs": considered_runs[:required_successes],
        "latest_matching_run": matching_runs[0] if matching_runs else None,
        "message": (
            f"promotion gate satisfied with {successful_streak} consecutive successful runs"
            if ready
            else f"promotion gate not ready: need {required_successes} consecutive successful runs, found {successful_streak}"
        ),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Real Backend Promotion Gate",
        "",
        f"- Status: `{report['status']}`",
        f"- Workflow: `{report['workflow_name']}`",
        f"- Required successes: `{report['required_successes']}`",
        f"- Successful streak: `{report['successful_streak']}`",
        f"- Matching run count: `{report['matching_run_count']}`",
    ]
    if report.get("branch"):
        lines.append(f"- Branch: `{report['branch']}`")
    if report.get("head_sha"):
        lines.append(f"- Head SHA: `{report['head_sha']}`")
    lines.extend(["", "## Considered Runs", ""])
    considered_runs = report.get("considered_runs") or []
    if not considered_runs:
        lines.append("_No matching runs found._")
    else:
        lines.append("| Run ID | Status | Conclusion | SHA | URL |")
        lines.append("|---:|---|---|---|---|")
        for run in considered_runs:
            lines.append(
                "| {database_id} | {status} | {conclusion} | `{sha}` | {url} |".format(
                    database_id=run.get("databaseId", ""),
                    status=run.get("status", ""),
                    conclusion=run.get("conclusion", ""),
                    sha=str(run.get("headSha", ""))[:12],
                    url=run.get("url", ""),
                )
            )
    lines.extend(["", report["message"], ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the promotion gate for the real-backend usefulness workflow."
    )
    parser.add_argument("--runs-json", required=True, type=Path, help="JSON file from `gh run list --json ...`.")
    parser.add_argument(
        "--workflow-name",
        default="rlm-real-backend-usefulness",
        help="Workflow name to evaluate.",
    )
    parser.add_argument("--branch", default="", help="Optional branch filter.")
    parser.add_argument("--head-sha", default="", help="Optional exact head SHA filter.")
    parser.add_argument(
        "--required-successes",
        type=int,
        default=3,
        help="Required consecutive successful runs before the gate is ready.",
    )
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-md", type=Path)
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Exit non-zero when the gate is not ready.",
    )
    args = parser.parse_args(argv)

    if args.required_successes < 1:
        raise SystemExit("--required-successes must be at least 1")

    report = build_report(
        load_runs(args.runs_json),
        workflow_name=args.workflow_name,
        branch=args.branch or None,
        head_sha=args.head_sha or None,
        required_successes=args.required_successes,
    )

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.output_md:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(render_markdown(report), encoding="utf-8")

    if args.require_ready and report["status"] != "ready":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
