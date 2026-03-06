#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "fixtures" / "replay" / "useful_tasks"
DEFAULT_TOUR_SCENARIO_IDS = [
    "customer-status",
    "support-policy-source",
    "customer-counts-by-plan",
    "partial-billing-answer",
    "broad-customer-query",
]
DEFAULT_LIVE_SMOKE_SCENARIO_IDS = [
    "customer-status",
    "support-policy-source",
    "customer-counts-by-plan",
]

sys.path.insert(0, str((ROOT / "scripts" / "replay").resolve()))
from replay_lib import load_json  # noqa: E402


def load_manifest() -> dict[str, Any]:
    return load_json(STORE / "benchmark_manifest.json")


def load_scenario(scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = load_manifest()
    for scenario in manifest.get("scenarios", []):
        if scenario.get("scenario_id") == scenario_id:
            replay = load_json(STORE / scenario["replay_path"])
            return scenario, replay
    raise SystemExit(f"unknown scenario_id: {scenario_id}")


def default_local_auth_secret() -> str:
    value = os.environ.get("PECR_LOCAL_AUTH_SHARED_SECRET", "").strip()
    return value or "pecr-local-demo-secret"


def build_live_headers(principal_id: str, local_auth_secret: str) -> dict[str, str]:
    request_id = f"demo-{int(time.time() * 1000)}"
    return {
        "x-pecr-principal-id": principal_id,
        "x-pecr-local-auth-secret": local_auth_secret,
        "x-pecr-request-id": request_id,
        "x-pecr-trace-id": request_id,
    }


def build_live_run_request(
    controller_url: str,
    principal_id: str,
    local_auth_secret: str,
    query: str,
) -> urllib_request.Request:
    payload = json.dumps({"query": query}).encode("utf-8")
    return urllib_request.Request(
        f"{controller_url.rstrip('/')}/v1/run",
        data=payload,
        headers={"content-type": "application/json", **build_live_headers(principal_id, local_auth_secret)},
        method="POST",
    )


def build_live_capabilities_request(
    controller_url: str,
    principal_id: str,
    local_auth_secret: str,
) -> urllib_request.Request:
    return urllib_request.Request(
        f"{controller_url.rstrip('/')}/v1/capabilities",
        headers=build_live_headers(principal_id, local_auth_secret),
        method="GET",
    )


def load_scenarios(scenario_ids: list[str]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [load_scenario(scenario_id) for scenario_id in scenario_ids]


def normalize_preview(text: str, *, limit: int = 220) -> str:
    collapsed = " ".join(str(text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def count_claims(payload: dict[str, Any]) -> int:
    return len(payload.get("claim_map", {}).get("claims", []))


def build_tour_result(
    *,
    scenario: dict[str, Any],
    payload: dict[str, Any],
    response_kind: str | None,
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    claim_map = payload.get("claim_map", {})
    notes = claim_map.get("notes")
    return {
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "category": scenario["category"],
        "job": scenario["job"],
        "query": scenario["query"],
        "terminal_mode": payload.get("terminal_mode")
        or payload.get("loop_terminal_mode")
        or payload.get("metadata", {}).get("terminal_mode"),
        "response_kind": response_kind,
        "claim_count": count_claims(payload),
        "response_text": payload.get("response_text"),
        "response_preview": normalize_preview(payload.get("response_text", "")),
        "notes": notes,
        "elapsed_ms": elapsed_ms,
    }


def build_fixture_tour_result(
    scenario: dict[str, Any],
    replay: dict[str, Any],
) -> dict[str, Any]:
    return build_tour_result(
        scenario=scenario,
        payload=replay,
        response_kind=scenario.get("expected_response_kind"),
    )


def build_live_tour_result(
    scenario: dict[str, Any],
    live_response: dict[str, Any],
    *,
    elapsed_ms: int,
) -> dict[str, Any]:
    return build_tour_result(
        scenario=scenario,
        payload=live_response,
        response_kind=live_response.get("response_kind"),
        elapsed_ms=elapsed_ms,
    )


def summarize_tour_results(results: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    terminal_modes = Counter(
        row["terminal_mode"]
        for row in results
        if row.get("terminal_mode")
    )
    response_kinds = Counter(
        row["response_kind"]
        for row in results
        if row.get("response_kind")
    )
    return {
        "terminal_modes": dict(sorted(terminal_modes.items())),
        "response_kinds": dict(sorted(response_kinds.items())),
    }


def build_tour_takeaways(
    *,
    results: list[dict[str, Any]],
    capability_count: int = 0,
) -> list[str]:
    supported_count = sum(1 for row in results if row.get("terminal_mode") == "SUPPORTED")
    partial_count = sum(1 for row in results if row.get("response_kind") == "partial_answer")
    ambiguous_count = sum(1 for row in results if row.get("response_kind") == "ambiguous")
    takeaways = [
        f"{supported_count} of {len(results)} curated scenarios produced grounded supported answers.",
    ]
    if partial_count:
        takeaways.append(
            f"{partial_count} scenario showed a partial grounded answer instead of an empty refusal."
        )
    if ambiguous_count:
        takeaways.append(
            f"{ambiguous_count} scenario returned narrowing guidance instead of a dead-end failure."
        )
    if capability_count:
        takeaways.append(
            f"The capability catalog advertised {capability_count} safe ask patterns before any run request."
        )
    return takeaways


def render_tour(payload: dict[str, Any]) -> str:
    lines = [
        f"PECR {'Live ' if payload.get('tour_mode') == 'live' else ''}Product Tour",
        f"Mode: {payload['tour_mode']}",
    ]
    if payload.get("controller_url"):
        lines.append(f"Controller: {payload['controller_url']}")
    if payload.get("principal_id"):
        lines.append(f"Principal: {payload['principal_id']}")
    lines.append("")

    capability_summary = payload.get("capability_summary")
    if capability_summary:
        lines.append("Capabilities")
        for capability in capability_summary.get("capabilities", [])[:3]:
            example = ""
            examples = capability.get("examples") or []
            if examples:
                example = f" Example: {examples[0]}"
            lines.append(f"- {capability['title']}.{example}")
        for suggestion in capability_summary.get("suggested_queries", [])[:2]:
            lines.append(f"- Suggested ask: {suggestion}")
        lines.append("")

    lines.append("Scenarios")
    for index, row in enumerate(payload.get("results", []), start=1):
        outcome = row.get("response_kind") or row.get("terminal_mode") or "unknown"
        timing = ""
        if row.get("elapsed_ms") is not None:
            timing = f" in {row['elapsed_ms']} ms"
        lines.append(f"{index}. {row['title']} [{row['category']}]")
        lines.append(f"   Query: {row['query']}")
        lines.append(f"   Outcome: {outcome}{timing}")
        lines.append(f"   Answer: {row['response_preview']}")
        if row.get("notes"):
            lines.append(f"   Notes: {row['notes']}")

    lines.append("")
    lines.append("Takeaways")
    for takeaway in payload.get("takeaways", []):
        lines.append(f"- {takeaway}")
    return "\n".join(lines)


def emit_payload(payload: dict[str, Any], *, output_format: str) -> int:
    if output_format == "pretty":
        print(render_tour(payload))
        return 0
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def invoke_json_request(
    request: urllib_request.Request,
    *,
    timeout_secs: float,
    operation: str,
) -> dict[str, Any]:
    url = request.full_url
    try:
        with urllib_request.urlopen(request, timeout=timeout_secs) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            error_payload = json.loads(body)
        except json.JSONDecodeError as err:  # pragma: no cover - defensive
            raise SystemExit(f"{operation} failed with HTTP {exc.code}: {body}") from err
        raise SystemExit(
            f"{operation} failed with HTTP {exc.code}: "
            f"{json.dumps(error_payload, sort_keys=True)}"
        ) from exc
    except urllib_error.URLError as exc:
        raise SystemExit(f"{operation} could not reach {url}: {exc.reason}") from exc


def invoke_live_run(
    controller_url: str,
    principal_id: str,
    local_auth_secret: str,
    query: str,
    timeout_secs: float,
) -> dict[str, Any]:
    request = build_live_run_request(
        controller_url=controller_url,
        principal_id=principal_id,
        local_auth_secret=local_auth_secret,
        query=query,
    )
    return invoke_json_request(request, timeout_secs=timeout_secs, operation="live demo request")


def invoke_live_capabilities(
    controller_url: str,
    principal_id: str,
    local_auth_secret: str,
    timeout_secs: float,
) -> dict[str, Any]:
    request = build_live_capabilities_request(
        controller_url=controller_url,
        principal_id=principal_id,
        local_auth_secret=local_auth_secret,
    )
    return invoke_json_request(
        request,
        timeout_secs=timeout_secs,
        operation="live capabilities request",
    )


def wait_for_live_capabilities(
    controller_url: str,
    principal_id: str,
    local_auth_secret: str,
    timeout_secs: float,
    wait_secs: float,
    poll_interval_secs: float = 1.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_secs
    last_error = ""
    while True:
        try:
            return invoke_live_capabilities(
                controller_url=controller_url,
                principal_id=principal_id,
                local_auth_secret=local_auth_secret,
                timeout_secs=timeout_secs,
            )
        except SystemExit as exc:
            last_error = str(exc)
            if time.monotonic() >= deadline:
                raise SystemExit(
                    f"timed out waiting for {controller_url.rstrip('/')}/v1/capabilities "
                    f"after {wait_secs:.1f}s. Last error: {last_error}"
                ) from exc
            time.sleep(poll_interval_secs)


def build_tour_payload(
    *,
    tour_mode: str,
    scenarios: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    results = [build_fixture_tour_result(scenario, replay) for scenario, replay in scenarios]
    summary = summarize_tour_results(results)
    return {
        "tour_name": "pecr_product_tour_v1",
        "tour_mode": tour_mode,
        "scenario_count": len(results),
        "results": results,
        "takeaways": build_tour_takeaways(results=results),
        **summary,
    }


def cmd_catalog(_: argparse.Namespace) -> int:
    manifest = load_manifest()
    payload = {
        "benchmark_name": manifest.get("benchmark_name"),
        "scenario_count": len(manifest.get("scenarios", [])),
        "scenarios": [
            {
                "scenario_id": scenario["scenario_id"],
                "title": scenario["title"],
                "category": scenario["category"],
                "job": scenario["job"],
                "query": scenario["query"],
            }
            for scenario in manifest.get("scenarios", [])
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_scenario(args: argparse.Namespace) -> int:
    scenario, replay = load_scenario(args.scenario_id)
    payload = {
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "category": scenario["category"],
        "job": scenario["job"],
        "query": replay.get("query"),
        "terminal_mode": replay.get("metadata", {}).get("terminal_mode"),
        "quality_score": replay.get("metadata", {}).get("quality_score"),
        "response_text": replay.get("response_text"),
        "claim_count": len(replay.get("claim_map", {}).get("claims", [])),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_benchmark(_: argparse.Namespace) -> int:
    manifest = load_manifest()
    categories = Counter(
        scenario.get("category", "unknown")
        for scenario in manifest.get("scenarios", [])
    )
    payload = {
        "benchmark_name": manifest.get("benchmark_name"),
        "scenario_count": len(manifest.get("scenarios", [])),
        "categories": dict(sorted(categories.items())),
        "suggested_commands": [
            "python -B scripts/demo/useful_workflows.py catalog",
            "python -B scripts/demo/useful_workflows.py tour",
            "python -B scripts/demo/useful_workflows.py scenario customer-status",
            "python -B scripts/demo/useful_workflows.py scenario customer-counts-by-plan",
            "python -B scripts/demo/useful_workflows.py scenario monthly-customer-trend",
            "python -B scripts/demo/useful_workflows.py live-tour",
            "python -B scripts/demo/useful_workflows.py live-scenario customer-status",
            "python -B scripts/demo/useful_workflows.py live-smoke",
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_tour(args: argparse.Namespace) -> int:
    scenario_ids = args.scenario_ids or list(DEFAULT_TOUR_SCENARIO_IDS)
    payload = build_tour_payload(tour_mode="fixture", scenarios=load_scenarios(scenario_ids))
    return emit_payload(payload, output_format=args.format)


def cmd_live_scenario(args: argparse.Namespace) -> int:
    scenario, _ = load_scenario(args.scenario_id)
    live_response = invoke_live_run(
        controller_url=args.controller_url,
        principal_id=args.principal_id,
        local_auth_secret=args.local_auth_secret,
        query=scenario["query"],
        timeout_secs=args.timeout_secs,
    )
    payload = {
        "scenario_id": scenario["scenario_id"],
        "title": scenario["title"],
        "category": scenario["category"],
        "job": scenario["job"],
        "query": scenario["query"],
        "controller_url": args.controller_url.rstrip("/"),
        "principal_id": args.principal_id,
        "terminal_mode": live_response.get("terminal_mode"),
        "response_kind": live_response.get("response_kind"),
        "response_text": live_response.get("response_text"),
        "claim_count": len(live_response.get("claim_map", {}).get("claims", [])),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_live_smoke(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    scenarios = {scenario["scenario_id"]: scenario for scenario in manifest.get("scenarios", [])}
    results = []
    for scenario_id in DEFAULT_LIVE_SMOKE_SCENARIO_IDS:
        if scenario_id not in scenarios:
            continue
        scenario = scenarios[scenario_id]
        live_response = invoke_live_run(
            controller_url=args.controller_url,
            principal_id=args.principal_id,
            local_auth_secret=args.local_auth_secret,
            query=scenario["query"],
            timeout_secs=args.timeout_secs,
        )
        results.append(
            {
                "scenario_id": scenario_id,
                "terminal_mode": live_response.get("terminal_mode"),
                "response_kind": live_response.get("response_kind"),
                "response_text": live_response.get("response_text"),
            }
        )

    print(
        json.dumps(
            {
                "controller_url": args.controller_url.rstrip("/"),
                "principal_id": args.principal_id,
                "scenario_count": len(results),
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_live_tour(args: argparse.Namespace) -> int:
    scenario_ids = args.scenario_ids or list(DEFAULT_TOUR_SCENARIO_IDS)
    scenarios = load_scenarios(scenario_ids)
    capability_summary = wait_for_live_capabilities(
        controller_url=args.controller_url,
        principal_id=args.principal_id,
        local_auth_secret=args.local_auth_secret,
        timeout_secs=args.timeout_secs,
        wait_secs=args.wait_secs,
    )
    results = []
    for scenario, _ in scenarios:
        started_at = time.monotonic()
        live_response = invoke_live_run(
            controller_url=args.controller_url,
            principal_id=args.principal_id,
            local_auth_secret=args.local_auth_secret,
            query=scenario["query"],
            timeout_secs=args.timeout_secs,
        )
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        results.append(
            build_live_tour_result(
                scenario,
                live_response,
                elapsed_ms=elapsed_ms,
            )
        )

    summary = summarize_tour_results(results)
    payload = {
        "tour_name": "pecr_product_tour_v1",
        "tour_mode": "live",
        "controller_url": args.controller_url.rstrip("/"),
        "principal_id": args.principal_id,
        "scenario_count": len(results),
        "capability_summary": {
            "capability_count": len(capability_summary.get("capabilities", [])),
            "capabilities": capability_summary.get("capabilities", []),
            "suggested_queries": capability_summary.get("suggested_queries", []),
        },
        "results": results,
        "takeaways": build_tour_takeaways(
            results=results,
            capability_count=len(capability_summary.get("capabilities", [])),
        ),
        **summary,
    }
    return emit_payload(payload, output_format=args.format)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run PECR useful benchmark demo workflows.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_catalog = sub.add_parser("catalog", help="list useful benchmark scenarios")
    p_catalog.set_defaults(func=cmd_catalog)

    p_tour = sub.add_parser("tour", help="show a curated fixture-backed PECR product tour")
    p_tour.add_argument(
        "--format",
        choices=["pretty", "json"],
        default="pretty",
        help="output format (default: %(default)s)",
    )
    p_tour.add_argument(
        "scenario_ids",
        nargs="*",
        help="optional scenario ids to include instead of the default tour set",
    )
    p_tour.set_defaults(func=cmd_tour)

    p_scenario = sub.add_parser("scenario", help="show one named scenario outcome")
    p_scenario.add_argument("scenario_id", help="scenario id from the benchmark manifest")
    p_scenario.set_defaults(func=cmd_scenario)

    p_benchmark = sub.add_parser("benchmark", help="show benchmark summary and suggested commands")
    p_benchmark.set_defaults(func=cmd_benchmark)

    p_live_scenario = sub.add_parser(
        "live-scenario", help="run one named scenario against a local controller"
    )
    p_live_scenario.add_argument("scenario_id", help="scenario id from the benchmark manifest")
    p_live_scenario.add_argument(
        "--controller-url",
        default="http://127.0.0.1:8081",
        help="controller base URL (default: %(default)s)",
    )
    p_live_scenario.add_argument(
        "--principal-id",
        default="dev",
        help="principal id to send in local-auth mode (default: %(default)s)",
    )
    p_live_scenario.add_argument(
        "--local-auth-secret",
        default=default_local_auth_secret(),
        help="local auth secret for docker-compose demo mode (default: %(default)s)",
    )
    p_live_scenario.add_argument(
        "--timeout-secs",
        type=float,
        default=5.0,
        help="request timeout in seconds (default: %(default)s)",
    )
    p_live_scenario.set_defaults(func=cmd_live_scenario)

    p_live_smoke = sub.add_parser(
        "live-smoke",
        help="run the recommended local usefulness scenarios against a local controller",
    )
    p_live_smoke.add_argument(
        "--controller-url",
        default="http://127.0.0.1:8081",
        help="controller base URL (default: %(default)s)",
    )
    p_live_smoke.add_argument(
        "--principal-id",
        default="dev",
        help="principal id to send in local-auth mode (default: %(default)s)",
    )
    p_live_smoke.add_argument(
        "--local-auth-secret",
        default=default_local_auth_secret(),
        help="local auth secret for docker-compose demo mode (default: %(default)s)",
    )
    p_live_smoke.add_argument(
        "--timeout-secs",
        type=float,
        default=5.0,
        help="request timeout in seconds (default: %(default)s)",
    )
    p_live_smoke.set_defaults(func=cmd_live_smoke)

    p_live_tour = sub.add_parser(
        "live-tour",
        help="run the curated PECR product tour against a local controller",
    )
    p_live_tour.add_argument(
        "--controller-url",
        default="http://127.0.0.1:8081",
        help="controller base URL (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "--principal-id",
        default="dev",
        help="principal id to send in local-auth mode (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "--local-auth-secret",
        default=default_local_auth_secret(),
        help="local auth secret for docker-compose demo mode (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "--timeout-secs",
        type=float,
        default=5.0,
        help="request timeout in seconds (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "--wait-secs",
        type=float,
        default=30.0,
        help="how long to wait for /v1/capabilities before failing (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "--format",
        choices=["pretty", "json"],
        default="pretty",
        help="output format (default: %(default)s)",
    )
    p_live_tour.add_argument(
        "scenario_ids",
        nargs="*",
        help="optional scenario ids to include instead of the default live tour set",
    )
    p_live_tour.set_defaults(func=cmd_live_tour)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
