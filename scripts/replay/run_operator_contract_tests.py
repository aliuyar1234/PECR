#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BUDGET = {
    "max_operator_calls": 20,
    "max_bytes": 65536,
    "max_wallclock_ms": 5000,
    "max_recursion_depth": 4,
    "max_parallelism": 1,
}


def request_json(url: str, *, headers: dict[str, str], payload: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, str]]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=body, method="POST")
    for key, value in headers.items():
        req.add_header(key, value)
    req.add_header("content-type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, data, hdrs
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        return err.code, parsed, {}


def resolve_path(data: Any, dotted_path: str) -> Any:
    current = data
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        raise KeyError(dotted_path)
    return current


def load_templates(templates_dir: Path) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    for path in sorted(templates_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as f:
            template = json.load(f)
        template["_path"] = str(path)
        templates.append(template)
    return templates


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run operator contract tests from template files against a live gateway."
    )
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--templates-dir",
        default="scripts/replay/operator_contract_templates",
        help="Directory containing operator contract templates (*.json).",
    )
    parser.add_argument("--principal-id", default="dev")
    parser.add_argument("--local-auth-secret")
    parser.add_argument("--continue-on-failure", action="store_true")
    args = parser.parse_args()

    templates = load_templates(Path(args.templates_dir))
    if not templates:
        print(f"no operator templates found in {args.templates_dir}")
        return 1

    base_headers = {
        "x-pecr-principal-id": args.principal_id,
        "x-pecr-request-id": "operator-contract-tests",
        "x-pecr-trace-id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    }
    if args.local_auth_secret:
        base_headers["x-pecr-local-auth-secret"] = args.local_auth_secret

    session_url = f"{args.gateway_url.rstrip('/')}/v1/sessions"
    status, session_body, session_headers = request_json(
        session_url,
        headers=base_headers,
        payload={"budget": DEFAULT_BUDGET},
    )
    if status != 200:
        print(f"failed to create session ({status}): {json.dumps(session_body)}")
        return 1

    session_id = session_body.get("session_id")
    session_token = session_headers.get("x-pecr-session-token")
    if not session_id or not session_token:
        print("session response missing session_id or x-pecr-session-token")
        return 1

    failures: list[str] = []
    for template in templates:
        name = template.get("name", "<unnamed>")
        op_name = template.get("op_name")
        if not op_name:
            failures.append(f"{name}: missing op_name ({template.get('_path')})")
            continue

        op_headers = dict(base_headers)
        op_headers["x-pecr-session-token"] = session_token
        op_url = f"{args.gateway_url.rstrip('/')}/v1/operators/{op_name}"
        payload = {
            "session_id": session_id,
            "params": template.get("params", {}),
        }
        status, body, _ = request_json(op_url, headers=op_headers, payload=payload)
        if status != 200:
            failures.append(f"{name}: operator call failed ({status})")
            if not args.continue_on_failure:
                break
            continue

        terminal_mode = body.get("terminal_mode")
        allowed_modes = template.get("allowed_terminal_modes", [])
        if allowed_modes and terminal_mode not in allowed_modes:
            failures.append(
                f"{name}: unexpected terminal_mode {terminal_mode} (allowed={allowed_modes})"
            )
            if not args.continue_on_failure:
                break

        result = body.get("result")
        for path in template.get("required_result_paths", []):
            try:
                resolve_path(result, path)
            except KeyError:
                failures.append(f"{name}: missing result path `{path}`")
                if not args.continue_on_failure:
                    break
        if failures and not args.continue_on_failure:
            break

    print("Operator Contract Checklist")
    print(f"- Session creation: {'ok' if session_id else 'failed'}")
    print(f"- Loaded templates: {len(templates)}")
    print(f"- Failures: {len(failures)}")

    if failures:
        print("Contract test failures:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("All operator contract templates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
