#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr, flush=True)


def repo_root_from_script() -> Path:
    # Repo layout:
    # - scripts/rlm/pecr_rlm_bridge.py
    # - vendor/rlm/rlm/...
    # In container:
    # - /usr/local/share/pecr/pecr_rlm_bridge.py
    # - /usr/local/share/pecr/vendor/rlm/rlm/...
    here = Path(__file__).resolve()
    if (here.parent / "vendor" / "rlm" / "rlm").exists():
        return here.parent
    if (here.parent.parent.parent / "vendor" / "rlm" / "rlm").exists():
        return here.parent.parent.parent
    return here.parent


def ensure_vendor_rlm_on_path() -> None:
    root = repo_root_from_script()
    vendor_rlm = root / "vendor" / "rlm"
    if vendor_rlm.exists():
        sys.path.insert(0, str(vendor_rlm))


def read_json_line() -> dict[str, Any]:
    line = sys.stdin.readline()
    if line == "":
        raise SystemExit("stdin closed")
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid json from stdin: {exc}") from exc
    if not isinstance(msg, dict):
        raise SystemExit("expected JSON object message")
    return msg


def write_json_line(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


@dataclass
class Budget:
    max_operator_calls: int
    max_bytes: int
    max_wallclock_ms: int
    max_recursion_depth: int

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Budget":
        return cls(
            max_operator_calls=int(raw.get("max_operator_calls", 0)),
            max_bytes=int(raw.get("max_bytes", 0)),
            max_wallclock_ms=int(raw.get("max_wallclock_ms", 0)),
            max_recursion_depth=int(raw.get("max_recursion_depth", 0)),
        )


class Bridge:
    def call_operator(self, *, depth: int, op_name: str, params: Any) -> dict[str, Any]:
        call_id = uuid.uuid4().hex
        write_json_line(
            {
                "type": "call_operator",
                "id": call_id,
                "depth": depth,
                "op_name": op_name,
                "params": params,
            }
        )
        resp = read_json_line()
        if resp.get("type") != "operator_result" or resp.get("id") != call_id:
            raise SystemExit(f"protocol error: expected operator_result for id={call_id}")
        return resp


def run_mock(bridge: Bridge, query: str, budget: Budget) -> dict[str, Any]:
    from rlm.utils.parsing import find_code_blocks, find_final_answer

    search_refs: list[dict[str, Any]] = []
    operator_calls_used = 0
    stop_reason = "plan_complete"

    def do(depth: int, op_name: str, params: Any) -> dict[str, Any]:
        nonlocal operator_calls_used
        operator_calls_used += 1
        return bridge.call_operator(depth=depth, op_name=op_name, params=params)

    # Depth is 0-indexed to match the controller's baseline loop convention.
    for depth in range(max(0, budget.max_recursion_depth)):
        if depth == 0:
            response = (
                "PLAN: list_versions\n```repl\n"
                + json.dumps(
                    {"op_name": "list_versions", "params": {"object_id": "public/public_1.txt"}}
                )
                + "\n```"
            )
        elif depth == 1:
            response = (
                "PLAN: fetch_rows\n```repl\n"
                + json.dumps(
                    {
                        "op_name": "fetch_rows",
                        "params": {
                            "view_id": "safe_customer_view_public",
                            "filter_spec": {"customer_id": "cust_public_1"},
                            "fields": ["status", "plan_tier"],
                        },
                    }
                )
                + "\n```"
            )
        elif depth == 2:
            response = (
                "PLAN: search\n```repl\n"
                + json.dumps(
                    {"op_name": "search", "params": {"query": query.strip(), "limit": 5}}
                )
                + "\n```"
            )
        elif depth == 3:
            calls: list[dict[str, Any]] = []
            for r in search_refs[:2]:
                object_id = r.get("object_id")
                if isinstance(object_id, str) and object_id.strip():
                    calls.append({"op_name": "fetch_span", "params": {"object_id": object_id}})

            if not calls:
                response = "PLAN: no spans\n"
            else:
                response = "PLAN: fetch_span\n" + "\n".join(
                    ["```repl\n" + json.dumps(call) + "\n```" for call in calls]
                )
        else:
            break

        for code in find_code_blocks(response):
            try:
                call = json.loads(code)
            except json.JSONDecodeError:
                continue
            if not isinstance(call, dict):
                continue
            op_name = call.get("op_name")
            params = call.get("params")
            if not isinstance(op_name, str) or not op_name.strip():
                continue
            resp = do(depth, op_name, params)
            if op_name == "search":
                result = resp.get("result") if isinstance(resp.get("result"), dict) else {}
                refs = result.get("refs") if isinstance(result, dict) else None
                if isinstance(refs, list):
                    search_refs = [r for r in refs if isinstance(r, dict)]

    if budget.max_recursion_depth <= 0:
        stop_reason = "budget_max_recursion_depth"
    elif budget.max_recursion_depth <= 4:
        stop_reason = "budget_max_recursion_depth"

    final_answer = find_final_answer("FINAL(UNKNOWN: insufficient evidence to answer the query.)")
    if final_answer is None:
        final_answer = "UNKNOWN: insufficient evidence to answer the query."
    return {
        "final_answer": final_answer,
        "stop_reason": stop_reason,
        "operator_calls_used": operator_calls_used,
        "depth_used": min(max(0, budget.max_recursion_depth), 5),
    }


def main() -> int:
    ensure_vendor_rlm_on_path()

    start = read_json_line()
    if start.get("type") != "start":
        eprint("expected start message")
        return 2

    query = start.get("query")
    if not isinstance(query, str):
        eprint("start.query must be a string")
        return 2

    budget_raw = start.get("budget")
    if not isinstance(budget_raw, dict):
        eprint("start.budget must be an object")
        return 2
    budget = Budget.from_json(budget_raw)

    backend = os.getenv("PECR_RLM_BACKEND", "mock").strip().lower() or "mock"
    if backend != "mock":
        eprint("only PECR_RLM_BACKEND=mock is supported in this build")
        return 3

    bridge = Bridge()
    result = run_mock(bridge, query, budget)
    write_json_line(
        {
            "type": "done",
            "final_answer": result["final_answer"],
            "stop_reason": result["stop_reason"],
            "operator_calls_used": result["operator_calls_used"],
            "depth_used": result["depth_used"],
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
