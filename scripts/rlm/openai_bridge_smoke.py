#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

from pecr_rlm_bridge import Budget, ensure_vendor_rlm_on_path, run_openai


class SmokeBridge:
    def __init__(self) -> None:
        self.operator_calls: list[tuple[int, str, object]] = []

    def call_operator(self, *, depth: int, op_name: str, params: object) -> dict[str, object]:
        self.operator_calls.append((depth, op_name, params))
        if op_name == "fetch_rows":
            return {
                "type": "operator_result",
                "id": op_name,
                "ok": True,
                "result": {
                    "rows": [
                        {
                            "customer_id": "cust_public_1",
                            "status": "active",
                            "plan_tier": "pro",
                        }
                    ]
                },
            }
        return {
            "type": "operator_result",
            "id": op_name,
            "ok": False,
            "terminal_mode": "SOURCE_UNAVAILABLE",
            "result": None,
        }

    def call_operator_batch(self, *, depth: int, calls: list[dict[str, object]]) -> list[dict[str, object]]:
        return [
            self.call_operator(
                depth=depth,
                op_name=str(call.get("op_name", "")),
                params=call.get("params"),
            )
            for call in calls
        ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a live smoke check against the PECR openai-backed RLM bridge seam."
    )
    parser.add_argument(
        "--query",
        default="What is the customer status and plan tier?",
        help="Query to send into the RLM bridge.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_vendor_rlm_on_path()

    bridge = SmokeBridge()
    budget = Budget(
        max_operator_calls=6,
        max_bytes=1024 * 1024,
        max_wallclock_ms=10_000,
        max_recursion_depth=5,
        max_parallelism=1,
    )
    result = run_openai(
        bridge,
        args.query,
        budget,
        planner_hints={
            "intent": "structured_lookup",
            "recommended_path": [
                {
                    "kind": "operator",
                    "op_name": "fetch_rows",
                    "params": {
                        "view_id": "safe_customer_view_public",
                        "filter_spec": {"customer_id": "cust_public_1"},
                        "fields": ["status", "plan_tier"],
                    },
                }
            ],
        },
        plan_request={
            "available_operator_names": ["fetch_rows"],
        },
    )

    final_answer = result.get("final_answer", "")
    if not isinstance(final_answer, str):
        print("Smoke failed: final_answer was not a string", file=sys.stderr)
        return 1
    if "active" not in final_answer.lower() or "pro" not in final_answer.lower():
        print(
            f"Smoke failed: expected final answer to contain active/pro, got: {final_answer}",
            file=sys.stderr,
        )
        return 1
    if int(result.get("operator_calls_used", 0)) < 1:
        print("Smoke failed: expected at least one operator call", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "query": args.query,
                "final_answer": final_answer,
                "operator_calls_used": result.get("operator_calls_used"),
                "depth_used": result.get("depth_used"),
                "operator_calls": bridge.operator_calls,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
