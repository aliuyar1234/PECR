#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUPPORTED_PROTOCOL_VERSION = 1
REPL_BLOCK_PATTERN = re.compile(r"```repl\s*\n(.*?)\n```", re.DOTALL)
FINAL_PATTERN = re.compile(r"^\s*FINAL\((.*)\)\s*$", re.MULTILINE | re.DOTALL)


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
        raise EOFError("stdin closed")
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid json from stdin: {exc}") from exc
    if not isinstance(msg, dict):
        raise ValueError("expected JSON object message")
    return msg


def write_json_line(msg: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def find_code_blocks(text: str) -> list[str]:
    return [match.group(1).strip() for match in REPL_BLOCK_PATTERN.finditer(text)]


def find_final_answer(text: str) -> str | None:
    match = FINAL_PATTERN.search(text)
    if match:
        return match.group(1).strip()
    return None


def negotiate_protocol_version(start: dict[str, Any]) -> int:
    protocol = start.get("protocol")
    if protocol is None:
        # Backward compatibility for older controller messages.
        return SUPPORTED_PROTOCOL_VERSION
    if not isinstance(protocol, dict):
        raise ValueError("start.protocol must be an object")

    min_version_raw = protocol.get("min_version", SUPPORTED_PROTOCOL_VERSION)
    max_version_raw = protocol.get("max_version", SUPPORTED_PROTOCOL_VERSION)
    if not isinstance(min_version_raw, int) or not isinstance(max_version_raw, int):
        raise ValueError("start.protocol.{min_version,max_version} must be integers")
    if min_version_raw > max_version_raw:
        raise ValueError("start.protocol min_version must be <= max_version")
    if not (min_version_raw <= SUPPORTED_PROTOCOL_VERSION <= max_version_raw):
        raise ValueError(
            "unsupported bridge protocol range "
            f"{min_version_raw}-{max_version_raw}; supported={SUPPORTED_PROTOCOL_VERSION}"
        )
    return SUPPORTED_PROTOCOL_VERSION


@dataclass
class Budget:
    max_operator_calls: int
    max_bytes: int
    max_wallclock_ms: int
    max_recursion_depth: int
    max_parallelism: int

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> "Budget":
        max_parallelism = raw.get("max_parallelism")
        if max_parallelism is None:
            parsed_parallelism = 1
        else:
            parsed_parallelism = int(max_parallelism)
            if parsed_parallelism <= 0:
                parsed_parallelism = 1

        return cls(
            max_operator_calls=int(raw.get("max_operator_calls", 0)),
            max_bytes=int(raw.get("max_bytes", 0)),
            max_wallclock_ms=int(raw.get("max_wallclock_ms", 0)),
            max_recursion_depth=int(raw.get("max_recursion_depth", 0)),
            max_parallelism=parsed_parallelism,
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
            raise ValueError(f"protocol error: expected operator_result for id={call_id}")
        return resp

    def call_operator_batch(self, *, depth: int, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        call_id = uuid.uuid4().hex
        write_json_line(
            {
                "type": "call_operator_batch",
                "id": call_id,
                "depth": depth,
                "calls": calls,
            }
        )
        resp = read_json_line()
        if resp.get("type") != "operator_batch_result" or resp.get("id") != call_id:
            raise ValueError(f"protocol error: expected operator_batch_result for id={call_id}")
        results = resp.get("results")
        if not isinstance(results, list):
            raise ValueError(f"protocol error: expected list results for id={call_id}")
        return [r for r in results if isinstance(r, dict)]


def default_mock_plan(query: str) -> list[dict[str, Any]]:
    return [
        {
            "kind": "operator",
            "op_name": "list_versions",
            "params": {"object_id": "public/public_1.txt"},
        },
        {
            "kind": "operator",
            "op_name": "fetch_rows",
            "params": {
                "view_id": "safe_customer_view_public",
                "filter_spec": {"customer_id": "cust_public_1"},
                "fields": ["status", "plan_tier"],
            },
        },
        {"kind": "operator", "op_name": "search", "params": {"query": query.strip(), "limit": 5}},
        {"kind": "search_ref_fetch_span", "max_refs": 2},
    ]


def normalized_query_text(query: str) -> str:
    return " ".join(query.split()).strip().lower()


def normalized_query_tokens(query: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", normalized_query_text(query))


def should_short_circuit_perf_probe(query: str, planner_hints: dict[str, Any] | None) -> bool:
    if normalized_query_text(query) != "smoke":
        return False

    if not isinstance(planner_hints, dict):
        return True

    intent = planner_hints.get("intent")
    if not isinstance(intent, str):
        return True

    return intent.strip().lower() in {"", "default"}


def normalize_planner_step(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    kind = raw.get("kind")
    if kind == "operator":
        op_name = raw.get("op_name")
        params = raw.get("params")
        if not isinstance(op_name, str) or not op_name.strip():
            return None
        return {"kind": "operator", "op_name": op_name.strip(), "params": params}

    if kind == "search_ref_fetch_span":
        max_refs_raw = raw.get("max_refs", 2)
        try:
            max_refs = int(max_refs_raw)
        except (TypeError, ValueError):
            return None
        if max_refs <= 0:
            return None
        return {"kind": "search_ref_fetch_span", "max_refs": max_refs}

    return None


def available_operator_names_for_plan_request(plan_request: dict[str, Any] | None) -> list[str]:
    if not isinstance(plan_request, dict):
        return []
    raw_names = plan_request.get("available_operator_names")
    if not isinstance(raw_names, list):
        return []
    return [name.strip() for name in raw_names if isinstance(name, str) and name.strip()]


def first_clarification_prompt(plan_request: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(plan_request, dict):
        return None
    prompts = plan_request.get("clarification_opportunities")
    if not isinstance(prompts, list):
        return None
    for prompt in prompts:
        if isinstance(prompt, dict) and isinstance(prompt.get("question"), str):
            return prompt
    return None


def render_clarification_prompt(prompt: dict[str, Any]) -> str:
    question = prompt.get("question")
    if not isinstance(question, str) or not question.strip():
        return "UNKNOWN: I can help, but I need one detail first."
    message = f"UNKNOWN: I can help, but I need one detail first. {question.strip()}"
    if not question.strip().endswith("?"):
        message += "?"
    options = prompt.get("options")
    if isinstance(options, list):
        rendered_options = [
            f"`{option.strip()}`"
            for option in options[:3]
            if isinstance(option, str) and option.strip()
        ]
        if rendered_options:
            message += " Options: "
            if len(rendered_options) == 1:
                message += rendered_options[0]
            else:
                message += ", ".join(rendered_options[:-1])
                message += f", or {rendered_options[-1]}"
            message += "."
    return message


def evidence_clause_requested(query: str) -> bool:
    tokens = set(normalized_query_tokens(query))
    return bool(tokens.intersection({"cite", "cites", "evidence", "policy", "quote", "source", "text"}))


def structured_lookup_requested(query: str) -> bool:
    tokens = set(normalized_query_tokens(query))
    return bool(tokens.intersection({"customer", "customers", "plan", "tier", "status", "tenant"}))


def default_structured_lookup_step() -> dict[str, Any]:
    return {
        "kind": "operator",
        "op_name": "fetch_rows",
        "params": {
            "view_id": "safe_customer_view_public",
            "filter_spec": {"customer_id": "cust_public_1"},
            "fields": ["status", "plan_tier"],
        },
    }


def ensure_multi_clause_coverage(
    query: str,
    steps: list[dict[str, Any]],
    available_operator_names: list[str],
) -> list[dict[str, Any]]:
    op_names = [step.get("op_name") for step in steps if step.get("kind") == "operator"]
    available = set(available_operator_names)
    augmented = list(steps)

    if evidence_clause_requested(query) and not any(
        name in {"lookup_evidence", "search"} for name in op_names
    ):
        if "lookup_evidence" in available:
            augmented.append(
                {
                    "kind": "operator",
                    "op_name": "lookup_evidence",
                    "params": {"query": query.strip(), "limit": 5, "max_refs": 2},
                }
            )
        elif "search" in available:
            augmented.append(
                {
                    "kind": "operator",
                    "op_name": "search",
                    "params": {"query": query.strip(), "limit": 5},
                }
            )
            augmented.append({"kind": "search_ref_fetch_span", "max_refs": 2})

    return augmented


def recovery_steps_for_failure(
    failed_op_name: str,
    query: str,
    available_operator_names: list[str],
    attempted_operator_names: set[str],
) -> list[dict[str, Any]]:
    available = set(available_operator_names)

    if failed_op_name in {"fetch_rows", "aggregate", "compare", "discover_dimensions", "list_versions", "diff"}:
        if "lookup_evidence" in available and "lookup_evidence" not in attempted_operator_names:
            return [
                {
                    "kind": "operator",
                    "op_name": "lookup_evidence",
                    "params": {"query": query.strip(), "limit": 5, "max_refs": 2},
                }
            ]
        if "search" in available and "search" not in attempted_operator_names:
            return [
                {
                    "kind": "operator",
                    "op_name": "search",
                    "params": {"query": query.strip(), "limit": 5},
                },
                {"kind": "search_ref_fetch_span", "max_refs": 2},
            ]

    if failed_op_name in {"lookup_evidence", "search"}:
        if (
            "fetch_rows" in available
            and "fetch_rows" not in attempted_operator_names
            and structured_lookup_requested(query)
        ):
            return [default_structured_lookup_step()]

    return []


def planner_steps_for_run(
    query: str,
    planner_hints: dict[str, Any] | None,
    plan_request: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if should_short_circuit_perf_probe(query, planner_hints):
        return []

    available_operator_names = available_operator_names_for_plan_request(plan_request)
    if isinstance(planner_hints, dict):
        recommended_path = planner_hints.get("recommended_path")
        if isinstance(recommended_path, list):
            normalized = [
                step for raw in recommended_path if (step := normalize_planner_step(raw)) is not None
            ]
            if normalized:
                return ensure_multi_clause_coverage(query, normalized, available_operator_names)

    return ensure_multi_clause_coverage(
        query,
        default_mock_plan(query),
        available_operator_names,
    )


def normalize_operator_response(resp: dict[str, Any]) -> Any:
    if not isinstance(resp, dict):
        return {"error": "invalid_operator_response"}
    if resp.get("ok") is False:
        return {
            "error": {
                "terminal_mode": resp.get("terminal_mode"),
                "result": resp.get("result"),
            }
        }
    result = resp.get("result")
    return result if result is not None else {}


def context_budget_from_plan_request(plan_request: dict[str, Any] | None) -> dict[str, int]:
    defaults = {
        "max_evidence_units": 6,
        "max_total_chars": 2400,
        "max_structured_rows": 6,
        "max_inline_citations": 4,
    }
    if not isinstance(plan_request, dict):
        return defaults
    raw = plan_request.get("context_budget")
    if not isinstance(raw, dict):
        return defaults
    budget = defaults.copy()
    for key in list(defaults.keys()):
        value = raw.get(key)
        if isinstance(value, int) and value > 0:
            budget[key] = value
    return budget


def preferred_evidence_pack_mode(
    plan_request: dict[str, Any] | None,
    planner_hints: dict[str, Any] | None,
) -> str:
    if isinstance(plan_request, dict):
        value = plan_request.get("preferred_evidence_pack_mode")
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    intent = planner_hints.get("intent") if isinstance(planner_hints, dict) else None
    if not isinstance(intent, str):
        return "compact"
    mapping = {
        "structured_lookup": "raw",
        "structured_aggregation": "summary",
        "evidence_lookup": "mixed",
        "version_review": "diff",
        "structured_evidence_lookup": "mixed",
        "structured_aggregation_evidence": "mixed",
        "structured_version_review": "diff",
        "default": "compact",
    }
    return mapping.get(intent.strip().lower(), "compact")


def compact_text(value: str, max_chars: int) -> str:
    normalized = " ".join(value.split()).strip()
    if len(normalized) <= max_chars:
        return normalized
    return normalized[: max(1, max_chars - 3)].rstrip() + "..."


def summarize_scalar(value: Any, max_chars: int) -> str | None:
    if isinstance(value, str):
        normalized = compact_text(value, max_chars)
        return normalized or None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return None


def summarize_content_for_context(content: Any, *, max_chars: int, max_rows: int) -> Any:
    scalar = summarize_scalar(content, max_chars)
    if scalar is not None:
        return scalar

    if isinstance(content, dict):
        rows = content.get("rows")
        if isinstance(rows, list):
            packed_rows = []
            for row in rows[: max_rows]:
                if not isinstance(row, dict):
                    continue
                packed_row = {}
                group = row.get("group")
                if isinstance(group, dict):
                    packed_row["group"] = group
                metrics = row.get("metrics")
                if isinstance(metrics, list):
                    packed_row["metrics"] = metrics[: max_rows]
                for key, value in row.items():
                    if key in {"group", "metrics"}:
                        continue
                    scalar_value = summarize_scalar(value, 48)
                    if scalar_value is not None:
                        packed_row[key] = scalar_value
                if packed_row:
                    packed_rows.append(packed_row)
            packed = {"rows": packed_rows}
            if len(rows) > len(packed_rows):
                packed["_truncated_rows"] = len(rows) - len(packed_rows)
            return packed

        scalar_items: dict[str, Any] = {}
        for key, value in content.items():
            scalar_value = summarize_scalar(value, 64)
            if scalar_value is not None:
                scalar_items[key] = scalar_value
            if len(scalar_items) >= 4:
                break
        if scalar_items:
            return scalar_items
        return compact_text(json.dumps(content, ensure_ascii=False, sort_keys=True), max_chars)

    if isinstance(content, list):
        packed_values = []
        for value in content[: max_rows]:
            scalar = summarize_scalar(value, 48)
            if scalar is not None:
                packed_values.append(scalar)
        if packed_values:
            return packed_values
        return compact_text(json.dumps(content[:max_rows], ensure_ascii=False), max_chars)

    return compact_text(str(content), max_chars)


def pack_evidence_unit_for_context(
    unit: dict[str, Any],
    *,
    query: str,
    context_budget: dict[str, int],
    preferred_mode: str,
) -> dict[str, Any]:
    packed = {
        "evidence_unit_id": unit.get("evidence_unit_id"),
        "source_system": unit.get("source_system"),
        "object_id": unit.get("object_id"),
        "version_id": unit.get("version_id"),
        "content_type": unit.get("content_type"),
        "span_or_row_spec": unit.get("span_or_row_spec"),
        "content_hash": unit.get("content_hash"),
    }
    per_item_chars = max(96, context_budget["max_total_chars"] // max(1, context_budget["max_evidence_units"]))
    content = summarize_content_for_context(
        unit.get("content"),
        max_chars=per_item_chars if preferred_mode != "raw" else min(per_item_chars * 2, 320),
        max_rows=context_budget["max_structured_rows"],
    )
    packed["content"] = content
    packed["_pecr_context_pack"] = {
        "mode": preferred_mode,
        "query": compact_text(query, 64),
        "approx_chars": len(json.dumps(content, ensure_ascii=False))
        if content is not None
        else 0,
        "citation_ready": bool(unit.get("evidence_unit_id")),
    }
    return packed


def pack_tool_result_for_context(
    result: Any,
    *,
    query: str,
    context_budget: dict[str, int],
    preferred_mode: str,
) -> Any:
    if not isinstance(result, (dict, list)):
        return result

    if isinstance(result, list):
        packed = [
            pack_evidence_unit_for_context(
                item,
                query=query,
                context_budget=context_budget,
                preferred_mode=preferred_mode,
            )
            if isinstance(item, dict) and "evidence_unit_id" in item
            else item
            for item in result[: context_budget["max_evidence_units"]]
        ]
        if len(result) > len(packed):
            return {
                "items": packed,
                "_pecr_context_pack": {
                    "mode": preferred_mode,
                    "truncated_items": len(result) - len(packed),
                },
            }
        return packed

    if "refs" in result and isinstance(result["refs"], list):
        refs = result["refs"][: context_budget["max_evidence_units"]]
        packed = dict(result)
        packed["refs"] = refs
        packed["_pecr_context_pack"] = {
            "mode": preferred_mode,
            "truncated_refs": max(0, len(result["refs"]) - len(refs)),
        }
        return packed

    if "rows" in result and isinstance(result["rows"], list):
        packed = summarize_content_for_context(
            result,
            max_chars=context_budget["max_total_chars"],
            max_rows=context_budget["max_structured_rows"],
        )
        if isinstance(packed, dict):
            packed["_pecr_context_pack"] = {
                "mode": preferred_mode,
                "query": compact_text(query, 64),
            }
            return packed
        return result

    if "evidence_unit_id" in result:
        return pack_evidence_unit_for_context(
            result,
            query=query,
            context_budget=context_budget,
            preferred_mode=preferred_mode,
        )

    packed_summary = summarize_content_for_context(
        result,
        max_chars=context_budget["max_total_chars"],
        max_rows=context_budget["max_structured_rows"],
    )
    if isinstance(packed_summary, dict):
        packed_summary["_pecr_context_pack"] = {"mode": preferred_mode}
        return packed_summary
    return packed_summary


def parse_bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def build_openai_backend_kwargs() -> dict[str, Any]:
    model_name = os.getenv("PECR_RLM_MODEL_NAME", "").strip()
    if not model_name:
        raise ValueError("PECR_RLM_MODEL_NAME is required when PECR_RLM_BACKEND=openai")

    kwargs: dict[str, Any] = {"model_name": model_name}
    base_url = os.getenv("PECR_RLM_BASE_URL", "").strip()
    if base_url:
        kwargs["base_url"] = base_url

    api_key = os.getenv("PECR_RLM_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY or PECR_RLM_API_KEY is required when PECR_RLM_BACKEND=openai"
        )
    kwargs["api_key"] = api_key

    return kwargs


def load_rlm_class():
    try:
        from rlm import RLM
    except Exception as exc:  # pragma: no cover - import error path depends on env
        raise RuntimeError(f"failed to import vendored RLM runtime: {exc}") from exc
    return RLM


def build_pecr_context(
    query: str,
    budget: Budget,
    planner_hints: dict[str, Any] | None,
    plan_request: dict[str, Any] | None,
) -> str:
    context_budget = context_budget_from_plan_request(plan_request)
    preferred_mode = preferred_evidence_pack_mode(plan_request, planner_hints)
    payload = {
        "query": query,
        "planner_hints": planner_hints or {},
        "budget": {
            "max_operator_calls": budget.max_operator_calls,
            "max_bytes": budget.max_bytes,
            "max_wallclock_ms": budget.max_wallclock_ms,
            "max_recursion_depth": budget.max_recursion_depth,
            "max_parallelism": budget.max_parallelism,
        },
        "context_budget": context_budget,
        "preferred_evidence_pack_mode": preferred_mode,
        "available_operator_names": (
            plan_request.get("available_operator_names", []) if isinstance(plan_request, dict) else []
        ),
        "operator_schemas": (
            plan_request.get("operator_schemas", []) if isinstance(plan_request, dict) else []
        ),
        "recommended_path": (
            planner_hints.get("recommended_path", []) if isinstance(planner_hints, dict) else []
        ),
        "prior_observations": (
            plan_request.get("prior_observations", []) if isinstance(plan_request, dict) else []
        ),
        "clarification_opportunities": (
            plan_request.get("clarification_opportunities", [])
            if isinstance(plan_request, dict)
            else []
        ),
        "failure_feedback": (
            plan_request.get("failure_feedback", []) if isinstance(plan_request, dict) else []
        ),
        "instructions": [
            "Use only PECR operator tools to inspect sources.",
            "Prefer evidence-backed answers over guesses.",
            "If evidence is insufficient, answer with UNKNOWN: insufficient evidence to answer the query.",
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def build_custom_tools(
    bridge: Bridge,
    *,
    budget: Budget,
    query: str,
    planner_hints: dict[str, Any] | None,
    plan_request: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, int]]:
    tool_state = {"operator_calls_used": 0, "depth_used": 0}
    context_budget = context_budget_from_plan_request(plan_request)
    preferred_mode = preferred_evidence_pack_mode(plan_request, planner_hints)
    available_operator_names = []
    operator_schemas_by_name: dict[str, dict[str, Any]] = {}
    if isinstance(plan_request, dict):
        raw_names = plan_request.get("available_operator_names")
        if isinstance(raw_names, list):
            available_operator_names = [
                name.strip() for name in raw_names if isinstance(name, str) and name.strip()
            ]
        raw_schemas = plan_request.get("operator_schemas")
        if isinstance(raw_schemas, list):
            for raw_schema in raw_schemas:
                if not isinstance(raw_schema, dict):
                    continue
                name = raw_schema.get("name")
                if not isinstance(name, str) or not name.strip():
                    continue
                operator_schemas_by_name[name.strip()] = raw_schema

    def note_call(call_count: int) -> None:
        tool_state["operator_calls_used"] += call_count
        if call_count > 0:
            tool_state["depth_used"] = max(tool_state["depth_used"], 1)

    def call_operator(op_name: str, **params: Any) -> Any:
        note_call(1)
        return pack_tool_result_for_context(
            normalize_operator_response(
                bridge.call_operator(depth=0, op_name=op_name, params=params)
            ),
            query=query,
            context_budget=context_budget,
            preferred_mode=preferred_mode,
        )

    def call_operator_batch(calls: list[dict[str, Any]]) -> list[Any]:
        note_call(len(calls))
        results = bridge.call_operator_batch(depth=0, calls=calls)
        return [
            pack_tool_result_for_context(
                normalize_operator_response(result),
                query=query,
                context_budget=context_budget,
                preferred_mode=preferred_mode,
            )
            for result in results
        ]

    def search_ref_fetch_span(refs: list[dict[str, Any]], max_refs: int = 2) -> list[Any]:
        calls: list[dict[str, Any]] = []
        if not isinstance(refs, list):
            return []
        for raw_ref in refs[: max(0, int(max_refs))]:
            if not isinstance(raw_ref, dict):
                continue
            object_id = raw_ref.get("object_id")
            if not isinstance(object_id, str) or not object_id.strip():
                continue
            params: dict[str, Any] = {"object_id": object_id}
            start_byte = raw_ref.get("start_byte")
            end_byte = raw_ref.get("end_byte")
            if isinstance(start_byte, int):
                params["start_byte"] = start_byte
            if isinstance(end_byte, int):
                params["end_byte"] = end_byte
            calls.append({"op_name": "fetch_span", "params": params})
        if not calls:
            return []
        return call_operator_batch(calls)

    custom_tools: dict[str, Any] = {
        "call_operator": {
            "tool": call_operator,
            "description": (
                "Call a PECR gateway operator by name. Pass keyword arguments that match the operator params. "
                "Use only names from AVAILABLE_OPERATORS."
            ),
        },
        "call_operator_batch": {
            "tool": call_operator_batch,
            "description": (
                "Call multiple PECR operators concurrently. Pass a list of dicts shaped like "
                "{'op_name': 'search', 'params': {...}}."
            ),
        },
        "search_ref_fetch_span": {
            "tool": search_ref_fetch_span,
            "description": (
                "Given search refs, fetch the referenced spans through batched fetch_span calls. "
                "Useful after search returns refs."
            ),
        },
        "AVAILABLE_OPERATORS": {
            "tool": available_operator_names,
            "description": "Allowlisted PECR operators available for this run.",
        },
        "PECR_OPERATOR_SCHEMAS": {
            "tool": plan_request.get("operator_schemas", []) if isinstance(plan_request, dict) else [],
            "description": "Structured PECR operator schema metadata, including descriptions and params.",
        },
        "PECR_QUERY": {
            "tool": query,
            "description": "The original user query for this run.",
        },
        "PECR_PLANNER_HINTS": {
            "tool": planner_hints or {},
            "description": "Controller-provided planner hints and recommended path.",
        },
        "PECR_PRIOR_OBSERVATIONS": {
            "tool": (
                plan_request.get("prior_observations", []) if isinstance(plan_request, dict) else []
            ),
            "description": "Structured observations from prior planner attempts for this run.",
        },
        "PECR_CLARIFICATION_OPPORTUNITIES": {
            "tool": (
                plan_request.get("clarification_opportunities", [])
                if isinstance(plan_request, dict)
                else []
            ),
            "description": "Clarification prompts the controller thinks may safely narrow the ask.",
        },
        "PECR_FAILURE_FEEDBACK": {
            "tool": (
                plan_request.get("failure_feedback", []) if isinstance(plan_request, dict) else []
            ),
            "description": "Structured failure feedback from earlier safe attempts in this run.",
        },
    }

    for op_name in available_operator_names:
        def op_tool(_op_name: str = op_name, **kwargs: Any) -> Any:
            return call_operator(_op_name, **kwargs)

        schema = operator_schemas_by_name.get(op_name, {})
        required_params = schema.get("required_params", [])
        optional_params = schema.get("optional_params", [])
        description_parts = []
        if isinstance(schema.get("description"), str) and schema["description"].strip():
            description_parts.append(schema["description"].strip())
        if isinstance(required_params, list) and required_params:
            description_parts.append(
                "Required params: " + ", ".join(
                    param for param in required_params if isinstance(param, str) and param.strip()
                )
            )
        if isinstance(optional_params, list) and optional_params:
            description_parts.append(
                "Optional params: " + ", ".join(
                    param for param in optional_params if isinstance(param, str) and param.strip()
                )
            )
        if not description_parts:
            description_parts.append(
                f"Call the PECR '{op_name}' operator directly. Keyword arguments become the operator params."
            )

        custom_tools[op_name] = {
            "tool": op_tool,
            "description": " ".join(description_parts),
        }

    return custom_tools, tool_state


def run_openai(
    bridge: Bridge,
    query: str,
    budget: Budget,
    planner_hints: dict[str, Any] | None = None,
    plan_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    RLM = load_rlm_class()
    backend_kwargs = build_openai_backend_kwargs()
    custom_tools, tool_state = build_custom_tools(
        bridge,
        budget=budget,
        query=query,
        planner_hints=planner_hints,
        plan_request=plan_request,
    )
    context = build_pecr_context(query, budget, planner_hints, plan_request)

    rlm = RLM(
        backend="openai",
        backend_kwargs=backend_kwargs,
        environment="local",
        max_depth=parse_positive_int_env("PECR_RLM_MAX_DEPTH", 1),
        max_iterations=parse_positive_int_env("PECR_RLM_MAX_ITERATIONS", 8),
        max_timeout=budget.max_wallclock_ms / 1000.0 if budget.max_wallclock_ms > 0 else None,
        verbose=parse_bool_env("PECR_RLM_VERBOSE", False),
        custom_tools=custom_tools,
    )
    completion = rlm.completion(context, root_prompt=query)
    final_answer = completion.response.strip()
    if not final_answer:
        final_answer = "UNKNOWN: insufficient evidence to answer the query."

    return {
        "final_answer": final_answer,
        "stop_reason": "rlm_openai_done",
        "operator_calls_used": tool_state["operator_calls_used"],
        "depth_used": tool_state["depth_used"],
    }


def run_mock(
    bridge: Bridge,
    query: str,
    budget: Budget,
    planner_hints: dict[str, Any] | None = None,
    plan_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    prompt = first_clarification_prompt(plan_request)
    if prompt is not None:
        return {
            "final_answer": render_clarification_prompt(prompt),
            "stop_reason": "clarification_requested",
            "operator_calls_used": 0,
            "depth_used": 0,
        }

    search_refs: list[dict[str, Any]] = []
    operator_calls_used = 0
    stop_reason = "plan_complete"
    executed_steps = 0
    recovered_from: str | None = None
    attempted_operator_names: set[str] = set()

    def do(depth: int, op_name: str, params: Any) -> dict[str, Any]:
        nonlocal operator_calls_used
        operator_calls_used += 1
        return bridge.call_operator(depth=depth, op_name=op_name, params=params)

    planned_steps = planner_steps_for_run(query, planner_hints, plan_request)
    max_depth = max(0, budget.max_recursion_depth)
    depth = 0

    while depth < len(planned_steps):
        step = planned_steps[depth]
        if depth >= max_depth:
            stop_reason = "budget_max_recursion_depth"
            break

        executed_steps = depth + 1

        if step["kind"] == "operator":
            op_name = step["op_name"]
            params = step.get("params")
            if op_name == "search" and not query.strip():
                depth += 1
                continue

            attempted_operator_names.add(op_name)
            resp = do(depth, op_name, params)
            if resp.get("ok") is False:
                fallback_steps = recovery_steps_for_failure(
                    op_name,
                    query,
                    available_operator_names_for_plan_request(plan_request),
                    attempted_operator_names,
                )
                if fallback_steps:
                    recovered_from = op_name
                    planned_steps = planned_steps[: depth + 1] + fallback_steps
                    depth += 1
                    continue
                stop_reason = "operator_error"
                break
            if op_name == "search":
                result = resp.get("result") if isinstance(resp.get("result"), dict) else {}
                refs = result.get("refs") if isinstance(result, dict) else None
                if isinstance(refs, list):
                    search_refs = [r for r in refs if isinstance(r, dict)]
            depth += 1
            continue

        if step["kind"] == "search_ref_fetch_span":
            calls: list[dict[str, Any]] = []
            max_refs = int(step.get("max_refs", 2))
            for r in search_refs[:max_refs]:
                object_id = r.get("object_id")
                if isinstance(object_id, str) and object_id.strip():
                    params = {"object_id": object_id}
                    start_byte = r.get("start_byte")
                    end_byte = r.get("end_byte")
                    if isinstance(start_byte, int):
                        params["start_byte"] = start_byte
                    if isinstance(end_byte, int):
                        params["end_byte"] = end_byte
                    calls.append({"op_name": "fetch_span", "params": params})

            if calls and budget.max_parallelism > 1:
                operator_calls_used += len(bridge.call_operator_batch(depth=depth, calls=calls))
                depth += 1
                continue

            for call in calls:
                do(depth, call["op_name"], call["params"])
            depth += 1
            continue

    if max_depth <= 0:
        stop_reason = "budget_max_recursion_depth"
    elif recovered_from is not None and stop_reason == "plan_complete":
        stop_reason = f"recovered_after_{recovered_from}"

    final_answer = find_final_answer("FINAL(UNKNOWN: insufficient evidence to answer the query.)")
    if final_answer is None:
        final_answer = "UNKNOWN: insufficient evidence to answer the query."
    return {
        "final_answer": final_answer,
        "stop_reason": stop_reason,
        "operator_calls_used": operator_calls_used,
        "depth_used": executed_steps,
    }


def emit_error(
    *,
    protocol_version: int | None,
    reason: str,
    code: str,
    message: str,
    retryable: bool,
) -> None:
    payload: dict[str, Any] = {
        "type": "error",
        "reason": reason,
        "code": code,
        "message": message,
        "retryable": retryable,
    }
    if protocol_version is not None:
        payload["protocol_version"] = protocol_version
    write_json_line(payload)


def run_backend(
    backend: str,
    bridge: Bridge,
    query: str,
    budget: Budget,
    planner_hints: dict[str, Any] | None,
    plan_request: dict[str, Any] | None,
) -> dict[str, Any]:
    if backend == "mock":
        return run_mock(
            bridge,
            query,
            budget,
            planner_hints=planner_hints,
            plan_request=plan_request,
        )
    if backend == "openai":
        return run_openai(
            bridge,
            query,
            budget,
            planner_hints=planner_hints,
            plan_request=plan_request,
        )
    raise ValueError("supported PECR_RLM_BACKEND values in this build: mock, openai")


def handle_start_message(start: dict[str, Any], backend: str) -> None:
    if start.get("type") != "start":
        raise ValueError("expected start message")

    query = start.get("query")
    if not isinstance(query, str):
        raise ValueError("start.query must be a string")

    budget_raw = start.get("budget")
    if not isinstance(budget_raw, dict):
        raise ValueError("start.budget must be an object")
    budget = Budget.from_json(budget_raw)

    protocol_version = negotiate_protocol_version(start)
    write_json_line(
        {
            "type": "start_ack",
            "protocol_version": protocol_version,
            "backend": backend,
            "session_mode": "persistent_worker",
        }
    )

    bridge = Bridge()
    planner_hints = start.get("planner_hints")
    if not isinstance(planner_hints, dict):
        planner_hints = None
    plan_request = start.get("plan_request")
    if not isinstance(plan_request, dict):
        plan_request = None

    result = run_backend(
        backend,
        bridge,
        query,
        budget,
        planner_hints=planner_hints,
        plan_request=plan_request,
    )
    write_json_line(
        {
            "type": "done",
            "protocol_version": protocol_version,
            "final_answer": result["final_answer"],
            "stop_reason": result["stop_reason"],
            "operator_calls_used": result["operator_calls_used"],
            "depth_used": result["depth_used"],
        }
    )


def main() -> int:
    ensure_vendor_rlm_on_path()
    backend = os.getenv("PECR_RLM_BACKEND", "mock").strip().lower() or "mock"

    while True:
        try:
            start = read_json_line()
        except EOFError:
            return 0
        except ValueError as exc:
            eprint(str(exc))
            return 2

        try:
            handle_start_message(start, backend)
        except ValueError as exc:
            emit_error(
                protocol_version=None,
                reason="bridge_invalid_request",
                code="ERR_RLM_BRIDGE_PROTOCOL",
                message=str(exc),
                retryable=False,
            )
        except RuntimeError as exc:
            emit_error(
                protocol_version=SUPPORTED_PROTOCOL_VERSION,
                reason="bridge_backend_unavailable",
                code="ERR_RLM_BACKEND_UNAVAILABLE",
                message=str(exc),
                retryable=True,
            )
        except Exception as exc:  # pragma: no cover - depends on runtime/backend availability
            emit_error(
                protocol_version=SUPPORTED_PROTOCOL_VERSION,
                reason="bridge_backend_runtime_error",
                code="ERR_RLM_BACKEND_RUNTIME",
                message=f"PECR_RLM_BACKEND={backend} failed: {exc}",
                retryable=True,
            )


if __name__ == "__main__":
    raise SystemExit(main())
