#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLANNER_ROOT = ROOT / "beam" / "pecr_planner"


def default_mix_cmd() -> str:
    return (
        shutil.which("mix")
        or shutil.which("mix.bat")
        or shutil.which("mix.cmd")
        or "mix"
    )


def planner_command(
    request: dict[str, Any],
    *,
    mix_cmd: str,
) -> tuple[list[str], dict[str, str]]:
    budget = request.get("budget") or {}
    planner_hints = request.get("planner_hints") or {}
    recovery_context = request.get("recovery_context") or {}
    planner_env = {
        "PECR_PLANNER_SCHEMA_VERSION": str(request.get("schema_version", 1)),
        "PECR_PLANNER_QUERY": str(request.get("query") or ""),
        "PECR_PLANNER_INTENT": str(planner_hints.get("intent") or "default"),
        "PECR_PLANNER_AVAILABLE_OPERATORS": ",".join(
            str(operator_name)
            for operator_name in (request.get("available_operator_names") or [])
        ),
        "PECR_PLANNER_ALLOW_SEARCH_REF_FETCH_SPAN": (
            "1" if request.get("allow_search_ref_fetch_span") is True else "0"
        ),
        "PECR_PLANNER_MAX_OPERATOR_CALLS": str(budget.get("max_operator_calls", 10)),
        "PECR_PLANNER_MAX_BYTES": str(budget.get("max_bytes", 2048)),
        "PECR_PLANNER_MAX_WALLCLOCK_MS": str(budget.get("max_wallclock_ms", 1000)),
        "PECR_PLANNER_MAX_RECURSION_DEPTH": str(
            budget.get("max_recursion_depth", 3)
        ),
    }

    max_parallelism = budget.get("max_parallelism")
    if max_parallelism is not None:
        planner_env["PECR_PLANNER_MAX_PARALLELISM"] = str(max_parallelism)
    if recovery_context:
        failed_step = str(recovery_context.get("failed_step") or "").strip()
        failure_terminal_mode = str(
            recovery_context.get("failure_terminal_mode") or ""
        ).strip()
        if failed_step:
            planner_env["PECR_PLANNER_RECOVERY_FAILED_STEP"] = failed_step
        if failure_terminal_mode:
            planner_env["PECR_PLANNER_RECOVERY_FAILURE_TERMINAL_MODE"] = (
                failure_terminal_mode
            )

    return [mix_cmd, "run", "scripts/shadow_cli.exs"], planner_env


def decode_b64(value: str | None) -> str | None:
    if not value:
        return None
    return base64.b64decode(value.encode("ascii")).decode("utf-8")


def parse_cli_response(stdout: str) -> tuple[int, dict[str, Any]]:
    fields: dict[str, str] = {}
    steps: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("step="):
            _, encoded_step = line.split("=", 1)
            parts = encoded_step.split("|")
            if parts[0] == "operator" and len(parts) >= 2:
                steps.append(
                    {
                        "kind": "operator",
                        "op_name": parts[1],
                        "params": {},
                    }
                )
            elif parts[0] == "search_ref_fetch_span" and len(parts) >= 2:
                steps.append(
                    {
                        "kind": "search_ref_fetch_span",
                        "max_refs": int(parts[1]),
                    }
                )
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value

    status = fields.get("status")
    if status == "ok":
        payload: dict[str, Any] = {
            "schema_version": int(fields.get("schema_version", "1")),
            "steps": steps,
        }
        planner_summary = decode_b64(fields.get("planner_summary_b64"))
        if planner_summary:
            payload["planner_summary"] = planner_summary
        return HTTPStatus.OK, payload

    errors = decode_b64(fields.get("errors_b64")) or "unknown planner error"
    return HTTPStatus.BAD_GATEWAY, {
        "error": fields.get("error_status", "planner_error"),
        "details": errors.splitlines(),
    }


class PlannerBridgeHandler(BaseHTTPRequestHandler):
    planner_root: Path
    mix_cmd: str

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown route")
            return

        self.respond(
            HTTPStatus.OK,
            {
                "status": "ok",
                "planner_root": str(self.planner_root),
                "mix_cmd": self.mix_cmd,
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/plan":
            self.send_error(HTTPStatus.NOT_FOUND, "unknown route")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
            return

        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except json.JSONDecodeError:
            self.respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return

        if not isinstance(payload, dict):
            self.respond(HTTPStatus.BAD_REQUEST, {"error": "plan_request_must_be_object"})
            return

        command, planner_env = planner_command(payload, mix_cmd=self.mix_cmd)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=self.planner_root,
            env={**os.environ, **planner_env},
            check=False,
        )
        if result.returncode not in (0, 2):
            self.respond(
                HTTPStatus.BAD_GATEWAY,
                {
                    "error": "planner_process_failed",
                    "returncode": result.returncode,
                    "stderr": result.stderr.strip(),
                },
            )
            return

        status, response_payload = parse_cli_response(result.stdout)
        self.respond(status, response_payload)

    def log_message(self, format: str, *args: object) -> None:
        return

    def respond(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expose the Elixir shadow planner over a tiny local HTTP /plan bridge."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    parser.add_argument("--planner-root", type=Path, default=DEFAULT_PLANNER_ROOT)
    parser.add_argument("--mix-cmd", default=default_mix_cmd())
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    PlannerBridgeHandler.planner_root = args.planner_root.resolve()
    PlannerBridgeHandler.mix_cmd = args.mix_cmd

    server = ThreadingHTTPServer((args.host, args.port), PlannerBridgeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
