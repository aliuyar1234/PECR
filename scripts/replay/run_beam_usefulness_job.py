#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLANNER_ROOT = ROOT / "beam" / "pecr_planner"


def default_mix_cmd() -> str:
    return (
        shutil.which("mix")
        or shutil.which("mix.bat")
        or shutil.which("mix.cmd")
        or "mix"
    )


def decode_b64(value: str | None) -> str | None:
    if not value:
        return None
    return base64.b64decode(value.encode("ascii")).decode("utf-8")


def parse_job_cli_output(stdout: str) -> tuple[int, dict[str, object]]:
    fields: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("artifact="):
            _, encoded_artifact = line.split("=", 1)
            key, encoded_value = encoded_artifact.split("|", 1)
            artifacts[key] = decode_b64(encoded_value) or ""
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value

    status = fields.get("status")
    if status == "ok":
        payload: dict[str, object] = {
            "status": "ok",
            "job_name": fields.get("job_name"),
            "job_status": fields.get("job_status"),
            "exit_status": int(fields.get("exit_status", "0")),
            "duration_ms": int(fields.get("duration_ms", "0")),
            "started_at_unix_ms": int(fields.get("started_at_unix_ms", "0")),
            "finished_at_unix_ms": int(fields.get("finished_at_unix_ms", "0")),
            "summary": decode_b64(fields.get("summary_b64")) or "",
            "command": decode_b64(fields.get("command_b64")) or "",
            "output": decode_b64(fields.get("output_b64")) or "",
            "artifacts": artifacts,
        }
        errors = decode_b64(fields.get("errors_b64"))
        if errors:
            payload["errors"] = errors.splitlines()
        return 0, payload

    errors = decode_b64(fields.get("errors_b64")) or "unknown usefulness job error"
    return 2, {
        "status": "error",
        "error_status": fields.get("error_status", "unknown"),
        "errors": errors.splitlines(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a supervised BEAM usefulness job and emit parsed JSON."
    )
    parser.add_argument(
        "job_name",
        choices=["validate-benchmark", "planner-compare", "scenario-preview", "nightly-report"],
    )
    parser.add_argument("--store")
    parser.add_argument("--benchmark-manifest")
    parser.add_argument("--evaluation-name")
    parser.add_argument("--engine-mode", choices=["baseline", "beam_planner", "rlm"])
    parser.add_argument("--output-json")
    parser.add_argument("--output-md")
    parser.add_argument("--python")
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--await-timeout-ms", type=int)
    parser.add_argument("--planner-root", type=Path, default=DEFAULT_PLANNER_ROOT)
    parser.add_argument("--mix-cmd", default=default_mix_cmd())
    return parser


def command_from_args(args: argparse.Namespace) -> list[str]:
    command = [
        args.mix_cmd,
        "run",
        "--no-start",
        "scripts/usefulness_job.exs",
        args.job_name,
    ]
    optional_args = [
        ("--store", args.store),
        ("--benchmark-manifest", args.benchmark_manifest),
        ("--evaluation-name", args.evaluation_name),
        ("--engine-mode", args.engine_mode),
        ("--output-json", args.output_json),
        ("--output-md", args.output_md),
        ("--python", args.python),
    ]
    for flag, value in optional_args:
        if value:
            command.extend([flag, value])
    if args.timeout_ms:
        command.extend(["--timeout-ms", str(args.timeout_ms)])
    if args.await_timeout_ms:
        command.extend(["--await-timeout-ms", str(args.await_timeout_ms)])
    return command


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = command_from_args(args)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        cwd=args.planner_root,
        check=False,
    )

    if result.returncode not in (0, 2):
        print(
            json.dumps(
                {
                    "status": "error",
                    "error_status": "beam_job_process_failed",
                    "errors": [
                        f"job process returned {result.returncode}",
                        result.stderr.strip(),
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return result.returncode

    exit_code, payload = parse_job_cli_output(result.stdout)
    if result.stderr.strip():
        payload["stderr"] = result.stderr.strip()
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
