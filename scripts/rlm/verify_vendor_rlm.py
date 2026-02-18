#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
DECISIONS_FILE = ROOT / "DECISIONS.md"
UPSTREAM_PIN_FILE = ROOT / "vendor" / "rlm" / "UPSTREAM_PIN"
PIN_LINE_RE = re.compile(
    r"Vendored upstream `alexzhang13/rlm` at commit `([0-9a-f]{40})` into `vendor/rlm`\."
)

REQUIRED_PATHS = [
    ROOT / "scripts" / "rlm" / "pecr_rlm_bridge.py",
    ROOT / "vendor" / "rlm" / "rlm" / "__init__.py",
    ROOT / "vendor" / "rlm" / "rlm" / "core" / "rlm.py",
    ROOT / "vendor" / "rlm" / "rlm" / "utils" / "parsing.py",
]


def run(cmd: Sequence[str]) -> None:
    subprocess.run(list(cmd), cwd=str(ROOT), check=True)


def parse_pinned_commit(text: str) -> str:
    match = PIN_LINE_RE.search(text)
    if match is None:
        raise SystemExit(
            "missing D-0001 vendored commit pin in DECISIONS.md "
            "(expected line with `alexzhang13/rlm` commit hash)"
        )
    return match.group(1)


def read_pinned_commit() -> tuple[str, str]:
    if UPSTREAM_PIN_FILE.exists():
        pinned_commit = UPSTREAM_PIN_FILE.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9a-f]{40}", pinned_commit):
            raise SystemExit(
                f"invalid upstream pin in {UPSTREAM_PIN_FILE.relative_to(ROOT)} "
                "(expected 40-char lowercase hex commit hash)"
            )
        return pinned_commit, str(UPSTREAM_PIN_FILE.relative_to(ROOT))

    if DECISIONS_FILE.exists():
        text = DECISIONS_FILE.read_text(encoding="utf-8")
        return parse_pinned_commit(text), str(DECISIONS_FILE.relative_to(ROOT))

    raise SystemExit(
        "missing upstream pin: expected either "
        f"{UPSTREAM_PIN_FILE.relative_to(ROOT)} (preferred) "
        f"or {DECISIONS_FILE.relative_to(ROOT)}"
    )


def collect_missing_paths(paths: Sequence[Path]) -> list[Path]:
    return [path for path in paths if not path.exists()]


def verify_structure() -> None:
    pinned_commit, source = read_pinned_commit()
    print(f"Pinned commit ({source}): {pinned_commit}")

    missing_paths = collect_missing_paths(REQUIRED_PATHS)
    if missing_paths:
        formatted = "\n".join(f"- {path.relative_to(ROOT)}" for path in missing_paths)
        raise SystemExit(f"missing required RLM integration paths:\n{formatted}")


def verify_tests() -> None:
    run([sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_rlm_bridge.py"])
    run(
        [
            "cargo",
            "test",
            "-p",
            "pecr-controller",
            "--features",
            "rlm",
            "rlm_loop_executes_batch_calls_with_parallelism_budget",
        ]
    )


def main() -> int:
    verify_structure()
    verify_tests()
    print("RLM vendor verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
