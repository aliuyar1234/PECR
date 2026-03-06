#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - exercised in real environments
    raise SystemExit(
        "PyYAML is required to validate GitHub workflows. Install it or run in the project CI environment."
    ) from exc


SHA_REF_RE = re.compile(r"^[0-9a-f]{40}$")


def workflow_files(root: Path) -> list[Path]:
    files = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    return [path for path in files if path.is_file()]


def iter_uses_entries(node: object, breadcrumb: str = "$"):
    if isinstance(node, dict):
        for key, value in node.items():
            current = f"{breadcrumb}.{key}"
            if key == "uses" and isinstance(value, str):
                yield current, value
            yield from iter_uses_entries(value, current)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_uses_entries(value, f"{breadcrumb}[{index}]")


def validate_uses_value(value: str) -> str | None:
    if value.startswith("./") or value.startswith("docker://"):
        return None

    target, sep, ref = value.rpartition("@")
    if not sep or "/" not in target:
        return "must use a local path, docker reference, or owner/repo@<40-char-sha>"
    if not SHA_REF_RE.fullmatch(ref):
        return "must pin uses: references to a 40-character commit SHA"
    return None


def validate_workflow_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path}: YAML parse error: {exc}"]

    if not isinstance(payload, dict):
        return [f"{path}: workflow file must contain a mapping at the document root"]

    for breadcrumb, value in iter_uses_entries(payload):
        error = validate_uses_value(value)
        if error:
            errors.append(f"{path}:{breadcrumb}: {value!r} {error}")

    return errors


def validate_workflow_tree(root: Path) -> list[str]:
    errors: list[str] = []
    files = workflow_files(root)
    if not files:
        return [f"{root}: no workflow files found"]

    for path in files:
        errors.extend(validate_workflow_file(path))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate repository GitHub workflow files.")
    parser.add_argument(
        "workflow_root",
        nargs="?",
        default=".github/workflows",
        help="Path to the workflow directory (default: .github/workflows)",
    )
    args = parser.parse_args()

    root = Path(args.workflow_root)
    errors = validate_workflow_tree(root)
    if errors:
        print("FAIL: workflow validation detected issues:")
        for error in errors:
            print(f"  - {error}")
        return 1

    count = len(workflow_files(root))
    print(f"PASS: validated {count} workflow file(s) under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
