#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
TARGETS = [
    ROOT / "docker-compose.yml",
    ROOT / "docker" / "gateway.Dockerfile",
    ROOT / "docker" / "controller.Dockerfile",
]


def main() -> int:
    violations: list[str] = []
    image_pattern = re.compile(r"^\s*image:\s*([^\s]+)\s*$")
    from_pattern = re.compile(r"^\s*FROM\s+([^\s]+)")

    for target in TARGETS:
        lines = target.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            image_match = image_pattern.match(line)
            from_match = from_pattern.match(line)
            ref = image_match.group(1) if image_match else (from_match.group(1) if from_match else None)
            if ref is None:
                continue
            if ":latest" in ref:
                violations.append(f"{target.relative_to(ROOT)}:{idx} uses latest tag: {ref}")

    if violations:
        print("FAIL: image pinning policy violation")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print("OK: no latest-tag image references found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
