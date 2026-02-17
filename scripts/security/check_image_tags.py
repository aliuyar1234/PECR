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

ALLOW_MAJOR_ONLY_TAGS = {
    "debian",
}


def normalize_ref(ref: str) -> str:
    return ref.strip().strip("\"'").strip()


def image_name_without_tag(ref: str) -> str:
    image = ref
    if "@" in image:
        image = image.split("@", 1)[0]
    slash_idx = image.rfind("/")
    colon_idx = image.rfind(":")
    if colon_idx > slash_idx:
        image = image[:colon_idx]
    return image


def validate_ref(ref: str, require_digest: bool = False) -> str | None:
    ref = normalize_ref(ref)
    if not ref:
        return "empty image reference"

    if "@" in ref:
        _image, digest = ref.rsplit("@", 1)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            return f"invalid digest pin: {ref}"
        return None

    if require_digest:
        return f"missing digest pin: {ref}"

    slash_idx = ref.rfind("/")
    colon_idx = ref.rfind(":")
    has_explicit_tag = colon_idx > slash_idx
    if not has_explicit_tag:
        return f"missing explicit tag or digest: {ref}"

    tag = ref[colon_idx + 1 :].lower()
    if tag == "latest":
        return f"uses latest tag: {ref}"

    image_name = image_name_without_tag(ref)
    repository = image_name.split("/")[-1]
    if re.fullmatch(r"\d+(?:[-_].*)?", tag) and repository not in ALLOW_MAJOR_ONLY_TAGS:
        return f"uses mutable major-only tag: {ref}"

    return None


def main() -> int:
    violations: list[str] = []
    image_pattern = re.compile(r"^\s*image:\s*([^\s]+)\s*$")
    from_pattern = re.compile(r"^\s*FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+\S+)?\s*$", re.IGNORECASE)

    for target in TARGETS:
        lines = target.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            image_match = image_pattern.match(line)
            from_match = from_pattern.match(line)
            ref = (
                image_match.group(1)
                if image_match
                else (from_match.group(1) if from_match else None)
            )
            if ref is None:
                continue
            violation = validate_ref(ref, require_digest=bool(from_match))
            if violation is not None:
                violations.append(f"{target.relative_to(ROOT)}:{idx} {violation}")

    if violations:
        print("FAIL: image pinning policy violation")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print("OK: image references satisfy pinning policy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
