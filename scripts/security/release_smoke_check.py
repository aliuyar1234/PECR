#!/usr/bin/env python3
"""Post-release smoke checks for binaries, assets, and container images."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    retries: int = 1,
    retry_delay_seconds: int = 5,
) -> subprocess.CompletedProcess[str]:
    for attempt in range(1, retries + 1):
        print(f"+ {' '.join(shlex.quote(part) for part in command)}")
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        if completed.returncode == 0:
            return completed
        if attempt < retries:
            print(
                f"Command failed (attempt {attempt}/{retries}); retrying in {retry_delay_seconds}s...",
                file=sys.stderr,
            )
            time.sleep(retry_delay_seconds)
            continue
        raise RuntimeError(
            f"Command failed after {retries} attempts: {' '.join(command)}"
        )


def parse_tarball_filenames(checksums_path: Path) -> list[str]:
    names: list[str] = []
    for line_number, raw_line in enumerate(
        checksums_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(
                f"Invalid SHA256SUMS format at {checksums_path}:{line_number}"
            )
        filename = parts[1].strip()
        if filename.startswith("*"):
            filename = filename[1:]
        names.append(filename)
    if not names:
        raise ValueError(f"No tarball entries found in {checksums_path}")
    return names


def parse_image_refs(manifest_path: Path) -> list[str]:
    entries: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep != "=":
            raise ValueError(
                f"Invalid image digest manifest entry at {manifest_path}:{line_number}"
            )
        entries[key.strip()] = value.strip()

    refs: list[str] = []
    for key in ("gateway", "controller"):
        value = entries.get(key)
        if value is None:
            raise ValueError(f"Missing required '{key}' entry in {manifest_path}")
        if "@sha256:" not in value:
            raise ValueError(
                f"Expected digest-pinned image reference for '{key}', got: {value}"
            )
        refs.append(value)
    return refs


def fetch_release_assets(repo: str, tag: str) -> set[str]:
    completed = run_command(
        ["gh", "release", "view", tag, "--repo", repo, "--json", "assets"],
        retries=5,
        retry_delay_seconds=5,
    )
    payload = json.loads(completed.stdout)
    assets = payload.get("assets", [])
    return {str(asset.get("name", "")) for asset in assets if asset.get("name")}


def verify_release_assets(repo: str, tag: str, expected_assets: list[str]) -> None:
    asset_names = fetch_release_assets(repo, tag)
    missing = [name for name in expected_assets if name not in asset_names]
    if missing:
        raise RuntimeError(
            "Release asset check failed; missing assets: " + ", ".join(missing)
        )
    print("release asset smoke check: PASS")


def verify_image_ref(image_ref: str) -> None:
    try:
        run_command(
            ["docker", "buildx", "imagetools", "inspect", image_ref],
            retries=5,
            retry_delay_seconds=5,
        )
        return
    except RuntimeError:
        run_command(
            ["docker", "manifest", "inspect", image_ref],
            retries=5,
            retry_delay_seconds=5,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run post-release smoke checks for binaries/assets/images."
    )
    parser.add_argument(
        "--release-dir",
        type=Path,
        default=Path("release"),
        help="Directory containing release payload files.",
    )
    parser.add_argument("--repo", required=True, help="Repository in OWNER/REPO form.")
    parser.add_argument("--tag", required=True, help="Release tag to inspect.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    release_dir = args.release_dir
    checksums_path = release_dir / "SHA256SUMS.txt"
    image_manifest_path = release_dir / "image-digests.txt"

    if not checksums_path.is_file():
        print(f"Missing required file: {checksums_path}", file=sys.stderr)
        return 1
    if not image_manifest_path.is_file():
        print(f"Missing required file: {image_manifest_path}", file=sys.stderr)
        return 1

    run_command(["sha256sum", "--check", "SHA256SUMS.txt"], cwd=release_dir)
    tarball_names = parse_tarball_filenames(checksums_path)
    expected_assets = sorted(
        [*tarball_names, checksums_path.name, image_manifest_path.name]
    )
    verify_release_assets(args.repo, args.tag, expected_assets)

    image_refs = parse_image_refs(image_manifest_path)
    for image_ref in image_refs:
        verify_image_ref(image_ref)
    print("image smoke checks: PASS")

    print("OK: release smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

