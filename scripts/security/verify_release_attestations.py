#!/usr/bin/env python3
"""Verify GitHub artifact attestations for release binaries and images."""

from __future__ import annotations

import argparse
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
) -> None:
    """Run a command and raise on failure, optionally retrying for eventual consistency."""
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
            return

        if attempt < retries:
            print(
                f"Command failed (attempt {attempt}/{retries}); retrying in {retry_delay_seconds}s...",
                file=sys.stderr,
            )
            time.sleep(retry_delay_seconds)
            continue

        raise RuntimeError(
            f"Command failed after {retries} attempt(s): {' '.join(command)}"
        )


def parse_image_refs(manifest_path: Path) -> list[str]:
    entries: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=":
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


def verify_attestation(
    subject: str,
    *,
    repo: str,
    signer_workflow: str,
    source_ref: str | None,
    deny_self_hosted_runners: bool,
    bundle_from_oci: bool = False,
) -> None:
    command = [
        "gh",
        "attestation",
        "verify",
        subject,
        "--repo",
        repo,
        "--signer-workflow",
        signer_workflow,
    ]

    if source_ref:
        command.extend(["--source-ref", source_ref])
    if deny_self_hosted_runners:
        command.append("--deny-self-hosted-runners")
    if bundle_from_oci:
        command.append("--bundle-from-oci")

    # Attestations can take a short moment to become queryable after creation.
    run_command(command, retries=5, retry_delay_seconds=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify release artifact and container image attestations."
    )
    parser.add_argument(
        "--release-dir",
        type=Path,
        default=Path("release"),
        help="Directory containing release artifacts (default: release).",
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository in OWNER/REPO format for attestation verification scope.",
    )
    parser.add_argument(
        "--signer-workflow",
        required=True,
        help="Expected signer workflow path (OWNER/REPO/.github/workflows/<file>.yml).",
    )
    parser.add_argument(
        "--source-ref",
        default=None,
        help="Optional expected source ref (for example refs/tags/v1.2.3).",
    )
    parser.add_argument(
        "--deny-self-hosted-runners",
        action="store_true",
        help="Fail attestation verification for self-hosted runner attestations.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    release_dir: Path = args.release_dir

    if not release_dir.exists():
        print(f"Release directory not found: {release_dir}", file=sys.stderr)
        return 1

    checksums_path = release_dir / "SHA256SUMS.txt"
    image_manifest_path = release_dir / "image-digests.txt"
    tarballs = sorted(release_dir.glob("*.tar.gz"))

    missing = [
        str(path)
        for path in (checksums_path, image_manifest_path)
        if not path.is_file()
    ]
    if missing:
        print("Missing required release files:", file=sys.stderr)
        for path in missing:
            print(f"  - {path}", file=sys.stderr)
        return 1
    if not tarballs:
        print(f"No release tarballs found in {release_dir}", file=sys.stderr)
        return 1

    run_command(["sha256sum", "--check", "SHA256SUMS.txt"], cwd=release_dir)

    local_subjects = [*tarballs, checksums_path, image_manifest_path]
    for path in local_subjects:
        verify_attestation(
            str(path),
            repo=args.repo,
            signer_workflow=args.signer_workflow,
            source_ref=args.source_ref,
            deny_self_hosted_runners=args.deny_self_hosted_runners,
            bundle_from_oci=False,
        )

    image_refs = parse_image_refs(image_manifest_path)
    for image_ref in image_refs:
        verify_attestation(
            f"oci://{image_ref}",
            repo=args.repo,
            signer_workflow=args.signer_workflow,
            source_ref=args.source_ref,
            deny_self_hosted_runners=args.deny_self_hosted_runners,
            bundle_from_oci=True,
        )

    print("OK: release artifact and image attestations verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
