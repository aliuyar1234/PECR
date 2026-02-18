#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
VENDOR_RLM_DIR = ROOT / "vendor" / "rlm"
DECISIONS_FILE = ROOT / "DECISIONS.md"
DEFAULT_UPSTREAM = "https://github.com/alexzhang13/rlm.git"
DEFAULT_REF = "refs/heads/main"

LS_REMOTE_LINE_RE = re.compile(r"^([0-9a-f]{40})\s+\S+$")
PIN_LINE_RE = re.compile(
    r"(Vendored upstream `alexzhang13/rlm` at commit `)([0-9a-f]{40})(` into `vendor/rlm`\.)"
)


def run(cmd: Sequence[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def parse_ls_remote_output(text: str) -> str:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = LS_REMOTE_LINE_RE.match(line)
        if match is None:
            raise SystemExit(f"unexpected git ls-remote output line: {line!r}")
        return match.group(1)
    raise SystemExit("git ls-remote returned no matching ref")


def resolve_commit(upstream: str, ref: str) -> str:
    out = run(["git", "ls-remote", upstream, ref], cwd=ROOT)
    return parse_ls_remote_output(out)


def is_full_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", value))


def checkout_commit(*, upstream: str, commit: str, checkout_dir: Path) -> None:
    run(["git", "init", str(checkout_dir)], cwd=ROOT)
    run(["git", "-C", str(checkout_dir), "remote", "add", "origin", upstream], cwd=ROOT)
    run(["git", "-C", str(checkout_dir), "fetch", "--depth", "1", "origin", commit], cwd=ROOT)
    run(["git", "-C", str(checkout_dir), "checkout", "--detach", "FETCH_HEAD"], cwd=ROOT)


def replace_vendor_tree(*, source_checkout: Path, vendor_dir: Path) -> None:
    staging_dir = vendor_dir.parent / f".{vendor_dir.name}.sync-staging"
    backup_dir = vendor_dir.parent / f".{vendor_dir.name}.sync-backup"

    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    if backup_dir.exists():
        shutil.rmtree(backup_dir)

    shutil.copytree(source_checkout, staging_dir, ignore=shutil.ignore_patterns(".git"))

    if vendor_dir.exists():
        vendor_dir.rename(backup_dir)

    try:
        staging_dir.rename(vendor_dir)
    except Exception:
        if vendor_dir.exists():
            shutil.rmtree(vendor_dir)
        if backup_dir.exists():
            backup_dir.rename(vendor_dir)
        raise
    else:
        if backup_dir.exists():
            shutil.rmtree(backup_dir)


def update_decisions_pin_text(text: str, commit: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{commit}{match.group(3)}"

    updated, count = PIN_LINE_RE.subn(_replace, text, count=1)
    if count != 1:
        raise SystemExit(
            "failed to update DECISIONS.md pinned commit; expected exactly one D-0001 pin line"
        )
    return updated


def update_decisions_pin_file(commit: str) -> None:
    current = DECISIONS_FILE.read_text(encoding="utf-8")
    updated = update_decisions_pin_text(current, commit)
    if updated != current:
        DECISIONS_FILE.write_text(updated, encoding="utf-8")


def run_verification() -> None:
    verify_script = ROOT / "scripts" / "rlm" / "verify_vendor_rlm.py"
    subprocess.run([sys.executable, str(verify_script)], cwd=str(ROOT), check=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sync vendor/rlm from upstream and update DECISIONS pin."
    )
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM, help="Upstream git repository URL.")
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help="Git ref to resolve when --commit is omitted (default: refs/heads/main).",
    )
    parser.add_argument(
        "--commit",
        default="",
        help="Optional explicit 40-char commit SHA to sync instead of resolving --ref.",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip post-sync verification checks.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only resolve and print the target commit; do not modify files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.commit:
        commit = args.commit.lower()
        if not is_full_sha(commit):
            raise SystemExit("--commit must be a full 40-character hex SHA")
    else:
        commit = resolve_commit(args.upstream, args.ref)

    print(f"Resolved upstream commit: {commit}")
    print(f"Upstream: {args.upstream}")
    print(f"Ref: {args.ref}")

    if args.dry_run:
        return 0

    with tempfile.TemporaryDirectory(prefix="pecr-rlm-sync-") as temp_dir:
        checkout_dir = Path(temp_dir) / "checkout"
        checkout_commit(upstream=args.upstream, commit=commit, checkout_dir=checkout_dir)
        replace_vendor_tree(source_checkout=checkout_dir, vendor_dir=VENDOR_RLM_DIR)

    update_decisions_pin_file(commit)

    if not args.skip_verify:
        run_verification()

    synced_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("Sync complete.")
    print(f"Pinned commit: {commit}")
    print(f"Synced at (UTC): {synced_at}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
