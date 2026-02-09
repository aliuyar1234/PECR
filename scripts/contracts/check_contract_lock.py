#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "contracts" / "contract-lock.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def tracked_files() -> list[Path]:
    files = [ROOT / "docs" / "openapi" / "pecr.v1.yaml"]
    files.extend(sorted((ROOT / "crates" / "contracts" / "schemas").glob("*.json")))
    return files


def load_lock() -> dict:
    if not LOCK_PATH.exists():
        raise SystemExit(
            "contract lock missing: contracts/contract-lock.json. "
            "Run `python scripts/contracts/update_contract_lock.py`."
        )
    with LOCK_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    lock = load_lock()
    lock_files = lock.get("files", {})

    missing = []
    changed = []
    extra = []

    expected_rel = set()
    for file_path in tracked_files():
        rel = file_path.relative_to(ROOT).as_posix()
        expected_rel.add(rel)
        if not file_path.exists():
            missing.append(rel)
            continue
        actual_hash = sha256_file(file_path)
        locked_hash = lock_files.get(rel)
        if locked_hash is None:
            changed.append((rel, "<missing-in-lock>", actual_hash))
        elif locked_hash != actual_hash:
            changed.append((rel, locked_hash, actual_hash))

    for rel in sorted(lock_files.keys()):
        if rel not in expected_rel:
            extra.append(rel)

    if not missing and not changed and not extra:
        print("OK: contract lock is up to date")
        return 0

    print("FAIL: contract lock drift detected")
    if missing:
        print("missing tracked files:")
        for rel in missing:
            print(f"  - {rel}")
    if changed:
        print("changed files:")
        for rel, old, new in changed:
            print(f"  - {rel}")
            print(f"    lock:    {old}")
            print(f"    current: {new}")
    if extra:
        print("stale lock entries:")
        for rel in extra:
            print(f"  - {rel}")

    print("run: python scripts/contracts/update_contract_lock.py")
    return 1


if __name__ == "__main__":
    sys.exit(main())
