#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path


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
    files = set()
    openapi_dir = ROOT / "docs" / "openapi"
    if openapi_dir.exists():
        files.update(openapi_dir.rglob("*.yaml"))
        files.update(openapi_dir.rglob("*.yml"))
        files.update(openapi_dir.rglob("*.json"))

    crates_dir = ROOT / "crates"
    if crates_dir.exists():
        files.update(crates_dir.rglob("schemas/*.json"))

    return sorted(path for path in files if path.is_file())


def main() -> None:
    files = tracked_files()
    lock = {
        "schema_version": 1,
        "generated_by": "scripts/contracts/update_contract_lock.py",
        "files": {},
    }

    for file_path in files:
        rel = file_path.relative_to(ROOT).as_posix()
        lock["files"][rel] = sha256_file(file_path)

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w", encoding="utf-8") as f:
        json.dump(lock, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"updated {LOCK_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
