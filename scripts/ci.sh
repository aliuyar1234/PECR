#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p pecr-controller --features rlm
cargo run -p pecr-boundary-check
cargo test --workspace --exclude e2e_smoke
cargo test -p e2e_smoke
python3 -m unittest discover -s scripts/tests -p "test_*.py"
python3 scripts/contracts/check_contract_lock.py
python3 scripts/security/check_image_tags.py
