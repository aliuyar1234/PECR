#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p pecr-controller --features rlm
python3 scripts/rlm/verify_vendor_rlm.py
cargo run -p pecr-boundary-check
cargo test --workspace --exclude e2e_smoke
cargo test -p e2e_smoke
bash -n scripts/ci.sh
bash -n scripts/perf/suite7.sh
python3 -m unittest discover -s scripts/tests -p "test_*.py"
python3 -m unittest discover -s scripts/perf -p "test_*.py"
python3 -m unittest discover -s scripts/ops -p "test_*.py"
python3 scripts/replay/regression_gate.py --store "${PECR_REPLAY_STORE_DIR:-target/replay}" --allow-empty
python3 scripts/contracts/check_contract_lock.py
python3 scripts/security/check_image_tags.py
