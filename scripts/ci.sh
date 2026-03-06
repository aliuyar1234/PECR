#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p pecr-controller --features rlm
python3 -B scripts/validate_workflows.py .github/workflows
python3 -B scripts/validate_openapi.py
python3 -B scripts/rlm/verify_vendor_rlm.py
cargo run -p pecr-boundary-check
cargo test --workspace --exclude e2e_smoke
if [[ "${PECR_RUN_E2E_SMOKE:-0}" == "1" ]]; then
  cargo test -p e2e_smoke
fi
bash -n scripts/ci.sh
bash -n scripts/perf/suite7.sh
python3 -B -m unittest discover -s scripts/tests -p "test_*.py"
python3 -B -m unittest discover -s scripts/perf -p "test_*.py"
python3 -B -m unittest discover -s scripts/ops -p "test_*.py"
python3 -B - <<'PY'
from pathlib import Path

for relative in [
    "scripts/security/check_image_tags.py",
    "scripts/security/verify_release_attestations.py",
    "scripts/security/release_smoke_check.py",
]:
    path = Path(relative)
    source = path.read_text(encoding="utf-8")
    compile(source, str(path), "exec")
PY
if [[ "${PECR_RUN_OPERATOR_CONTRACT_TESTS:-0}" == "1" ]]; then
  contract_cmd=(python3 -B scripts/replay/run_operator_contract_tests.py)
  if [[ -n "${PECR_OPERATOR_CONTRACT_GATEWAY_URL:-}" ]]; then
    contract_cmd+=(--gateway-url "${PECR_OPERATOR_CONTRACT_GATEWAY_URL}")
  fi
  if [[ -n "${PECR_LOCAL_AUTH_SHARED_SECRET:-}" ]]; then
    contract_cmd+=(--local-auth-secret "${PECR_LOCAL_AUTH_SHARED_SECRET}")
  fi
  "${contract_cmd[@]}"
fi
python3 -B scripts/replay/regression_gate.py \
  --store fixtures/replay/terminal_modes \
  --require-terminal-mode SUPPORTED \
  --require-terminal-mode INSUFFICIENT_EVIDENCE \
  --require-terminal-mode INSUFFICIENT_PERMISSION \
  --require-terminal-mode SOURCE_UNAVAILABLE
if [[ -n "${PECR_REPLAY_STORE_DIR:-}" ]]; then
  python3 -B scripts/replay/regression_gate.py --store "${PECR_REPLAY_STORE_DIR}"
fi
python3 -B scripts/contracts/check_contract_lock.py
python3 -B scripts/security/check_image_tags.py
