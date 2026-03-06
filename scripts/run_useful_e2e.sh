#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONDONTWRITEBYTECODE=1
export PECR_E2E_REQUIRE_DB_URL="${PECR_E2E_REQUIRE_DB_URL:-1}"

CARGO_FEATURE_ARGS=()
if [[ -n "${PECR_E2E_CARGO_FEATURES:-}" ]]; then
  CARGO_FEATURE_ARGS=(--features "${PECR_E2E_CARGO_FEATURES}")
fi

if [[ -z "${PECR_TEST_DB_URL:-}" ]]; then
  echo "PECR_TEST_DB_URL must be set to run the usefulness e2e suites." >&2
  exit 1
fi

python3 -B scripts/replay/useful_benchmark_cli.py validate
cargo test -p e2e_smoke "${CARGO_FEATURE_ARGS[@]}" useful_real_stack_suite_exercises_named_queries -- --nocapture
cargo test -p e2e_smoke "${CARGO_FEATURE_ARGS[@]}" useful_fault_injection_suite_degrades_cleanly -- --nocapture
