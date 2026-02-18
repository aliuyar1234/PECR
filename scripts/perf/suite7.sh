#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BASELINE_VUS="${BASELINE_VUS:-10}"
BASELINE_DURATION="${BASELINE_DURATION:-10s}"
FAULT_VUS="${FAULT_VUS:-10}"
FAULT_DURATION="${FAULT_DURATION:-5s}"
CONTROLLER_P99_BUDGET_MS="${CONTROLLER_P99_BUDGET_MS:-${P99_BUDGET_MS:-1500}}"
GATEWAY_P99_BUDGET_MS="${GATEWAY_P99_BUDGET_MS:-900}"
BVR_THRESHOLD="${BVR_THRESHOLD:-0.005}"
SER_THRESHOLD="${SER_THRESHOLD:-0.005}"
WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-90}"
RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-3}"
RETRY_SLEEP_SECS="${RETRY_SLEEP_SECS:-2}"
PECR_LOCAL_AUTH_SHARED_SECRET="${PECR_LOCAL_AUTH_SHARED_SECRET:-suite7-local-auth-secret}"
METRICS_PRINCIPAL_ID="${METRICS_PRINCIPAL_ID:-dev}"
METRICS_AUTH_HEADER="${METRICS_AUTH_HEADER:-}"
PECR_CONTROLLER_ENGINE_OVERRIDE="${PECR_CONTROLLER_ENGINE_OVERRIDE:-}"
PECR_RLM_SANDBOX_ACK="${PECR_RLM_SANDBOX_ACK:-1}"
SUITE7_EXPECTATIONS_FILE="${SUITE7_EXPECTATIONS_FILE:-perf/config/suite7_expectations.v1.json}"
SUITE7_EXPECTATIONS_SCHEMA_VERSION="${SUITE7_EXPECTATIONS_SCHEMA_VERSION:-1}"
SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS="${SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS:-0}"
SUITE7_BASELINE_REPEATS="${SUITE7_BASELINE_REPEATS:-1}"
USER_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE="${CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_RLM_BASELINE_EXPECT_TERMINAL_MODE="${RLM_BASELINE_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_GATEWAY_BASELINE_EXPECT_TERMINAL_MODE="${GATEWAY_BASELINE_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_ENFORCE_GATEWAY_FETCH_ROWS="${SUITE7_ENFORCE_GATEWAY_FETCH_ROWS-__UNSET__}"
USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_FAULT_GATEWAY_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_GATEWAY_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE-__UNSET__}"
USER_SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE-__UNSET__}"
export PECR_LOCAL_AUTH_SHARED_SECRET

OUT_DIR="target/perf"
CONTROLLER_BASELINE_SUMMARY_NAME="${CONTROLLER_BASELINE_SUMMARY_NAME:-suite7_baseline.summary.json}"
GATEWAY_BASELINE_SUMMARY_NAME="${GATEWAY_BASELINE_SUMMARY_NAME:-suite7_gateway_baseline.summary.json}"
METRICS_GATES_FILE="${METRICS_GATES_FILE:-${OUT_DIR}/suite7_metrics_gates.json}"
SUITE7_SKIP_FAULTS="${SUITE7_SKIP_FAULTS:-0}"
COMPOSE_OVERRIDE_FILE=""

mkdir -p "$OUT_DIR"
chmod 777 "$OUT_DIR"

if [[ -n "${PECR_CONTROLLER_ENGINE_OVERRIDE}" ]]; then
  COMPOSE_OVERRIDE_FILE="$(mktemp)"
  cat >"${COMPOSE_OVERRIDE_FILE}" <<EOF
services:
  controller:
    environment:
      PECR_CONTROLLER_ENGINE: "${PECR_CONTROLLER_ENGINE_OVERRIDE}"
      PECR_RLM_SANDBOX_ACK: "${PECR_RLM_SANDBOX_ACK}"
EOF
fi

docker_compose() {
  if [[ -n "${COMPOSE_OVERRIDE_FILE}" ]]; then
    docker compose -f docker-compose.yml -f "${COMPOSE_OVERRIDE_FILE}" "$@"
  else
    docker compose "$@"
  fi
}

retry_cmd() {
  local attempts="${RETRY_ATTEMPTS}"
  local try=1
  while true; do
    if "$@"; then
      return 0
    fi
    if (( try >= attempts )); then
      return 1
    fi
    try=$((try + 1))
    sleep "${RETRY_SLEEP_SECS}"
  done
}

suite7_cleanup() {
  local exit_code="$1"
  set +e

  if (( exit_code != 0 )); then
    docker_compose ps >"${OUT_DIR}/compose_ps.txt" 2>&1 || true
    docker_compose logs --no-color --timestamps >"${OUT_DIR}/compose_logs.txt" 2>&1 || true
  fi

  if [[ "${PECR_PERF_KEEP_STACK:-0}" != "1" ]]; then
    docker_compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi

  if [[ -n "${COMPOSE_OVERRIDE_FILE}" && -f "${COMPOSE_OVERRIDE_FILE}" ]]; then
    rm -f "${COMPOSE_OVERRIDE_FILE}"
  fi
}

load_suite7_expectations() {
  local engine_key="baseline"
  if [[ "${PECR_CONTROLLER_ENGINE_OVERRIDE,,}" == "rlm" ]]; then
    engine_key="rlm"
  fi

  local assignments
  assignments="$(python3 - "${SUITE7_EXPECTATIONS_FILE}" "${SUITE7_EXPECTATIONS_SCHEMA_VERSION}" "${engine_key}" <<'PY'
import json
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_schema = int(sys.argv[2])
engine_key = sys.argv[3]

try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except FileNotFoundError as exc:
    raise SystemExit(f"suite7 expectations file missing: {path}") from exc
except json.JSONDecodeError as exc:
    raise SystemExit(f"suite7 expectations file invalid JSON ({path}): {exc}") from exc

schema_version = payload.get("schema_version")
if schema_version != expected_schema:
    raise SystemExit(
        f"suite7 expectations schema mismatch: expected {expected_schema}, got {schema_version}"
    )

engines = payload.get("engines")
if not isinstance(engines, dict):
    raise SystemExit("suite7 expectations config missing engines object")

engine_cfg = engines.get(engine_key)
if not isinstance(engine_cfg, dict):
    raise SystemExit(f"suite7 expectations missing engine entry: {engine_key!r}")

def read_expected(section: str, default: str = "") -> str:
    node = engine_cfg.get(section)
    if not isinstance(node, dict):
        return default
    value = node.get("expected_terminal_mode", default)
    if value is None:
        return ""
    return str(value)

faults = engine_cfg.get("faults", {})
if not isinstance(faults, dict):
    faults = {}

def read_fault(name: str, default: str = "") -> str:
    node = faults.get(name)
    if not isinstance(node, dict):
        return default
    value = node.get("expected_terminal_mode", default)
    if value is None:
        return ""
    return str(value)

gateway_section = engine_cfg.get("gateway_fetch_rows_baseline", {})
if not isinstance(gateway_section, dict):
    gateway_section = {}

values = {
    "CFG_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE": read_expected("controller_baseline", ""),
    "CFG_GATEWAY_BASELINE_EXPECT_TERMINAL_MODE": read_expected(
        "gateway_fetch_rows_baseline", "SUPPORTED"
    ),
    "CFG_ENFORCE_GATEWAY_FETCH_ROWS": "1"
    if bool(gateway_section.get("enforce", False))
    else "0",
    "CFG_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE": read_fault(
        "opa_unavailable", "SOURCE_UNAVAILABLE"
    ),
    "CFG_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE": read_fault(
        "opa_timeout", "SOURCE_UNAVAILABLE"
    ),
    "CFG_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE": read_fault(
        "postgres_unavailable", "SOURCE_UNAVAILABLE"
    ),
    "CFG_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE": read_fault(
        "pg_statement_timeout", "SOURCE_UNAVAILABLE"
    ),
}

for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
)"

  eval "${assignments}"
}

apply_suite7_expectations() {
  CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE="${CFG_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}"
  if [[ "${USER_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE="${USER_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}"
  fi

  RLM_BASELINE_EXPECT_TERMINAL_MODE="${CFG_CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}"
  if [[ "${USER_RLM_BASELINE_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    RLM_BASELINE_EXPECT_TERMINAL_MODE="${USER_RLM_BASELINE_EXPECT_TERMINAL_MODE}"
  fi

  GATEWAY_BASELINE_EXPECT_TERMINAL_MODE="${CFG_GATEWAY_BASELINE_EXPECT_TERMINAL_MODE}"
  if [[ "${USER_GATEWAY_BASELINE_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    GATEWAY_BASELINE_EXPECT_TERMINAL_MODE="${USER_GATEWAY_BASELINE_EXPECT_TERMINAL_MODE}"
  fi

  SUITE7_ENFORCE_GATEWAY_FETCH_ROWS="${CFG_ENFORCE_GATEWAY_FETCH_ROWS}"
  if [[ "${USER_SUITE7_ENFORCE_GATEWAY_FETCH_ROWS}" != "__UNSET__" ]]; then
    SUITE7_ENFORCE_GATEWAY_FETCH_ROWS="${USER_SUITE7_ENFORCE_GATEWAY_FETCH_ROWS}"
  fi

  SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE="${CFG_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE}"
  SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE="${CFG_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE}"
  SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE="${CFG_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE}"
  SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE="${CFG_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE}"

  if [[ "${USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE}"
    SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE}"
    SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE}"
    SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_EXPECT_TERMINAL_MODE}"
  fi

  if [[ "${USER_SUITE7_FAULT_GATEWAY_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_GATEWAY_EXPECT_TERMINAL_MODE}"
  fi

  if [[ "${USER_SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE}"
  fi
  if [[ "${USER_SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE}"
  fi
  if [[ "${USER_SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE}"
  fi
  if [[ "${USER_SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE}" != "__UNSET__" ]]; then
    SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE="${USER_SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE}"
  fi

  # Backward-compatible aggregate aliases.
  SUITE7_FAULT_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE}"
  SUITE7_FAULT_GATEWAY_EXPECT_TERMINAL_MODE="${SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE}"
}

validate_suite7_runtime_args() {
  case "${SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS}" in
    0|1) ;;
    *)
      echo "SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS must be 0 or 1" >&2
      return 1
      ;;
  esac

  case "${SUITE7_ENFORCE_GATEWAY_FETCH_ROWS}" in
    0|1) ;;
    *)
      echo "SUITE7_ENFORCE_GATEWAY_FETCH_ROWS must be 0 or 1" >&2
      return 1
      ;;
  esac

  if ! [[ "${SUITE7_BASELINE_REPEATS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "SUITE7_BASELINE_REPEATS must be a positive integer (>=1)" >&2
    return 1
  fi
}

effective_expected_mode() {
  local expected="$1"
  if [[ "${SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS}" == "1" ]]; then
    printf "%s" "${expected}"
  else
    printf ""
  fi
}

trap 'suite7_cleanup $?' EXIT

load_suite7_expectations
apply_suite7_expectations
validate_suite7_runtime_args

if [[ "${COLD_START:-0}" == "1" ]]; then
  retry_cmd docker_compose down -v --remove-orphans || true
fi

retry_cmd docker_compose up -d --build

wait_for_postgres() {
  local deadline
  deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    if docker_compose exec -T postgres pg_isready -U pecr -d pecr >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "postgres did not become ready in time" >&2
  return 1
}

wait_for_http() {
  local name="$1"
  local url="$2"
  local deadline
  deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "${name} did not become ready in time (${url})" >&2
  return 1
}

ensure_safeview_fixtures() {
  retry_cmd docker_compose exec -T postgres \
    psql -U pecr -d pecr -f /docker-entrypoint-initdb.d/002_safeview_fixtures.sql >/dev/null
}

recreate_gateway() {
  retry_cmd docker_compose up -d --no-deps --force-recreate gateway
  wait_for_http "gateway" "http://127.0.0.1:8080/healthz"
}

scrape_metrics() {
  local url="$1"
  local out="$2"
  local curl_args=()
  if [[ -n "${METRICS_AUTH_HEADER}" ]]; then
    curl_args+=(-H "Authorization: ${METRICS_AUTH_HEADER}")
  else
    curl_args+=(-H "x-pecr-principal-id: ${METRICS_PRINCIPAL_ID}")
    if [[ -n "${PECR_LOCAL_AUTH_SHARED_SECRET}" ]]; then
      curl_args+=(-H "x-pecr-local-auth-secret: ${PECR_LOCAL_AUTH_SHARED_SECRET}")
    fi
  fi
  curl -fsS "${curl_args[@]}" "$url" >"$out"
}

run_k6_controller() {
  local name="$1"
  local expected="$2"
  local enforce_p99="$3"
  docker_compose --profile perf run --rm -T \
    -e BASE_URL="http://controller:8081" \
    -e PRINCIPAL_ID="dev" \
    -e LOCAL_AUTH_SECRET="${PECR_LOCAL_AUTH_SHARED_SECRET}" \
    -e QUERY="smoke" \
    -e EXPECT_TERMINAL_MODE="$expected" \
    -e ENFORCE_P99="$enforce_p99" \
    -e P99_BUDGET_MS="$CONTROLLER_P99_BUDGET_MS" \
    -e VUS="$FAULT_VUS" \
    -e DURATION="$FAULT_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/${name}.summary.json" /scripts/suite7_controller_run.js
}

run_k6_controller_baseline_once() {
  local summary_name="$1"
  local expected_mode="$2"

  docker_compose --profile perf run --rm -T \
    -e BASE_URL="http://controller:8081" \
    -e PRINCIPAL_ID="dev" \
    -e LOCAL_AUTH_SECRET="${PECR_LOCAL_AUTH_SHARED_SECRET}" \
    -e QUERY="smoke" \
    -e EXPECT_TERMINAL_MODE="${expected_mode}" \
    -e ENFORCE_P99="1" \
    -e P99_BUDGET_MS="$CONTROLLER_P99_BUDGET_MS" \
    -e VUS="$BASELINE_VUS" \
    -e DURATION="$BASELINE_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/${summary_name}" /scripts/suite7_controller_run.js
}

run_k6_controller_baseline() {
  local expected_mode="${CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}"
  if [[ "${PECR_CONTROLLER_ENGINE_OVERRIDE,,}" == "rlm" ]]; then
    expected_mode="${RLM_BASELINE_EXPECT_TERMINAL_MODE}"
  fi
  expected_mode="$(effective_expected_mode "${expected_mode}")"

  local repeats="${SUITE7_BASELINE_REPEATS}"
  local summary_prefix="${CONTROLLER_BASELINE_SUMMARY_NAME%.summary.json}"
  local run_paths=()
  local run_summary_name
  local run_index

  for (( run_index=1; run_index<=repeats; run_index++ )); do
    run_summary_name="${CONTROLLER_BASELINE_SUMMARY_NAME}"
    if (( repeats > 1 )); then
      run_summary_name="${summary_prefix}.run${run_index}.summary.json"
    fi
    run_k6_controller_baseline_once "${run_summary_name}" "${expected_mode}"
    run_paths+=("${OUT_DIR}/${run_summary_name}")
  done

  if (( repeats > 1 )); then
    python3 scripts/perf/select_median_summary.py \
      --metric "http_req_duration:p(95)" \
      --output "${OUT_DIR}/${CONTROLLER_BASELINE_SUMMARY_NAME}" \
      --metadata-json "${OUT_DIR}/${summary_prefix}.median.json" \
      "${run_paths[@]}"
  fi
}

run_k6_gateway_fetch_rows() {
  local name="$1"
  local expected="$2"
  local view_id="$3"
  local enforce_p99="$4"
  local p99_budget_ms="$5"
  docker_compose --profile perf run --rm -T \
    -e BASE_URL="http://gateway:8080" \
    -e PRINCIPAL_ID="dev" \
    -e LOCAL_AUTH_SECRET="${PECR_LOCAL_AUTH_SHARED_SECRET}" \
    -e EXPECT_TERMINAL_MODE="$expected" \
    -e VIEW_ID="$view_id" \
    -e ENFORCE_P99="$enforce_p99" \
    -e P99_BUDGET_MS="$p99_budget_ms" \
    -e VUS="$FAULT_VUS" \
    -e DURATION="$FAULT_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/${name}.summary.json" /scripts/suite7_gateway_fetch_rows_timeout.js
}

run_k6_gateway_fetch_rows_checked() {
  local name="$1"
  local expected="$2"
  local view_id="$3"
  local enforce_p99="$4"
  local p99_budget_ms="$5"

  if run_k6_gateway_fetch_rows "$name" "$expected" "$view_id" "$enforce_p99" "$p99_budget_ms"; then
    return 0
  fi

  if [[ "${SUITE7_ENFORCE_GATEWAY_FETCH_ROWS}" == "1" ]]; then
    echo "[suite7] gateway fetch_rows scenario failed and enforcement is enabled: ${name}" >&2
    return 1
  fi

  echo "[suite7] warning: gateway fetch_rows scenario failed (${name}); continuing because SUITE7_ENFORCE_GATEWAY_FETCH_ROWS=0" >&2
  return 0
}

wait_for_postgres
ensure_safeview_fixtures
wait_for_http "gateway" "http://127.0.0.1:8080/healthz"
wait_for_http "controller" "http://127.0.0.1:8081/healthz"

echo "[suite7] baseline controller (p99 budget ${CONTROLLER_P99_BUDGET_MS}ms; vus=${BASELINE_VUS}; duration=${BASELINE_DURATION}; repeats=${SUITE7_BASELINE_REPEATS})"
scrape_metrics "http://127.0.0.1:8080/metrics" "${OUT_DIR}/metrics_gateway.before.prom"
scrape_metrics "http://127.0.0.1:8081/metrics" "${OUT_DIR}/metrics_controller.before.prom"
run_k6_controller_baseline
scrape_metrics "http://127.0.0.1:8080/metrics" "${OUT_DIR}/metrics_gateway.after.prom"
scrape_metrics "http://127.0.0.1:8081/metrics" "${OUT_DIR}/metrics_controller.after.prom"
python3 scripts/perf/check_bvr_ser.py \
  --gateway-before "${OUT_DIR}/metrics_gateway.before.prom" \
  --gateway-after "${OUT_DIR}/metrics_gateway.after.prom" \
  --controller-before "${OUT_DIR}/metrics_controller.before.prom" \
  --controller-after "${OUT_DIR}/metrics_controller.after.prom" \
  --bvr-threshold "${BVR_THRESHOLD}" \
  --ser-threshold "${SER_THRESHOLD}" \
  --output-json "${METRICS_GATES_FILE}"

echo "[suite7] baseline gateway fetch_rows (p99 budget ${GATEWAY_P99_BUDGET_MS}ms; vus=${FAULT_VUS}; duration=${FAULT_DURATION})"
gateway_baseline_expected_mode="$(effective_expected_mode "${GATEWAY_BASELINE_EXPECT_TERMINAL_MODE}")"
run_k6_gateway_fetch_rows_checked \
  "${GATEWAY_BASELINE_SUMMARY_NAME%.summary.json}" \
  "${gateway_baseline_expected_mode}" \
  "safe_customer_view_public" \
  "1" \
  "$GATEWAY_P99_BUDGET_MS"

if [[ "${SUITE7_SKIP_FAULTS}" == "1" ]]; then
  echo "[suite7] faults skipped (SUITE7_SKIP_FAULTS=1)"
else
  echo "[suite7] fault: opa unavailable"
  retry_cmd docker_compose stop opa
  run_k6_controller "suite7_fault_opa_unavailable" "$(effective_expected_mode "${SUITE7_FAULT_OPA_UNAVAILABLE_EXPECT_TERMINAL_MODE}")" "0"
  retry_cmd docker_compose start opa
  wait_for_http "gateway" "http://127.0.0.1:8080/healthz"

  echo "[suite7] fault: opa timeout"
  retry_cmd docker_compose --profile faults up -d --force-recreate opa_blackhole
  PECR_OPA_URL="http://opa_blackhole:8181" PECR_OPA_TIMEOUT_MS="50" recreate_gateway
  run_k6_controller "suite7_fault_opa_timeout" "$(effective_expected_mode "${SUITE7_FAULT_OPA_TIMEOUT_EXPECT_TERMINAL_MODE}")" "0"
  recreate_gateway
  retry_cmd docker_compose --profile faults stop opa_blackhole

  echo "[suite7] fault: postgres unavailable"
  retry_cmd docker_compose stop postgres
  run_k6_controller "suite7_fault_postgres_unavailable" "$(effective_expected_mode "${SUITE7_FAULT_POSTGRES_UNAVAILABLE_EXPECT_TERMINAL_MODE}")" "0"
  retry_cmd docker_compose start postgres
  wait_for_postgres
  ensure_safeview_fixtures
  recreate_gateway

  echo "[suite7] fault: adapter statement_timeout (pg_safeview)"
  PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS="5" recreate_gateway
  run_k6_gateway_fetch_rows_checked \
    "suite7_fault_pg_statement_timeout" \
    "$(effective_expected_mode "${SUITE7_FAULT_PG_STATEMENT_TIMEOUT_EXPECT_TERMINAL_MODE}")" \
    "safe_customer_view_public_slow" \
    "0" \
    "$GATEWAY_P99_BUDGET_MS"
  recreate_gateway
fi

echo "[suite7] done; summaries in ${OUT_DIR}"
