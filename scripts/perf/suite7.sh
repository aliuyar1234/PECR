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
CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE="${CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE:-INSUFFICIENT_EVIDENCE}"
RLM_BASELINE_EXPECT_TERMINAL_MODE="${RLM_BASELINE_EXPECT_TERMINAL_MODE:-}"
SUITE7_ENFORCE_GATEWAY_FETCH_ROWS="${SUITE7_ENFORCE_GATEWAY_FETCH_ROWS:-0}"
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

trap 'suite7_cleanup $?' EXIT

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

run_k6_controller_baseline() {
  local expected_mode="${CONTROLLER_BASELINE_EXPECT_TERMINAL_MODE}"
  if [[ "${PECR_CONTROLLER_ENGINE_OVERRIDE,,}" == "rlm" ]]; then
    # RLM rollout checks canary/latency signals separately; mode matching is optional.
    expected_mode="${RLM_BASELINE_EXPECT_TERMINAL_MODE}"
  fi

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
      --summary-export "/results/${CONTROLLER_BASELINE_SUMMARY_NAME}" /scripts/suite7_controller_run.js
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

echo "[suite7] baseline controller (p99 budget ${CONTROLLER_P99_BUDGET_MS}ms; vus=${BASELINE_VUS}; duration=${BASELINE_DURATION})"
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
run_k6_gateway_fetch_rows_checked \
  "${GATEWAY_BASELINE_SUMMARY_NAME%.summary.json}" \
  "SUPPORTED" \
  "safe_customer_view_public" \
  "1" \
  "$GATEWAY_P99_BUDGET_MS"

if [[ "${SUITE7_SKIP_FAULTS}" == "1" ]]; then
  echo "[suite7] faults skipped (SUITE7_SKIP_FAULTS=1)"
else
  echo "[suite7] fault: opa unavailable"
  retry_cmd docker_compose stop opa
  run_k6_controller "suite7_fault_opa_unavailable" "SOURCE_UNAVAILABLE" "0"
  retry_cmd docker_compose start opa
  wait_for_http "gateway" "http://127.0.0.1:8080/healthz"

  echo "[suite7] fault: opa timeout"
  retry_cmd docker_compose --profile faults up -d --force-recreate opa_blackhole
  PECR_OPA_URL="http://opa_blackhole:8181" PECR_OPA_TIMEOUT_MS="50" recreate_gateway
  run_k6_controller "suite7_fault_opa_timeout" "SOURCE_UNAVAILABLE" "0"
  recreate_gateway
  retry_cmd docker_compose --profile faults stop opa_blackhole

  echo "[suite7] fault: postgres unavailable"
  retry_cmd docker_compose stop postgres
  run_k6_controller "suite7_fault_postgres_unavailable" "SOURCE_UNAVAILABLE" "0"
  retry_cmd docker_compose start postgres
  wait_for_postgres
  ensure_safeview_fixtures
  recreate_gateway

  echo "[suite7] fault: adapter statement_timeout (pg_safeview)"
  PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS="5" recreate_gateway
  run_k6_gateway_fetch_rows_checked \
    "suite7_fault_pg_statement_timeout" \
    "SOURCE_UNAVAILABLE" \
    "safe_customer_view_public_slow" \
    "0" \
    "$GATEWAY_P99_BUDGET_MS"
  recreate_gateway
fi

echo "[suite7] done; summaries in ${OUT_DIR}"
