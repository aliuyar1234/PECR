#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BASELINE_VUS="${BASELINE_VUS:-10}"
BASELINE_DURATION="${BASELINE_DURATION:-10s}"
FAULT_VUS="${FAULT_VUS:-10}"
FAULT_DURATION="${FAULT_DURATION:-5s}"
P99_BUDGET_MS="${P99_BUDGET_MS:-2000}"
BVR_THRESHOLD="${BVR_THRESHOLD:-0.01}"
SER_THRESHOLD="${SER_THRESHOLD:-0.01}"

OUT_DIR="target/perf"

mkdir -p "$OUT_DIR"

if [[ "${COLD_START:-0}" == "1" ]]; then
  docker compose down -v
fi

docker compose up -d --build

wait_for_postgres() {
  local deadline
  deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    if docker compose exec -T postgres pg_isready -U pecr -d pecr >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "postgres did not become ready in time" >&2
  return 1
}

ensure_safeview_fixtures() {
  docker compose exec -T postgres psql -U pecr -d pecr -f /docker-entrypoint-initdb.d/002_safeview_fixtures.sql >/dev/null
}

recreate_gateway() {
  docker compose up -d --no-deps --force-recreate gateway
}

scrape_metrics() {
  local url="$1"
  local out="$2"
  curl -fsS "$url" >"$out"
}

run_k6_controller() {
  local name="$1"
  local expected="$2"
  local enforce_p99="$3"
  docker compose --profile perf run --rm -T \
    -e BASE_URL="http://controller:8081" \
    -e PRINCIPAL_ID="dev" \
    -e QUERY="smoke" \
    -e EXPECT_TERMINAL_MODE="$expected" \
    -e ENFORCE_P99="$enforce_p99" \
    -e P99_BUDGET_MS="$P99_BUDGET_MS" \
    -e VUS="$FAULT_VUS" \
    -e DURATION="$FAULT_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/${name}.summary.json" /scripts/suite7_controller_run.js
}

run_k6_controller_baseline() {
  docker compose --profile perf run --rm -T \
    -e BASE_URL="http://controller:8081" \
    -e PRINCIPAL_ID="dev" \
    -e QUERY="smoke" \
    -e EXPECT_TERMINAL_MODE="INSUFFICIENT_EVIDENCE" \
    -e ENFORCE_P99="1" \
    -e P99_BUDGET_MS="$P99_BUDGET_MS" \
    -e VUS="$BASELINE_VUS" \
    -e DURATION="$BASELINE_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/suite7_baseline.summary.json" /scripts/suite7_controller_run.js
}

run_k6_gateway_safeview_timeout() {
  docker compose --profile perf run --rm -T \
    -e BASE_URL="http://gateway:8080" \
    -e PRINCIPAL_ID="dev" \
    -e EXPECT_TERMINAL_MODE="SOURCE_UNAVAILABLE" \
    -e VUS="$FAULT_VUS" \
    -e DURATION="$FAULT_DURATION" \
    k6 run --summary-trend-stats "min,avg,med,max,p(90),p(95),p(99)" \
      --summary-export "/results/suite7_fault_pg_statement_timeout.summary.json" /scripts/suite7_gateway_fetch_rows_timeout.js
}

wait_for_postgres
ensure_safeview_fixtures

echo "[suite7] baseline (p99 budget ${P99_BUDGET_MS}ms; vus=${BASELINE_VUS}; duration=${BASELINE_DURATION})"
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
  --output-json "${OUT_DIR}/suite7_metrics_gates.json"

echo "[suite7] fault: opa unavailable"
docker compose stop opa
run_k6_controller "suite7_fault_opa_unavailable" "SOURCE_UNAVAILABLE" "0"
docker compose start opa

echo "[suite7] fault: opa timeout"
docker compose --profile faults up -d opa_blackhole
PECR_OPA_URL="http://opa_blackhole:8181" PECR_OPA_TIMEOUT_MS="50" recreate_gateway
run_k6_controller "suite7_fault_opa_timeout" "SOURCE_UNAVAILABLE" "0"
recreate_gateway
docker compose --profile faults stop opa_blackhole

echo "[suite7] fault: postgres unavailable"
docker compose stop postgres
run_k6_controller "suite7_fault_postgres_unavailable" "SOURCE_UNAVAILABLE" "0"
docker compose start postgres
wait_for_postgres
ensure_safeview_fixtures
recreate_gateway

echo "[suite7] fault: adapter statement_timeout (pg_safeview)"
PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS="5" recreate_gateway
run_k6_gateway_safeview_timeout
recreate_gateway

echo "[suite7] done; summaries in ${OUT_DIR}"
