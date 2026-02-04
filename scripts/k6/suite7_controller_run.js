import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const vus = parseInt(__ENV.VUS || "10", 10);
const duration = __ENV.DURATION || "20s";
const baseUrl = __ENV.BASE_URL || "http://controller:8081";
const principalId = __ENV.PRINCIPAL_ID || "dev";
const query = __ENV.QUERY || "smoke";
const expectedTerminalMode = __ENV.EXPECT_TERMINAL_MODE || "";
const enforceP99 = (__ENV.ENFORCE_P99 || "1") === "1";
const p99BudgetMs = parseInt(__ENV.P99_BUDGET_MS || "2000", 10);
const healthTimeoutMs = parseInt(__ENV.HEALTH_TIMEOUT_MS || "60000", 10);

const wrongModeRate = new Rate("wrong_mode_rate");

const thresholds = {};
if (enforceP99) {
  thresholds.http_req_duration = [`p(99)<${p99BudgetMs}`];
}
if (expectedTerminalMode) {
  thresholds.wrong_mode_rate = ["rate==0"];
}

export const options = {
  vus,
  duration,
  thresholds,
};

function waitForHealthz() {
  const deadline = Date.now() + healthTimeoutMs;
  while (Date.now() < deadline) {
    const res = http.get(`${baseUrl}/healthz`);
    if (res.status === 200) return;
    sleep(0.25);
  }
  throw new Error(`controller not ready at ${baseUrl}/healthz after ${healthTimeoutMs}ms`);
}

export function setup() {
  waitForHealthz();
  return {};
}

function extractTerminalMode(res) {
  let payload;
  try {
    payload = res.json();
  } catch (_) {
    return "";
  }
  return payload.terminal_mode || payload.terminal_mode_hint || "";
}

export default function () {
  const requestId = `k6-${__VU}-${__ITER}-${Date.now()}`;

  const res = http.post(`${baseUrl}/v1/run`, JSON.stringify({ query }), {
    headers: {
      "Content-Type": "application/json",
      "x-pecr-principal-id": principalId,
      "x-pecr-request-id": requestId,
    },
    timeout: "30s",
  });

  const terminalMode = extractTerminalMode(res);
  const hasTerminalMode = terminalMode.length > 0;

  check(res, {
    "response is json": (r) =>
      (r.headers["Content-Type"] || "").includes("application/json"),
    "terminal_mode present": () => hasTerminalMode,
  });

  if (expectedTerminalMode) {
    wrongModeRate.add(!hasTerminalMode || terminalMode !== expectedTerminalMode);
  }
}
