import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const vus = parseInt(__ENV.VUS || "5", 10);
const duration = __ENV.DURATION || "15s";
const baseUrl = __ENV.BASE_URL || "http://gateway:8080";
const principalId = __ENV.PRINCIPAL_ID || "dev";
const localAuthSecret = __ENV.LOCAL_AUTH_SECRET || "";
const expectedTerminalMode = __ENV.EXPECT_TERMINAL_MODE || "SOURCE_UNAVAILABLE";
const viewId = __ENV.VIEW_ID || "safe_customer_view_public_slow";
const enforceP99 = (__ENV.ENFORCE_P99 || "0") === "1";
const p99BudgetMs = parseInt(__ENV.P99_BUDGET_MS || "1500", 10);
const healthTimeoutMs = parseInt(__ENV.HEALTH_TIMEOUT_MS || "60000", 10);

const wrongModeRate = new Rate("wrong_mode_rate");

const thresholds = {
  wrong_mode_rate: ["rate==0"],
};
if (enforceP99) {
  thresholds.http_req_duration = [`p(99)<${p99BudgetMs}`];
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
  throw new Error(`gateway not ready at ${baseUrl}/healthz after ${healthTimeoutMs}ms`);
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

function headerValue(res, name) {
  const target = name.toLowerCase();
  for (const k in res.headers) {
    if (k.toLowerCase() === target) return res.headers[k];
  }
  return "";
}

function createSession(requestId) {
  const headers = {
    "Content-Type": "application/json",
    "x-pecr-principal-id": principalId,
    "x-pecr-request-id": requestId,
  };
  if (localAuthSecret) {
    headers["x-pecr-local-auth-secret"] = localAuthSecret;
  }

  const res = http.post(
    `${baseUrl}/v1/sessions`,
    JSON.stringify({
      budget: {
        // Perf harness reuses this session across VUs and iterations.
        max_operator_calls: 1000000,
        max_bytes: 104857600,
        max_wallclock_ms: 600000,
        max_recursion_depth: 16,
        max_parallelism: 1,
      },
    }),
    {
      headers,
      timeout: "10s",
    }
  );

  const sessionToken = headerValue(res, "x-pecr-session-token");
  let sessionId = "";
  try {
    sessionId = res.json().session_id || "";
  } catch (_) {
    sessionId = "";
  }

  return { res, sessionId, sessionToken };
}

export default function (data) {
  const requestId = `k6-${__VU}-${__ITER}-${Date.now()}`;
  const sessionId = data && data.sessionId ? data.sessionId : "";
  const sessionToken = data && data.sessionToken ? data.sessionToken : "";

  if (!sessionId || !sessionToken) {
    wrongModeRate.add(true);
    return;
  }

  const headers = {
    "Content-Type": "application/json",
    "x-pecr-principal-id": principalId,
    "x-pecr-request-id": requestId,
    "x-pecr-session-token": sessionToken,
  };
  if (localAuthSecret) {
    headers["x-pecr-local-auth-secret"] = localAuthSecret;
  }

  const operatorRes = http.post(
    `${baseUrl}/v1/operators/fetch_rows`,
    JSON.stringify({
      session_id: sessionId,
      params: {
        view_id: viewId,
        fields: ["tenant_id", "customer_id", "status", "plan_tier", "updated_at"],
        filter_spec: { customer_id: "cust_public_1" },
      },
    }),
    {
      headers,
      timeout: "10s",
    }
  );

  const terminalMode = extractTerminalMode(operatorRes);
  const hasTerminalMode = terminalMode.length > 0;

  check(operatorRes, {
    "operator response is json": (r) =>
      (r.headers["Content-Type"] || "").includes("application/json"),
    "terminal_mode present": () => hasTerminalMode,
  });

  wrongModeRate.add(!hasTerminalMode || terminalMode !== expectedTerminalMode);
}

export function setup() {
  waitForHealthz();
  const requestId = `setup-${Date.now()}`;
  const session = createSession(requestId);
  const ok = check(session.res, {
    "session create json": (r) =>
      (r.headers["Content-Type"] || "").includes("application/json"),
    "session create status 200": (r) => r.status === 200,
    "session_id present": () => session.sessionId.length > 0,
    "session_token present": () => session.sessionToken.length > 0,
  });

  if (!ok || !session.sessionId || !session.sessionToken) {
    throw new Error("failed to create reusable session for gateway perf scenario");
  }

  return {
    sessionId: session.sessionId,
    sessionToken: session.sessionToken,
  };
}
