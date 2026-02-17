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
        max_operator_calls: 3,
        max_bytes: 4096,
        max_wallclock_ms: 1000,
        max_recursion_depth: 2,
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

export default function () {
  const requestId = `k6-${__VU}-${__ITER}-${Date.now()}`;

  const session = createSession(requestId);
  check(session.res, {
    "session create json": (r) =>
      (r.headers["Content-Type"] || "").includes("application/json"),
    "session_id present": () => session.sessionId.length > 0,
    "session_token present": () => session.sessionToken.length > 0,
  });

  if (!session.sessionId || !session.sessionToken) {
    wrongModeRate.add(true);
    return;
  }

  const headers = {
    "Content-Type": "application/json",
    "x-pecr-principal-id": principalId,
    "x-pecr-request-id": requestId,
    "x-pecr-session-token": session.sessionToken,
  };
  if (localAuthSecret) {
    headers["x-pecr-local-auth-secret"] = localAuthSecret;
  }

  const operatorRes = http.post(
    `${baseUrl}/v1/operators/fetch_rows`,
    JSON.stringify({
      session_id: session.sessionId,
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
