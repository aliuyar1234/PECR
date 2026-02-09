# PECR — Policy‑Enforced Context Runtime

[![CI](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml)
[![Release](badges/release.svg)](https://github.com/aliuyar1234/pecr/releases)

> Note: the Release badge is committed as `badges/release.svg` so it renders for private repos (hosted badge services cannot read private GitHub releases).

PECR (Policy‑Enforced Context Runtime) is a **governance plane for context**: it turns heterogeneous systems‑of‑record into **policy‑correct, time‑correct, evidence‑auditable** context bundles — while keeping the model/controller **non‑privileged**.

If you know “ChatGPT + RAG”: PECR is the missing runtime layer that makes retrieval **safe, reviewable, and repeatable** (deny‑by‑default policy, immutable evidence IDs, audit ledger, deterministic refusal modes).

This repository is the Rust implementation of PECR/CEGP (spec SSOT lives in a separate internal pack, `pcdr`).

## Maturity Snapshot (February 9, 2026)

PECR is a solo-built Rust project with enterprise-focused engineering standards.

- **Modular trust boundary**: privileged Gateway and non-privileged Controller are separated by design and verified in CI.
- **Security-first runtime**: deny-by-default policy, fail-closed decisions, append-only audit ledger, and deterministic redaction/evidence hashing.
- **Reliability hardening**: session bootstrap is transactional and per-session operator/finalize execution is serialized to prevent race-driven state drift.
- **Quality automation**: formatting, clippy, boundary checks, unit/integration/e2e suites, contract-lock drift checks, and image pinning policy checks are all enforced.
- **Contract discipline**: versioned OpenAPI and schema lockfiles keep interfaces stable and reviewable.

Current positioning: strong enterprise-grade groundwork with a clear path to 9/10 in performance evidence and operations maturity.

### Path To 9/10 Enterprise Readiness

1. Add sustained-load SLO gates (p95/p99 latency + error budget) as merge blockers.
2. Expand chaos and recovery verification (DB failover, OPA outage windows, backup/restore drills).
3. Add dedicated high-concurrency integration tests for session/operator/finalize race resistance.
4. Maintain a formal security assurance cadence (threat model updates, dependency/CVE review, hardening baseline checks).

## What You Get (Guarantees)

- **Hard trust boundary**: privileged **Gateway** vs non‑privileged **Controller** (the controller holds no source credentials).
- **Deny‑by‑default policy enforcement** (OPA) for session creation, every operator call, and finalize.
- **State consistency under concurrency**: session runtime is initialized transactionally and per-session operations are serialized.
- **EvidenceUnits**: immutable, versioned, **hashed after redaction**, bound to **policy snapshot** and **as‑of time**.
- **Claim↔Evidence gate**: answers are compiled into atomic claims mapped to EvidenceUnit IDs (or you get a refusal terminal mode).
- **Budgeted execution**: strict caps on operator calls, bytes, wallclock, recursion depth (plus parallelism).
- **Auditability**: append‑only Postgres ledger + `trace_id` correlation across requests, evidence, and finalization.
- **Release‑blocking suites**: leakage, injection, staleness/time‑travel correctness, claim↔evidence, cache bleed, telemetry leakage.
- **Performance + fault injection harness**: k6 p99 run + injected OPA/Postgres faults + regression checks.

## Why This Isn’t “Just RAG”

**RAG is a retrieval strategy. PECR is the architecture around retrieval.**

RAG *can* exist inside `search()` (dense/hybrid/BM25/vector). But PECR removes the “top‑k → stuff into prompt → hope” failure mode by enforcing:

- **Policy**: who can retrieve what (and which fields must be redacted) is evaluated per call.
- **Provenance**: retrieved material is packaged as **EvidenceUnits** with deterministic IDs/hashes.
- **Time correctness**: evidence is anchored to an `as_of_time` so you can answer “as of last Tuesday” deterministically.
- **Governance**: the final answer must pass a **Claim↔Evidence** coverage gate.
- **Safe failure**: the system returns one of four terminal modes (no “partial success” ambiguity).

Mini‑picture:

```text
+-----------------------------+
| Controller (LLM optional)  |
| - plans / calls operators  |
| - never touches data stores|
+--------------+-------------+
               |
               | operator calls only
               v
+-----------------------------+
| PECR Gateway (privileged)   |
| - allowlist + validation    |
| - OPA policy + redaction    |
| - EvidenceUnit emitter      |
| - append-only ledger writer |
+-----------------------------+
```

### Where PECR Shines

- **Enterprise assistants** that must respect RBAC/ABAC and field‑level redaction across multiple systems‑of‑record.
- **Regulated environments** (PII/finance/health) where provenance, auditability, and deterministic failure matter.
- **Time‑travel answers** (“as of last week”) without silently mixing data from different points in time.
- **Agentic workflows** where the model must not have direct access to databases, APIs, or credentials.

## Architecture (Trust Boundary)

```text
+---------------------------+           mTLS            +------------------------------+
| Controller (non-privileged)|  --------------------->  | PECR Gateway (privileged)    |
| - Budgeted context loop    |                          | - Operator runtime (allowlist)|
| - LLM provider (optional)  |                          | - Policy client (OPA)         |
| - Claim draft + mapping    |                          | - EvidenceUnit emitter        |
+-------------+-------------+                          | - Ledger writer (append-only)|
              |                                        +---------------+--------------+
              |                                                        |
              |                                                        | SQL
              |                                                        v
              |                                        +------------------------------+
              |                                        | PostgreSQL (ledger datastore)|
              |                                        +------------------------------+
              |
              |  HTTP (policy queries)                  +------------------------------+
              +---------------------------------------> | OPA (policy engine sidecar) |
                                                         +------------------------------+

Adapters live behind the Gateway operator boundary:
- Filesystem adapter (deterministic dev/test)
- Postgres safe-view adapter (structured rows/fields provenance)
```

## Critical Flow (End‑to‑End)

1) **Session**: client starts a session via the Gateway; Gateway computes a **policy snapshot** and returns a capability token.
2) **Context loop**: controller runs a budgeted loop by calling **typed operators** through the Gateway.
3) **Evidence**: Gateway returns EvidenceUnits/refs (already policy‑enforced + redacted) and writes ledger events.
4) **Finalize**: controller submits the candidate answer + ClaimMap to Gateway `/v1/finalize`.
5) **Gate**: Gateway verifies Claim↔Evidence contracts, enforces terminal mode, appends ledger events, returns the final result.

The controller’s `/v1/run` response shape:

```json
{
  "terminal_mode": "INSUFFICIENT_EVIDENCE",
  "trace_id": "01KG...",
  "claim_map": { "claims": [ /* atomic claims */ ] },
  "response_text": "UNKNOWN: ..."
}
```

## Core Concepts (Quick Glossary)

### Terminal modes (exactly 4; fail‑closed)

- `SUPPORTED`: only allowed if Claim↔Evidence coverage thresholds pass.
- `INSUFFICIENT_EVIDENCE`: you didn’t retrieve enough admissible evidence within budget.
- `INSUFFICIENT_PERMISSION`: policy denied the required access.
- `SOURCE_UNAVAILABLE`: a required dependency is down or timing out (OPA, adapters, database, …).

### Operators (typed allowlist)

Gateway exposes a fixed operator surface:
`search`, `fetch_span`, `fetch_rows`, `aggregate`, `list_versions`, `diff`, `redact`.

### EvidenceUnit (immutable evidence package)

EvidenceUnit is a versioned, hashed record of what was retrieved, under which policy snapshot, at which as‑of time.
Hashes are computed **after redaction**, so the evidence ID is safe to persist and compare.

### ClaimMap (claim↔evidence link)

Answers are compiled into atomic claims. Each `SUPPORTED` claim must reference ≥1 EvidenceUnit ID.
Finalize rejects unsupported “supported” claims and enforces coverage thresholds.

## Quickstart (Deterministic Local Run)

Prerequisites:
- Docker + Docker Compose
- Rust toolchain
- `bash` (Windows: WSL or Git Bash)

### 1) Start the stack

```bash
docker compose up -d
```

Postgres is exposed as `127.0.0.1:${PECR_POSTGRES_PORT:-55432}` (override with `PECR_POSTGRES_PORT` before `docker compose up`).

### 2) Send a request (controller `/v1/run`)

```bash
curl -sS -X POST http://127.0.0.1:8081/v1/run \
  -H 'content-type: application/json' \
  -H 'x-pecr-principal-id: dev' \
  -H 'x-pecr-request-id: demo' \
  -d '{"query":"smoke"}'
```

PowerShell:

```powershell
$body = @{ query = "smoke" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8081/v1/run" `
  -Headers @{ "x-pecr-principal-id"="dev"; "x-pecr-request-id"="demo" } `
  -ContentType "application/json" `
  -Body $body
```

### 3) Run the same checks CI runs

```bash
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr bash scripts/ci.sh
```

PowerShell:

```powershell
$env:PECR_TEST_DB_URL = "postgres://pecr:pecr@localhost:55432/pecr"
bash scripts/ci.sh
```

### 4) Run performance + fault injection (Suite 7)

```bash
bash scripts/perf/suite7.sh
```

Outputs are written to `target/perf/`.

More operational details: `RUNBOOK.md`.

## API Surface

Gateway:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/sessions`
- `POST /v1/operators/{search|fetch_span|fetch_rows|aggregate|list_versions|diff|redact}`
- `POST /v1/finalize`

Controller:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/run`

Versioned API contract:
- `docs/openapi/pecr.v1.yaml`

## Configuration (Quick Reference)

Config is loaded from the environment, optionally merged with `PECR_CONFIG_PATH` (a `KEY=VALUE` file).

Gateway (minimum):
- `PECR_DB_URL`
- `PECR_OPA_URL`
- `PECR_POLICY_BUNDLE_HASH` (64 lowercase hex chars)
- `PECR_FS_CORPUS_PATH` (defaults to `fixtures/fs_corpus`)

Controller (minimum):
- `PECR_GATEWAY_URL`
- `PECR_MODEL_PROVIDER` (use `mock`)
- `PECR_BUDGET_DEFAULTS` (Budget JSON)

## RLM Controller Engine (Experimental)

The controller can run an **RLM‑style** planner loop behind a feature flag. This is **not** a trust boundary: it can only obtain evidence via policy‑enforced operator calls.

Enable it:
- Build `pecr-controller` with feature `rlm` (the docker compose controller image does this by default).
- Set:
  - `PECR_CONTROLLER_ENGINE=rlm`
  - `PECR_RLM_SANDBOX_ACK=1`

Runtime knobs:
- `PECR_RLM_BACKEND` (default: `mock`; currently only `mock` is implemented)
- `PECR_RLM_PYTHON` (override Python executable; defaults to `python3` on Linux, `python` on Windows)
- `PECR_RLM_SCRIPT_PATH` (override bridge script path; default search includes `scripts/rlm/pecr_rlm_bridge.py` and `/usr/local/share/pecr/pecr_rlm_bridge.py`)

For the full set of env vars and defaults, see:
- `crates/gateway/src/config.rs`
- `crates/controller/src/config.rs`

## Authentication Modes

### Local/dev mode (default)

- `PECR_AUTH_MODE=local` (default)
- Client supplies `x-pecr-principal-id` on requests.
- Gateway issues an opaque capability token via `x-pecr-session-token` (required for operator calls).

### OIDC/JWT mode (production baseline)

- Set `PECR_AUTH_MODE=oidc` on both gateway and controller.
- Client supplies `Authorization: Bearer <JWT>`.
- The controller forwards `Authorization` to the gateway for internal calls.

Required configuration keys:
- `PECR_OIDC_ISSUER`
- `PECR_OIDC_JWKS_URL` or `PECR_OIDC_JWKS_JSON`
- `PECR_OIDC_TENANT_CLAIM` or `PECR_OIDC_TENANT_ID_STATIC`

Notes:
- Both gateway and controller **refuse non‑local bind** unless `PECR_AUTH_MODE=oidc` (docker compose uses `PECR_DEV_ALLOW_NONLOCAL_BIND=1` as a dev‑only escape hatch).
- See `RUNBOOK.md` for the full list of OIDC‑related env vars and defaults.

## Policy (OPA)

The gateway calls OPA for every decision and fails closed if the policy engine is unavailable.

- Bundle entrypoint: `opa/bundle/policy.rego`
- Compose runs OPA as `openpolicyagent/opa` with the bundle mounted read‑only.

OPA returns `{ allow, cacheable, reason, redaction }`. Redaction directives support:
- `{"deny_fields": ["field", ...]}` or
- `{"allow_fields": ["field", ...]}`

## Redaction

- **Policy‑driven redaction enforcement**: DB operator outputs (`fetch_rows`, `aggregate`) automatically apply OPA redaction directives.
- **Explicit redaction operator**: `redact` transforms EvidenceUnits (JSON only) into redacted EvidenceUnits with new hashes/IDs and an appended `transform_chain` step.

## Observability

- JSON logs via `tracing` (no raw evidence payloads by default; suites verify canaries do not leak).
- Prometheus metrics on `/metrics`.
- Optional OTLP traces: set `PECR_OTEL_ENABLED=1` and configure your collector using standard `OTEL_*` environment variables.

## Quality Gates

- `bash scripts/ci.sh`: formatting, clippy, architecture boundary check, full tests, e2e smoke, contract lock, and image pinning policy checks.
- `bash scripts/perf/suite7.sh`: k6‑based p99 run + fault injection + BVR/SER checks and perf regression comparison.
- `.github/workflows/ci.yml`: explicit gate job requires `quality`, `perf`, and `contracts` jobs to pass.
- `.github/workflows/security.yml`: dependency audit, secret scanning, SBOM generation, and Trivy vulnerability enforcement.
- `.github/workflows/codeql.yml`: static analysis for Rust, JavaScript, Python, and workflow logic.
- Enterprise guardrail policy: `docs/enterprise/QUALITY_GUARDRAILS.md`.

## Repository Layout

- `crates/gateway`: privileged runtime (OPA calls, adapters, ledger writes)
- `crates/controller`: non‑privileged budgeted context loop + claim map building
- `crates/contracts`: schemas + canonicalization/hashing helpers
- `crates/ledger`: migrations + append‑only ledger writer
- `crates/auth`: local and OIDC/JWT authentication helpers
- `crates/boundary-check`: enforces the controller boundary in CI
- `crates/e2e_smoke`: end‑to‑end smoke + release‑blocking suites
- `opa/bundle`: OPA bundle used by docker compose and local perf harness
- `db/init`: deterministic SQL fixtures and schema init
- `scripts`: CI + perf harnesses (`scripts/ci.sh`, `scripts/perf/suite7.sh`)
- `perf/baselines`: perf regression baselines for Suite 7

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Or run the repo’s CI script:

```bash
bash scripts/ci.sh
```

## Notes / Current Limitations

- `PECR_MODEL_PROVIDER=external` is intentionally **not implemented** and will refuse startup (use `mock`).
- RLM engine is **experimental**; current backend is `mock` (the bridge + operator RPC wiring is real).
