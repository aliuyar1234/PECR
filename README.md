# PECR — Policy‑Enforced Context Runtime

[![CI](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml)
[![Release](badges/release.svg)](https://github.com/aliuyar1234/pecr/releases)

> Note: the Release badge is committed as `badges/release.svg` so it renders for private repos (hosted badge services cannot read private GitHub releases).

PECR (Policy‑Enforced Context Runtime) is a **governance plane for context**: it turns heterogeneous systems‑of‑record into **policy‑correct, time‑correct, evidence‑auditable** context bundles — while keeping the model/controller **non‑privileged**.

PECR adds the governance layer that plain retrieval pipelines typically miss: policy enforcement, immutable evidence, auditability, and deterministic terminal modes.

This repository contains the Rust implementation of PECR.

## System Overview

PECR enforces policy, provenance, and deterministic behavior for retrieval-based AI workflows.
It separates orchestration from data access, so models/controllers can coordinate work without holding direct source credentials.

## Architecture (High Level)

```mermaid
flowchart LR
    Client[Client / API Consumer]

    subgraph NonPriv[Non-Privileged Zone]
      Controller[PECR Controller<br/>Orchestration + Budget Loop]
    end

    subgraph Priv[Privileged Zone]
      Gateway[PECR Gateway<br/>Policy Enforcement + Redaction + Evidence]
      OPA[OPA Policy Engine]
      Ledger[(PostgreSQL Ledger)]
      Sources[(Systems of Record<br/>Filesystem / PostgreSQL / APIs)]
    end

    Client -->|POST /v1/run| Controller
    Controller -->|typed operator calls| Gateway
    Controller -->|finalize payload| Gateway
    Gateway -->|policy decisions| OPA
    Gateway -->|read with policy context| Sources
    Gateway -->|append-only events + runtime state| Ledger
    Gateway -->|terminal result| Controller
    Controller -->|response| Client
```

Trust boundary: the controller is non-privileged and never accesses systems of record directly.

## How the System Works

1. A client request starts a session and captures policy/time context.
2. The controller runs a budgeted loop and calls only typed gateway operators.
3. The gateway enforces policy, applies redaction, and emits immutable evidence units.
4. The controller submits `response_text` plus a `claim_map` to `/v1/finalize`.
5. The gateway verifies claim-to-evidence coverage, writes audit events, and returns a terminal mode.

The controller `/v1/run` response shape:

```json
{
  "terminal_mode": "INSUFFICIENT_EVIDENCE",
  "trace_id": "01KG...",
  "claim_map": { "claims": [ /* atomic claims */ ] },
  "response_text": "UNKNOWN: ..."
}
```

## Engineering Properties

- **Trust-domain separation**: privileged data access is isolated in the gateway; the controller remains non-privileged.
- **Policy-first execution**: OPA decisions are enforced for session creation, operator calls, and finalize.
- **Concurrent state integrity**: session runtime initialization is transactional and per-session operations are serialized.
- **Evidence provenance model**: evidence units are immutable, versioned, and hashed after redaction under policy/time context.
- **Deterministic finalization contract**: claim-to-evidence coverage is validated before returning terminal outcomes.
- **Resource governance**: operator calls, bytes, wallclock, recursion depth, and optional parallelism are budgeted.
- **Auditability**: append-only ledger records policy decisions, evidence events, and finalization events under a shared `trace_id`.
- **Release discipline**: leakage, injection, staleness, cache-isolation, and telemetry suites are CI-blocking checks.
- **Performance and resilience validation**: k6 p99 and fault-injection harnesses are part of the quality workflow.

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
export PECR_LOCAL_AUTH_SHARED_SECRET='replace-with-random-secret'
docker compose up -d
```

Postgres is exposed as `127.0.0.1:${PECR_POSTGRES_PORT:-55432}` (override with `PECR_POSTGRES_PORT` before `docker compose up`).

### 2) Send a request (controller `/v1/run`)

```bash
curl -sS -X POST http://127.0.0.1:8081/v1/run \
  -H 'content-type: application/json' \
  -H 'x-pecr-principal-id: dev' \
  -H "x-pecr-local-auth-secret: ${PECR_LOCAL_AUTH_SHARED_SECRET}" \
  -H 'x-pecr-request-id: demo' \
  -d '{"query":"smoke"}'
```

PowerShell:

```powershell
$env:PECR_LOCAL_AUTH_SHARED_SECRET = "replace-with-random-secret"
$body = @{ query = "smoke" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8081/v1/run" `
  -Headers @{ "x-pecr-principal-id"="dev"; "x-pecr-local-auth-secret"=$env:PECR_LOCAL_AUTH_SHARED_SECRET; "x-pecr-request-id"="demo" } `
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
- `PECR_LOCAL_AUTH_SHARED_SECRET` when using local auth with non-loopback bind

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
- When local auth is used with non-loopback bind, clients must also supply `x-pecr-local-auth-secret`.

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
- Metrics can require auth (`PECR_METRICS_REQUIRE_AUTH=1` for non-loopback binds by default).
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

## Module Boundaries And Ownership

The table below documents intended coupling and change ownership. Boundary rules are enforced by
`crates/boundary-check` in CI.

| Module | Primary responsibility | Allowed runtime dependencies | Forbidden coupling | Ownership scope |
|---|---|---|---|---|
| `crates/controller` | Non-privileged orchestration and budget loop | `crates/contracts`, `crates/auth`, outbound HTTP to gateway | Direct datastore/source access; direct imports from `gateway`/`ledger` | Orchestration and model-loop maintainers |
| `crates/gateway` | Privileged policy enforcement, source adapters, evidence emission | `crates/contracts`, `crates/auth`, `crates/ledger`, `crates/policy`, OPA/Postgres/filesystem | Importing controller internals; bypassing OPA decisions for protected actions | Gateway and policy-runtime maintainers |
| `crates/policy` + `opa/bundle` | Shared policy decision model and policy bundle semantics | `serde`, `serde_json` (crate); OPA/Rego runtime (bundle) | Service-specific transport logic | Policy maintainers |
| `crates/ledger` + `db/init` + `crates/ledger/migrations` | Append-only audit/runtime persistence and schema evolution | Postgres/sqlx | Embedding gateway/controller policy logic in SQL paths | Data/audit maintainers |
| `crates/contracts` | Canonical schemas, hashing/canonicalization, API invariants | Schema JSON + serde types | Runtime side effects, IO logic | Contracts/API maintainers |
| `scripts/*` + workflows | CI, perf, security, release automation | Workspace CLI + Docker | Silent policy bypasses or untracked gate changes | Build/release maintainers |

Cross-module changes should be split by concern: contracts first, runtime second, docs/runbook third.

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
