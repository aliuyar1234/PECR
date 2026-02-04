# PECR - Policy-Enforced Context Runtime

[![CI](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/aliuyar1234/pecr/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/aliuyar1234/pecr)](https://github.com/aliuyar1234/pecr/releases)

PECR is a **gateway + controller** runtime that turns heterogeneous systems-of-record into **policy-correct, time-correct, evidence-auditable** context bundles - while keeping the model/controller **non-privileged**.

This repo is the Rust implementation of the PECR/CEGP SSOT spec pack (`pcdr`, not included here).

## What This Repo Provides

- **Deny-by-default policy enforcement** via OPA for session creation, operator calls, and finalize.
- **Immutable EvidenceUnits** with deterministic IDs and content hashes (hashes are computed **after redaction**).
- **Append-only Postgres ledger** for policy snapshots, sessions, evidence, and audit events.
- **Budgeted context loop** (controller) + **finalize gate** (gateway) with strict terminal modes.
- **Release-blocking suites** (leakage, injection, staleness, claim<->evidence, cache bleed, telemetry leakage) and a k6-based p99 + fault injection harness.
- **Observability**: JSON logs + Prometheus `/metrics`; optional OTLP traces.

## Architecture (High Level)

The trust boundary is explicit:

```
client
  |
  v
controller (non-privileged)
  |  HTTP (mTLS in prod)
  v
gateway (privileged runtime)
  +--> OPA (policy decisions + redaction directives)
  +--> adapters (filesystem corpus, Postgres safe-view)
  \\--> Postgres ledger (append-only)
```

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

### 2) Run the same checks CI runs

```bash
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr bash scripts/ci.sh
```

PowerShell:
```powershell
$env:PECR_TEST_DB_URL = "postgres://pecr:pecr@localhost:55432/pecr"
bash scripts/ci.sh
```

### 3) Run the performance + fault injection suite (Suite 7)

```bash
bash scripts/perf/suite7.sh
```

Outputs are written to `target/perf/`.

More operational details: `RUNBOOK.md`.

## Endpoints

Gateway:
- `GET /healthz`
- `GET /metrics`
- `POST /v1/sessions`
- `POST /v1/operators/{search|fetch_span|fetch_rows|aggregate|list_versions|diff|redact}`
- `POST /v1/finalize`

Controller:
- `GET /healthz`
- `GET /metrics`
- `POST /v1/run`

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
- Both gateway and controller **refuse non-local bind** unless `PECR_AUTH_MODE=oidc` (docker compose uses `PECR_DEV_ALLOW_NONLOCAL_BIND=1` as a dev-only escape hatch).
- See `RUNBOOK.md` for the full list of OIDC-related env vars and defaults.

## Policy (OPA)

The gateway calls OPA for every decision and fails closed if the policy engine is unavailable.

- Bundle entrypoint: `opa/bundle/policy.rego`
- Compose runs OPA as `openpolicyagent/opa` with the bundle mounted read-only.

OPA returns `{ allow, cacheable, reason, redaction }`. Redaction directives support:
- `{"deny_fields": ["field", ...]}` or
- `{"allow_fields": ["field", ...]}`

## Redaction

There are two ways to apply redaction:
- **Policy-driven redaction enforcement**: DB operator outputs (`fetch_rows`, `aggregate`) automatically apply OPA redaction directives when present.
- **Explicit redaction operator**: `redact` transforms EvidenceUnits (JSON only) into redacted EvidenceUnits with new hashes/IDs and an appended `transform_chain` step.

## Observability

- JSON logs via `tracing` (no raw evidence payloads by default; suites verify canaries do not leak).
- Prometheus metrics on `/metrics`.
- Optional OTLP traces: set `PECR_OTEL_ENABLED=1` and configure your collector using standard `OTEL_*` environment variables.

## Repository Layout

- `crates/gateway`: privileged runtime (OPA calls, adapters, ledger writes)
- `crates/controller`: non-privileged budgeted context loop + claim map building
- `crates/contracts`: schemas + canonicalization/hashing helpers
- `crates/ledger`: migrations + append-only ledger writer
- `crates/auth`: local and OIDC/JWT authentication helpers
- `crates/boundary-check`: enforces the controller boundary in CI
- `crates/e2e_smoke`: end-to-end smoke + release-blocking suites
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

Or run the repo's CI script:
```bash
bash scripts/ci.sh
```

## Notes / Current Limitations

- `PECR_MODEL_PROVIDER=external` is intentionally **not implemented** and will refuse startup (use `mock`).
- The optional `rlm` controller engine is vendored behind a feature flag and is **not wired yet**; selecting it currently delegates to the baseline loop.
