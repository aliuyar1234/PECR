# PECR - Policy-Enforced Context Runtime

[![CI](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/ci.yml?branch=master&label=CI&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/security.yml?branch=master&label=Security&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/security.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/codeql.yml?branch=master&label=CodeQL&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/codeql.yml)
[![Latest Release](https://img.shields.io/github/v/release/aliuyar1234/PECR?include_prereleases&sort=semver&style=flat-square)](https://github.com/aliuyar1234/PECR/releases)
[![License](https://img.shields.io/github/license/aliuyar1234/PECR?style=flat-square)](LICENSE)
Current stable tag: [`v1.0.3`](https://github.com/aliuyar1234/PECR/releases/tag/v1.0.3)

PECR is a governance runtime for AI context retrieval.
It keeps orchestration non-privileged, enforces policy at every data access boundary, and returns deterministic outcomes with auditable evidence.

## What PECR Solves

Plain RAG pipelines usually leave hard governance gaps around policy, provenance, and deterministic failure handling.
PECR adds those missing controls by design:

- Policy-first execution through OPA decisions.
- Immutable, hash-stable EvidenceUnits with provenance metadata.
- Deterministic terminal modes (`SUPPORTED`, `INSUFFICIENT_EVIDENCE`, `INSUFFICIENT_PERMISSION`, `SOURCE_UNAVAILABLE`).
- Strict trust boundary between non-privileged controller and privileged gateway.
- Replay and evaluation APIs for repeatability and quality gates.

## High-Level Architecture

PECR is an AI runtime with two orchestration paths (baseline and RLM), wrapped by a policy/evidence governance plane.

```mermaid
flowchart LR
    Client["Client / Agent UI"]

    subgraph AIPlane["AI Execution Plane (Non-Privileged)"]
      Controller["PECR Controller API"]
      Baseline["Baseline Planner Loop"]
      RLM["RLM Planner Bridge<br/>(vendored upstream rlm)"]
      Scheduler["Budget Scheduler + Batch Executor"]
      Replay["Replay Store + Evaluation APIs"]
    end

    subgraph Governance["Policy + Evidence Plane (Privileged)"]
      Gateway["PECR Gateway"]
      OPA["OPA Policy Engine"]
      Evidence["Redaction + Evidence Builder"]
      Finalize["Claim-Evidence Finalize Gate"]
      Ledger[("Append-Only Ledger")]
    end

    subgraph SoR["Systems of Record"]
      FS["Filesystem Corpus"]
      PG["PostgreSQL Safe Views"]
      EXT["External Sources / Adapters"]
    end

    subgraph Ops["Quality + Operability"]
      Eval["Replay Regression + Scorecards"]
      Canary["Canary + Auto-Fallback"]
      Obs["Metrics + Traces + SLO Dashboards"]
    end

    Client -->|POST /v1/run| Controller
    Controller --> Baseline
    Controller --> RLM
    Baseline --> Scheduler
    RLM -->|call_operator_batch plan| Scheduler

    Scheduler -->|typed operator calls| Gateway
    Gateway -->|authz decisions| OPA
    Gateway --> Evidence
    Evidence --> Finalize
    Finalize -->|deterministic terminal mode| Controller

    Gateway -->|policy-scoped reads| FS
    Gateway -->|policy-scoped reads| PG
    Gateway -->|policy-scoped reads| EXT
    Gateway -->|append-only audit events| Ledger

    Controller -->|persist run artifacts| Replay
    Replay --> Eval
    Eval --> Canary
    Canary -->|runtime control knobs| Controller

    Controller --> Obs
    Gateway --> Obs
```

Controller remains non-privileged: it never reads systems of record directly and only uses typed, policy-enforced gateway operations.

## Request Lifecycle

1. Client starts a request (or full `/v1/run`) with principal identity.
2. Controller executes a budgeted loop and calls only allowlisted gateway operators.
3. Gateway enforces policy, applies redaction, and emits evidence.
4. Controller submits response text plus claim map to finalize.
5. Gateway validates claim-to-evidence coverage and returns terminal mode.

## API Surface (v1)

OpenAPI contract: `docs/openapi/pecr.v1.yaml`

Gateway:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/sessions`
- `POST /v1/policies/simulate`
- `POST /v1/operators/{op_name}`
- `POST /v1/finalize`

Controller:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/run`
- `GET /v1/replays`
- `GET /v1/replays/{run_id}`
- `POST /v1/evaluations`
- `GET /v1/evaluations/{evaluation_id}`
- `GET /v1/evaluations/scorecards`

## Quickstart (Local)

### Prerequisites

- Docker + Docker Compose
- Rust toolchain
- Bash (or WSL/Git Bash on Windows)

### 1) Start the stack

```bash
export PECR_LOCAL_AUTH_SHARED_SECRET='replace-with-random-secret'
docker compose up -d
```

Postgres is exposed on `127.0.0.1:${PECR_POSTGRES_PORT:-55432}`.

### 2) Run a smoke request

```bash
curl -sS -X POST http://127.0.0.1:8081/v1/run \
  -H 'content-type: application/json' \
  -H 'x-pecr-principal-id: dev' \
  -H "x-pecr-local-auth-secret: ${PECR_LOCAL_AUTH_SHARED_SECRET}" \
  -H 'x-pecr-request-id: demo' \
  -d '{"query":"smoke"}'
```

### 3) Run local quality gates

```bash
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr bash scripts/ci.sh
```

### 4) Run perf and fault harness

```bash
bash scripts/perf/suite7.sh
```

Outputs: `target/perf/`

## Replay and Evaluation Tooling

- Replay/eval CLI: `scripts/replay/replay_eval_cli.py`
- Regression gate: `scripts/replay/regression_gate.py`
- Contract templates runner: `scripts/replay/run_operator_contract_tests.py`

Examples:

```bash
python3 scripts/replay/replay_eval_cli.py --store target/replay list
python3 scripts/replay/replay_eval_cli.py --store target/replay replay --run-id <run_id>
python3 scripts/replay/replay_eval_cli.py --store target/replay scorecards
python3 scripts/replay/regression_gate.py --store target/replay --allow-empty
```

## RLM Engine (Optional, Experimental)

PECR includes an optional RLM-style controller engine behind explicit runtime guards.

Enable RLM mode:

- Build `pecr-controller` with feature `rlm`
- Set:
  - `PECR_CONTROLLER_ENGINE=rlm`
  - `PECR_RLM_SANDBOX_ACK=1`

Useful knobs:
- `PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED`
- `PECR_CONTROLLER_BATCH_MODE_ENABLED`
- `PECR_OPERATOR_CONCURRENCY_POLICIES`
- `PECR_RLM_SCRIPT_PATH`

Vendored upstream sync:

```bash
python3 scripts/rlm/sync_vendor_rlm.py
python3 scripts/rlm/sync_vendor_rlm.py --commit <40-char-sha>
python3 scripts/rlm/verify_vendor_rlm.py
```

Automation: `.github/workflows/vendor-rlm-sync.yml`

## Configuration Quick Reference

Configuration comes from environment variables (optionally merged from `PECR_CONFIG_PATH`).

Gateway minimum:
- `PECR_DB_URL`
- `PECR_OPA_URL`
- `PECR_POLICY_BUNDLE_HASH`
- `PECR_FS_CORPUS_PATH` (default `fixtures/fs_corpus`)

Controller minimum:
- `PECR_GATEWAY_URL`
- `PECR_MODEL_PROVIDER` (`mock` for local)
- `PECR_BUDGET_DEFAULTS` (JSON)

Auth modes:
- `PECR_AUTH_MODE=local` (default)
- `PECR_AUTH_MODE=oidc` (production baseline)

## Observability and Operations

- Structured logs via `tracing`
- Prometheus metrics at `/metrics`
- Optional OTLP traces (`PECR_OTEL_ENABLED=1`)
- Dashboards and alerts:
  - `docs/observability/dashboards/pecr_runtime_health.dashboard.json`
  - `docs/observability/dashboards/pecr_budget_scheduler.dashboard.json`
  - `docs/observability/alerts/pecr_slo_alerts.yaml`

Operational runbook: `RUNBOOK.md`

## Security and Release Integrity

- Fail-closed policy behavior and deterministic terminal modes.
- CI security checks (audit, secret scanning, SBOM, Trivy).
- Release provenance and attestation verification in release workflow.
- Artifact provenance policy: `docs/standards/ARTIFACT_PROVENANCE_POLICY.md`

## Repository Layout

- `crates/controller`: non-privileged orchestration and budget scheduler
- `crates/gateway`: privileged policy enforcement, adapters, evidence emission
- `crates/contracts`: schemas, canonicalization, hashing helpers
- `crates/ledger`: append-only ledger and migrations
- `crates/auth`: local and OIDC auth helpers
- `crates/e2e_smoke`: release-gating adversarial and smoke suites
- `opa/bundle`: OPA policy bundle
- `scripts`: CI, replay/eval, perf/fault, and security tooling
- `vendor/rlm`: vendored upstream RLM integration source

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/ci.sh
```

## Documentation Map

- Architecture:
  - `docs/architecture/controller_state_machine.md`
  - `docs/architecture/request_path_blocking_audit.md`
- Standards:
  - `docs/standards/POLICY_SIMULATION_CONTRACT.md`
  - `docs/standards/ROLLOUT_CONTROL_PLANE_CONTRACT.md`
  - `docs/standards/OBSERVABILITY_STACK_TARGET.md`
  - `docs/standards/REPLAY_PERSISTENCE_MODEL.md`
  - `docs/standards/EVALUATION_DATA_LIFECYCLE.md`
  - `docs/standards/ARTIFACT_PROVENANCE_POLICY.md`
- Guardrails:
  - `docs/enterprise/QUALITY_GUARDRAILS.md`
