# PECR - Policy-Enforced Context Runtime

[![CI](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/ci.yml?branch=master&label=CI&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/security.yml?branch=master&label=Security&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/security.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/codeql.yml?branch=master&label=CodeQL&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/codeql.yml)
[![Latest Release](https://img.shields.io/github/v/release/aliuyar1234/pecr?display_name=tag&label=release&style=flat-square)](https://github.com/aliuyar1234/PECR/releases/latest)
[![License](https://img.shields.io/github/license/aliuyar1234/PECR?style=flat-square)](LICENSE)

Current stable tag: [`v1.0.4`](https://github.com/aliuyar1234/PECR/tree/v1.0.4)

PECR is an RLM-first governed reasoning runtime for AI retrieval and synthesis. It keeps orchestration non-privileged, enforces policy at the data-access boundary, and only returns `SUPPORTED` answers when the gateway can prove claim-to-evidence coverage.

`v1.0.4` marks the repo's current product posture:

- `rlm` is the primary runtime path.
- `baseline` remains only as a reference, shadow, and rollback lane.
- long-context evidence synthesis, replay visibility, rollout controls, and real-backend operating lanes are part of the shipped design.
- the secret-backed real-backend promotion gate is implemented, but broader real-backend automation still depends on configured credentials and repeated green runs.

## What PECR Is

PECR combines a reasoning plane with a governance plane:

- the controller owns planning, budget enforcement, replay persistence, and the public API
- the gateway owns policy checks, source access, evidence emission, redaction, and finalize enforcement
- RLM improves planning, recovery, clarification, batching, and long-context synthesis
- replay, evaluation, perf, and contract lanes keep the system testable instead of hand-wavy

This is not "raw long-context plus hope." Retrieval still matters. Policy still matters. Finalize still matters.

## Current Product State

| Area | Current state |
|---|---|
| Default product runtime | `rlm` |
| Reference and rollback path | `baseline` |
| Local compose default | `rlm` plus the mock bridge backend, with baseline auto-fallback available |
| First real backend seam | `PECR_RLM_BACKEND=openai` behind the Python RLM bridge |
| Public API posture | `/v1/run` stays provider-agnostic; backend details do not leak into the public contract |
| Real-backend promotion | gated by secret-backed usefulness and pre-release evidence lanes |
| Upstream RLM model | research upstream is `alexzhang13/rlm`; PECR ships a reviewed vendored integration from `vendor/rlm` |

## High-Level Architecture

```mermaid
flowchart LR
    classDef edge fill:#ffffff,stroke:#0f172a,stroke-width:1.2px,color:#0f172a;
    classDef control fill:#eef4ff,stroke:#1d4ed8,stroke-width:1.4px,color:#0f172a;
    classDef governance fill:#ecfdf3,stroke:#059669,stroke-width:1.4px,color:#0f172a;
    classDef storage fill:#fff7ed,stroke:#ea580c,stroke-width:1.4px,color:#0f172a;
    classDef ops fill:#f5f3ff,stroke:#7c3aed,stroke-width:1.4px,color:#0f172a;

    Client["Client or Agent UI"]

    subgraph AI["AI Execution Plane - Non-Privileged"]
      Controller["Controller API"]
      RLM["RLM Planner Bridge"]
      Baseline["Baseline Reference Lane"]
      Scheduler["Budget Scheduler and Batch Executor"]
      Replay["Replay Store and Evaluation APIs"]
    end

    subgraph GOV["Governance Plane - Privileged"]
      Gateway["Gateway"]
      OPA["OPA Policy Engine"]
      Evidence["Evidence and Redaction"]
      Finalize["Finalize Gate"]
      Ledger["Append-Only Ledger"]
    end

    subgraph DATA["Systems of Record"]
      FS["Filesystem Corpus"]
      PG["Postgres Safe Views"]
      EXT["External Adapters"]
    end

    subgraph OPS["Quality and Operability"]
      Eval["Replay Regression and Scorecards"]
      Canary["Canary and Auto-Fallback"]
      Obs["Metrics, Traces, and SLOs"]
    end

    Client -->|"POST /v1/run"| Controller
    Controller -->|"primary reasoning"| RLM
    Controller -.->|"shadow or rollback"| Baseline
    RLM -->|"plan, replan, batch, recover"| Scheduler
    Baseline -->|"reference execution"| Scheduler

    Scheduler -->|"typed operators"| Gateway
    Gateway -->|"authz"| OPA
    Gateway -->|"evidence units"| Evidence
    Evidence -->|"claim coverage"| Finalize
    Finalize -->|"terminal mode"| Controller

    Gateway -->|"policy-scoped reads"| FS
    Gateway -->|"policy-scoped reads"| PG
    Gateway -->|"policy-scoped reads"| EXT
    Gateway -->|"audit events"| Ledger

    Controller -->|"persist run artifacts"| Replay
    Replay --> Eval
    Eval --> Canary
    Canary -->|"runtime controls"| Controller

    Controller --> Obs
    Gateway --> Obs

    class Client edge;
    class Controller,RLM,Baseline,Scheduler,Replay control;
    class Gateway,OPA,Evidence,Finalize,Ledger governance;
    class FS,PG,EXT storage;
    class Eval,Canary,Obs ops;
```

Controller code never reads source systems directly. The gateway remains the only privileged data-access boundary.

## Request Flow

1. A client sends `POST /v1/run` to the controller with principal identity and request metadata.
2. The controller runs a budgeted RLM loop and can shadow or fall back to baseline when configured.
3. The controller invokes only typed, allowlisted gateway operators.
4. The gateway enforces policy, reads sources, redacts where needed, and emits evidence units.
5. The controller assembles response text plus claim metadata and asks the gateway to finalize.
6. The gateway returns a deterministic terminal mode such as `SUPPORTED`, `INSUFFICIENT_EVIDENCE`, `INSUFFICIENT_PERMISSION`, or `SOURCE_UNAVAILABLE`.
7. The controller persists replay artifacts so the run can be inspected, scored, and compared later.

## API Surface (v1)

OpenAPI contract: `docs/openapi/pecr.v1.yaml`

Gateway:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `POST /v1/sessions`
- `GET /v1/policies/capabilities`
- `POST /v1/policies/simulate`
- `POST /v1/operators/{op_name}`
- `POST /v1/finalize`

Controller:
- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /v1/capabilities`
- `POST /v1/run`
- `GET /v1/replays`
- `GET /v1/replays/{run_id}`
- `POST /v1/evaluations`
- `GET /v1/evaluations/{evaluation_id}`
- `GET /v1/evaluations/scorecards`

## 5-Minute Local Start

Prerequisites:

- Docker + Docker Compose
- Rust toolchain
- Bash, WSL, Git Bash, or PowerShell

Start the stack:

```bash
docker compose up -d --build
```

Verify health:

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
```

Run the quickest product demo:

```bash
python -B scripts/demo/useful_workflows.py tour
python -B scripts/demo/useful_workflows.py live-tour
python -B scripts/demo/useful_workflows.py live-scenario customer-status
python -B scripts/demo/useful_workflows.py live-smoke
```

Run one raw request:

```bash
curl -sS -X POST http://127.0.0.1:8081/v1/run \
  -H 'content-type: application/json' \
  -H 'x-pecr-principal-id: dev' \
  -H 'x-pecr-local-auth-secret: pecr-local-demo-secret' \
  -H 'x-pecr-request-id: demo' \
  -d '{"query":"What is the customer status and plan tier?"}'
```

Run local verification:

```bash
bash scripts/verify.sh
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr cargo test -p e2e_smoke -- --nocapture
SUITE7_SKIP_FAULTS=1 bash scripts/perf/suite7.sh
```

Local compose defaults `PECR_LOCAL_AUTH_SHARED_SECRET` to `pecr-local-demo-secret`, so the demo paths work without extra setup.

## Runtime Modes

| Mode | How to enable | Use |
|---|---|---|
| Local default | Leave `PECR_CONTROLLER_ENGINE` unset and use compose defaults | `rlm` path with mock bridge backend, baseline auto-fallback available |
| Explicit RLM | `PECR_CONTROLLER_ENGINE=rlm` and `PECR_RLM_SANDBOX_ACK=1` | Primary reasoning path |
| Baseline reference | `PECR_CONTROLLER_ENGINE=baseline` or `PECR_BASELINE_SHADOW_PERCENT>0` | Reference, shadow comparison, rollback |
| Real backend | `PECR_RLM_BACKEND=openai`, `PECR_RLM_MODEL_NAME`, and `OPENAI_API_KEY` or `PECR_RLM_API_KEY` | Opt-in bridge-backed real model runs |

Important current truth:

- the controller still rejects `PECR_MODEL_PROVIDER=external`
- the first real backend lands through `scripts/rlm/pecr_rlm_bridge.py`, not through the Rust model-provider switch
- the public `/v1/run` API remains provider-agnostic

Manual real-backend smoke:

```bash
PECR_RLM_BACKEND=openai \
PECR_RLM_MODEL_NAME=<model> \
OPENAI_API_KEY=<key> \
python -B scripts/rlm/openai_bridge_smoke.py
```

## Replay, Evaluation, Benchmarking, And Perf

Replay and evaluation:

```bash
python3 scripts/replay/replay_eval_cli.py --store target/replay list
python3 scripts/replay/replay_eval_cli.py --store target/replay replay --run-id <run_id>
python3 scripts/replay/replay_eval_cli.py --store target/replay scorecards
python3 scripts/replay/regression_gate.py --store target/replay --allow-empty
```

Named usefulness demos and benchmarks:

```bash
python3 scripts/demo/useful_workflows.py catalog
python3 scripts/demo/useful_workflows.py benchmark
python3 scripts/run_useful_e2e.sh
```

Perf harness:

```bash
bash scripts/perf/suite7.sh
PECR_CONTROLLER_ENGINE_OVERRIDE=rlm \
PECR_RLM_SANDBOX_ACK=1 \
SUITE7_SKIP_FAULTS=1 \
CONTROLLER_BASELINE_SUMMARY_NAME=suite7_rlm_baseline.summary.json \
GATEWAY_BASELINE_SUMMARY_NAME=suite7_rlm_gateway_baseline.summary.json \
METRICS_GATES_FILE=target/perf/suite7_rlm_metrics_gates.json \
bash scripts/perf/suite7.sh
```

Real-backend evidence lanes:

- `.github/workflows/rlm-real-backend-smoke.yml`
- `.github/workflows/rlm-real-backend-usefulness.yml`
- `.github/workflows/rlm-real-backend-pre-release.yml`

The real-backend promotion gate is implemented, but it is not fully earned until the repo has credentials configured and repeated green usefulness runs on the same head SHA.

## RLM Upstream And Vendored Runtime Policy

PECR intentionally separates the research upstream from the shipped runtime:

- research upstream: `https://github.com/alexzhang13/rlm`
- shipped PECR runtime: the reviewed vendored integration in `vendor/rlm`
- integration seam: `scripts/rlm/pecr_rlm_bridge.py`
- active vendored pin: `vendor/rlm/UPSTREAM_PIN`

Update policy:

- upstream changes may be proposed automatically or synced manually
- adoption into PECR is explicit and review-gated
- shipped behavior only changes when the vendored copy is updated, verified, and merged

Vendor sync commands:

```bash
python3 scripts/rlm/sync_vendor_rlm.py
python3 scripts/rlm/sync_vendor_rlm.py --commit <40-char-sha>
python3 scripts/rlm/verify_vendor_rlm.py
```

Automation:

- `.github/workflows/vendor-rlm-sync.yml`

## Release And Integrity

Release workflow:

- tag format: `vX.Y.Z`
- workflow: `.github/workflows/release.yml`
- CI gate: `.github/workflows/ci.yml`

Release integrity is enforced with:

- checksum validation for release tarballs
- artifact provenance verification via `scripts/security/verify_release_attestations.py`
- post-release smoke checks via `scripts/security/release_smoke_check.py`

This repo also keeps the real-backend promotion gate separate from binary release publication. That keeps the shipped open-source release honest even while the secret-backed real-backend lane is still being proven operationally.

## Repository Layout

- `crates/`: Rust workspace crates, including controller, gateway, contracts, policy, adapters, boundary-check, and e2e smoke
- `db/init/`: Postgres bootstrap schema
- `docker/` and `docker-compose.yml`: local stack wiring
- `fixtures/`: deterministic corpora, named usefulness scenarios, and replay fixtures
- `opa/`: policy assets
- `perf/`: baseline summaries and expectations
- `scripts/`: CI, replay, perf, demo, security, and release tooling
- `vendor/rlm/`: vendored RLM runtime
- `docs/`: architecture, observability, standards, and API documentation

## Development

Main verification commands:

```bash
docker compose up -d --build
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude e2e_smoke
cargo test -p e2e_smoke
cargo run -p pecr-boundary-check
bash scripts/ci.sh
bash scripts/perf/suite7.sh
```

## Docs Index

- Product principles: `PRODUCT_PRINCIPLES.md`
- Migration status: `RLM_FIRST_MIGRATION_PLAN.md`
- Runbook: `RUNBOOK.md`
- Client-facing behavior: `docs/client_integration.md`
- OpenAPI contract: `docs/openapi/pecr.v1.yaml`
- RLM runtime envelope: `docs/architecture/rlm_runtime_envelope.md`
- Useful benchmark definition: `docs/useful_benchmark.md`
- Real-backend operations: `docs/observability/rlm_real_backend_operations.md`
