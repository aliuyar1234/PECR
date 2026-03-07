# PECR - Policy-Enforced Context Runtime

[![CI](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/ci.yml?branch=master&label=CI&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/security.yml?branch=master&label=Security&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/security.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/aliuyar1234/PECR/codeql.yml?branch=master&label=CodeQL&logo=githubactions&style=flat-square)](https://github.com/aliuyar1234/PECR/actions/workflows/codeql.yml)
[![Latest Release](https://img.shields.io/github/v/release/aliuyar1234/pecr?display_name=tag&label=release&style=flat-square)](https://github.com/aliuyar1234/PECR/releases/latest)
[![License](https://img.shields.io/github/license/aliuyar1234/PECR?style=flat-square)](LICENSE)

PECR is an RLM-first governance runtime for AI retrieval and reasoning.
It keeps orchestration non-privileged, enforces policy at every data access boundary, and returns deterministic outcomes with auditable evidence.

## Product Direction

PECR now has one clear product shape:

- RLM should be the primary reasoning and planning runtime.
- the controller and gateway should remain the trust, policy, evidence, and finalize boundary.
- baseline and other planner paths should exist only as shadow, evaluation, or fallback tools.
- BEAM-era planner work is now an internal experiment/reference lane, not a scheduled product-default lane.

The working migration plan for that direction lives in `RLM_FIRST_MIGRATION_PLAN.md`.
The first supported real backend shape for that migration is defined in `docs/architecture/rlm_runtime_envelope.md`.

## What PECR Solves

Plain RAG pipelines and agentic retrieval loops usually leave hard governance gaps around policy, provenance, and deterministic failure handling.
PECR adds those missing controls while aiming for more capable RLM-style planning and long-context synthesis:

- Policy-first execution through OPA decisions.
- Immutable, hash-stable EvidenceUnits with provenance metadata.
- Deterministic terminal modes (`SUPPORTED`, `INSUFFICIENT_EVIDENCE`, `INSUFFICIENT_PERMISSION`, `SOURCE_UNAVAILABLE`).
- Strict trust boundary between non-privileged controller and privileged gateway.
- Replay and evaluation APIs for repeatability and quality gates.

## High-Level Architecture

PECR is an RLM-first AI runtime wrapped by a policy/evidence governance plane.
The repo still contains baseline and limited BEAM-era compatibility surfaces for reference, shadow evaluation, and legacy/internal experiments, but the product shape is one primary RLM reasoning path over one governance plane.

```mermaid
flowchart LR
    Client["Client / Agent UI"]

    subgraph AIPlane["AI Execution Plane - Non Privileged"]
      Controller["PECR Controller API"]
      Baseline["Baseline Shadow / Reference Loop"]
      RLM["RLM Planner Bridge (vendored upstream rlm)"]
      Scheduler["Budget Scheduler + Batch Executor"]
      Replay["Replay Store + Evaluation APIs"]
    end

    subgraph Governance["Policy + Evidence Plane - Privileged"]
      Gateway["PECR Gateway"]
      OPA["OPA Policy Engine"]
      Evidence["Redaction + Evidence Builder"]
      Finalize["Claim-Evidence Finalize Gate"]
      Ledger["Append-Only Ledger"]
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
    Controller -->|shadow/reference lane| Baseline
    Controller -->|primary reasoning direction| RLM
    Baseline --> Scheduler
    RLM -->|plan, replan, batch, recover| Scheduler

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
RLM is meant to own reasoning behavior, not privileged access.

## Request Lifecycle

1. Client starts a request (or full `/v1/run`) with principal identity.
2. Controller executes a budgeted RLM-driven loop and calls only allowlisted gateway operators.
3. Gateway enforces policy, applies redaction, and emits evidence.
4. Controller submits response text plus claim map to finalize.
5. Gateway validates claim-to-evidence coverage and returns terminal mode.

During migration, a baseline/reference path may still run for shadowing or fallback, but it is not the intended long-term product center.

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

## 5-Minute Fast Start (Local)

### Prerequisites

- Docker + Docker Compose
- Rust toolchain
- Bash (or WSL/Git Bash on Windows)

### 1) Start the stack

Bash:

```bash
docker compose up -d --build
```

PowerShell:

```powershell
docker compose up -d --build
```

Postgres is exposed on `127.0.0.1:${PECR_POSTGRES_PORT:-55432}` by default.
The local compose path also defaults `PECR_LOCAL_AUTH_SHARED_SECRET` to `pecr-local-demo-secret`, so the demo commands below work without extra tuning.
Local compose also defaults into the RLM controller path with the mock bridge backend plus baseline auto-fallback, so the fast start stays zero-setup.

### 2) Verify health endpoints

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
```

### 3) Run a useful live scenario

```bash
curl -sS http://127.0.0.1:8081/v1/capabilities \
  -H 'x-pecr-principal-id: dev' \
  -H 'x-pecr-local-auth-secret: pecr-local-demo-secret'

python -B scripts/demo/useful_workflows.py tour
python -B scripts/demo/useful_workflows.py live-tour
python -B scripts/demo/useful_workflows.py live-scenario customer-status
python -B scripts/demo/useful_workflows.py live-smoke
```

`tour` gives a fast fixture-backed product walkthrough. `live-tour` waits for the local controller, fetches the safe-ask catalog, then runs a curated set of grounded product scenarios so new contributors can see structured lookup, source citation, aggregate comparison, partial answers, and narrowing guidance in one pass.

### 4) Run a raw smoke request

```bash
curl -sS -X POST http://127.0.0.1:8081/v1/run \
  -H 'content-type: application/json' \
  -H 'x-pecr-principal-id: dev' \
  -H 'x-pecr-local-auth-secret: pecr-local-demo-secret' \
  -H 'x-pecr-request-id: demo' \
  -d '{"query":"What is the customer status and plan tier?"}'
```

The capability catalog gives callers a low-friction way to discover safe structured lookups, comparisons, evidence asks, and version-review prompts before they send a full `/v1/run` request.

### 5) Run local quality, e2e, and perf smoke

```bash
bash scripts/verify.sh
pwsh -File scripts/verify.ps1
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr cargo test -p e2e_smoke -- --nocapture
SUITE7_SKIP_FAULTS=1 bash scripts/perf/suite7.sh
```

Outputs: `target/perf/`

## Runtime Paths

| Path | Engine | Enablement | Typical use |
|---|---|---|---|
| RLM | `rlm` | Explicit `PECR_CONTROLLER_ENGINE=rlm`, or default when `PECR_CONTROLLER_ENGINE` is unset and `PECR_RLM_DEFAULT_ENABLED=1`, plus `PECR_RLM_SANDBOX_ACK=1` (controller built with `--features rlm`) | Primary product path with adaptive planning, batching, recovery behavior, and optional baseline shadow comparison |
| Baseline Reference | `baseline` | Explicit `PECR_CONTROLLER_ENGINE=baseline`, or sampled as a shadow/reference lane via `PECR_BASELINE_SHADOW_PERCENT>0` while RLM serves the user-visible response | Reference, shadow comparison, migration safety, and rollback lane rather than a peer product mode |

Perf harness commands:

```bash
# Baseline
bash scripts/perf/suite7.sh

# RLM baseline matrix lane
PECR_CONTROLLER_ENGINE_OVERRIDE=rlm \
PECR_RLM_SANDBOX_ACK=1 \
SUITE7_SKIP_FAULTS=1 \
CONTROLLER_BASELINE_SUMMARY_NAME=suite7_rlm_baseline.summary.json \
GATEWAY_BASELINE_SUMMARY_NAME=suite7_rlm_gateway_baseline.summary.json \
METRICS_GATES_FILE=target/perf/suite7_rlm_metrics_gates.json \
bash scripts/perf/suite7.sh
```

Suite7 expectations are versioned in `perf/config/suite7_expectations.v1.json`.
Terminal-mode assertions are explicit opt-in via `SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS=1`.

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

## Useful Demo Workflows

If you want to see PECR’s user-value paths without booting the full stack first, use the named usefulness corpus in `fixtures/replay/useful_tasks/`.

```bash
python3 scripts/demo/useful_workflows.py catalog
python3 scripts/demo/useful_workflows.py tour
python3 scripts/demo/useful_workflows.py scenario customer-status
python3 scripts/demo/useful_workflows.py scenario customer-counts-by-plan
python3 scripts/demo/useful_workflows.py benchmark
python3 scripts/demo/useful_workflows.py live-tour
python3 scripts/demo/useful_workflows.py live-scenario customer-status
python3 scripts/demo/useful_workflows.py live-smoke
```

`tour` is the quickest guided product summary without booting services. `live-tour` is the best under-five-minute contributor demo once `docker compose up -d --build` is running, because it uses `/v1/capabilities` and a curated set of live asks instead of isolated spot checks.

These workflows cover structured lookup, source-backed evidence lookup, version review, compare, trend, partial-answer, and narrowing-guidance jobs. For the benchmark catalog and validation details, see `docs/useful_benchmark.md`.

The `live-*` commands assume the default local compose secret `pecr-local-demo-secret` unless `PECR_LOCAL_AUTH_SHARED_SECRET` overrides it. To exercise the same named scenarios against the real stack, set `PECR_TEST_DB_URL` and run `scripts/run_useful_e2e.sh`.

## Client Integration Semantics

PECR returns `response_text` as the main user-facing answer, then uses `response_kind` and claim metadata to tell clients how to present edge cases cleanly:

- No `response_kind`: treat the response as a normal grounded answer.
- `partial_answer`: show the grounded portion normally and surface `claim_map.notes` as the unresolved-details callout.
- `ambiguous`: render `claim_map.clarification_prompt.question` and its `options` as the next-step UX.
- `blocked` or `source_down`: show the error `message`, then present `what_failed` and `safe_alternative` as the safe recovery path.

For concrete payload examples, see `docs/client_integration.md` and the `/v1/run` examples in `docs/openapi/pecr.v1.yaml`.

## RLM Runtime Direction

PECR now defaults local runtime wiring toward an RLM-first controller path.
The migration in `RLM_FIRST_MIGRATION_PLAN.md` is about proving that default operationally, not about keeping baseline as a peer product mode.

The first supported real backend envelope is documented in `docs/architecture/rlm_runtime_envelope.md`.
Important current truth: the controller still rejects `PECR_MODEL_PROVIDER=external`, so the real RLM backend must land through the bridge/runtime path first rather than through the current Rust model-provider switch. Local compose defaults to the `mock` bridge backend; the initial `openai` seam is real but still opt-in.

RLM upstream/update model:

- research upstream: `alexzhang13/rlm` and its accompanying Recursive Language Models paper
- shipped PECR runtime: the vendored integration in `vendor/rlm`, adapted behind `scripts/rlm/pecr_rlm_bridge.py`
- update policy: upstream changes may be proposed automatically or synced manually, but adoption into PECR is explicit and review-gated, not automatic at runtime

Phase 6 local-development decision:

- keep the real backend explicit and opt-in for now
- do not add a second default compose profile yet
- when you want the live bridge backend locally, set `PECR_RLM_BACKEND=openai`, `PECR_RLM_MODEL_NAME`, and `OPENAI_API_KEY` or `PECR_RLM_API_KEY` before running `docker compose up`

Enable RLM mode:

- Build `pecr-controller` with feature `rlm`
- Set:
  - either `PECR_CONTROLLER_ENGINE=rlm`, or leave `PECR_CONTROLLER_ENGINE` unset and use `PECR_RLM_DEFAULT_ENABLED=1`
  - `PECR_RLM_SANDBOX_ACK=1`

Useful knobs:
- `PECR_RLM_BACKEND` (`mock` or `openai`)
- `PECR_RLM_MODEL_NAME`
- `PECR_RLM_API_KEY` or standard `OPENAI_API_KEY`
- `PECR_RLM_BASE_URL`
- `PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED`
- `PECR_CONTROLLER_BATCH_MODE_ENABLED`
- `PECR_RLM_AUTO_FALLBACK_TO_BASELINE`
- `PECR_BASELINE_SHADOW_PERCENT`
- `PECR_OPERATOR_CONCURRENCY_POLICIES`
- `PECR_RLM_SCRIPT_PATH`
- the controller now keeps a persistent bridge worker alive across requests, auto-falls back to baseline on bridge degradation when enabled, and records bridge backend/stop-reason detail in replay-visible planner traces

Current transition note:

- `rlm` is the default local product path.
- `baseline` remains intentionally available as a reference/shadow/fallback lane, not as a peer default product mode.
- scheduled usefulness lanes now center the baseline reference lane and the primary `rlm` lane.
- the bridge-backed real backend seam currently starts with `PECR_RLM_BACKEND=openai` plus `PECR_RLM_MODEL_NAME` and `OPENAI_API_KEY` or `PECR_RLM_API_KEY`.
- the governance model does not change: gateway policy, evidence capture, and finalize remain authoritative for every engine path.

Manual live smoke for the real bridge seam:

```bash
PECR_RLM_BACKEND=openai \
PECR_RLM_MODEL_NAME=<model> \
OPENAI_API_KEY=<key> \
python3 -B scripts/rlm/openai_bridge_smoke.py
```

Manual Actions lane:
- `.github/workflows/rlm-real-backend-smoke.yml`
- configure repo variable `PECR_RLM_OPENAI_MODEL_NAME`
- configure secret `OPENAI_API_KEY`

Pre-release gate and workflow:
- `python3 -B scripts/ops/check_real_backend_promotion_gate.py`
- `.github/workflows/rlm-real-backend-pre-release.yml`

Vendored upstream sync:

```bash
python3 scripts/rlm/sync_vendor_rlm.py
python3 scripts/rlm/sync_vendor_rlm.py --commit <40-char-sha>
python3 scripts/rlm/verify_vendor_rlm.py
```

The sync path updates `vendor/rlm` plus `vendor/rlm/UPSTREAM_PIN`; PECR still ships only what is reviewed and merged.

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

RLM migration note:
- local compose defaults `PECR_RLM_DEFAULT_ENABLED=1`, `PECR_RLM_SANDBOX_ACK=1`, and `PECR_RLM_AUTO_FALLBACK_TO_BASELINE=1`
- use `PECR_BASELINE_SHADOW_PERCENT` when you want replay-visible baseline comparison runs during the rollout
- keep `PECR_MODEL_PROVIDER=mock` as the honest default until Rust-native external-provider support exists
- use `docs/architecture/rlm_runtime_envelope.md` as the source of truth for the first real backend shape

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

## Operator Troubleshooting (CI/Perf/Release)

| Symptom | Inspect first | Operator action |
|---|---|---|
| Perf gate fails in CI | `artifacts/perf/perf_failure_reasons.json`, `artifacts/perf/benchmark_matrix.md` | Re-run `scripts/perf/suite7.sh` locally, compare against `perf/baselines/suite7_baseline.summary.json`, and review `failed_checks`/`failure_reasons` artifacts. |
| Release publish fails while fetching artifacts | Release job step `Fetch release artifacts with retry/backoff and validate checksums` | Re-run release via `workflow_dispatch` using `mode=republish`, `tag=<release-tag>`, and `source_run_id=<previous-run-id>`. |
| Release attestation verification fails | `scripts/security/verify_release_attestations.py` output in release logs | Re-run dispatch with correct `source_ref` for the artifact-producing run (for tag-triggered runs, use `refs/tags/<tag>`). |
| Post-release smoke check fails | `scripts/security/release_smoke_check.py` logs | Verify `release/SHA256SUMS.txt`, `release/image-digests.txt`, and GH release assets; then republish from existing artifacts after correcting manifest/asset mismatch. |
| Terminal-mode assertions are noisy | `perf/config/suite7_expectations.v1.json` + Suite7 env in CI | Keep mode assertions opt-in (`SUITE7_ENFORCE_TERMINAL_MODE_ASSERTIONS=0` by default) and only enable when validating mode-specific behavior. |

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
- `RLM_FIRST_MIGRATION_PLAN.md`: phased roadmap to make PECR RLM-first

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude e2e_smoke
PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr cargo test -p e2e_smoke
bash scripts/verify.sh
pwsh -File scripts/verify.ps1
```

## Docs Index

- Architecture:
  - `docs/architecture/controller_state_machine.md`
  - `docs/architecture/request_path_blocking_audit.md`
  - `docs/architecture/invariants.md`
  - `docs/architecture/rlm_runtime_envelope.md`
  - `RLM_FIRST_MIGRATION_PLAN.md`
- Runbook:
  - `RUNBOOK.md`
  - `docs/observability/baselines.md`
- Replay/Eval:
  - `scripts/replay/replay_eval_cli.py`
  - `scripts/replay/regression_gate.py`
  - `docs/standards/REPLAY_PERSISTENCE_MODEL.md`
  - `docs/standards/EVALUATION_DATA_LIFECYCLE.md`
- Client integration:
  - `docs/client_integration.md`
  - `docs/openapi/pecr.v1.yaml`
- Release:
  - `.github/workflows/release.yml`
  - `scripts/security/verify_release_attestations.py`
  - `scripts/security/release_smoke_check.py`
  - `docs/standards/ARTIFACT_PROVENANCE_POLICY.md`
- Operability and quality:
  - `RUNBOOK.md`
  - `docs/observability/README.md`
  - `docs/enterprise/QUALITY_GUARDRAILS.md`
