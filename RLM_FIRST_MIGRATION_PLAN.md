# RLM-First Migration Plan

This is the working plan to move PECR from "RLM is one engine option" to "RLM is the primary reasoning runtime, with PECR providing the policy, evidence, finalize, and replay plane underneath it."

The intent matches the product direction in `PRODUCT_PRINCIPLES.md`: PECR should become a more useful version of the forked RLM project, not just a safer wrapper around fixed retrieval loops.

## Why This Plan Uses Phases And Gates

RLM-first is the right direction, but it touches multiple failure-prone areas at once:

- planner behavior
- runtime performance
- gateway tool safety
- evidence and finalize correctness
- replay visibility
- rollout and fallback behavior

Because of that, the project should not move to the next phase just because the code "mostly works". Each phase below has a gate. If the gate is not green in CI and reproducible locally, the next phase does not start.

## Target End State

When this plan is complete:

- `rlm` is the default and primary execution path for `/v1/run`.
- RLM owns planning, replanning, clarification, batching decisions, and recovery behavior.
- the controller still owns budgets, allowlists, operator execution, replay persistence, and the public API.
- the gateway still owns policy checks, source access, evidence emission, and finalize enforcement.
- long-context reasoning is used intentionally for evidence synthesis, not as a replacement for policy-scoped retrieval.
- `baseline` exists only as a temporary shadow or reference lane, then is retired or reduced to evaluation-only use.
- `beam_planner` is either frozen as an experiment or explicitly scoped to help the RLM-first product, not compete with it.

## Current State

Today the repository is only partway to that target:

- the controller can route into `rlm`
- the governance plane is real and already strong
- replay, evaluations, contracts, and CI are in place
- but the RLM bridge is still mock-oriented rather than a fully productized RLM backend
- baseline, beam, and RLM still appear as peer engine modes instead of one clear product direction

That means the architecture is ready for RLM-first, but the implementation and product posture are not yet fully aligned.

## Non-Negotiable Invariants

This migration must preserve the invariants already documented in `docs/architecture/invariants.md` and `docs/architecture/planner_contract.md`.

- The controller must not read source systems directly.
- The gateway must remain the only privileged data-access boundary.
- `SUPPORTED` must continue to require evidence-backed finalize approval.
- planner output must remain advisory and bounded by controller-enforced budgets and operator allowlists.
- every successful run must stay replayable and auditable.
- planner or model failure must degrade gracefully, not create user-visible corruption or silent unsupported answers.

## Phase 0: Product Reset And Success Definition

Goal: make the RLM-first direction explicit, measurable, and hard to accidentally drift away from.

- [x] Declare RLM as the primary product direction in roadmap and top-level product docs.
  Files: `README.md`, `PRODUCT_PRINCIPLES.md`, `IMPLEMENTATION_ROADMAP.md`, this file
- [ ] Freeze new feature work that makes `baseline` or `beam_planner` more product-central unless it directly supports RLM-first migration, eval, or fallback safety.
  Files: roadmap docs, `TODO.md`
- [x] Define the primary RLM-first scorecard:
  Files: `docs/useful_benchmark.md`, `docs/observability/baselines.md`
  Metrics:
  - useful-answer rate
  - supported-answer rate
  - fallback recovery rate
  - finalize downgrade rate
  - p95 latency
  - throughput
  - shadow delta versus baseline
- [x] Define the named benchmark suite that RLM must win before becoming the default path.
  Files: `fixtures/replay/useful_tasks/`, `scripts/replay/`, `docs/useful_benchmark.md`
- [x] Decide the supported model/backend envelope for the first real RLM runtime.
  Files: `RUNBOOK.md`, `docker-compose.yml`, `docs/architecture/`

Gate before Phase 1:

- [x] The docs state clearly that PECR is moving to RLM-first behavior.
- [x] The benchmark scenarios and success metrics are committed in the repo.
- [ ] New work is being judged primarily by whether it improves the RLM-first path.

## Phase 1: Replace The Mock Bridge With A Real RLM Runtime Seam

Goal: move from "controller can talk to a mock RLM bridge" to "controller can reliably execute a real RLM-backed planning loop."

- [x] Replace mock-only bridge behavior with a real backend adapter over the vendored RLM runtime.
  Files: `scripts/rlm/pecr_rlm_bridge.py`, `vendor/rlm/`, `scripts/tests/test_rlm_bridge.py`
- [x] Keep the bridge protocol explicit and versioned, including structured messages for start, tool calls, batched tool calls, completion, and bridge failure reasons.
  Files: `scripts/rlm/pecr_rlm_bridge.py`, `crates/controller/src/http/orchestration.rs`, `docs/architecture/planner_contract.md`
- [x] Eliminate per-request spawn overhead where possible with a persistent worker model or pooled bridge processes.
  Files: `crates/controller/src/http/orchestration.rs`, `scripts/rlm/pecr_rlm_bridge.py`, `docs/architecture/request_path_blocking_audit.md`
- [x] Make bridge stop reasons and tool trajectories replay-visible.
  Files: `crates/controller/src/replay.rs`, `crates/controller/src/http/orchestration.rs`, `scripts/replay/`
- [x] Add deterministic failure mapping for bridge timeout, protocol drift, backend unavailability, and invalid tool requests.
  Files: `crates/controller/src/http.rs`, `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/tests.rs`
- [x] Add local and CI setup for the real RLM lane rather than a mock-only verification story.
  Files: `docker-compose.yml`, `.github/workflows/`, `RUNBOOK.md`

Gate before Phase 2:

- [x] `controller_engine=rlm` runs with a real bridge/backend in local and CI environments.
- [x] `cargo test --workspace --exclude e2e_smoke` is green.
- [x] `cargo test -p e2e_smoke` is green.
- [x] `python -m unittest scripts.tests.test_rlm_bridge` is green.
- [x] `cargo run -p pecr-boundary-check` is green.
- [x] Bridge failures degrade cleanly without corrupting terminal-mode semantics or replay artifacts.

## Phase 2: Make RLM The Planner Of Record

Goal: let RLM drive the reasoning path, while Rust remains the enforcement and execution owner.

- [x] Expand the planner contract so RLM sees the information it actually needs:
  Files: `crates/contracts/src/lib.rs`, `docs/architecture/planner_contract.md`
  Add:
  - richer tool schema
  - recovery context
  - prior tool observations
  - clarification opportunities
  - structured failure feedback
- [x] Move more path-selection logic out of fixed Rust heuristics and into the RLM plan itself.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/tests.rs`
- [x] Teach RLM to handle multi-clause questions without collapsing them to one narrow path.
  Files: `crates/controller/src/http/orchestration.rs`, `fixtures/replay/useful_tasks/`, `scripts/replay/`
- [x] Teach RLM to recover after a weak or blocked first attempt by selecting a second safe path when one exists.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http.rs`, `crates/controller/src/http/tests.rs`
- [x] Add explicit clarification behavior for ambiguous asks instead of relying mostly on fallback text generation.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/finalize.rs`, `docs/openapi/pecr.v1.yaml`
- [x] Improve batching and parallel tool-call planning where the operator and budget policies allow it.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/config.rs`, `docs/observability/baselines.md`

Gate before Phase 3:

- [x] RLM beats or matches `baseline` on the named core usefulness benchmark.
- [x] Multi-part benchmark scenarios no longer depend on hard-coded Rust-first planner heuristics to pass.
- [x] Clarification and recovery behavior are replay-visible and covered by tests.
- [x] `bash scripts/perf/suite7.sh` is stable across repeated runs in both local and CI environments.
- [x] Finalize correctness stays green for both straightforward and recovery-driven RLM scenarios.

## Phase 3: Build Long-Context Evidence Synthesis That Is Actually Product-Useful

Goal: use larger model context windows to improve synthesis, comparison, and version review without weakening grounding.

- [x] Add an explicit evidence-packing and compaction layer for large evidence sets.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/finalize.rs`, `crates/contracts/src/lib.rs`
- [x] Separate context budget management from operator-call budget management.
  Files: `crates/contracts/src/lib.rs`, `crates/controller/src/config.rs`, `crates/controller/src/http/orchestration.rs`
- [x] Define when the system should pass raw evidence, compacted evidence, summaries, diffs, or a mixed bundle into the RLM context.
  Files: `docs/architecture/controller_state_machine.md`, `docs/architecture/`, `crates/controller/src/http/orchestration.rs`
- [x] Improve claim and citation synthesis for cross-document, cross-version, and compare-style answers.
  Files: `crates/controller/src/http/finalize.rs`, `crates/controller/src/http/tests.rs`
- [x] Add benchmark scenarios with large evidence fan-out, version-heavy queries, and mixed structured-plus-unstructured asks.
  Files: `fixtures/replay/useful_tasks/`, `scripts/replay/`, `docs/useful_benchmark.md`
- [x] Add observability for context pack size, evidence compaction ratio, and citation coverage quality.
  Files: `docs/observability/`, `crates/controller/src/metrics.rs`, dashboards and alerts

Gate before Phase 4:

- [x] RLM can handle large multi-document or version-heavy tasks without losing finalize supportability.
- [x] Supported claims still satisfy coverage requirements after compaction or summarization.
- [x] Long-context scenarios improve usefulness scores, not just token usage.
- [x] Latency, throughput, and cost stay inside the agreed envelope for the benchmark suite.

## Phase 4: Roll Out RLM As The Default Runtime

Goal: make RLM the default product path while keeping safe fallback controls during rollout.

- [x] Add an explicit RLM-default rollout flag so unset-engine environments can canary into RLM without losing a clean rollback path.
  Files: `crates/controller/src/config.rs`, `docker-compose.yml`, `docs/standards/ROLLOUT_CONTROL_PLANE_CONTRACT.md`
- [x] Make `rlm` the default engine in config, docs, and local runtime defaults.
  Files: `crates/controller/src/config.rs`, `README.md`, `docker-compose.yml`, `RUNBOOK.md`
- [x] Move `baseline` into shadow or reference mode only.
  Files: `crates/controller/src/http.rs`, `crates/controller/src/replay.rs`, `scripts/replay/`, `.github/workflows/`
- [x] Decide whether `beam_planner` remains as an internal experiment, is folded into evaluation tooling, or is retired from the product path.
  Files: `IMPLEMENTATION_ROADMAP.md`, `BEAM_MIGRATION_PLAN.md`, `.github/workflows/`, `beam/`
- [x] Add rollout knobs and canary controls for:
  Files: `docs/standards/ROLLOUT_CONTROL_PLANE_CONTRACT.md`, `crates/controller/src/config.rs`, `.github/workflows/`
  Controls:
  - enable or disable RLM defaulting
  - change shadow percentage
  - auto-fallback on bridge degradation
  - compare shadow outputs in replay scorecards
- [x] Add dashboards and alerts for bridge health, tool planning quality, finalize downgrade drift, and shadow deltas.
  Files: `docs/observability/`, dashboards and alerts

Gate before Phase 5:

- [x] Fresh installs and local demos use RLM by default.
- [x] Shadow baseline remains available as a regression detector.
- [x] At least 10 consecutive nightly or pre-release runs are green for usefulness, perf, e2e smoke, and contract lanes.
- [x] Rollback and auto-fallback controls are documented and tested.

Implementation note:

- Phase 4 implementation work is complete in-repo.
- The rollout evidence gate was satisfied on `2026-03-07` by 10 consecutive green `ci` runs on commit `c723d8d234bf0d9eeda5766d2c08ac95c89657a7`.
- Recorded run IDs: `22804181871`, `22804184647`, `22804185384`, `22804186066`, `22804186829`, `22804187671`, `22804188428`, `22804189241`, `22804190277`, `22804191241`.
- Phase 5 is complete.

## Phase 5: Simplify The Repo Around The RLM-First Product

Goal: stop presenting PECR as a three-way engine experiment once the product direction is proven.

- [x] Remove or hide user-facing product surfaces that imply `baseline` and `beam_planner` are equal long-term product modes.
  Files: `README.md`, `RUNBOOK.md`, `docs/openapi/`, `crates/controller/src/config.rs`
- [x] Retain only the minimum shadow or reference path needed for regression detection and offline evaluation.
  Files: `crates/controller/src/replay.rs`, `scripts/replay/`, `.github/workflows/`
- [x] Delete dead code, dead env vars, and dead CI lanes that only supported the earlier multi-engine transition period.
  Files: `crates/controller/src/config.rs`, `crates/controller/src/http/orchestration.rs`, `.github/workflows/`, `perf/`, `scripts/`
- [x] Re-baseline performance, usefulness, and reliability targets around the real RLM-first runtime.
  Files: `perf/`, `docs/observability/baselines.md`, `docs/useful_benchmark.md`
- [x] Update the public architecture story so PECR is clearly described as an RLM-first governed reasoning runtime.
  Files: `README.md`, `docs/architecture/`, `PRODUCT_PRINCIPLES.md`

Gate for completion:

- [x] The repo no longer treats `baseline` as a peer product strategy.
- [x] CI validates the RLM-first path as the main product path.
- [x] Any remaining shadow or reference path is intentional, documented, and low-maintenance.
- [x] The product story, architecture docs, and runtime defaults all agree.

## Phase 6: Productionize The Real RLM Backend

Goal: graduate from an opt-in real-backend seam to a supported real-backend operating lane.

- [x] Add a secret-backed real-backend usefulness lane that exercises bridge smoke plus named useful RLM scenarios on the actual backend.
  Files: `.github/workflows/rlm-real-backend-usefulness.yml`, `RUNBOOK.md`, `docs/architecture/rlm_runtime_envelope.md`
- [ ] Add backend-specific observability and runbook coverage for rate limits, credential expiry, backend timeouts, and provider drift.
  Files: `docs/observability/`, `RUNBOOK.md`, dashboards and alerts
- [ ] Define the promotion gate from manual real-backend validation into a scheduled or pre-release required lane.
  Files: `.github/workflows/`, `RUNBOOK.md`, `docs/architecture/rlm_runtime_envelope.md`
- [ ] Decide whether the real backend remains opt-in locally or gets a first-class supported development profile beyond mock-default compose.
  Files: `docker-compose.yml`, `README.md`, `docs/architecture/rlm_runtime_envelope.md`

Gate for completion:

- [ ] The secret-backed real-backend usefulness lane is green on repeated runs with replay-visible artifacts.
- [ ] Useful-answer and finalize semantics remain correct on the real backend lane without hidden dependence on baseline fallback.
- [ ] Credential, cost, and backend-incident response guidance are documented for operators.
- [ ] The promotion criteria for broader release automation are explicit and approved.

Implementation note:

- Phase 6 is started in-repo with a manual secret-backed real-backend usefulness workflow.

## Cross-Phase Rules

These apply to every phase:

- [ ] Do not bypass gateway policy or finalize just to make RLM look stronger.
- [ ] Do not let long context become an excuse for weak retrieval or unsupported claims.
- [ ] Any API shape change must update:
  - `docs/openapi/pecr.v1.yaml`
  - `docs/openapi/contract_manifest.json`
  - contract-lock and shape tests
- [ ] Any planner-contract change must update:
  - `docs/architecture/planner_contract.md`
  - replay artifacts and replay readers
  - controller and bridge tests
- [ ] Any trust-boundary change must keep `boundary-check` green or be intentionally reviewed.
- [ ] Any perf change must be validated locally and in GitHub Actions before the phase can be considered done.

## Recommended Immediate Execution Order

If work starts now, the next sequence should be:

1. Lock the product position and metrics in Phase 0.
2. Replace the mock-first bridge assumptions in Phase 1.
3. Make RLM the planner of record in Phase 2 before investing heavily in more baseline-side heuristics.
4. Build long-context evidence synthesis in Phase 3 only after the real RLM seam is stable.
5. Default to RLM in Phase 4.
6. Simplify the repo in Phase 5 after the rollout is proven.

## Success Definition

This migration is successful when a new contributor can look at the repo and immediately understand:

- PECR is an RLM-first product.
- RLM is responsible for reasoning behavior.
- PECR is responsible for safety, evidence, finalize, replay, and operability.
- the system is more useful because of RLM, not just more complicated around it.
