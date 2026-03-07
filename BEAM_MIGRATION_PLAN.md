# BEAM Migration Plan

Archived historical context:

- This document is no longer the active product roadmap.
- The active roadmap is `RLM_FIRST_MIGRATION_PLAN.md`.
- Keep this file only as reference for legacy/internal BEAM experiments that still inform replay evaluation or migration history.

Goal: make PECR a more useful, resilient, and maintainable product without weakening its trust boundaries, replay guarantees, or evidence model.

Phase 4 RLM-first decision:

- BEAM remains an internal experiment and reference lane only.
- Scheduled product-facing usefulness lanes now center `baseline` and `rlm`.
- The old BEAM-specific usefulness wrappers have been removed from the active repo workflow surface.

## Recommendation

Do not rewrite PECR wholesale into Elixir, Gleam, or Erlang.

Use a hybrid architecture:

- keep the gateway, contracts, ledger, auth, and replay-critical controller surfaces in Rust
- introduce a BEAM service for planning, orchestration, fallback logic, and supervised background workflows

For this repo, that is the highest-leverage path to "very good software."

## Technology Choice

- Choose `Elixir` first if the goal is faster delivery, strong BEAM ergonomics, and a mature ecosystem.
- Consider `Gleam` later for pure planning libraries or isolated typed logic if the team wants stronger compile-time guarantees on BEAM.
- Do not start with Erlang unless the team already wants Erlang specifically.

Recommendation: start with `Elixir`, not `Gleam`.

## What Stays In Rust

These areas already fit Rust well and should remain the system boundary:

- controller HTTP surface and replay persistence: [http.rs](E:/PECR/crates/controller/src/http.rs)
- gateway policy, source access, session enforcement, and finalize gate: [http.rs](E:/PECR/crates/gateway/src/http.rs)
- contracts and schema lock: [lib.rs](E:/PECR/crates/contracts/src/lib.rs)
- ledger and Postgres persistence: [lib.rs](E:/PECR/crates/ledger/src/lib.rs)
- auth and OIDC/JWKS handling: [lib.rs](E:/PECR/crates/auth/src/lib.rs)
- boundary enforcement: [main.rs](E:/PECR/crates/boundary-check/src/main.rs)

Reason: these pieces are performance-sensitive, security-sensitive, or both.

## What Moves To BEAM

Best candidates:

- query planning
- retry and fallback orchestration
- multi-step workflow coordination
- timeout-aware recovery behavior
- asynchronous evaluation and benchmark jobs
- long-lived supervised planner workers

This should start by replacing or augmenting the current RLM orchestration logic, not the whole controller.

## Target Architecture

Add a new optional service, for example `beam/pecr_planner`:

- Rust controller sends query, budget, session metadata, and allowed operator list
- BEAM planner returns an explicit plan or next operator action
- Rust controller executes operators through the existing gateway
- Rust controller still owns evidence collection, finalize, replay bundles, and API responses

Critical rule: the BEAM planner must not read source systems directly.

## Migration Phases

### Phase 1: Shadow Planner

- add an Elixir service that accepts a planning request and returns a plan only
- keep Rust baseline execution as the source of truth
- log planner output into replay artifacts for comparison

Done when:

- planner output is replayed and diffable
- no production behavior depends on it yet

### Phase 2: Feature-Flagged Planner Execution

- add a new controller engine mode such as `beam_planner`
- let the Rust controller ask the planner for the next best operator path
- keep strict timeout, budget, and allowlist enforcement in Rust

Done when:

- controller can safely fall back to baseline if planner is unavailable
- planner decisions improve named usefulness benchmarks

### Phase 3: Fallback And Recovery

- move retry/fallback policy into BEAM supervision workflows
- let the planner suggest alternate safe paths when the first operator chain fails
- persist planner decisions and fallback branches in replay bundles

Done when:

- useful-answer rate improves under partial failure
- planner failures do not break the core answer path

### Phase 4: Background Work

- add supervised BEAM workers for nightly usefulness evaluation, scenario expansion, and batch planning experiments
- keep user-facing request handling bounded and Rust-controlled

Done when:

- background evaluation becomes easier to operate and recover
- request path remains deterministic and replayable

## Design Rules

- BEAM may plan; Rust must enforce.
- BEAM may suggest; gateway must authorize.
- BEAM may coordinate; finalize must still require evidence-backed supported claims.
- Every planner decision must be replay-visible.
- Planner unavailability must degrade to baseline mode, not outage.

These rules preserve the invariants in [invariants.md](E:/PECR/docs/architecture/invariants.md).

## First Concrete Implementation

1. Create `beam/pecr_planner` as an Elixir app.
2. Define a narrow JSON contract for `plan_request` and `plan_response`.
3. Add a controller-side planner client behind a feature flag.
4. Start in shadow mode only.
5. Compare `baseline` vs `beam_planner_shadow` on the usefulness benchmark before switching execution paths.

## Success Metrics

- higher useful-answer rate on named benchmark scenarios
- fewer dead-end `INSUFFICIENT_EVIDENCE` outcomes for recoverable queries
- better degraded-path behavior under OPA/source issues
- no regression in replay determinism, finalize safety, or policy enforcement

## Non-Goals

- rewriting the gateway in Elixir
- moving DB/source adapters into BEAM first
- replacing the evidence model
- making planner behavior opaque or hard to replay

## Verdict

Yes, BEAM can make PECR better, but only if it is used surgically.

The right strategy is:

- Rust for boundaries, evidence, contracts, auth, and performance-critical execution
- Elixir for resilient planning and orchestration
- Gleam later, only if typed BEAM libraries become worth the extra complexity
