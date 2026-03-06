# Next Phase Roadmap

Primary goal for the next phase: make PECR more useful, not just safer.

The current foundation is strong enough to build on. Safety, replayability, contract checks, and local verification are in place. From here, the highest-value work is improving answer quality, operator usefulness, and real user workflows while preserving the invariants in `docs/architecture/invariants.md`.

## Completed Foundation

- [x] Evidence-backed `SUPPORTED` flow is implemented end-to-end.
- [x] Replay persistence, replay evaluation, and regression gating exist.
- [x] Gateway and controller HTTP layers have been decomposed to a maintainable baseline.
- [x] OpenAPI and handler shape drift checks exist.
- [x] One-command local verification works in both Bash and PowerShell.
- [x] Architecture and observability baselines are documented.

## Phase 1: Answer Quality First

- [x] Improve controller query planning so operator choice is driven by user intent instead of a mostly fixed loop.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/finalize.rs`, `crates/controller/src/http/tests.rs`
  Done when: different query classes produce meaningfully different operator plans and better final claim maps.

- [x] Add evidence ranking and deduplication before finalize.
  Files: `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/finalize.rs`
  Done when: redundant evidence is collapsed and final responses prefer the strongest evidence units.

- [x] Improve claim synthesis so supported claims are derived from evidence content more intelligently.
  Files: `crates/controller/src/http/finalize.rs`, `crates/controller/src/http/tests.rs`
  Done when: claim text is more specific, less repetitive, and still evidence-bound.

- [x] Add golden run fixtures for representative user tasks.
  Files: `fixtures/replay/`, `scripts/tests/`, `crates/controller/src/http/tests.rs`
  Done when: at least 5 realistic task patterns are replayable and regression-tested.

## Phase 2: Operator Usefulness

- [x] Expand retrieval ergonomics for `search`.
  Files: `crates/gateway/src/http/operator_api.rs`, `crates/gateway/src/http/runtime.rs`, `crates/adapters/src/lib.rs`
  Done when: search supports better filtering, ranking inputs, and clearer result payloads for the controller.

- [x] Add richer structured fetch/aggregate flows for common analyst-style questions.
  Files: `crates/controller/src/config.rs`, `crates/controller/src/http/orchestration.rs`, `crates/controller/src/http/finalize.rs`, `crates/controller/src/http/tests.rs`, `crates/gateway/src/http/operator_api.rs`, `crates/gateway/src/http/runtime.rs`
  Done when: the controller can answer more "compare", "summarize", and "trend" queries without awkward operator chaining.

- [x] Add user-useful evidence summaries or snippets alongside raw evidence payloads.
  Files: `crates/gateway/src/http/operator_api.rs`, `crates/controller/src/http/finalize.rs`, `docs/openapi/pecr.v1.yaml`
  Done when: final responses can cite concise evidence without requiring clients to inspect raw units manually.

- [x] Improve operator parameter normalization and error clarity.
  Files: `crates/adapters/src/lib.rs`, `crates/gateway/src/http/operator_api.rs`
  Done when: malformed-but-recoverable inputs are normalized consistently and invalid inputs fail with clear guidance.

## Phase 3: User-Facing Product Value

- [x] Add a small benchmark corpus of real "useful answer" scenarios.
  Files: `fixtures/`, `scripts/replay/`, `docs/`
  Done when: the repo has named scenarios that reflect real user jobs, not only infrastructure behavior.

- [x] Improve replay evaluation scoring to measure usefulness, not just safety semantics.
  Files: `crates/controller/src/replay.rs`, `scripts/replay/replay_eval_cli.py`, `scripts/tests/`
  Done when: scorecards include answer-quality dimensions such as evidence coverage quality, citation quality, or benchmark pass rate.

- [x] Add example workflows and demo scripts for common repository use cases.
  Files: `README.md`, `RUNBOOK.md`, `scripts/`
  Done when: a new contributor can run 2-3 useful end-to-end scenarios without reverse-engineering the system.

## Phase 4: Productization After Usefulness Gains

- [x] Add a real-stack integration lane that exercises the documented useful scenarios.
  Files: `.github/workflows/ci.yml`, `crates/e2e_smoke/`, `scripts/`
  Done when: CI proves the main user-value paths, not just component behavior.

- [x] Add targeted fault injection for usefulness-critical paths.
  Files: `scripts/perf/`, `crates/e2e_smoke/`, `docs/observability/baselines.md`
  Done when: we can show how answer quality degrades under OPA, replay-store, or source failures.

## Suggested Order

1. Query planning
2. Evidence ranking and claim synthesis
3. Search and aggregate operator improvements
4. Golden useful-task fixtures
5. Replay scoring upgrades
6. Demo workflows
7. Real-stack usefulness CI

## Notes

- Safety is not the primary feature target for this phase, but it remains a non-negotiable constraint.
- Any API shape changes in this phase must update:
  - `docs/openapi/pecr.v1.yaml`
  - `docs/openapi/contract_manifest.json`
  - contract-lock and shape tests
