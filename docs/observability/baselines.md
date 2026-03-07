# Observability Baselines

Use these baselines as the minimum production operating posture.

## RLM-First Operating Scorecard

For the RLM-first rollout, every nightly lane and release candidate should report at least:

- useful-answer rate on the named usefulness corpus
- supported-answer rate on the same corpus
- fallback recovery rate for degraded-path scenarios
- finalize downgrade rate after a planner path appeared promising
- context pack size and evidence-pack mode distribution for long-context scenarios
- evidence compaction ratio for packed planner/finalize context
- citation quality for supported claims after compaction or summarization
- p95 latency for `/v1/run`
- throughput for the standard perf lane
- shadow delta versus baseline on matched benchmark scenarios

Release posture should not advance if these numbers are invisible, unstable, or moving in the wrong direction.
Before `rlm` becomes the default path, shadow delta versus baseline should be non-negative on the core benchmark set and the finalize downgrade rate should not show unexplained regression.

## Core SLOs

- Gateway and controller availability: target `99.9%` on `/readyz`.
- Finalize success after policy allow: target `99.5%+`.
- Replay persistence success: target `99.9%+` for successful `/v1/run` completions.
- OPA decision latency: page if sustained p95 crosses the configured timeout safety margin.

## Alerts That Should Exist

- `readyz` degraded by dependency:
  - gateway: `ledger`, `postgres`, `opa`
  - controller: `gateway`, `auth`, `replay_store`
- RLM bridge or backend degradation:
  - bridge spawn or worker failures
  - backend timeout or protocol errors
  - abnormal fallback activation rate
- `SOURCE_UNAVAILABLE` rate spike on `/v1/run`, `/v1/operators`, or `/v1/finalize`.
- replay-store read/write failures.
- sustained finalize gate downgrade spikes if they indicate evidence coverage regression.
- abnormal evidence compaction ratio shifts or evidence-pack mode drift on the long-context cohort.
- citation-quality regression on supported answers after long-context packing changes.
- shadow delta regression where RLM drops below baseline on the named benchmark set.

## Operator Runbook Expectations

- Replay-store failures:
  - stop treating runs as healthy until persistence is restored
  - preserve the failing artifacts directory for diagnosis
- OPA degradation:
  - check `readyz`, timeout settings, circuit-breaker state, and recent bundle rollouts
- Gateway degradation:
  - verify Postgres reachability, ledger writes, and safe-view source health
- Finalize regressions:
  - compare recent replay bundles against canonical fixtures and evaluation scorecards
- Long-context regressions:
  - inspect context-budget settings, evidence-pack mode distribution, compaction ratios, and claim-map citation quality before retuning prompts or perf gates
- RLM shadow delta regressions:
  - compare the latest `rlm` and `baseline` replay scorecards on matched scenarios
  - inspect planner traces, bridge stop reasons, and finalize downgrade causes before tuning perf gates

## Validation Hooks

- `scripts/validate_openapi.py` protects documented API invariants.
- `scripts/replay/regression_gate.py` protects terminal-mode and replay expectations.
- `scripts/perf/suite7.sh` plus the perf tests protect latency and semantic regressions.
- `scripts/run_useful_e2e.sh` proves the named usefulness scenarios and their fault-degradation behavior on the real stack.
- `scripts/replay/useful_benchmark_cli.py` is the primary RLM-first usefulness scorecard for named scenarios.
- `/metrics` should surface `pecr_controller_evidence_packs_total`, `pecr_controller_evidence_pack_units`, `pecr_controller_evidence_compaction_ratio`, and `pecr_controller_citation_quality` before treating Phase 3 as operationally complete.

## Usefulness Degradation Expectations

- Healthy useful-scenario runs should stay `SUPPORTED` for the named queries exercised by `useful_real_stack_suite_exercises_named_queries`.
- OPA or source failures should degrade useful `/v1/run` queries to `SOURCE_UNAVAILABLE` rather than silently returning weak or unsupported claims.
- Replay-store failures should make controller `/readyz` and replay APIs degrade, even if an in-flight useful answer can still complete.
- `scripts/perf/suite7.sh` should keep the default `"smoke"` controller probe and the usefulness-focused query probe aligned on terminal-mode expectations during OPA and Postgres faults.
- `scripts/replay/useful_benchmark_cli.py validate` should pass before treating usefulness fixtures or scorecards as release-grade evidence.
- RLM-first rollout decisions should use both perf and usefulness evidence; passing throughput alone is not enough if shadow delta or finalize downgrade rate is regressing.
