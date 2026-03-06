# Observability Baselines

Use these baselines as the minimum production operating posture.

## Core SLOs

- Gateway and controller availability: target `99.9%` on `/readyz`.
- Finalize success after policy allow: target `99.5%+`.
- Replay persistence success: target `99.9%+` for successful `/v1/run` completions.
- OPA decision latency: page if sustained p95 crosses the configured timeout safety margin.

## Alerts That Should Exist

- `readyz` degraded by dependency:
  - gateway: `ledger`, `postgres`, `opa`
  - controller: `gateway`, `auth`, `replay_store`
- `SOURCE_UNAVAILABLE` rate spike on `/v1/run`, `/v1/operators`, or `/v1/finalize`.
- replay-store read/write failures.
- sustained finalize gate downgrade spikes if they indicate evidence coverage regression.

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

## Validation Hooks

- `scripts/validate_openapi.py` protects documented API invariants.
- `scripts/replay/regression_gate.py` protects terminal-mode and replay expectations.
- `scripts/perf/suite7.sh` plus the perf tests protect latency and semantic regressions.
- `scripts/run_useful_e2e.sh` proves the named usefulness scenarios and their fault-degradation behavior on the real stack.

## Usefulness Degradation Expectations

- Healthy useful-scenario runs should stay `SUPPORTED` for the named queries exercised by `useful_real_stack_suite_exercises_named_queries`.
- OPA or source failures should degrade useful `/v1/run` queries to `SOURCE_UNAVAILABLE` rather than silently returning weak or unsupported claims.
- Replay-store failures should make controller `/readyz` and replay APIs degrade, even if an in-flight useful answer can still complete.
- `scripts/perf/suite7.sh` should keep the default `"smoke"` controller probe and the usefulness-focused query probe aligned on terminal-mode expectations during OPA and Postgres faults.
- `scripts/replay/useful_benchmark_cli.py validate` should pass before treating usefulness fixtures or scorecards as release-grade evidence.
