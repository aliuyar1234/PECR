# Rollout Control-Plane Contract

## Scope
- Controller runtime rollout behavior for baseline and RLM execution paths.
- Feature-flag controls, canary signals, and fallback policy.

## Feature Flags
- `PECR_CONTROLLER_ENGINE`:
  - `baseline`
  - `rlm`
- `PECR_RLM_DEFAULT_ENABLED`:
  - `false`/`true` (controller config default `false`; local compose default `true`)
  - only applies when `PECR_CONTROLLER_ENGINE` is unset or empty
  - when `true`, the controller defaults to `rlm` instead of `baseline`
- `PECR_RLM_AUTO_FALLBACK_TO_BASELINE`:
  - `false`/`true` (default `true`)
  - when `true`, the controller retries the request through the baseline runtime when the RLM bridge degrades with a replay-visible bridge failure
- `PECR_BASELINE_SHADOW_PERCENT`:
  - integer `0-100` (default `0`)
  - sampled percentage of RLM-served requests that also persist a baseline comparison replay
- `PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED`:
  - `true`/`false` (default `true`)
- `PECR_CONTROLLER_BATCH_MODE_ENABLED`:
  - `true`/`false` (default `true`)
- `PECR_OPERATOR_CONCURRENCY_POLICIES`:
  - JSON map: operator -> `{max_in_flight?, fairness_weight?}`

## Canary Signals
- Request-level:
  - `pecr_controller_http_request_duration_seconds`
  - `pecr_controller_http_requests_total`
- Runtime:
  - `pecr_controller_budget_violations_total`
  - `pecr_controller_budget_stop_reasons_total`
  - `pecr_controller_inflight_ops`
  - `pecr_controller_operator_queue_wait_seconds`
- Outcome:
  - `pecr_controller_terminal_modes_total`
- Replay/evaluation:
  - engine scorecards and `engine_comparisons` from replay evaluation results
  - nightly usefulness reports for baseline-shadow delta, finalize downgrade drift, and fallback recovery rate

## Auto-Fallback Policy
- Trigger rollback to safer settings when any condition is met for a sustained window (recommended: 5-10 minutes):
  - Budget violation rate exceeds baseline by configured threshold.
  - p95/p99 latency exceeds SLO threshold.
  - Source-unavailable/error terminal modes increase past threshold.
- Fallback order:
  1. Disable adaptive parallelism (`PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED=false`)
  2. Disable batch mode (`PECR_CONTROLLER_BATCH_MODE_ENABLED=false`)
  3. Disable RLM defaulting (`PECR_RLM_DEFAULT_ENABLED=0`)
  4. Switch engine to baseline (`PECR_CONTROLLER_ENGINE=baseline`)
- Recovery requires explicit operator acknowledgment and fresh canary run.

## Shadow Comparison Contract
- Baseline is no longer a peer default runtime; it is a reference lane.
- Sampled shadow runs should persist as normal replay bundles with `engine_mode=baseline` so replay scorecards and `engine_comparisons` can compare them against the primary `rlm` runs on matched queries.
- Scheduled nightly usefulness runs should keep the `baseline` lane and the `rlm` lane; the `rlm` lane may also sample baseline shadow runs for same-query comparisons.
- BEAM usefulness lanes are no longer part of the default rollout-control workflow and must not be required for the product release question.

## Deployment Contract
- Every rollout must define:
  - flag delta
  - canary cohort
  - expected SLO envelope
  - rollback owner
- Changes to control-plane semantics must update this document and runbook.

## Automation Path (OPS-002)
- Canary policy evaluator:
  - `python3 scripts/ops/canary_rollout_guard.py --summary <k6-summary.json> --metrics-gates <suite7_metrics_gates.json>`
- Generated artifacts:
  - JSON decision report (fallback status + trigger details)
  - Markdown summary (operator handoff)
  - ENV patch snippet (next fallback stage)
- CI integration:
  - `.github/workflows/ci.yml` perf job runs the guard for the RLM benchmark pass and publishes artifacts for rollout operators.
  - `.github/workflows/nightly-usefulness.yml` keeps only the baseline reference lane and the primary `rlm` lane active.
