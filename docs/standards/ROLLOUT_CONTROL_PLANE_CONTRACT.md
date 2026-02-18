# Rollout Control-Plane Contract

## Scope
- Controller runtime rollout behavior for baseline and RLM execution paths.
- Feature-flag controls, canary signals, and fallback policy.

## Feature Flags
- `PECR_CONTROLLER_ENGINE`:
  - `baseline` (default)
  - `rlm`
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

## Auto-Fallback Policy
- Trigger rollback to safer settings when any condition is met for a sustained window (recommended: 5-10 minutes):
  - Budget violation rate exceeds baseline by configured threshold.
  - p95/p99 latency exceeds SLO threshold.
  - Source-unavailable/error terminal modes increase past threshold.
- Fallback order:
  1. Disable adaptive parallelism (`PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED=false`)
  2. Disable batch mode (`PECR_CONTROLLER_BATCH_MODE_ENABLED=false`)
  3. Switch engine to baseline (`PECR_CONTROLLER_ENGINE=baseline`)
- Recovery requires explicit operator acknowledgment and fresh canary run.

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
