# Observability Stack Target

## Objective
- Provide consistent dashboards, alert ownership, and incident-routing standards for PECR runtime and policy paths.

## Signals
- Metrics:
  - Controller: request latency/error, terminal mode distribution, budget stops/violations, in-flight ops, operator queue wait.
  - Gateway: request latency/error, policy-engine error/timeout behavior.
- Traces:
  - Required span families:
    - `planner.*`
    - `scheduler.*`
    - `operator.*`
    - `policy.evaluate`
    - `finalize.*`
    - `ledger.append`
- Logs:
  - Structured fields required on critical paths:
    - `trace_id`, `request_id`, `session_id`, `principal_id`, `policy_snapshot_id` when applicable.

## Dashboard Set
- `PECR / Runtime Health`
  - p50/p95/p99 latency by route and engine mode.
  - error-rate and source-unavailable trend.
- `PECR / Budget & Scheduler`
  - budget stop reasons over time.
  - inflight ops + queue wait heatmap.
- `PECR / Policy`
  - policy allow/deny ratio.
  - OPA timeout/unavailable rate.

## Repository Artifacts (OBS-003)
- Dashboard definitions:
  - `docs/observability/dashboards/pecr_runtime_health.dashboard.json`
  - `docs/observability/dashboards/pecr_budget_scheduler.dashboard.json`
- Alert definitions:
  - `docs/observability/alerts/pecr_slo_alerts.yaml`
- Artifact index:
  - `docs/observability/README.md`

## Alert Targets
- P1:
  - sustained gateway/controller 5xx rate above threshold.
  - OPA unavailable/circuit-open sustained.
  - budget-violation spike suggesting runaway scheduling.
- P2:
  - p95/p99 latency regression above SLO budget.
  - terminal-mode drift to `SOURCE_UNAVAILABLE`/`INSUFFICIENT_EVIDENCE`.

## Ownership
- Runtime orchestration alerts: controller owners.
- Policy-engine alerts: gateway/policy owners.
- Data-plane/ledger alerts: gateway + ledger owners.

## Change Management
- New critical route must be added to runtime dashboard and alert policy before release.
- Any new metric/trace family must be documented in this standard and runbook.
