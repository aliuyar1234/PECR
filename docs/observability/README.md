# Observability Artifacts

This directory contains versioned observability artifacts for PECR runtime SLOs.

## Dashboards
- `dashboards/pecr_runtime_health.dashboard.json`
  - Runtime latency/error overview (p95/p99, 5xx, terminal-mode drift).
- `dashboards/pecr_budget_scheduler.dashboard.json`
  - Scheduler safety and budget behavior (queue wait, inflight ops, stop reasons, violation rates).

## Alerts
- `alerts/pecr_slo_alerts.yaml`
  - Prometheus alert rules for P1/P2 conditions from `docs/standards/OBSERVABILITY_STACK_TARGET.md`.

## Operational Flow
1. Import dashboards into Grafana (or track as Jsonnet/Tanka in downstream infra repos).
2. Load alert rules into Prometheus/Alertmanager.
3. Keep this directory in lockstep with runtime metric additions and runbook updates.
