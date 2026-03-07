# Observability Artifacts

This directory contains versioned observability artifacts for PECR runtime SLOs.

## Dashboards
- `dashboards/pecr_runtime_health.dashboard.json`
  - Runtime latency/error overview (p95/p99, 5xx, bridge health, terminal-mode drift, finalize downgrade watch).
- `dashboards/pecr_budget_scheduler.dashboard.json`
  - Scheduler safety and budget behavior (queue wait, inflight ops, stop reasons, violation rates, fallback and planning-quality review).

## Alerts
- `alerts/pecr_slo_alerts.yaml`
  - Prometheus alert rules for P1/P2 conditions from `docs/standards/OBSERVABILITY_STACK_TARGET.md`, including rollout-era bridge and terminal-mode drift signals.

## Real-Backend Ops
- `rlm_real_backend_operations.md`
  - Real-backend bridge operations, promotion-gate expectations, and incident-response signals for rate limits, credential expiry, timeouts, and provider drift.

## Operational Flow
1. Import dashboards into Grafana (or track as Jsonnet/Tanka in downstream infra repos).
2. Load alert rules into Prometheus/Alertmanager.
3. Pair runtime metrics with replay/nightly usefulness artifacts when you need shadow-delta or engine-comparison evidence.
4. Keep this directory in lockstep with runtime metric additions and runbook updates.
