# RLM Real-Backend Operations

This guide covers the first supported real RLM backend path behind the controller bridge.
Use it together with `RUNBOOK.md`, replay artifacts, and the real-backend usefulness workflows.

## Scope

- controller-side bridge-backed `PECR_RLM_BACKEND=openai`
- real-backend usefulness and pre-release evidence lanes
- incidents that degrade planning quality without changing PECR's policy or finalize rules

## Core Signals

Prometheus:

- `pecr_controller_http_request_duration_seconds`
  - watch `/v1/run` p95/p99 during real-backend canaries and pre-release checks
- `pecr_controller_http_requests_total`
  - watch 5xx drift during backend incidents
- `pecr_controller_terminal_modes_total`
  - focus on `/v1/run` `SOURCE_UNAVAILABLE` and unexpected `INSUFFICIENT_EVIDENCE` drift
- `pecr_controller_budget_stop_reasons_total`
  - focus on bridge and runtime stop reasons such as `bridge_backend_unavailable`, `bridge_backend_runtime_error`, `bridge_invalid_json`, `bridge_invalid_message`, `bridge_unknown_message`, `bridge_eof`, `bridge_read_error`, and sustained `wallclock_ms`
- `pecr_controller_operator_queue_wait_seconds`
  - helps separate backend latency from controller-side queuing or scheduler pressure
- `pecr_controller_evidence_packs_total`
- `pecr_controller_evidence_pack_units`
- `pecr_controller_evidence_compaction_ratio`
- `pecr_controller_citation_quality`
  - these prove that long-context packing quality stayed healthy while the real backend was active

Replay and workflow artifacts:

- replay-visible planner traces retain bridge backend, stop reason, and bridge detail
- `.github/workflows/rlm-real-backend-usefulness.yml`
  - uploads JSON and Markdown usefulness reports plus the raw log
- `.github/workflows/rlm-real-backend-pre-release.yml`
  - validates the promotion gate, reruns the real-backend checks, and uploads the gate report

## Failure Modes

### Rate limits

Expected signals:

- bridge stop reasons skew toward `bridge_backend_runtime_error`
- `/v1/run` latency rises before throughput collapses
- usefulness workflow log shows provider-side throttling or backoff details

Operator response:

- confirm whether rate limiting is transient or quota-related
- reduce concurrency before changing product semantics
- keep `PECR_RLM_AUTO_FALLBACK_TO_BASELINE=1` in production if the live backend is unstable
- do not treat fallback as success evidence for the real-backend promotion gate

### Credential expiry or revocation

Expected signals:

- bridge stop reasons skew toward `bridge_backend_unavailable` or `bridge_backend_runtime_error`
- real-backend smoke and usefulness lanes fail immediately
- replay-visible bridge detail points to auth failures rather than retrieval or finalize regressions

Operator response:

- rotate the controller-only credential
- re-run smoke before re-running usefulness or pre-release checks
- preserve the failing workflow artifacts for auditability

### Backend timeouts

Expected signals:

- `/v1/run` p95/p99 rises, followed by `SOURCE_UNAVAILABLE`
- stop reasons show `wallclock_ms` or bridge runtime errors
- queue wait stays relatively flat while request duration rises

Operator response:

- compare controller wallclock budget with observed backend latency
- confirm whether slowdown is provider-side versus controller scheduler pressure
- only relax budgets after replay and finalize semantics remain healthy

### Provider drift

Expected signals:

- usefulness scorecards regress without obvious infrastructure errors
- finalize downgrades or citation-quality regressions increase
- planner traces still show a healthy bridge, but answer quality drops

Operator response:

- compare the latest real-backend usefulness report to the last healthy report on the same model config
- inspect replay artifacts before retuning prompts or weakening finalize
- treat provider drift as a quality incident even if uptime looks healthy

## Promotion Gate

Before promoting the manual real-backend usefulness lane into broader automation, require:

1. Three consecutive successful `rlm-real-backend-usefulness` runs on `master` for the same head SHA.
2. Those runs must keep `PECR_RLM_AUTO_FALLBACK_TO_BASELINE=0`.
3. The paired usefulness report must still show baseline-vs-RLM comparison coverage and healthy supported/citation behavior.
4. A fresh `rlm-real-backend-pre-release` run must pass on the same head SHA.

Use `scripts/ops/check_real_backend_promotion_gate.py` against `gh run list --json ...` output to validate the streak.

## Alerting Expectations

At minimum, real-backend operations should alert on:

- sustained bridge failure stop-reason spikes
- `/v1/run` `SOURCE_UNAVAILABLE` ratio spikes
- controller p99 latency budget breaches
- replay-visible usefulness regressions during pre-release checks

Prometheus covers the first three. The pre-release workflows and replay reports cover the last one.
