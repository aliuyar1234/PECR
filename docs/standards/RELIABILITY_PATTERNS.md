# Reliability Patterns

This document defines mandatory patterns for critical dependency calls.

## Retry policy

- Retry only transient failures: timeout, connection reset, 5xx.
- Maximum attempts: 3 total (initial + 2 retries).
- Backoff: exponential with jitter, bounded.
- Requests must remain time-bounded end-to-end.

## Circuit breaker policy

- Use consecutive-failure threshold to open the circuit.
- While open, fail fast for a short interval.
- Probe after open interval; close on first successful probe.
- Emit clear logs/metrics for open and close events.

## Health model

- `/healthz`: process liveness only.
- `/readyz`: dependency readiness and rollout gating.
- Readiness must include all critical path dependencies.

## Session and state model

- Session/runtime state must be persisted in shared storage.
- Stateless service instances may recover session state after restart.
- In-memory caches are optional and must not be source of truth.
