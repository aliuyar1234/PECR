# Request-Path Blocking Risk Audit (IO-001)

Date: 2026-02-18

## Scope
- Controller request paths: `/v1/run`, `/v1/replays*`, `/v1/evaluations*`
- Gateway request path: `/v1/operators/search`
- DB and network request-path behavior in gateway/controller

## Findings
| Surface | Previous Risk | Mitigation Implemented | Residual Risk |
|---|---|---|---|
| Controller replay persistence (`/v1/run`) | Synchronous replay store filesystem work on async request path | Replay persistence now runs via blocking-pool offload (`spawn_blocking`) | Disk saturation can still increase latency, but async worker threads are not blocked |
| Controller replay/eval APIs (`/v1/replays*`, `/v1/evaluations*`) | Synchronous replay/eval filesystem reads on async request path | Replay/eval store calls now offloaded to blocking pool with explicit error mapping | Heavy replay stores can still be slow, but runtime reactor threads remain responsive |
| Gateway `search` operator | Recursive sync filesystem traversal and reads per request | Async search path with filesystem index cache + async traversal/reads | Large corpora can still be expensive; bounded by cache TTL and operator/rate limits |
| Gateway DB access | Potential long-running safe-view queries | `statement_timeout` + explicit source-unavailable handling already active | Slow database/storage can still trigger retryable source-unavailable responses |
| OPA/network calls | Policy service delays/outages | OPA timeout/circuit-breaker/retry controls already active | External outage still degrades availability, but degrades fail-closed with clear terminal modes |

## Validation
- `cargo test -p pecr-gateway`
- `cargo test -p pecr-controller --features rlm`
- `cargo test -p e2e_smoke -- --nocapture`
