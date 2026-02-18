# Controller State Machine and Budget Scheduler

This document defines the controller orchestration model used by both baseline and RLM engine paths.

## Scope
- Baseline engine loop: `crates/controller/src/http/orchestration.rs`
- RLM bridge loop: `crates/controller/src/http/orchestration.rs`
- Budget scheduler: `crates/controller/src/http/budget.rs`

## State Machine

The controller loop is modeled as transitions over a bounded execution state:
- `Init`: validate inputs, initialize counters (`operator_calls_used`, `bytes_used`, `depth_used`), create scheduler.
- `PlanStep` (baseline) or `BridgeMessage` (RLM): select next operation source.
- `BudgetGate`: enforce depth/operator/wallclock/bytes constraints before any operator call.
- `DispatchOperator`: call gateway operator with timeout.
- `CollectResult`: parse response, collect evidence refs/units, update counters.
- `Terminal`: exit with stop reason and terminal mode.

Common stop reasons:
- `plan_complete`
- `rlm_done`
- `budget_max_operator_calls`
- `budget_max_wallclock_ms`
- `budget_max_recursion_depth`
- `budget_max_bytes`
- bridge failure reasons (`bridge_eof`, `bridge_read_error`, `bridge_invalid_message`, `bridge_unknown_message`, `bridge_operator_not_allowlisted`)

## Budget Scheduler Contract

The scheduler is the single source for budget gates:
- `check_depth(depth_used)`
- `check_operator_calls(used)`
- `check_operator_calls_with_reserved(used, reserved)`
- `remaining_wallclock()`
- `check_bytes(used)`
- `effective_parallelism()`

These methods map to canonical stop reasons via `BudgetStopReason`.

## Protocol Handshake (RLM Bridge)

RLM loop starts by sending:
- `type: "start"`
- `protocol: { min_version, max_version }`
- `query`
- `budget`

Bridge should reply with:
- `type: "start_ack"`
- `protocol_version`

Backward compatibility:
- If bridge emits operational messages immediately (without `start_ack`), controller accepts and proceeds.

## Observability

Controller metrics include:
- `pecr_controller_inflight_ops`
- `pecr_controller_operator_queue_wait_seconds`
- `pecr_controller_budget_stop_reasons_total`
- existing HTTP/terminal/budget counters

These metrics are emitted from the orchestration loop and operator dispatch path.
