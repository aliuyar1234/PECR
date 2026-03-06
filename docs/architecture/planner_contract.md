# Planner Contract

PECR now defines a narrow planner seam for future shadow planners, including a BEAM/Elixir planner.

## Purpose

- Keep Rust as the execution and trust boundary.
- Make planner inputs and outputs explicit, versioned, and replayable.
- Let future planners improve path selection without bypassing gateway policy, budgets, or finalize rules.

## Request

`PlanRequest` is the advisory input sent to a planner.

- `schema_version`: planner contract version, currently `1`
- `query`: normalized user ask
- `budget`: execution budget the controller must still enforce
- `planner_hints`: controller-derived task intent plus a recommended safe path
- `recovery_context`: optional failed-step context when Rust asks the planner for a safe fallback
- `available_operator_names`: operators the planner may choose from
- `allow_search_ref_fetch_span`: whether the controller supports the fan-out helper step

## Response

`PlanResponse` is the planner's suggested execution path.

- `schema_version`: planner contract version, currently `1`
- `steps`: ordered planner steps
- `planner_summary`: optional short explanation for debugging and replay analysis

The response is advisory. It does not grant new capabilities.

When `recovery_context` is present, the planner is being asked to suggest a fallback after a
recoverable operator failure such as `SOURCE_UNAVAILABLE` or `INSUFFICIENT_PERMISSION`. Rust still
chooses whether to use that fallback and still enforces all budgets and operator allowlists.

## Current Controller Behavior

- The Rust controller already emits `plan_request` to the existing RLM bridge.
- The legacy top-level `query`, `budget`, and `planner_hints` fields remain for backward compatibility.
- The current bridge may ignore `plan_request`; future shadow planners should prefer it.

## Guardrails

- Planner output must stay within controller-enforced budgets.
- Planner output must use gateway operators only.
- Planner output must not bypass policy checks, evidence capture, or finalize.
- Planner failure must degrade to Rust-owned planner behavior, not outage.
- Recovery planning may suggest another path, but it must never talk to source systems directly.
