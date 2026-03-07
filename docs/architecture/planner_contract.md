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
- `context_budget`: separate long-context budget for evidence units, total packed characters, structured rows, and inline citations
- `planner_hints`: controller-derived task intent plus a recommended safe path
- `preferred_evidence_pack_mode`: controller hint for whether the planner should expect `raw`, `compact`, `summary`, `diff`, or `mixed` evidence packing
- `recovery_context`: optional failed-step context when Rust asks the planner for a safe fallback
  - includes `failed_step_details` when the controller can point at the exact failed step
- `available_operator_names`: operators the planner may choose from
- `operator_schemas`: richer operator metadata, including descriptions, required params, optional params, and an advisory param schema
- `allow_search_ref_fetch_span`: whether the controller supports the fan-out helper step
- `prior_observations`: replayable observations from earlier planner attempts in the same run
- `clarification_opportunities`: safe narrowing prompts the controller already knows how to ask
- `failure_feedback`: structured feedback from prior safe failures, separate from raw bridge stop reasons

## Response

`PlanResponse` is the planner's suggested execution path.

- `schema_version`: planner contract version, currently `1`
- `steps`: ordered planner steps
- `planner_summary`: optional short explanation for debugging and replay analysis

The response is advisory. It does not grant new capabilities.

When `recovery_context` is present, the planner is being asked to suggest a fallback after a
recoverable operator failure such as `SOURCE_UNAVAILABLE` or `INSUFFICIENT_PERMISSION`. Rust still
chooses whether to use that fallback and still enforces all budgets and operator allowlists.

The Phase 2 contract expansion is intentionally additive. Rust still owns execution, budgets,
allowlists, policy, evidence capture, and finalize. The richer request shape exists so RLM can make
better decisions with less hard-coded Rust-side path selection.

Phase 3 extends that same contract so planners can reason about long-context tradeoffs without
owning the trust boundary. The controller now decides the context envelope and advisory packing
mode, while the bridge compacts tool results into that envelope before they enter the RLM context.

## Current Controller Behavior

- The Rust controller already emits `plan_request` to the existing RLM bridge.
- The legacy top-level `query`, `budget`, and `planner_hints` fields remain for backward compatibility.
- The current bridge may ignore `plan_request`; future shadow planners should prefer it.
- The bridge protocol is explicitly versioned around JSON message types:
  - `start`
  - `start_ack`
  - `call_operator`
  - `operator_result`
  - `call_operator_batch`
  - `operator_batch_result`
  - `done`
  - `error`
- The controller now preserves bridge `stop_reason`, backend metadata, and failure detail in replay-visible planner summaries.
- The controller reuses a persistent bridge worker process across requests, rather than spawning a fresh bridge process for every `/v1/run`.
- The RLM bridge can now receive a failed operator result and continue planning, which enables recovery paths instead of forcing Rust to terminate the loop on the first blocked tool.
- The bridge may also return an explicit clarification-oriented final answer and stop reason when the planner contract already says the ask is too ambiguous to spend tool budget well.

## Guardrails

- Planner output must stay within controller-enforced budgets.
- Planner output must use gateway operators only.
- Planner output must not bypass policy checks, evidence capture, or finalize.
- Planner failure must degrade cleanly into replay-visible terminal modes, not opaque outage-only behavior.
- Recovery planning may suggest another path, but it must never talk to source systems directly.
