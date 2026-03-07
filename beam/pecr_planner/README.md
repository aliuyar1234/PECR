# PECR Planner (BEAM Shadow Scaffold)

`pecr_planner` is a shadow-only Elixir scaffold for a future BEAM planner.

## Status

- Shadow-only
- Non-production
- Rust still owns execution, policy, finalize, and replay truth
- This app must not talk to source systems, OPA, or the PECR gateway directly

The current goal is narrow: accept the Rust planner contract through a local bridge, produce a
contract-compatible `PlanResponse`, and let PECR benchmark BEAM planner suggestions before we ever
let them drive execution.

## What It Does Today

- validates the Rust-side planner request shape
- chooses conservative shadow planner steps from `planner_hints.intent` and the allowlisted
  operator set
- returns a contract-compatible `PlanResponse`
- exposes a tiny CLI surface that the local HTTP shim can call safely
- can run supervised, shadow-safe usefulness prep jobs against existing replay fixtures

It does **not** execute operators or make policy decisions.

## Local Use

Run the Elixir tests:

```bash
cd beam/pecr_planner
mix test
```

Inspect the example contract in `iex`:

```bash
cd beam/pecr_planner
iex -S mix
```

```elixir
PecrPlanner.request_example()
PecrPlanner.response_example()
```

Historical note: the old repo-root Python HTTP bridge wrapper was removed during the Phase 5 RLM-first cleanup.
If you need to inspect legacy BEAM planner behavior, run the Mix scripts in this directory directly
instead of relying on repo-level wrappers.

Run a supervised usefulness prep job from the repo root:

```bash
cd beam/pecr_planner
mix run --no-start scripts/usefulness_job.exs validate-benchmark --store fixtures/replay/useful_tasks
```

Generate a fixture-backed nightly usefulness report artifact:

```bash
cd beam/pecr_planner
mix run --no-start scripts/nightly_report.exs \
  --store fixtures/replay/useful_tasks \
  --evaluation-name beam-shadow-fixture-report \
  --output-json beam/pecr_planner/tmp/nightly.json \
  --output-md beam/pecr_planner/tmp/nightly.md
```

Supported job names:

- `validate-benchmark`
- `planner-compare`
- `scenario-preview`
- `nightly-report`

These jobs are intentionally allowlisted and shell only into replay/report scripts that operate on
fixture or replay stores. They must not access source systems, the gateway, or policy endpoints.

These job entrypoints remain useful only for legacy/internal planner experiments. They are no longer
part of the active rollout or nightly usefulness workflow.

## Contract Shape

The scaffold expects the same fields the Rust controller already sends:

- `schema_version`
- `query`
- `budget`
- `planner_hints.intent`
- `recovery_context` when Rust is asking for a safe fallback after a recoverable failure
- `available_operator_names`
- `allow_search_ref_fetch_span`

The response shape matches the Rust planner contract:

- `schema_version`
- `steps`
- `planner_summary`

## Guardrails

- Shadow output is advisory only.
- BEAM suggestions must stay within the Rust-provided allowlist.
- If this planner is unavailable, PECR must keep working in Rust-owned mode.
- Supervised usefulness jobs are offline helpers only; they may inspect replay fixtures and write
  requested report artifacts, but they must not reach into PECR source systems.
