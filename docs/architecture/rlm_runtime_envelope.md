# RLM Runtime Envelope

This document defines the first supported real RLM backend shape for PECR's RLM-first migration.

It is a Phase 0 decision document. It does not claim that the backend is fully implemented today.
It defines the backend envelope Phase 1 should build toward.

## Current Truth

As of March 7, 2026:

- `PECR_CONTROLLER_ENGINE=rlm` exists.
- the controller can run the Python bridge in `scripts/rlm/pecr_rlm_bridge.py`.
- the bridge now supports `PECR_RLM_BACKEND=mock` and an initial opt-in `PECR_RLM_BACKEND=openai` seam.
- local compose now defaults into the RLM controller path with `PECR_RLM_DEFAULT_ENABLED=1`, `PECR_RLM_SANDBOX_ACK=1`, and baseline auto-fallback enabled.
- controller startup still refuses `PECR_MODEL_PROVIDER=external`.

So the repository now defaults into an RLM-first controller posture, but the real remote backend seam is still opt-in and should not be treated as rollout-complete.

## Phase 0 Decision

The first supported real RLM backend envelope should be:

- one primary remote model backend
- one primary model family/configuration per environment
- bridge-configured, not request-configured
- local compose defaults into the RLM path with the mock backend; the real remote backend remains opt-in during migration
- isolated to the controller/RLM bridge path only

In practice, that means:

- RLM remains the reasoning runtime.
- the real model backend is configured behind the Python RLM bridge.
- gateway and source adapters never see model credentials.
- the public `/v1/run` API does not expose provider or model selection.
- per-request backend switching is out of scope for the first rollout.

## Recommended First Backend Shape

Phase 1 should support exactly one real remote backend family first, then prove it in replay, perf, and e2e lanes before widening the matrix.

Recommended shape:

- one vendor-backed remote LLM client behind the vendored RLM runtime
- one deployment model per environment
- one credentials path for the controller only
- one replay-visible bridge protocol

The important product decision is not "support every provider". It is "support one real backend well enough that RLM can become the default product path."

## Why This Envelope

This is the smallest envelope that still gets PECR to a real RLM-first product:

- small enough to debug
- small enough to benchmark honestly
- small enough to keep CI and rollout manageable
- large enough to prove real planning, replanning, batching, recovery, and long-context synthesis

Trying to support multiple providers, multiple model families, and request-level model routing in Phase 1 would create too much instability before the bridge, replay, and finalize contracts are settled.

## Configuration Rules

For the first rollout:

- keep `PECR_MODEL_PROVIDER=mock` as the controller default until Rust-native external-provider support actually exists
- configure the real RLM backend at the bridge/runtime layer, not through the current controller model-provider switch
- local compose may default into `rlm` as long as the bridge backend stays `mock` and rollback controls remain enabled
- require explicit opt-in only for the real remote-backend path in local development, CI, and pre-release environments

Current opt-in bridge envs for the initial seam:

- `PECR_RLM_BACKEND=openai`
- `PECR_RLM_MODEL_NAME=<model>`
- `OPENAI_API_KEY=<key>` or `PECR_RLM_API_KEY=<key>`
- optional `PECR_RLM_BASE_URL=<openai-compatible-endpoint>`

This avoids pretending the current Rust config layer already supports a real external model path when it does not.

## Environment Story

The first supported backend envelope should behave differently by environment:

### Local default

- RLM plus the mock bridge backend is now the zero-setup developer path
- local compose should continue to boot without model credentials
- usefulness demos should still work without external model access

### Local real-backend RLM integration

- explicit opt-in
- controller built with `--features rlm`
- `PECR_CONTROLLER_ENGINE=rlm` or `PECR_RLM_DEFAULT_ENABLED=1`
- `PECR_RLM_SANDBOX_ACK=1`
- `PECR_RLM_BACKEND=openai`
- `PECR_RLM_MODEL_NAME=<model>`
- `OPENAI_API_KEY=<key>` or `PECR_RLM_API_KEY=<key>`
- real model credentials injected only into the controller runtime

### CI

- normal PR lanes should stay deterministic unless a dedicated secret-backed RLM lane is intentionally provided
- once the real backend lane exists, it should run in a dedicated integration or nightly path first
- promotion to blocking CI should happen only after bridge stability, perf stability, and finalize correctness are proven

### Pre-release and production

- RLM bridge/backend health must be observable
- rollout must support shadowing and auto-fallback
- baseline should remain available as a temporary rollback/reference lane until Phase 5 cleanup

## Explicit Non-Goals For The First Backend

Do not include these in the first supported real backend envelope:

- multiple production providers
- request-level provider selection
- request-level model switching
- gateway access to model credentials
- policy decisions inside the model layer
- bypassing finalize because the model output "looks right"

## Acceptance Criteria

The first backend envelope is ready when all of the following are true:

- the bridge can use a real backend instead of `mock`
- local opt-in RLM runs succeed with replay-visible traces
- e2e smoke stays green on the real backend lane
- finalize semantics remain correct on the real backend lane
- perf is stable enough to pass the agreed rollout gate
- bridge failures degrade cleanly without silent unsupported answers

## Follow-On Work

After this envelope is stable, the project can consider:

- additional provider support
- additional model classes
- parallel bridge worker pools beyond the current persistent worker baseline
- more advanced long-context packing
- retiring baseline from product-default duty

Those are Phase 1+ and later concerns. They should not block the first real backend from landing.
