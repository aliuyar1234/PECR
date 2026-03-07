# Architecture Invariants

These are the rules future changes must preserve.

## Control Plane Boundaries

- The controller orchestrates runs and persists replay artifacts, but it does not read source systems directly.
- The gateway owns policy checks, source access, evidence emission, and session runtime enforcement.
- `boundary-check` is the safety rail. If a new dependency crosses the controller/gateway trust boundary, update the boundary rules intentionally or fail the build.
- Legacy `beam_planner` compatibility may choose or recover a plan, but Rust still owns operator execution, budget checks, allowlist enforcement, gateway auth, finalize, replay persistence, and the external API contract.
- Legacy BEAM planner failures must degrade to the Rust-owned baseline reference path, not to a user-visible outage.

## Finalize Semantics

- `SUPPORTED` requires evidence-backed supported claims after the finalize gate runs.
- Claims marked `SUPPORTED` without emitted evidence must be downgraded before the response leaves the gateway.
- Coverage thresholds are part of the product contract, not presentation logic. Changes to finalize thresholds or claim synthesis must update tests, replay fixtures, and the API contract manifest.

## Replay And Audit Guarantees

- Every successful controller run should produce a replay bundle that can be evaluated later.
- Gateway evidence ids, claim ids, and replay metadata must remain deterministic for the same canonical inputs.
- Replay persistence and replay-store readiness are production-critical. Treat “best effort” changes here as behavior changes that require review.

## Auth And Session Invariants

- `local` and `oidc` modes must preserve the same authorization semantics even if the credential source differs.
- Session tokens are capability tokens scoped to one session and principal; principal mismatch or rotated/expired tokens must fail closed.
- JWKS refresh behavior must remain safe under key rotation. Unknown `kid` values should trigger refresh, not a long stale-cache window.

## Change Checklist

When changing routes, request/response bodies, or replay semantics:

- Update `docs/openapi/pecr.v1.yaml`.
- Update `docs/openapi/contract_manifest.json`.
- Keep Rust shape tests and `scripts/validate_openapi.py` green.
