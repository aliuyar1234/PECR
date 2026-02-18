# Policy Simulation Contract

## Endpoint
- `POST /v1/policies/simulate`

## Purpose
- Provide a dry-run policy decision API for evaluating allow/deny/redaction outcomes without executing operators or mutating session state.

## Authentication and Authorization
- Uses the same principal extraction/auth flow as other gateway endpoints:
  - Local mode: `x-pecr-principal-id` (+ `x-pecr-local-auth-secret` when configured).
  - OIDC mode: `Authorization: Bearer <JWT>`.
- Requests without valid auth fail closed with `401`.

## Request Contract
- `action`: required non-empty string.
- `params`: required JSON object.
- `policy_snapshot_hash`: optional SHA-256 lowercase hex (`64` chars).
- `policy_bundle_hash`: optional SHA-256 lowercase hex (`64` chars). Defaults to configured `PECR_POLICY_BUNDLE_HASH`.
- `as_of_time`: optional timestamp in `YYYY-MM-DDTHH:MM:SSZ` format. Defaults to gateway `as_of_time` default when omitted.

## Response Contract
- `allow`: boolean.
- `cacheable`: boolean.
- `reason`: optional string.
- `redaction`: optional JSON object.

## Safety Envelope
- No operator execution.
- No session creation/finalization side effects.
- OPA failures return fail-closed errors via standard gateway error contract:
  - `503 ERR_SOURCE_UNAVAILABLE` when policy engine is unavailable.
  - `504 ERR_SOURCE_TIMEOUT` on policy timeout.
- Input validation errors return `400 ERR_INVALID_PARAMS`.
- Request is metrics-instrumented (`/v1/policies/simulate`) for auditability and SLO tracking.

## Caching Semantics
- OPA decision caching key includes:
  - principal id
  - action
  - params hash
  - policy snapshot hash
  - policy bundle hash
  - as_of_time
- This prevents cross-principal and cross-policy cache bleed for simulation requests.
