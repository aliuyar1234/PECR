# Enterprise Quality Guardrails

This repository is run with strict, release-blocking quality controls.

## Required quality checks

All pull requests must pass:

- `ci / quality` (format, lint, architecture boundary checks, tests, e2e smoke)
- `ci / perf` (k6 regression gate)
- `ci / contracts` (OpenAPI + schema contract lock)
- `security / cargo_audit`
- `security / secrets`
- `security / sbom_and_vuln_budget`
- `codeql / Analyze`

## Ownership model

- Module ownership is defined in `.github/CODEOWNERS`.
- Every change in owned paths requires owner review.

## Branch protection settings

Apply these in GitHub repository settings:

- Require pull request before merging.
- Require approvals.
- Require review from Code Owners.
- Require status checks to pass (all checks listed above).
- Require branches to be up to date before merging.
- Restrict force pushes and deletion on protected branches.

## Contract governance

- API and schema contracts are versioned under:
  - `docs/openapi/pecr.v1.yaml`
  - `crates/contracts/schemas/*.json`
- Contract drift is blocked by `scripts/contracts/check_contract_lock.py`.
- Intentional contract updates require running:
  - `python scripts/contracts/update_contract_lock.py`
  - and reviewing the resulting lock changes in `contracts/contract-lock.json`.

## Reliability standards

- Use `/healthz` only for process liveness.
- Use `/readyz` for dependency readiness and rollout gating.
- Critical dependency calls (OPA, datastore, gateway) use bounded retries and circuit-breaker policies.

## Security baseline

- No `latest` tags in runtime images.
- Dependency updates are automated by Dependabot.
- CI enforces vulnerability budget and secret scanning.
- SBOM is generated for every PR and protected branch run.
