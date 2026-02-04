# RUNBOOK

This repo follows the SSOT runbook baseline in `pcdr/spec/12_RUNBOOK.md`.

## Local prerequisites

- Docker + Docker Compose
- Rust toolchain
- `bash` available (on Windows: use WSL or Git Bash)

## Deterministic local run

1) Start services:
- `docker compose up -d`

2) Run the end-to-end suites (requires a Postgres URL):
- PowerShell: `$env:PECR_TEST_DB_URL='postgres://pecr:pecr@localhost:5432/pecr'; cargo test -p e2e_smoke`
- Bash: `PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:5432/pecr cargo test -p e2e_smoke`

3) Run the full CI script locally:
- `bash scripts/ci.sh`

## Performance harness (Suite 7)

- `bash scripts/perf/suite7.sh`
- Outputs: `target/perf/` (k6 summaries + metric snapshots)

## Service endpoints (docker compose)

- Gateway: `http://127.0.0.1:8080` (`/healthz`, `/metrics`)
- Controller: `http://127.0.0.1:8081` (`/healthz`, `/metrics`)

## Auth modes

Default docker compose uses `PECR_AUTH_MODE=local`.

OIDC mode (RS256 / JWKS) is available in both gateway and controller:
- Set `PECR_AUTH_MODE=oidc`
- Configure `PECR_OIDC_*` in each service (issuer + JWKS + claim mapping)

## Policy bundle updates

`PECR_POLICY_BUNDLE_HASH` is snapshotted into PolicySnapshots/EvidenceUnits and should be updated whenever the deployed OPA bundle changes.

