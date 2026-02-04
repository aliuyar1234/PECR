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

## Production deployment baseline (summary)

Recommended baseline:
- Separate gateway and controller deployments.
- Keep the gateway-to-OPA network private (OPA sidecar or private policy deployment).
- Use a managed Postgres (or a dedicated stateful deployment) for the ledger datastore.
- Use mTLS between controller and gateway; controller stays non-privileged (no datastore access).

## Rollback strategy

- Schema changes follow expand/contract migrations.
- Ledger migrations live in `crates/ledger/migrations/` and are applied on gateway startup via `LedgerWriter::connect_and_migrate(...)`.

## Backup and restore (ledger)

Minimum expectations:
- Back up all ledger tables and policy snapshots.
- Restore into an isolated environment and verify payload hashes.

Repo check:
- `cargo test -p pecr-ledger` (includes payload hash verification and append-only migration tests).

## Incident triage (quick actions)

Suspected leakage:
- Run leakage + cache-bleed suites: `cargo test -p e2e_smoke leakage_suite_role_matrix_canaries cache_bleed_suite_cross_principal_reuse_is_zero`

Suspected injection/tool misuse:
- Run injection suite: `cargo test -p e2e_smoke injection_suite_context_as_malware_tool_steering`

Tail latency regression / wrong terminal modes under faults:
- Run Suite 7: `bash scripts/perf/suite7.sh`

## Release checklist (repo-local)

- `bash scripts/ci.sh`
- `bash scripts/perf/suite7.sh`
