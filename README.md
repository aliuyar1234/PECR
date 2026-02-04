# PECR (Policy-Enforced Context Runtime)

Rust implementation repo for the PECR/CEGP SSOT spec pack (`pcdr`).

## Quickstart (deterministic local run)

1) Start local dependencies and services:
- `docker compose up -d`

2) Run CI checks + suites (requires Postgres reachable on localhost):
- PowerShell: `$env:PECR_TEST_DB_URL='postgres://pecr:pecr@localhost:55432/pecr'; bash scripts/ci.sh`
- Bash: `PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr bash scripts/ci.sh`

If `55432` is in use, set `PECR_POSTGRES_PORT` before starting compose and update the DB URL accordingly.

More details: `RUNBOOK.md`.
