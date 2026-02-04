# PECR (Policy-Enforced Context Runtime)

Rust implementation repo for the PECR/CEGP SSOT spec pack (`pcdr`).

## Quickstart (deterministic local run)

1) Start local dependencies and services:
- `docker compose up -d`

2) Run CI checks + suites (requires Postgres reachable on localhost):
- PowerShell: `$env:PECR_TEST_DB_URL='postgres://pecr:pecr@localhost:5432/pecr'; bash scripts/ci.sh`
- Bash: `PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:5432/pecr bash scripts/ci.sh`

More details: `RUNBOOK.md`.

