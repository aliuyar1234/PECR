# RUNBOOK

This repo follows the SSOT runbook baseline in `pcdr/spec/12_RUNBOOK.md`.

## Local prerequisites

- Docker + Docker Compose
- Rust toolchain
- `bash` available (on Windows: use WSL or Git Bash)

## Deterministic local run

1) Start services:
- `export PECR_LOCAL_AUTH_SHARED_SECRET='replace-with-random-secret'; docker compose up -d`

Notes:
- Postgres is exposed on `127.0.0.1:${PECR_POSTGRES_PORT:-55432}` by default (override via `PECR_POSTGRES_PORT`).

2) Run the end-to-end suites (requires a Postgres URL):
- PowerShell: `$env:PECR_TEST_DB_URL='postgres://pecr:pecr@localhost:55432/pecr'; cargo test -p e2e_smoke`
- Bash: `PECR_TEST_DB_URL=postgres://pecr:pecr@localhost:55432/pecr cargo test -p e2e_smoke`

3) Run the full CI script locally:
- `bash scripts/ci.sh`

## RLM vendor update workflow

Use the dedicated sync script to keep `vendor/rlm` aligned with upstream:

- Latest upstream `main`:
  - `python3 scripts/rlm/sync_vendor_rlm.py`
- Specific upstream commit:
  - `python3 scripts/rlm/sync_vendor_rlm.py --commit <40-char-sha>`
- Verification only:
  - `python3 scripts/rlm/verify_vendor_rlm.py`

The sync command updates `vendor/rlm`, rewrites the D-0001 pin in `DECISIONS.md`, and runs verification checks.
CI also enforces RLM verification via `scripts/rlm/verify_vendor_rlm.py` inside `scripts/ci.sh`.

## Performance harness (Suite 7)

- `bash scripts/perf/suite7.sh`
- Outputs: `target/perf/` (k6 summaries + metric snapshots)
- Baseline-vs-RLM matrix (CI-equivalent):
  - `PECR_CONTROLLER_ENGINE_OVERRIDE=rlm PECR_RLM_SANDBOX_ACK=1 SUITE7_SKIP_FAULTS=1 CONTROLLER_BASELINE_SUMMARY_NAME=suite7_rlm_baseline.summary.json GATEWAY_BASELINE_SUMMARY_NAME=suite7_rlm_gateway_baseline.summary.json METRICS_GATES_FILE=target/perf/suite7_rlm_metrics_gates.json bash scripts/perf/suite7.sh`
  - `python3 scripts/perf/compare_k6_baseline.py --baseline perf/baselines/suite7_baseline.summary.json --current target/perf/suite7_rlm_baseline.summary.json --alarm-label rlm --output-json target/perf/perf_alarm_rlm.json`
  - `python3 scripts/perf/benchmark_matrix.py --baseline perf/baselines/suite7_baseline.summary.json --candidate baseline=target/perf/suite7_baseline.summary.json --candidate rlm=target/perf/suite7_rlm_baseline.summary.json --output-json target/perf/benchmark_matrix.json --output-md target/perf/benchmark_matrix.md`

## Service endpoints (docker compose)

- Gateway: `http://127.0.0.1:8080` (`/healthz`, `/readyz`, `/metrics`)
- Controller: `http://127.0.0.1:8081` (`/healthz`, `/readyz`, `/metrics`)
- Policy simulation dry-run: `POST /v1/policies/simulate` (gateway)
- Replay metadata/detail: `GET /v1/replays`, `GET /v1/replays/{run_id}` (controller)
- Evaluation APIs: `POST /v1/evaluations`, `GET /v1/evaluations/{evaluation_id}`, `GET /v1/evaluations/scorecards` (controller)

## Controller runtime knobs (throughput controls)

- `PECR_CONTROLLER_ADAPTIVE_PARALLELISM_ENABLED` (default enabled).
- `PECR_CONTROLLER_BATCH_MODE_ENABLED` (default enabled).
- `PECR_OPERATOR_CONCURRENCY_POLICIES` (JSON map by operator, supports `max_in_flight` and `fairness_weight`).

Replay/eval knobs:
- `PECR_REPLAY_STORE_DIR` (default: `target/replay`).
- `PECR_REPLAY_RETENTION_DAYS` (default: `30`; `0` disables cleanup).
- `PECR_REPLAY_LIST_LIMIT` (default: `200`).

## Replay/Eval developer commands

- List replay metadata:
  - `python3 scripts/replay/replay_eval_cli.py --store target/replay list`
- Reconstruct run outcome from persisted bundle:
  - `python3 scripts/replay/replay_eval_cli.py --store target/replay replay --run-id <run_id>`
- Compute scorecards by engine mode:
  - `python3 scripts/replay/replay_eval_cli.py --store target/replay scorecards`
- Replay regression gate (used in CI):
  - `python3 scripts/replay/regression_gate.py --store "${PECR_REPLAY_STORE_DIR:-target/replay}" --allow-empty`
- Operator contract templates/checklist:
  - `python3 scripts/replay/run_operator_contract_tests.py --gateway-url http://127.0.0.1:8080 --local-auth-secret "$PECR_LOCAL_AUTH_SHARED_SECRET"`
  - `scripts/replay/OPERATOR_CONTRACT_CHECKLIST.md`

## Canary rollout guard (OPS-002 path)

- Evaluate canary SLOs and auto-fallback action:
  - `python3 scripts/ops/canary_rollout_guard.py --summary target/perf/suite7_rlm_baseline.summary.json --metrics-gates target/perf/suite7_rlm_metrics_gates.json --engine rlm --adaptive-enabled true --batch-enabled true --output-json target/perf/canary_guard.json --output-md target/perf/canary_guard.md --output-env target/perf/canary_fallback.env`
- Fallback order encoded by the tool:
  - Disable adaptive parallelism.
  - Disable batch mode.
  - Switch engine to baseline.

## Observability artifacts (OBS-003)

- Dashboards:
  - `docs/observability/dashboards/pecr_runtime_health.dashboard.json`
  - `docs/observability/dashboards/pecr_budget_scheduler.dashboard.json`
- Alerts:
  - `docs/observability/alerts/pecr_slo_alerts.yaml`
- Index and ownership notes:
  - `docs/observability/README.md`

## Auth modes

Default docker compose uses `PECR_AUTH_MODE=local`.
- For local auth on non-loopback binds, set `PECR_LOCAL_AUTH_SHARED_SECRET` and send `x-pecr-local-auth-secret` on client requests.
- Metrics default to auth-required on non-loopback binds (`PECR_METRICS_REQUIRE_AUTH=1`).

OIDC mode (RS256 / JWKS) is available in both gateway and controller:
- Set `PECR_AUTH_MODE=oidc`
- Configure `PECR_OIDC_*` in each service:
  - Required:
    - `PECR_OIDC_ISSUER`
    - `PECR_OIDC_JWKS_URL` or `PECR_OIDC_JWKS_JSON`
    - `PECR_OIDC_TENANT_CLAIM` or `PECR_OIDC_TENANT_ID_STATIC`
  - Optional:
    - `PECR_OIDC_AUDIENCE`
    - `PECR_OIDC_PRINCIPAL_ID_CLAIM` (default: `sub`)
    - `PECR_OIDC_ROLES_CLAIM`
    - `PECR_OIDC_ABAC_CLAIMS` (comma-separated claim names)
    - `PECR_OIDC_JWKS_TIMEOUT_MS` (default: `2000`)
    - `PECR_OIDC_JWKS_REFRESH_TTL_SECS` (default: `300`)
    - `PECR_OIDC_CLOCK_SKEW_SECS` (default: `60`)

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

RLM bridge/protocol failures (`ERR_RLM_BRIDGE_*`):
- Verify script path resolution:
  - `echo $PECR_RLM_SCRIPT_PATH` (or unset it to use defaults)
  - Confirm one exists: `scripts/rlm/pecr_rlm_bridge.py` or `/usr/local/share/pecr/pecr_rlm_bridge.py`
- Run bridge verification suite:
  - `python3 scripts/rlm/verify_vendor_rlm.py`
- Check protocol compatibility:
  - Controller currently supports bridge protocol version range `1..=1`.
  - Bridge emits `start_ack` with `protocol_version`; mismatches fail closed.
- Inspect controller logs for stop reasons:
  - `bridge_eof`, `bridge_read_error`, `bridge_invalid_message`, `bridge_unknown_message`, `bridge_operator_not_allowlisted`
- Recovery:
  - Re-sync vendored bridge/runtime: `python3 scripts/rlm/sync_vendor_rlm.py`
  - Rebuild controller with RLM feature and re-run CI: `bash scripts/ci.sh`

## Module ownership and coupling checklist

Use this checklist before merging cross-module changes:
- Controller boundary: `crates/controller` must not directly access ledgers/sources; only gateway HTTP.
- Gateway policy path: `crates/gateway` policy decisions must flow through OPA + `crates/policy` types.
- Data ownership: schema or migration changes in `db/init` and `crates/ledger/migrations` require ledger test pass.
- Contracts first: when payloads change, update `crates/contracts` schemas and keep OpenAPI aligned.
- Boundary enforcement: run `cargo test -p pecr-boundary-check` if coupling changed.

Operational ownership by area:
- Orchestration: `crates/controller`
- Policy runtime: `crates/policy`, `opa/bundle`, policy wiring in `crates/gateway`
- Data/audit plane: `crates/ledger`, `db/init`, `crates/ledger/migrations`
- API/contracts: `docs/openapi`, `crates/contracts/schemas`
- Build/release: `.github/workflows`, `scripts/`

## Release provenance verification

Release promotion is blocked unless provenance verification succeeds in `.github/workflows/release.yml`.

The blocking gate runs:
- `sha256sum --check` for release tarballs listed in `release/SHA256SUMS.txt`
- `python3 scripts/security/verify_release_attestations.py` for:
  - release tarballs
  - `release/SHA256SUMS.txt`
  - `release/image-digests.txt`
  - GHCR image digests for `pecr-gateway` and `pecr-controller`

Manual operator invocation (for incident triage or re-verification in CI jobs):
- `python3 scripts/security/verify_release_attestations.py --release-dir release --repo <owner/repo> --signer-workflow <owner/repo/.github/workflows/release.yml> --source-ref <refs/tags/vX.Y.Z>`

Policy reference:
- `docs/standards/ARTIFACT_PROVENANCE_POLICY.md`

## Release checklist (repo-local)

- `bash scripts/ci.sh`
- `bash scripts/perf/suite7.sh`
- Security workflows green in GitHub Actions:
  - `security`
  - `codeql`
- Release workflow provenance gate green in GitHub Actions:
  - `release` (`Verify release provenance attestations`)
