# Repo Full-Sweep TODO (All Identified Issues)

This checklist captures every issue identified in the full repository analysis.

## Critical

- [x] Add release/deployment automation and reproducible artifact publishing (images/binaries/checksums/tags). Current CI only gates tests/perf/contracts and has no release job.  
  Refs: `.github/workflows/ci.yml`

- [x] Fix DB init/migration parity: `pecr_session_runtime` is required by runtime code but not created in base init SQL.  
  Refs: `db/init/001_ledger_schema.sql`, `crates/ledger/src/lib.rs`, `crates/ledger/migrations/20260209000100_session_runtime.sql`

## High

- [x] Declare required auth/session headers in OpenAPI (e.g. `x-pecr-session-token`, auth scheme/principal flow). Implementation requires them, spec currently does not.  
  Refs: `docs/openapi/pecr.v1.yaml`, `crates/gateway/src/http.rs`

- [x] Fix OIDC JWKS refresh locking: avoid awaiting network refresh while holding write lock (auth request serialization / latency-DoS risk).  
  Refs: `crates/auth/src/lib.rs`

- [x] Remove/replace blocking filesystem reads from async request paths (`std::fs::*` in handlers).  
  Refs: `crates/gateway/src/http.rs`

- [x] Break up controller god-module (`http.rs`) into route/orchestration/budget/finalize modules.  
  Refs: `crates/controller/src/http.rs`

- [x] Break up gateway god-module (`http.rs`) into route/session/operator/policy/finalize modules.  
  Refs: `crates/gateway/src/http.rs`

- [x] Replace hard-coded control plan in controller loop with configurable/pluggable strategy.  
  Refs: `crates/controller/src/http.rs`

- [x] Increase meaningful test coverage for critical crates (`boundary-check`, `ledger`, `auth`) instead of compile-only/trivial coverage.  
  Refs: `crates/boundary-check/src/main.rs`, `crates/ledger/src/lib.rs`, `crates/auth/src/lib.rs`

- [x] Remove dynamic `cargo install cargo-audit` in security CI path or pin/vendored execution for stronger supply-chain reproducibility.  
  Refs: `.github/workflows/security.yml`

- [x] Fix budget semantics bug: `max_wallclock_ms == 0` currently results in immediate controller loop stop.  
  Refs: `crates/controller/src/http.rs`

## Medium

- [x] Enforce immutable base image pinning (digest pin) for runtime/build images; current policy allows mutable major tags (`debian:12-slim`).  
  Refs: `docker/gateway.Dockerfile`, `docker/controller.Dockerfile`, `scripts/security/check_image_tags.py`

- [x] Add explicit perf/ops signaling (PR annotations/alerts), not artifact-only review of regressions.  
  Refs: `.github/workflows/ci.yml`

- [x] Expand e2e coverage beyond happy path to include policy deny, source unavailable, timeouts, and budget exhaustion.  
  Refs: `crates/e2e_smoke/tests/smoke.rs`

- [x] Strengthen assertions in contract/canonical tests to cover broader payload/invariant surfaces.  
  Refs: `crates/contracts/src/lib.rs`, `crates/contracts/src/canonical.rs`

- [x] Add unit tests for perf/security gate scripts (parsing and threshold behavior).  
  Refs: `scripts/perf/check_bvr_ser.py`, `scripts/perf/compare_k6_baseline.py`, `scripts/security/check_image_tags.py`

- [x] Tighten and broaden performance regression gates (more scenarios/endpoints, less permissive thresholds).  
  Refs: `scripts/perf/suite7.sh`, `scripts/k6/suite7_controller_run.js`, `scripts/perf/compare_k6_baseline.py`

- [x] Improve CI perf-job resilience/cleanup to reduce flake risk (compose lifecycle and startup variability handling).  
  Refs: `.github/workflows/ci.yml`, `scripts/perf/suite7.sh`

- [x] Replace placeholder `policy` crate implementation or clarify ownership to avoid architectural confusion.  
  Refs: `crates/policy/src/lib.rs`

- [x] Document module boundaries/coupling and ownership in architecture docs (beyond high-level overview).  
  Refs: `README.md`, `RUNBOOK.md`, `DECISIONS.md`

- [x] Make OpenAPI distributable/self-contained for client generators (avoid hard dependency on workspace-relative schema files).  
  Refs: `docs/openapi/pecr.v1.yaml`, `crates/contracts/schemas/*`

- [x] Implement real policy-driven redaction directives; current OPA policy emits empty redaction objects.  
  Refs: `opa/bundle/policy.rego`, `crates/gateway/src/http.rs`

- [x] Revisit ledger indexing strategy for long-term scale (hot lookup/join columns need explicit index review).  
  Refs: `db/init/001_ledger_schema.sql`, `crates/ledger/migrations/*.sql`

## Low

- [x] Fail fast on safe-view schema drift (validate specs/columns at startup) instead of discovering mismatches at request time.  
  Refs: `crates/gateway/src/http.rs`, `db/init/002_safeview_fixtures.sql`

## Validation Follow-up

- [x] Harden ledger startup/write timeout behavior under Docker/CI variability (increase DB connect/migration timeouts and relax default write timeout from 500ms to 2000ms).
  Refs: `crates/ledger/src/lib.rs`, `crates/gateway/src/config.rs`, `crates/ledger/tests/migrations.rs`

- [x] Re-run Docker stack + integration validation after fixes (`docker compose`, `/readyz`, `e2e_smoke`, ledger migrations tests, `scripts/ci.sh`) to confirm no runtime regressions remain.
  Refs: `docker-compose.yml`, `crates/e2e_smoke/tests/smoke.rs`, `crates/ledger/tests/migrations.rs`, `scripts/ci.sh`
