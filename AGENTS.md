# Repository Guidelines

## Product Direction
PECR is moving to an RLM-first product shape. Use `RLM_FIRST_MIGRATION_PLAN.md`, `PRODUCT_PRINCIPLES.md`, and `docs/architecture/rlm_runtime_envelope.md` as the source of truth for that direction.

- Prefer work that strengthens the `rlm` path as the primary reasoning runtime.
- Treat `baseline` and `beam_planner` as transition, shadow, evaluation, or fallback tools unless a task explicitly says otherwise.
- Preserve the controller/gateway trust boundary, gateway policy enforcement, evidence emission, finalize semantics, and replay guarantees while making RLM more central.
- Be willing to delete dead code, duplicate heuristics, stale env flags, and misleading product-facing surfaces when they no longer support the RLM-first migration.
- Do not present baseline, BEAM, and RLM as equal long-term product bets in new docs or new code paths unless the repository direction changes intentionally.

## Project Structure & Module Organization
`crates/` is the Cargo workspace and holds the main Rust services and libraries: `pecr-controller`, `pecr-gateway`, `pecr-policy`, `pecr-ledger`, `pecr-auth`, `pecr-adapters`, `pecr-boundary-check`, `pecr-contracts`, and `e2e_smoke`. Keep production code in each crate's `src/`; place integration tests in crate-local `tests/`. Use `db/init/` for SQL bootstrap files, `opa/` for policy assets, `docker/` plus `docker-compose.yml` for local runtime wiring, `scripts/` for CI/perf/replay/security automation, `perf/` for baselines and expectations, and `fixtures/` for deterministic test data. Treat `vendor/` as synced upstream code, not a casual edit target.

## Build, Test, and Development Commands
- `docker compose up -d --build`: start the local stack (Postgres, OPA, gateway, controller).
- `cargo fmt --check`: verify Rust formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: enforce lint-clean Rust code.
- `cargo test --workspace --exclude e2e_smoke`: run the standard Rust test suite.
- `cargo test -p e2e_smoke`: run end-to-end smoke coverage.
- `cargo run -p pecr-boundary-check`: validate the controller/gateway trust boundary.
- `bash scripts/ci.sh`: run the full CI-equivalent validation, including Rust, Python, contract, and script checks.
- `bash scripts/perf/suite7.sh`: run perf smoke when changing controller/gateway behavior or perf thresholds.

## Coding Style & Naming Conventions
Use Rust 2024 conventions with 4-space indentation and `rustfmt` defaults. Prefer `snake_case` for files, modules, and functions, `UpperCamelCase` for types, and `SCREAMING_SNAKE_CASE` for constants and env vars. Keep crate names aligned with the existing `pecr-` prefix. Python helpers under `scripts/` should stay stdlib-first, small, and testable; name tests `test_*.py`. Do not hand-edit vendored RLM sources; use `python3 scripts/rlm/sync_vendor_rlm.py` and `python3 scripts/rlm/verify_vendor_rlm.py`.

## Testing Guidelines
Add unit tests in the affected crate and integration tests in that crate's `tests/` directory. For automation changes, add `unittest` coverage under `scripts/tests`, `scripts/perf`, or `scripts/ops`. If you touch contracts, run `python3 scripts/contracts/check_contract_lock.py`; if you change release/security scripts, run the matching Python test discovery used by `scripts/ci.sh`. No fixed coverage percentage is documented, but every change should ship with the narrowest meaningful automated check plus a clean `bash scripts/ci.sh` before merge.

## Commit & Pull Request Guidelines
Follow the existing Conventional Commit style with scopes, for example `fix(ci): ...`, `docs(readme): ...`, or `feat(controller): ...`. Keep commits focused and easy to bisect. Pull requests should summarize the behavior change, list the verification commands you ran, link related issues, and call out any contract, policy, schema, or perf-baseline updates. Include request/response samples or relevant logs when changing gateway or controller behavior.
