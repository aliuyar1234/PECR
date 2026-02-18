# Replay Persistence Model

## Scope

- Controller replay bundles persisted for each successful `POST /v1/run`.
- Local and CI replay/eval workflows that consume persisted bundles.

## Storage Model

- Store root: `PECR_REPLAY_STORE_DIR` (default: `target/replay`).
- Replay bundle path: `replays/<run_id>.json`.
- Evaluation result path: `evaluations/<evaluation_id>.json`.
- Bundles are written atomically (temp file + rename).

## Replay Bundle Contract

- Contract type: `ReplayBundle` (`crates/contracts/src/lib.rs`).
- Includes:
  - `metadata` (`run_id`, `trace_id`, `engine_mode`, `terminal_mode`, quality score, hash)
  - request context (`query`, `budget`)
  - finalize output (`response_text`, `claim_map`)
  - execution counters (`operator_calls_used`, `bytes_used`, `depth_used`)
  - evidence summary (`evidence_ref_count`, `evidence_unit_ids`)

## Hash Invariants

- Every bundle stores `metadata.bundle_hash` (SHA-256 lowercase hex).
- Hash input is canonical JSON for bundle payload with `bundle_hash` temporarily blank.
- Readers must treat hash mismatch as invalid replay material.

## Privacy Boundary

- Persisted metadata stores `principal_id_hash` instead of raw principal id.
- Replay/eval APIs are principal-scoped: callers can only list/fetch bundles for their hash.
- Replay data is intended for controlled ops/dev environments, not public distribution.

## Retention and Cleanup

- Retention knob: `PECR_REPLAY_RETENTION_DAYS` (default: `30`).
- Cleanup runs opportunistically during replay persistence.
- `0` disables age-based cleanup (manual lifecycle management required).

## Failure Semantics

- Replay persistence is best-effort and additive.
- `/v1/run` success/failure semantics are unchanged by replay persistence failures.
- Persistence failures are logged and do not remove existing runtime capabilities.
