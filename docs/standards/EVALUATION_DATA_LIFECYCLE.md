# Evaluation Data Model and Lifecycle

## Scope

- Replay-based evaluation submission and result APIs on the controller.
- Local replay/eval developer commands and CI replay regression gate.

## Submission Contract

- API: `POST /v1/evaluations`
- Contract type: `ReplayEvaluationSubmission`
- Inputs:
  - `evaluation_name` (required)
  - `replay_ids` (optional explicit run set)
  - `engine_mode` (optional filter: `baseline` or `rlm`)
  - `min_quality_score` (optional gate threshold `[0, 100]`)
  - `max_source_unavailable_rate` (optional gate threshold `[0, 1]`)

## Result Contract

- API: `GET /v1/evaluations/{evaluation_id}`
- Contract type: `ReplayEvaluationResult`
- Includes:
  - selected `replay_ids`
  - `missing_replay_ids`
  - per-run metrics (`ReplayRunScore`)
  - per-engine scorecards (`RunQualityScorecard`)
  - `overall_pass` gate outcome

## Scoring and Aggregation

- Per-run quality score (`0..100`) is computed at replay persistence time.
- Scorecards are grouped by `engine_mode`.
- Scorecards expose:
  - run count
  - average/min/max quality score
  - supported-rate
  - source-unavailable-rate
  - average claim coverage observed

## Gate Semantics

- Evaluation `overall_pass` requires all of:
  - no missing requested replays
  - every selected run quality score >= `min_quality_score`
  - aggregate source-unavailable-rate <= `max_source_unavailable_rate`

## Retention and Access

- Evaluation results are stored under replay store root (`evaluations/*.json`).
- Access is principal-scoped via `principal_id_hash`.
- Retention follows replay retention policy (`PECR_REPLAY_RETENTION_DAYS`).

## Operational Usage

- Local DX commands:
  - `python3 scripts/replay/replay_eval_cli.py ...`
  - `python3 scripts/replay/regression_gate.py ...`
- CI gate integration:
  - `scripts/ci.sh` executes replay regression gate with `--allow-empty`.
