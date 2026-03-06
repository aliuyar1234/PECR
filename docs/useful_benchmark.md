# Useful Benchmark

PECR now has a named usefulness corpus at `fixtures/replay/useful_tasks/`. It is meant to track real user jobs, not just terminal-mode semantics.

## Scenario Set

The benchmark currently covers:

- structured lookup: customer status and plan tier
- evidence lookup: support policy, annual refund terms, billing terms
- version review: latest support document change
- aggregate compare: active customer counts by plan tier
- aggregate trend: monthly customer trend over time
- ambiguity guidance: broad customer and policy asks that should narrow safely instead of dead-ending
- partial answer: grounded billing guidance with explicit unresolved remainder

Each scenario is declared in `fixtures/replay/useful_tasks/benchmark_manifest.json` and backed by a replay bundle under `fixtures/replay/useful_tasks/replays/`.

## Commands

List the benchmark catalog:

```bash
python -B scripts/replay/useful_benchmark_cli.py list
```

Validate that the manifest and replay fixtures stay aligned:

```bash
python -B scripts/replay/useful_benchmark_cli.py validate
```

Compare planner behavior on the named scenarios. This grades `baseline`, `rlm`,
`beam_planner`, and `beam_planner_shadow` traces against the scenario-declared planner
prefixes when the replay store contains `planner_traces`. Recovery traces emitted as
`beam_recovery` are folded into the `beam_planner` planner mode so recovered runs stay visible in
the same benchmark lane:

```bash
python -B scripts/replay/useful_benchmark_cli.py --store target/replay planner-compare
```

Validation now checks more than terminal mode and score. Scenarios may also declare:

- `expected_response_kind` such as `ambiguous` or `partial_answer`
- `expected_response_substrings` for narrowing or grounded-response text
- `expected_note_substrings` for claim-map notes such as the partial-answer marker

Generate a markdown/json report from a replay store:

```bash
python -B scripts/replay/nightly_usefulness_report.py \
  --store target/replay \
  --evaluation-name nightly-usefulness-baseline \
  --engine-mode baseline \
  --output-json target/replay/nightly_usefulness_baseline.json \
  --output-md target/replay/nightly_usefulness_baseline.md
```

Generate the same report through the supervised BEAM job lane:

```bash
python -B scripts/replay/run_beam_usefulness_job.py nightly-report \
  --store target/replay \
  --evaluation-name nightly-usefulness-beam \
  --engine-mode beam_planner \
  --output-json target/replay/nightly_usefulness_beam.json \
  --output-md target/replay/nightly_usefulness_beam.md
```

Use this corpus when adding planner, retrieval, finalize, or evaluation changes that are supposed to improve answer usefulness. If a change helps only synthetic safety checks but hurts these named scenarios, treat that as a regression.

When your replay store contains paired `baseline`, `rlm`, and `beam_planner` runs for the same
queries, local evaluation now emits an `engine_comparisons` section that compares them on matched
queries or named scenarios. Use it to answer the practical question: did the alternate planner
actually help on the same job, or just score well in aggregate?

```bash
python -B scripts/replay/replay_eval_cli.py --store target/replay evaluate --name usefulness-compare
```

Nightly usefulness reports now include a separate planner section. Across the execution and shadow
lanes that means the same artifact can show:

- execution scorecards for the Rust-owned, `rlm`, or `beam_planner` engine that actually served the answer
- planner scorecards for `baseline`, `rlm`, `beam_planner`, and `beam_planner_shadow` traces observed in those runs
- planner comparisons that tell us whether BEAM shadow or BEAM execution planning is matching or beating the current planner on the same scenarios

Automation: `.github/workflows/nightly-usefulness.yml` runs the named usefulness suites and publishes nightly artifacts for `baseline`, `rlm`, `beam_planner`, and the BEAM shadow-planner benchmark lane. The BEAM lanes now generate their nightly report, planner comparison artifact, and scenario preview through the supervised `pecr_planner` job wrapper so the background job path is exercised continuously.
