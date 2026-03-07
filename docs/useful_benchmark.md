# Useful Benchmark

PECR now has a named usefulness corpus at `fixtures/replay/useful_tasks/`. It is meant to track real user jobs, not just terminal-mode semantics.
For the RLM-first migration, this corpus is the primary product scorecard, not a side benchmark.

## RLM-First Scorecard

Before `rlm` becomes the default product path, every release candidate or nightly lane should be judged on the same core questions:

- useful-answer rate: does the system satisfy the named scenario expectations?
- supported-answer rate: how often do useful scenarios finish as grounded `SUPPORTED` answers?
- fallback recovery rate: when a first path is weak, blocked, or unavailable, how often does the system recover to another safe useful path?
- finalize downgrade rate: how often does finalize reject or downgrade an answer path that looked promising earlier in the run?
- p95 latency: does the RLM-first path stay operationally usable?
- throughput: does the runtime stay inside the deployment envelope?
- shadow delta versus baseline: when the same scenario is run through both lanes, is RLM at least matching and ideally beating the reference path?

`baseline` and `beam_planner` may still appear in reports during migration, but they are comparison lanes. The product question is whether the RLM-first path is good enough to own the default runtime.

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
The current named scenario files are:

- `customer_status_plan.json`
- `support_policy_source_text.json`
- `annual_refund_source_text.json`
- `billing_terms_policy.json`
- `latest_support_document_change.json`
- `customer_counts_by_plan_tier.json`
- `monthly_customer_trend.json`
- `broad_customer_query_narrowing.json`
- `broad_policy_query_narrowing.json`
- `partial_billing_answer.json`

## Commands

List the benchmark catalog:

```bash
python -B scripts/replay/useful_benchmark_cli.py list
```

Validate that the manifest and replay fixtures stay aligned:

```bash
python -B scripts/replay/useful_benchmark_cli.py validate
```

Compare planner behavior on the named scenarios. During migration this may still grade `baseline`,
`rlm`, `beam_planner`, and `beam_planner_shadow` traces against the scenario-declared planner
prefixes when the replay store contains `planner_traces`. Recovery traces emitted as
`beam_recovery` are folded into the `beam_planner` planner mode so recovered runs stay visible in
the same benchmark lane, but only `rlm` is the target execution lane for the long-term product:

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

During the RLM-first rollout, treat these scenarios as the default answer to:

- did RLM actually help users on the jobs we care about?
- did long-context reasoning improve synthesis instead of just increasing cost?
- did planner changes improve recovery and clarification behavior?
- did finalize stay aligned with the higher-capability path?

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

Automation: `.github/workflows/nightly-usefulness.yml` runs the named usefulness suites and publishes nightly artifacts for `baseline`, `rlm`, `beam_planner`, and the BEAM shadow-planner benchmark lane. During the RLM-first migration, those extra lanes are still useful as comparison artifacts, but the release question should always be framed around whether `rlm` is strong enough to own the default path.
