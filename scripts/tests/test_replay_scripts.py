import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
USEFUL_TASK_FIXTURE_DIR = ROOT / "fixtures" / "replay" / "useful_tasks"
USEFUL_TASK_MANIFEST = USEFUL_TASK_FIXTURE_DIR / "benchmark_manifest.json"


def has_working_mix() -> bool:
    mix_cmd = shutil.which("mix") or shutil.which("mix.bat") or shutil.which("mix.cmd")
    if not mix_cmd:
        return False
    try:
        result = subprocess.run(
            [mix_cmd, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


HAS_WORKING_MIX = has_working_mix()


def make_planner_trace(
    *,
    planner_source: str,
    steps: list[dict[str, object]],
    selected_for_execution: bool,
    used_fallback_plan: bool = False,
    stop_reason: str = "plan_complete",
    expected_usefulness_score: float | None = 0.9,
    selection_rationale: str | None = None,
) -> dict[str, object]:
    return {
        "plan_request": {
            "schema_version": 1,
            "query": "smoke",
            "budget": {
                "max_operator_calls": 10,
                "max_bytes": 2048,
                "max_wallclock_ms": 1000,
                "max_recursion_depth": 3,
                "max_parallelism": 1,
            },
            "planner_hints": {
                "intent": "structured_lookup",
                "recommended_path": steps,
            },
            "available_operator_names": ["fetch_rows", "lookup_evidence", "aggregate", "compare"],
            "allow_search_ref_fetch_span": True,
        },
        "output_steps": steps,
        "decision_summary": {
            "planner_source": planner_source,
            "stop_reason": stop_reason,
            "selected_for_execution": selected_for_execution,
            "used_fallback_plan": used_fallback_plan,
            "expected_usefulness_score": expected_usefulness_score,
            "expected_usefulness_reasons": ["matches the benchmarked recommended planner path"],
            "selection_rationale": selection_rationale
            or f"{planner_source} was preferred because expected usefulness scored highly.",
        },
    }


def write_sample_bundle(
    store_dir: Path,
    *,
    run_id: str,
    engine_mode: str,
    terminal_mode: str,
    quality_score: float,
    query: str = "smoke",
    recorded_at_unix_ms: int = 1700000000000,
    planner_traces: list[dict[str, object]] | None = None,
) -> None:
    replays_dir = store_dir / "replays"
    replays_dir.mkdir(parents=True, exist_ok=True)
    bundle = {
        "metadata": {
            "schema_version": 1,
            "run_id": run_id,
            "trace_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "request_id": "req-1",
            "principal_id_hash": "a" * 64,
            "engine_mode": engine_mode,
            "recorded_at_unix_ms": recorded_at_unix_ms,
            "terminal_mode": terminal_mode,
            "quality_score": quality_score,
            "bundle_hash": "b" * 64,
        },
        "query": query,
        "budget": {
            "max_operator_calls": 10,
            "max_bytes": 2048,
            "max_wallclock_ms": 1000,
            "max_recursion_depth": 3,
            "max_parallelism": 1,
        },
        "session_id": "session",
        "policy_snapshot_id": "policy",
        "loop_terminal_mode": terminal_mode,
        "response_text": "UNKNOWN: smoke",
        "claim_map": {
            "claim_map_id": "claim_map_1",
            "terminal_mode": terminal_mode,
            "claims": [],
            "coverage_threshold": 0.95,
            "coverage_observed": 1.0,
        },
        "operator_calls_used": 2,
        "bytes_used": 100,
        "depth_used": 2,
        "evidence_ref_count": 0,
        "evidence_unit_ids": [],
        "planner_traces": planner_traces or [],
    }
    with (replays_dir / f"{run_id}.json").open("w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
        f.write("\n")


class ReplayScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pecr-replay-scripts-"))
        write_sample_bundle(
            self.temp_dir,
            run_id="run-baseline-1",
            engine_mode="baseline",
            terminal_mode="INSUFFICIENT_EVIDENCE",
            quality_score=61.2,
        )
        write_sample_bundle(
            self.temp_dir,
            run_id="run-rlm-1",
            engine_mode="rlm",
            terminal_mode="SOURCE_UNAVAILABLE",
            quality_score=20.0,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def write_temp_benchmark_manifest(self, *, query: str, expected_planner_prefixes: list[list[str]]) -> None:
        manifest = {
            "benchmark_name": "temp_useful_answer_benchmark",
            "scenarios": [
                {
                    "scenario_id": "temp-scenario",
                    "title": "Temp Scenario",
                    "category": "structured_lookup",
                    "job": "Check planner path scoring",
                    "query": query,
                    "run_id": "temp-run",
                    "replay_path": "replays/temp-run.json",
                    "expected_terminal_mode": "SUPPORTED",
                    "minimum_quality_score": 0.0,
                    "expected_planner_prefixes": expected_planner_prefixes,
                }
            ],
        }
        (self.temp_dir / "benchmark_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_replay_eval_cli_reconstructs_outcome(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "replay_eval_cli.py"),
            "--store",
            str(self.temp_dir),
            "replay",
            "--run-id",
            "run-baseline-1",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["trace_id"], "01ARZ3NDEKTSV4RRFFQ69G5FAV")
        self.assertEqual(payload["terminal_mode"], "INSUFFICIENT_EVIDENCE")

    def test_replay_eval_cli_scorecards_groups_by_engine_mode(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "replay_eval_cli.py"),
            "--store",
            str(self.temp_dir),
            "scorecards",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        scorecards = payload["scorecards"]
        self.assertEqual(len(scorecards), 2)
        modes = {row["engine_mode"] for row in scorecards}
        self.assertEqual(modes, {"baseline", "rlm"})
        self.assertTrue(all("average_citation_quality" in row for row in scorecards))
        self.assertTrue(all("benchmark_pass_rate" in row for row in scorecards))
        comparisons = payload["engine_comparisons"]
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(comparisons[0]["primary_engine_mode"], "baseline")
        self.assertEqual(comparisons[0]["secondary_engine_mode"], "rlm")
        self.assertEqual(comparisons[0]["paired_query_count"], 1)
        self.assertEqual(comparisons[0]["more_helpful_engine_mode"], "baseline")

    def test_regression_gate_fails_on_high_quality_threshold(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "regression_gate.py"),
            "--store",
            str(self.temp_dir),
            "--min-quality-score",
            "95",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("quality_score", result.stdout + result.stderr)

    def test_regression_gate_requires_requested_terminal_modes(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "regression_gate.py"),
            "--store",
            str(self.temp_dir),
            "--require-terminal-mode",
            "SUPPORTED",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required terminal_mode fixture: SUPPORTED", result.stdout + result.stderr)

    def test_regression_gate_accepts_canonical_terminal_mode_fixtures(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "regression_gate.py"),
            "--store",
            str(ROOT / "fixtures" / "replay" / "terminal_modes"),
            "--require-terminal-mode",
            "SUPPORTED",
            "--require-terminal-mode",
            "INSUFFICIENT_EVIDENCE",
            "--require-terminal-mode",
            "INSUFFICIENT_PERMISSION",
            "--require-terminal-mode",
            "SOURCE_UNAVAILABLE",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_regression_gate_accepts_useful_task_fixtures(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "regression_gate.py"),
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
            "--require-terminal-mode",
            "SUPPORTED",
            "--min-quality-score",
            "90",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_useful_task_fixture_set_matches_benchmark_manifest(self):
        manifest = json.loads(USEFUL_TASK_MANIFEST.read_text(encoding="utf-8"))
        replays_dir = USEFUL_TASK_FIXTURE_DIR / "replays"
        bundles = {
            json.loads(path.read_text(encoding="utf-8"))["metadata"]["run_id"]
            for path in replays_dir.glob("*.json")
        }
        self.assertEqual(
            bundles,
            {scenario["run_id"] for scenario in manifest["scenarios"]},
        )

    def test_useful_benchmark_cli_lists_named_scenarios(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "useful_benchmark_cli.py"),
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
            "list",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["benchmark_name"], "useful_answer_benchmark_v1")
        scenario_ids = {row["scenario_id"] for row in payload["scenarios"]}
        self.assertIn("customer-counts-by-plan", scenario_ids)
        self.assertIn("monthly-customer-trend", scenario_ids)
        self.assertIn("broad-customer-query", scenario_ids)
        self.assertIn("partial-billing-answer", scenario_ids)
        self.assertEqual(len(payload["scenarios"]), 10)
        rows_by_id = {row["scenario_id"]: row for row in payload["scenarios"]}
        self.assertEqual(
            rows_by_id["broad-customer-query"]["actual_response_kind"], "ambiguous"
        )
        self.assertEqual(
            rows_by_id["partial-billing-answer"]["actual_response_kind"],
            "partial_answer",
        )
        self.assertEqual(
            rows_by_id["support-policy-source"][
                "actual_max_supported_claim_evidence_units"
            ],
            2,
        )

    def test_useful_benchmark_cli_validates_manifest_against_replays(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "useful_benchmark_cli.py"),
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
            "validate",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scenario_count"], 10)
        self.assertEqual(payload["categories"]["aggregate_compare"], 1)
        self.assertEqual(payload["categories"]["aggregate_trend"], 1)
        self.assertEqual(payload["categories"]["ambiguity_guidance"], 2)
        self.assertEqual(payload["categories"]["partial_answer"], 1)

    def test_useful_benchmark_cli_planner_compare_reports_shadow_mode(self):
        query = "What is the customer status and plan tier?"
        planner_steps = [
            {
                "kind": "operator",
                "op_name": "fetch_rows",
                "params": {"view_id": "safe_customer_view_public"},
            }
        ]
        self.write_temp_benchmark_manifest(
            query=query,
            expected_planner_prefixes=[["fetch_rows"]],
        )
        write_sample_bundle(
            self.temp_dir,
            run_id="run-baseline-shadow",
            engine_mode="baseline",
            terminal_mode="SUPPORTED",
            quality_score=97.0,
            query=query,
            recorded_at_unix_ms=1700000000100,
            planner_traces=[
                make_planner_trace(
                    planner_source="rust_owned",
                    steps=planner_steps,
                    selected_for_execution=True,
                ),
                make_planner_trace(
                    planner_source="beam_shadow",
                    steps=planner_steps,
                    selected_for_execution=False,
                    stop_reason="shadow_only",
                ),
            ],
        )
        write_sample_bundle(
            self.temp_dir,
            run_id="run-rlm-shadow",
            engine_mode="rlm",
            terminal_mode="SUPPORTED",
            quality_score=96.0,
            query=query,
            recorded_at_unix_ms=1700000000200,
            planner_traces=[
                make_planner_trace(
                    planner_source="rlm_bridge",
                    steps=planner_steps,
                    selected_for_execution=True,
                )
            ],
        )

        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "useful_benchmark_cli.py"),
            "--store",
            str(self.temp_dir),
            "planner-compare",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        scorecards = {row["planner_mode"]: row for row in payload["planner_scorecards"]}
        self.assertEqual(
            set(scorecards.keys()),
            {"baseline", "rlm", "beam_planner_shadow"},
        )
        self.assertEqual(scorecards["beam_planner_shadow"]["scenario_coverage_rate"], 1.0)
        self.assertEqual(scorecards["beam_planner_shadow"]["benchmark_pass_rate"], 1.0)
        self.assertIn("average_expected_usefulness_score", scorecards["beam_planner_shadow"])
        comparison_pairs = {
            (row["primary_planner_mode"], row["secondary_planner_mode"])
            for row in payload["planner_comparisons"]
        }
        self.assertEqual(
            comparison_pairs,
            {
                ("baseline", "beam_planner_shadow"),
                ("baseline", "rlm"),
                ("beam_planner_shadow", "rlm"),
            },
        )
        self.assertTrue(
            all(
                "average_expected_usefulness_delta" in row
                for row in payload["planner_comparisons"]
            )
        )

    def test_useful_benchmark_cli_planner_compare_counts_beam_recovery_as_beam_planner(self):
        query = "What is the customer status and plan tier?"
        planner_steps = [
            {
                "kind": "operator",
                "op_name": "lookup_evidence",
                "params": {},
            }
        ]
        self.write_temp_benchmark_manifest(
            query=query,
            expected_planner_prefixes=[["lookup_evidence"]],
        )
        write_sample_bundle(
            self.temp_dir,
            run_id="run-beam-recovery",
            engine_mode="beam_planner",
            terminal_mode="SUPPORTED",
            quality_score=97.0,
            query=query,
            recorded_at_unix_ms=1700000000300,
            planner_traces=[
                make_planner_trace(
                    planner_source="beam_planner",
                    steps=[
                        {
                            "kind": "operator",
                            "op_name": "fetch_rows",
                            "params": {"view_id": "safe_customer_view_public"},
                        }
                    ],
                    selected_for_execution=False,
                    stop_reason="recovered_by_beam_worker",
                ),
                make_planner_trace(
                    planner_source="beam_recovery",
                    steps=planner_steps,
                    selected_for_execution=True,
                    used_fallback_plan=True,
                ),
            ],
        )

        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "useful_benchmark_cli.py"),
            "--store",
            str(self.temp_dir),
            "planner-compare",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        scorecards = {row["planner_mode"]: row for row in payload["planner_scorecards"]}
        self.assertIn("beam_planner", scorecards)
        self.assertEqual(scorecards["beam_planner"]["benchmark_pass_rate"], 1.0)
        self.assertEqual(scorecards["beam_planner"]["fallback_rate"], 1.0)

    @unittest.skipUnless(HAS_WORKING_MIX, "mix not installed")
    def test_run_beam_usefulness_job_wrapper_returns_json(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "run_beam_usefulness_job.py"),
            "scenario-preview",
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["job_name"], "scenario-preview")
        self.assertEqual(payload["job_status"], "succeeded")
        self.assertIn("useful_answer_benchmark_v1", payload["output"])

    @unittest.skipUnless(HAS_WORKING_MIX, "mix not installed")
    def test_beam_shadow_http_bridge_returns_contract_response(self):
        port = "9199"
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "scripts" / "planner" / "beam_shadow_http_bridge.py"),
                "--host",
                "127.0.0.1",
                "--port",
                port,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            for _ in range(30):
                try:
                    with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/health", timeout=2
                    ) as response:
                        if response.status == 200:
                            break
                except Exception:
                    time.sleep(0.25)
            else:
                self.fail("beam shadow bridge did not become ready")

            request = {
                "schema_version": 1,
                "query": "What is the customer status and plan tier?",
                "budget": {
                    "max_operator_calls": 10,
                    "max_bytes": 2048,
                    "max_wallclock_ms": 1000,
                    "max_recursion_depth": 3,
                    "max_parallelism": 1,
                },
                "planner_hints": {
                    "intent": "structured_lookup",
                    "recommended_path": [],
                },
                "available_operator_names": ["fetch_rows", "lookup_evidence"],
                "allow_search_ref_fetch_span": True,
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/plan",
                data=json.dumps(request).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))

            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(
                payload["steps"],
                [{"kind": "operator", "op_name": "fetch_rows", "params": {}}],
            )
            self.assertIn("planner_summary", payload)
        finally:
            process.terminate()
            process.wait(timeout=10)

    def test_replay_eval_cli_reports_benchmark_usefulness_fields(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "replay_eval_cli.py"),
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
            "evaluate",
            "--name",
            "useful-benchmark",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertTrue(all("citation_quality" in row for row in payload["run_results"]))
        self.assertTrue(all("response_kind" in row for row in payload["run_results"]))
        self.assertTrue(
            all(row["benchmark_scenario_id"] is not None for row in payload["run_results"])
        )
        self.assertTrue(all(row["benchmark_pass"] for row in payload["run_results"]))
        self.assertEqual(payload["scorecards"][0]["benchmark_pass_rate"], 1.0)
        self.assertIn("partial_answer_rate", payload["scorecards"][0])
        self.assertIn("refusal_friction_rate", payload["scorecards"][0])
        self.assertEqual(payload["engine_comparisons"], [])

    def test_replay_eval_cli_evaluate_reports_engine_comparison_summary(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "replay_eval_cli.py"),
            "--store",
            str(self.temp_dir),
            "evaluate",
            "--name",
            "engine-compare",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["engine_comparisons"]), 1)
        comparison = payload["engine_comparisons"][0]
        self.assertEqual(comparison["primary_engine_mode"], "baseline")
        self.assertEqual(comparison["secondary_engine_mode"], "rlm")
        self.assertEqual(comparison["paired_query_count"], 1)
        self.assertGreater(comparison["average_quality_score_delta"], 0.0)
        self.assertEqual(comparison["more_helpful_engine_mode"], "baseline")

    def test_nightly_usefulness_report_generates_json_and_markdown(self):
        output_dir = self.temp_dir / "nightly"
        output_json = output_dir / "nightly_usefulness_baseline.json"
        output_md = output_dir / "nightly_usefulness_baseline.md"
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "nightly_usefulness_report.py"),
            "--store",
            str(USEFUL_TASK_FIXTURE_DIR),
            "--evaluation-name",
            "nightly-usefulness-baseline",
            "--engine-mode",
            "baseline",
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(output_json.read_text(encoding="utf-8"))
        self.assertEqual(payload["evaluation_name"], "nightly-usefulness-baseline")
        self.assertEqual(payload["engine_mode"], "baseline")
        markdown = output_md.read_text(encoding="utf-8")
        self.assertIn("# nightly-usefulness-baseline", markdown)
        self.assertIn("| Engine | Runs | Benchmark pass |", markdown)

    def test_nightly_usefulness_report_includes_planner_sections_when_present(self):
        query = "What is the customer status and plan tier?"
        planner_steps = [
            {
                "kind": "operator",
                "op_name": "fetch_rows",
                "params": {"view_id": "safe_customer_view_public"},
            }
        ]
        self.write_temp_benchmark_manifest(
            query=query,
            expected_planner_prefixes=[["fetch_rows"]],
        )
        write_sample_bundle(
            self.temp_dir,
            run_id="run-baseline-shadow",
            engine_mode="baseline",
            terminal_mode="SUPPORTED",
            quality_score=97.0,
            query=query,
            recorded_at_unix_ms=1700000000100,
            planner_traces=[
                make_planner_trace(
                    planner_source="rust_owned",
                    steps=planner_steps,
                    selected_for_execution=True,
                ),
                make_planner_trace(
                    planner_source="beam_shadow",
                    steps=planner_steps,
                    selected_for_execution=False,
                    stop_reason="shadow_only",
                ),
            ],
        )

        output_dir = self.temp_dir / "nightly-planner"
        output_json = output_dir / "nightly_usefulness_shadow.json"
        output_md = output_dir / "nightly_usefulness_shadow.md"
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "replay" / "nightly_usefulness_report.py"),
            "--store",
            str(self.temp_dir),
            "--benchmark-manifest",
            str(self.temp_dir / "benchmark_manifest.json"),
            "--evaluation-name",
            "nightly-usefulness-shadow",
            "--engine-mode",
            "baseline",
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(output_json.read_text(encoding="utf-8"))
        planner_modes = {row["planner_mode"] for row in payload["planner_scorecards"]}
        self.assertEqual(planner_modes, {"baseline", "beam_planner_shadow"})
        self.assertTrue(
            all(
                "average_expected_usefulness_score" in row
                for row in payload["planner_scorecards"]
            )
        )
        markdown = output_md.read_text(encoding="utf-8")
        self.assertIn("## Planner Scorecards", markdown)
        self.assertIn("## Planner Comparisons", markdown)

    def test_useful_workflows_catalog_lists_all_named_scenarios(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "demo" / "useful_workflows.py"),
            "catalog",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["scenario_count"], 10)
        self.assertIn("customer-status", {row["scenario_id"] for row in payload["scenarios"]})

    def test_useful_workflows_tour_reports_curated_scenarios(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "demo" / "useful_workflows.py"),
            "tour",
            "--format",
            "json",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["tour_mode"], "fixture")
        self.assertEqual(payload["scenario_count"], 5)
        self.assertIn("SUPPORTED", payload["terminal_modes"])
        self.assertIn(
            "1 scenario returned narrowing guidance instead of a dead-end failure.",
            payload["takeaways"],
        )

    def test_useful_workflows_scenario_reports_outcome(self):
        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "demo" / "useful_workflows.py"),
            "scenario",
            "monthly-customer-trend",
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(payload["terminal_mode"], "SUPPORTED")
        self.assertIn("time_bucket=2026-03-01", payload["response_text"])


if __name__ == "__main__":
    unittest.main()
