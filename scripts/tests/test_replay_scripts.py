import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def write_sample_bundle(store_dir: Path, *, run_id: str, engine_mode: str, terminal_mode: str, quality_score: float) -> None:
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
            "recorded_at_unix_ms": 1700000000000,
            "terminal_mode": terminal_mode,
            "quality_score": quality_score,
            "bundle_hash": "b" * 64,
        },
        "query": "smoke",
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


if __name__ == "__main__":
    unittest.main()
