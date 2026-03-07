import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load_module(module_name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def write_runs(path: Path, runs: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(runs), encoding="utf-8")


class RealBackendPromotionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module(
            "check_real_backend_promotion_gate",
            "scripts/ops/check_real_backend_promotion_gate.py",
        )

    def test_gate_is_ready_after_three_successes_on_same_sha(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runs = tmp / "runs.json"
            report = tmp / "report.json"
            write_runs(
                runs,
                [
                    {
                        "databaseId": 103,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:03:00Z",
                        "url": "https://example.test/runs/103",
                    },
                    {
                        "databaseId": 102,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:02:00Z",
                        "url": "https://example.test/runs/102",
                    },
                    {
                        "databaseId": 101,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:01:00Z",
                        "url": "https://example.test/runs/101",
                    },
                ],
            )

            argv = [
                "check_real_backend_promotion_gate.py",
                "--runs-json",
                str(runs),
                "--branch",
                "master",
                "--head-sha",
                "abc123",
                "--required-successes",
                "3",
                "--output-json",
                str(report),
                "--require-ready",
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(payload["status"], "ready")
            self.assertEqual(payload["successful_streak"], 3)

    def test_gate_breaks_on_first_non_successful_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runs = tmp / "runs.json"
            report = tmp / "report.json"
            write_runs(
                runs,
                [
                    {
                        "databaseId": 103,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "failure",
                        "createdAt": "2026-03-07T12:03:00Z",
                        "url": "https://example.test/runs/103",
                    },
                    {
                        "databaseId": 102,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:02:00Z",
                        "url": "https://example.test/runs/102",
                    },
                ],
            )

            argv = [
                "check_real_backend_promotion_gate.py",
                "--runs-json",
                str(runs),
                "--branch",
                "master",
                "--head-sha",
                "abc123",
                "--output-json",
                str(report),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(payload["status"], "not_ready")
            self.assertEqual(payload["successful_streak"], 0)

    def test_gate_ignores_other_workflows_and_branches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            runs = tmp / "runs.json"
            report = tmp / "report.json"
            write_runs(
                runs,
                [
                    {
                        "databaseId": 103,
                        "workflowName": "ci",
                        "headBranch": "master",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:03:00Z",
                        "url": "https://example.test/runs/103",
                    },
                    {
                        "databaseId": 102,
                        "workflowName": "rlm-real-backend-usefulness",
                        "headBranch": "feature",
                        "headSha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "createdAt": "2026-03-07T12:02:00Z",
                        "url": "https://example.test/runs/102",
                    },
                ],
            )

            argv = [
                "check_real_backend_promotion_gate.py",
                "--runs-json",
                str(runs),
                "--branch",
                "master",
                "--output-json",
                str(report),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(payload["matching_run_count"], 0)
            self.assertEqual(payload["successful_streak"], 0)


if __name__ == "__main__":
    unittest.main()
