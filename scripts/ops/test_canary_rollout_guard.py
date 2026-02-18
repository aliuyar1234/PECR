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


def write_summary(path: Path, p95: float, p99: float) -> None:
    payload = {"metrics": {"http_req_duration": {"p(95)": p95, "p(99)": p99}}}
    path.write_text(json.dumps(payload), encoding="utf-8")


def write_gates(path: Path, bvr: float, ser: float, bvr_threshold: float, ser_threshold: float) -> None:
    payload = {
        "rates": {"bvr": bvr, "ser": ser},
        "thresholds": {"bvr": bvr_threshold, "ser": ser_threshold},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class CanaryRolloutGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("canary_rollout_guard", "scripts/ops/canary_rollout_guard.py")

    def test_guard_recommends_disabling_adaptive_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            summary = tmp / "summary.json"
            gates = tmp / "gates.json"
            report = tmp / "report.json"
            write_summary(summary, p95=1800.0, p99=2200.0)
            write_gates(gates, bvr=0.02, ser=0.01, bvr_threshold=0.005, ser_threshold=0.005)

            argv = [
                "canary_rollout_guard.py",
                "--summary",
                str(summary),
                "--metrics-gates",
                str(gates),
                "--adaptive-enabled",
                "true",
                "--batch-enabled",
                "true",
                "--output-json",
                str(report),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            self.assertEqual(code, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "fallback_required")
            self.assertEqual(
                payload["recommended_fallback"]["step"],
                "disable_adaptive_parallelism",
            )

    def test_guard_switches_to_baseline_when_flags_already_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            summary = tmp / "summary.json"
            gates = tmp / "gates.json"
            report = tmp / "report.json"
            write_summary(summary, p95=1700.0, p99=2100.0)
            write_gates(gates, bvr=0.02, ser=0.01, bvr_threshold=0.005, ser_threshold=0.005)

            argv = [
                "canary_rollout_guard.py",
                "--summary",
                str(summary),
                "--metrics-gates",
                str(gates),
                "--engine",
                "rlm",
                "--adaptive-enabled",
                "false",
                "--batch-enabled",
                "false",
                "--output-json",
                str(report),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            self.assertEqual(code, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["recommended_fallback"]["step"], "switch_engine_to_baseline")

    def test_guard_passes_for_healthy_canary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            summary = tmp / "summary.json"
            gates = tmp / "gates.json"
            report = tmp / "report.json"
            write_summary(summary, p95=300.0, p99=450.0)
            write_gates(gates, bvr=0.001, ser=0.001, bvr_threshold=0.005, ser_threshold=0.005)

            argv = [
                "canary_rollout_guard.py",
                "--summary",
                str(summary),
                "--metrics-gates",
                str(gates),
                "--output-json",
                str(report),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.mod.main()

            self.assertEqual(code, 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
