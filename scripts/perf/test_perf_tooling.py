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


def write_summary(path: Path, p95: float, p99: float, rate: float) -> None:
    payload = {
        "metrics": {
            "http_req_duration": {"p(95)": p95, "p(99)": p99, "p(90)": p95},
            "http_reqs": {"rate": rate},
        }
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class PerfToolingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compare_mod = load_module("compare_k6_baseline_new", "scripts/perf/compare_k6_baseline.py")
        cls.matrix_mod = load_module("benchmark_matrix", "scripts/perf/benchmark_matrix.py")
        cls.median_mod = load_module("select_median_summary", "scripts/perf/select_median_summary.py")

    def test_compare_gh_escape_encodes_colon_and_newline(self):
        escaped = self.compare_mod.gh_escape("a:b\nc")
        self.assertEqual(escaped, "a%3Ab%0Ac")

    def test_matrix_parse_candidate_requires_label_path(self):
        label, path = self.matrix_mod.parse_candidate("rlm=target/perf/rlm.json")
        self.assertEqual(label, "rlm")
        self.assertEqual(path.as_posix(), "target/perf/rlm.json")
        with self.assertRaises(SystemExit):
            self.matrix_mod.parse_candidate("missing-separator")

    def test_matrix_main_strict_passes_when_candidate_within_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            baseline = tmp / "baseline.json"
            candidate = tmp / "candidate.json"
            out_json = tmp / "matrix.json"
            out_md = tmp / "matrix.md"
            write_summary(baseline, p95=100.0, p99=120.0, rate=20.0)
            write_summary(candidate, p95=110.0, p99=130.0, rate=19.0)

            argv = [
                "benchmark_matrix.py",
                "--baseline",
                str(baseline),
                "--candidate",
                f"rlm={candidate}",
                "--output-json",
                str(out_json),
                "--output-md",
                str(out_md),
                "--strict",
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.matrix_mod.main()

            self.assertEqual(code, 0)
            self.assertTrue(out_json.exists())
            self.assertTrue(out_md.exists())

    def test_matrix_main_strict_fails_when_candidate_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            baseline = tmp / "baseline.json"
            out_json = tmp / "matrix.json"
            out_md = tmp / "matrix.md"
            write_summary(baseline, p95=100.0, p99=120.0, rate=20.0)

            argv = [
                "benchmark_matrix.py",
                "--baseline",
                str(baseline),
                "--candidate",
                f"rlm={tmp / 'missing.json'}",
                "--output-json",
                str(out_json),
                "--output-md",
                str(out_md),
                "--strict",
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.matrix_mod.main()

            self.assertEqual(code, 1)

    def test_matrix_output_contains_failure_reasons(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            baseline = tmp / "baseline.json"
            out_json = tmp / "matrix.json"
            out_md = tmp / "matrix.md"
            write_summary(baseline, p95=100.0, p99=120.0, rate=20.0)

            argv = [
                "benchmark_matrix.py",
                "--baseline",
                str(baseline),
                "--candidate",
                f"rlm={tmp / 'missing.json'}",
                "--output-json",
                str(out_json),
                "--output-md",
                str(out_md),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.matrix_mod.main()

            self.assertEqual(code, 0)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertIn("failure_reasons", payload)
            self.assertEqual(payload["failure_reasons"][0]["label"], "rlm")
            self.assertEqual(payload["failure_reasons"][0]["status"], "MISSING")

    def test_compare_output_contains_status_and_failed_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            baseline = tmp / "baseline.json"
            current = tmp / "current.json"
            out_json = tmp / "alarm.json"
            write_summary(baseline, p95=100.0, p99=120.0, rate=20.0)
            write_summary(current, p95=1000.0, p99=1200.0, rate=1.0)

            argv = [
                "compare_k6_baseline.py",
                "--baseline",
                str(baseline),
                "--current",
                str(current),
                "--output-json",
                str(out_json),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.compare_mod.main()

            self.assertEqual(code, 1)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "FAIL")
            self.assertGreaterEqual(len(payload["failed_checks"]), 1)

    def test_select_median_summary_picks_middle_by_metric(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            low = tmp / "low.json"
            mid = tmp / "mid.json"
            high = tmp / "high.json"
            output = tmp / "selected.json"
            metadata = tmp / "metadata.json"

            write_summary(low, p95=90.0, p99=120.0, rate=20.0)
            write_summary(mid, p95=110.0, p99=120.0, rate=20.0)
            write_summary(high, p95=140.0, p99=120.0, rate=20.0)

            argv = [
                "select_median_summary.py",
                "--metric",
                "http_req_duration:p(95)",
                "--output",
                str(output),
                "--metadata-json",
                str(metadata),
                str(high),
                str(low),
                str(mid),
            ]
            with patch.object(sys, "argv", argv):
                with redirect_stdout(io.StringIO()):
                    code = self.median_mod.main()

            self.assertEqual(code, 0)
            selected_payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                selected_payload["metrics"]["http_req_duration"]["p(95)"],
                110.0,
            )
            meta = json.loads(metadata.read_text(encoding="utf-8"))
            self.assertTrue(meta["selected_path"].endswith("mid.json"))


if __name__ == "__main__":
    unittest.main()
