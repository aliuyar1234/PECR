import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(module_name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class CheckBvrSerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("check_bvr_ser", "scripts/perf/check_bvr_ser.py")

    def test_parse_prometheus_text_with_labels(self):
        text = """
# HELP pecr_gateway_budget_violations_total test
pecr_gateway_budget_violations_total 2
pecr_gateway_http_requests_total{route="/v1/finalize",method="POST",status="200"} 10
"""
        samples = self.mod.parse_prometheus_text(text)
        finalize = self.mod.sum_metric(
            samples,
            "pecr_gateway_http_requests_total",
            {"route": "/v1/finalize", "method": "POST", "status": "200"},
        )
        self.assertEqual(finalize, 10.0)

    def test_sum_metric_reports_missing_required_sample(self):
        samples = self.mod.parse_prometheus_text("metric_without_labels 1\n")
        with self.assertRaises(SystemExit) as ctx:
            self.mod.sum_metric(samples, "missing_metric", {}, required=True)
        self.assertIn("missing metric sample", str(ctx.exception))

    def test_non_negative_delta_rejects_counter_regression(self):
        with self.assertRaises(SystemExit) as ctx:
            self.mod.non_negative_delta(5, 4, "counter")
        self.assertIn("counter went backwards", str(ctx.exception))


class CompareK6BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("compare_k6_baseline", "scripts/perf/compare_k6_baseline.py")

    def test_allowed_ms_uses_max_of_factor_and_absolute_delta(self):
        self.assertEqual(self.mod.allowed_ms(100.0, 1.1, 50.0), 150.0)
        self.assertEqual(self.mod.allowed_ms(100.0, 2.0, 10.0), 200.0)

    def test_get_metric_value_requires_metric_key(self):
        summary = {"metrics": {"http_req_duration": {"p(95)": 123.0}}}
        with self.assertRaises(SystemExit) as ctx:
            self.mod.get_metric_value(summary, "http_req_duration", "p(99)")
        self.assertIn("missing key", str(ctx.exception))


class CheckImageTagsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("check_image_tags", "scripts/security/check_image_tags.py")

    def test_validate_ref_requires_digest_for_from_lines(self):
        self.assertEqual(
            self.mod.validate_ref("debian:12-slim", require_digest=True),
            "missing digest pin: debian:12-slim",
        )

    def test_validate_ref_accepts_valid_sha256_digest(self):
        ref = "debian:12-slim@sha256:" + ("a" * 64)
        self.assertIsNone(self.mod.validate_ref(ref, require_digest=True))

    def test_validate_ref_rejects_latest_tag(self):
        self.assertEqual(
            self.mod.validate_ref("example/repo:latest"),
            "uses latest tag: example/repo:latest",
        )


if __name__ == "__main__":
    unittest.main()
