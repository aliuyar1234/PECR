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


class FakeBridge:
    def __init__(self):
        self.operator_calls = []
        self.batch_calls = []

    def call_operator(self, *, depth, op_name, params):
        self.operator_calls.append((depth, op_name, params))
        if op_name == "search":
            return {
                "type": "operator_result",
                "id": "search",
                "result": {
                    "refs": [
                        {"object_id": "public/public_1.txt"},
                        {"object_id": "public/public_2.txt"},
                    ]
                },
            }
        return {"type": "operator_result", "id": op_name, "result": {}}

    def call_operator_batch(self, *, depth, calls):
        self.batch_calls.append((depth, calls))
        return [{"ok": True, "result": {}} for _ in calls]


class RlmBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("pecr_rlm_bridge", "scripts/rlm/pecr_rlm_bridge.py")
        cls.mod.ensure_vendor_rlm_on_path()

    def test_budget_from_json_defaults_parallelism_to_one(self):
        budget = self.mod.Budget.from_json(
            {
                "max_operator_calls": 10,
                "max_bytes": 1024,
                "max_wallclock_ms": 5000,
                "max_recursion_depth": 5,
            }
        )
        self.assertEqual(budget.max_parallelism, 1)

    def test_run_mock_uses_batch_calls_when_parallelism_is_set(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=2,
        )

        result = self.mod.run_mock(bridge, "query", budget)

        self.assertEqual(len(bridge.batch_calls), 1)
        self.assertEqual(len(bridge.batch_calls[0][1]), 2)
        self.assertEqual(result["operator_calls_used"], 5)

    def test_run_mock_falls_back_to_sequential_calls_when_parallelism_is_one(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=1,
        )

        result = self.mod.run_mock(bridge, "query", budget)
        fetch_span_calls = [call for call in bridge.operator_calls if call[1] == "fetch_span"]

        self.assertEqual(len(bridge.batch_calls), 0)
        self.assertEqual(len(fetch_span_calls), 2)
        self.assertEqual(result["operator_calls_used"], 5)


if __name__ == "__main__":
    unittest.main()
