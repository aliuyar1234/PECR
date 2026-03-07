import importlib.util
import json
import os
import subprocess
import sys
import unittest
import warnings
from pathlib import Path
from unittest.mock import Mock, patch


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
        if op_name == "fetch_rows":
            return {
                "type": "operator_result",
                "id": op_name,
                "result": {
                    "rows": [
                        {
                            "customer_id": "cust_public_1",
                            "status": "active",
                            "plan_tier": "pro",
                        }
                    ]
                },
            }
        return {"type": "operator_result", "id": op_name, "result": {}}

    def call_operator_batch(self, *, depth, calls):
        self.batch_calls.append((depth, calls))
        return [{"ok": True, "result": {}} for _ in calls]


class FakeRLM:
    init_kwargs = None
    last_prompt = None
    last_root_prompt = None

    def __init__(self, **kwargs):
        type(self).init_kwargs = kwargs

    def completion(self, prompt, root_prompt=None):
        type(self).last_prompt = prompt
        type(self).last_root_prompt = root_prompt
        fetch_rows = type(self).init_kwargs["custom_tools"]["fetch_rows"]["tool"]
        result = fetch_rows(
            view_id="safe_customer_view_public",
            filter_spec={"customer_id": "cust_public_1"},
            fields=["status", "plan_tier"],
        )
        return type("Completion", (), {"response": f"SUPPORTED: {result}"})()


def create_mock_lm(mod, responses, model_name="mock-openai"):
    mock = Mock()
    mock.model_name = model_name
    mock.completion.side_effect = list(responses)
    usage = mod.UsageSummary(
        model_usage_summaries={
            model_name: mod.ModelUsageSummary(
                total_calls=1,
                total_input_tokens=100,
                total_output_tokens=50,
            )
        }
    )
    mock.get_usage_summary.return_value = usage
    mock.get_last_usage.return_value = usage
    return mock


def default_start_message(query="smoke"):
    return {
        "type": "start",
        "protocol": {"min_version": 1, "max_version": 1},
        "query": query,
        "budget": {
            "max_operator_calls": 10,
            "max_bytes": 1024 * 1024,
            "max_wallclock_ms": 10_000,
            "max_recursion_depth": 4,
            "max_parallelism": 1,
        },
        "planner_hints": {"intent": "default", "recommended_path": []},
        "plan_request": {
            "schema_version": 1,
            "query": query,
            "budget": {
                "max_operator_calls": 10,
                "max_bytes": 1024 * 1024,
                "max_wallclock_ms": 10_000,
                "max_recursion_depth": 4,
                "max_parallelism": 1,
            },
            "planner_hints": {"intent": "default", "recommended_path": []},
            "recovery_context": None,
            "available_operator_names": ["fetch_rows", "search", "fetch_span"],
            "allow_search_ref_fetch_span": True,
        },
    }


def spawn_bridge_process(env):
    return subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "rlm" / "pecr_rlm_bridge.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )


class RlmBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.filterwarnings("ignore", category=ResourceWarning)
        cls.mod = load_module("pecr_rlm_bridge", "scripts/rlm/pecr_rlm_bridge.py")
        cls.mod.ensure_vendor_rlm_on_path()
        import rlm.core.rlm as rlm_module
        from rlm.core.types import ModelUsageSummary, UsageSummary

        cls.rlm_module = rlm_module
        cls.ModelUsageSummary = ModelUsageSummary
        cls.UsageSummary = UsageSummary

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

    def test_run_mock_prefers_structured_lookup_planner_hint(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=1,
        )

        result = self.mod.run_mock(
            bridge,
            "What is the customer status and plan tier?",
            budget,
            planner_hints={
                "intent": "structured_lookup",
                "recommended_path": [
                    {
                        "kind": "operator",
                        "op_name": "fetch_rows",
                        "params": {
                            "view_id": "safe_customer_view_public",
                            "fields": ["status", "plan_tier"],
                        },
                    }
                ],
            },
        )

        self.assertEqual(bridge.operator_calls, [(0, "fetch_rows", {
            "view_id": "safe_customer_view_public",
            "fields": ["status", "plan_tier"],
        })])
        self.assertEqual(result["operator_calls_used"], 1)
        self.assertEqual(result["depth_used"], 1)

    def test_run_mock_short_circuits_default_smoke_probe_even_with_recommended_path(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=2,
        )

        result = self.mod.run_mock(
            bridge,
            "smoke",
            budget,
            planner_hints={
                "intent": "default",
                "recommended_path": [
                    {
                        "kind": "operator",
                        "op_name": "fetch_rows",
                        "params": {
                            "view_id": "safe_customer_view_public",
                            "fields": ["status", "plan_tier"],
                        },
                    },
                    {
                        "kind": "operator",
                        "op_name": "search",
                        "params": {"query": "smoke", "limit": 5},
                    },
                ],
            },
        )

        self.assertEqual(bridge.operator_calls, [])
        self.assertEqual(bridge.batch_calls, [])
        self.assertEqual(result["operator_calls_used"], 0)
        self.assertEqual(result["depth_used"], 0)

    def test_run_mock_keeps_non_default_smoke_hint_on_normal_path(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=1,
        )

        result = self.mod.run_mock(
            bridge,
            "smoke",
            budget,
            planner_hints={
                "intent": "structured_lookup",
                "recommended_path": [
                    {
                        "kind": "operator",
                        "op_name": "fetch_rows",
                        "params": {
                            "view_id": "safe_customer_view_public",
                            "fields": ["status", "plan_tier"],
                        },
                    }
                ],
            },
        )

        self.assertEqual(bridge.operator_calls, [(0, "fetch_rows", {
            "view_id": "safe_customer_view_public",
            "fields": ["status", "plan_tier"],
        })])
        self.assertEqual(result["operator_calls_used"], 1)
        self.assertEqual(result["depth_used"], 1)

    def test_run_mock_prefers_evidence_lookup_planner_hint(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=2,
        )

        result = self.mod.run_mock(
            bridge,
            "Show the source text for the support policy",
            budget,
            planner_hints={
                "intent": "evidence_lookup",
                "recommended_path": [
                    {
                        "kind": "operator",
                        "op_name": "search",
                        "params": {"query": "Show the source text for the support policy", "limit": 5},
                    },
                    {"kind": "search_ref_fetch_span", "max_refs": 2},
                ],
            },
        )

        self.assertEqual(bridge.operator_calls, [(0, "search", {
            "query": "Show the source text for the support policy",
            "limit": 5,
        })])
        self.assertEqual(len(bridge.batch_calls), 1)
        self.assertEqual(len(bridge.batch_calls[0][1]), 2)
        self.assertEqual(result["operator_calls_used"], 3)

    def test_negotiate_protocol_version_accepts_default_legacy_message(self):
        version = self.mod.negotiate_protocol_version({"type": "start"})
        self.assertEqual(version, 1)

    def test_negotiate_protocol_version_accepts_supported_range(self):
        version = self.mod.negotiate_protocol_version(
            {"type": "start", "protocol": {"min_version": 1, "max_version": 1}}
        )
        self.assertEqual(version, 1)

    def test_negotiate_protocol_version_rejects_unsupported_range(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.negotiate_protocol_version(
                {"type": "start", "protocol": {"min_version": 2, "max_version": 3}}
            )
        self.assertIn("unsupported bridge protocol range", str(ctx.exception))

    def test_build_openai_backend_kwargs_requires_model_name(self):
        old_model = os.environ.pop("PECR_RLM_MODEL_NAME", None)
        old_api_key = os.environ.pop("PECR_RLM_API_KEY", None)
        old_openai_api_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            with self.assertRaises(ValueError) as ctx:
                self.mod.build_openai_backend_kwargs()
            self.assertIn("PECR_RLM_MODEL_NAME", str(ctx.exception))
        finally:
            if old_model is not None:
                os.environ["PECR_RLM_MODEL_NAME"] = old_model
            if old_api_key is not None:
                os.environ["PECR_RLM_API_KEY"] = old_api_key
            if old_openai_api_key is not None:
                os.environ["OPENAI_API_KEY"] = old_openai_api_key

    def test_build_openai_backend_kwargs_uses_optional_overrides(self):
        old_model = os.environ.get("PECR_RLM_MODEL_NAME")
        old_base_url = os.environ.get("PECR_RLM_BASE_URL")
        old_api_key = os.environ.get("PECR_RLM_API_KEY")
        try:
            os.environ["PECR_RLM_MODEL_NAME"] = "gpt-test"
            os.environ["PECR_RLM_BASE_URL"] = "https://example.test/v1"
            os.environ["PECR_RLM_API_KEY"] = "secret"
            kwargs = self.mod.build_openai_backend_kwargs()
            self.assertEqual(kwargs["model_name"], "gpt-test")
            self.assertEqual(kwargs["base_url"], "https://example.test/v1")
            self.assertEqual(kwargs["api_key"], "secret")
        finally:
            if old_model is None:
                os.environ.pop("PECR_RLM_MODEL_NAME", None)
            else:
                os.environ["PECR_RLM_MODEL_NAME"] = old_model
            if old_base_url is None:
                os.environ.pop("PECR_RLM_BASE_URL", None)
            else:
                os.environ["PECR_RLM_BASE_URL"] = old_base_url
            if old_api_key is None:
                os.environ.pop("PECR_RLM_API_KEY", None)
            else:
                os.environ["PECR_RLM_API_KEY"] = old_api_key

    def test_build_openai_backend_kwargs_requires_api_key(self):
        old_model = os.environ.get("PECR_RLM_MODEL_NAME")
        old_api_key = os.environ.pop("PECR_RLM_API_KEY", None)
        old_openai_api_key = os.environ.pop("OPENAI_API_KEY", None)
        try:
            os.environ["PECR_RLM_MODEL_NAME"] = "gpt-test"
            with self.assertRaises(ValueError) as ctx:
                self.mod.build_openai_backend_kwargs()
            self.assertIn("OPENAI_API_KEY or PECR_RLM_API_KEY", str(ctx.exception))
        finally:
            if old_model is None:
                os.environ.pop("PECR_RLM_MODEL_NAME", None)
            else:
                os.environ["PECR_RLM_MODEL_NAME"] = old_model
            if old_api_key is not None:
                os.environ["PECR_RLM_API_KEY"] = old_api_key
            if old_openai_api_key is not None:
                os.environ["OPENAI_API_KEY"] = old_openai_api_key

    def test_run_openai_uses_controller_backed_operator_tools(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=1,
        )
        old_model = os.environ.get("PECR_RLM_MODEL_NAME")
        old_api_key = os.environ.get("PECR_RLM_API_KEY")
        old_loader = self.mod.load_rlm_class
        try:
            os.environ["PECR_RLM_MODEL_NAME"] = "gpt-test"
            os.environ["PECR_RLM_API_KEY"] = "secret"
            self.mod.load_rlm_class = lambda: FakeRLM
            result = self.mod.run_openai(
                bridge,
                "What is the customer status and plan tier?",
                budget,
                planner_hints={"intent": "structured_lookup"},
                plan_request={
                    "available_operator_names": ["fetch_rows", "search"],
                },
            )
        finally:
            self.mod.load_rlm_class = old_loader
            if old_model is None:
                os.environ.pop("PECR_RLM_MODEL_NAME", None)
            else:
                os.environ["PECR_RLM_MODEL_NAME"] = old_model
            if old_api_key is None:
                os.environ.pop("PECR_RLM_API_KEY", None)
            else:
                os.environ["PECR_RLM_API_KEY"] = old_api_key

        self.assertEqual(
            bridge.operator_calls,
            [
                (
                    0,
                    "fetch_rows",
                    {
                        "view_id": "safe_customer_view_public",
                        "filter_spec": {"customer_id": "cust_public_1"},
                        "fields": ["status", "plan_tier"],
                    },
                )
            ],
        )
        self.assertEqual(result["operator_calls_used"], 1)
        self.assertEqual(result["depth_used"], 1)
        self.assertEqual(FakeRLM.last_root_prompt, "What is the customer status and plan tier?")
        self.assertIn("available_operator_names", FakeRLM.last_prompt)
        self.assertEqual(FakeRLM.init_kwargs["backend"], "openai")
        self.assertEqual(FakeRLM.init_kwargs["backend_kwargs"]["model_name"], "gpt-test")

    def test_run_openai_exercises_actual_vendored_rlm_loop_with_mock_client(self):
        bridge = FakeBridge()
        budget = self.mod.Budget(
            max_operator_calls=10,
            max_bytes=1024 * 1024,
            max_wallclock_ms=10_000,
            max_recursion_depth=5,
            max_parallelism=1,
        )
        old_model = os.environ.get("PECR_RLM_MODEL_NAME")
        old_api_key = os.environ.get("PECR_RLM_API_KEY")
        responses = [
            "\n".join(
                [
                    "Let me inspect the customer row first.",
                    "```repl",
                    "result = fetch_rows(view_id='safe_customer_view_public', filter_spec={'customer_id': 'cust_public_1'}, fields=['status', 'plan_tier'])",
                    "answer = f\"SUPPORTED: {result['rows'][0]['status']} / {result['rows'][0]['plan_tier']}\"",
                    "print(answer)",
                    "```",
                ]
            ),
            "FINAL_VAR(answer)",
        ]
        try:
            os.environ["PECR_RLM_MODEL_NAME"] = "gpt-test"
            os.environ["PECR_RLM_API_KEY"] = "secret"
            with patch.object(self.rlm_module, "get_client") as mock_get_client:
                mock_get_client.return_value = create_mock_lm(self, responses)
                result = self.mod.run_openai(
                    bridge,
                    "What is the customer status and plan tier?",
                    budget,
                    planner_hints={"intent": "structured_lookup"},
                    plan_request={
                        "available_operator_names": ["fetch_rows"],
                    },
                )
        finally:
            if old_model is None:
                os.environ.pop("PECR_RLM_MODEL_NAME", None)
            else:
                os.environ["PECR_RLM_MODEL_NAME"] = old_model
            if old_api_key is None:
                os.environ.pop("PECR_RLM_API_KEY", None)
            else:
                os.environ["PECR_RLM_API_KEY"] = old_api_key

        self.assertEqual(
            bridge.operator_calls,
            [
                (
                    0,
                    "fetch_rows",
                    {
                        "view_id": "safe_customer_view_public",
                        "filter_spec": {"customer_id": "cust_public_1"},
                        "fields": ["status", "plan_tier"],
                    },
                )
            ],
        )
        self.assertEqual(result["final_answer"], "SUPPORTED: active / pro")
        self.assertEqual(result["operator_calls_used"], 1)
        self.assertEqual(result["depth_used"], 1)

    def test_bridge_main_reuses_one_process_for_multiple_start_messages(self):
        env = os.environ.copy()
        env["PECR_RLM_BACKEND"] = "mock"

        proc = spawn_bridge_process(env)
        try:
            assert proc.stdin is not None
            assert proc.stdout is not None

            for _ in range(2):
                proc.stdin.write(json.dumps(default_start_message("smoke")) + "\n")
                proc.stdin.flush()
                start_ack = json.loads(proc.stdout.readline())
                done = json.loads(proc.stdout.readline())
                self.assertEqual(start_ack["type"], "start_ack")
                self.assertEqual(start_ack["protocol_version"], 1)
                self.assertEqual(start_ack["session_mode"], "persistent_worker")
                self.assertEqual(done["type"], "done")
                self.assertEqual(
                    done["final_answer"],
                    "UNKNOWN: insufficient evidence to answer the query.",
                )

            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=5), 0)
        finally:
            proc.kill()

    def test_bridge_main_emits_structured_error_for_openai_config_gap(self):
        env = os.environ.copy()
        env["PECR_RLM_BACKEND"] = "openai"
        env.pop("PECR_RLM_MODEL_NAME", None)
        env.pop("PECR_RLM_API_KEY", None)
        env.pop("OPENAI_API_KEY", None)

        proc = spawn_bridge_process(env)
        try:
            assert proc.stdin is not None
            assert proc.stdout is not None

            proc.stdin.write(json.dumps(default_start_message("What is the customer status?")) + "\n")
            proc.stdin.flush()

            start_ack = json.loads(proc.stdout.readline())
            err = json.loads(proc.stdout.readline())
            self.assertEqual(start_ack["type"], "start_ack")
            self.assertEqual(err["type"], "error")
            self.assertEqual(err["reason"], "bridge_invalid_request")
            self.assertEqual(err["code"], "ERR_RLM_BRIDGE_PROTOCOL")
            self.assertIn("PECR_RLM_MODEL_NAME", err["message"])

            proc.stdin.close()
            self.assertEqual(proc.wait(timeout=5), 0)
        finally:
            proc.kill()


if __name__ == "__main__":
    unittest.main()
