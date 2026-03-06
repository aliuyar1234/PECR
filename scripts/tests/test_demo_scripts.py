import argparse
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str((ROOT / "scripts" / "demo").resolve()))

import useful_workflows  # noqa: E402


class DemoScriptTests(unittest.TestCase):
    def test_default_local_auth_secret_uses_demo_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                useful_workflows.default_local_auth_secret(),
                "pecr-local-demo-secret",
            )

    def test_build_live_run_request_uses_expected_headers(self):
        request = useful_workflows.build_live_run_request(
            controller_url="http://127.0.0.1:8081",
            principal_id="dev",
            local_auth_secret="demo-secret",
            query="What is the customer status and plan tier?",
        )

        self.assertEqual(request.full_url, "http://127.0.0.1:8081/v1/run")
        self.assertEqual(request.get_method(), "POST")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["query"], "What is the customer status and plan tier?")

        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["x-pecr-principal-id"], "dev")
        self.assertEqual(headers["x-pecr-local-auth-secret"], "demo-secret")
        self.assertIn("x-pecr-request-id", headers)
        self.assertIn("x-pecr-trace-id", headers)

    def test_build_live_capabilities_request_uses_expected_headers(self):
        request = useful_workflows.build_live_capabilities_request(
            controller_url="http://127.0.0.1:8081",
            principal_id="dev",
            local_auth_secret="demo-secret",
        )

        self.assertEqual(request.full_url, "http://127.0.0.1:8081/v1/capabilities")
        self.assertEqual(request.get_method(), "GET")
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(headers["x-pecr-principal-id"], "dev")
        self.assertEqual(headers["x-pecr-local-auth-secret"], "demo-secret")
        self.assertIn("x-pecr-request-id", headers)
        self.assertIn("x-pecr-trace-id", headers)

    def test_live_scenario_prints_live_response_summary(self):
        args = argparse.Namespace(
            scenario_id="customer-status",
            controller_url="http://127.0.0.1:8081",
            principal_id="dev",
            local_auth_secret="demo-secret",
            timeout_secs=5.0,
        )
        with mock.patch.object(
            useful_workflows,
            "invoke_live_run",
            return_value={
                "terminal_mode": "SUPPORTED",
                "response_kind": None,
                "response_text": "SUPPORTED: customer is active on starter.",
                "claim_map": {"claims": [{"claim_text": "customer is active"}]},
            },
        ):
            buffer = io.StringIO()
            with mock.patch("sys.stdout", buffer):
                exit_code = useful_workflows.cmd_live_scenario(args)

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["scenario_id"], "customer-status")
        self.assertEqual(payload["terminal_mode"], "SUPPORTED")
        self.assertEqual(payload["claim_count"], 1)

    def test_live_tour_prints_json_summary(self):
        args = argparse.Namespace(
            controller_url="http://127.0.0.1:8081",
            principal_id="dev",
            local_auth_secret="demo-secret",
            timeout_secs=5.0,
            wait_secs=30.0,
            format="json",
            scenario_ids=["customer-status", "broad-customer-query"],
        )
        with mock.patch.object(
            useful_workflows,
            "wait_for_live_capabilities",
            return_value={
                "capabilities": [
                    {
                        "title": "Look up customer fields",
                        "examples": ["What is the customer status and plan tier?"],
                    }
                ],
                "suggested_queries": ["What is the customer status and plan tier?"],
            },
        ), mock.patch.object(
            useful_workflows,
            "invoke_live_run",
            side_effect=[
                {
                    "terminal_mode": "SUPPORTED",
                    "response_kind": None,
                    "response_text": "SUPPORTED: customer is active on starter.",
                    "claim_map": {"claims": [{"claim_text": "customer is active"}]},
                },
                {
                    "terminal_mode": "INSUFFICIENT_EVIDENCE",
                    "response_kind": "ambiguous",
                    "response_text": "UNKNOWN: narrow the customer query.",
                    "claim_map": {"claims": []},
                },
            ],
        ):
            buffer = io.StringIO()
            with mock.patch("sys.stdout", buffer):
                exit_code = useful_workflows.cmd_live_tour(args)

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["tour_mode"], "live")
        self.assertEqual(payload["scenario_count"], 2)
        self.assertEqual(payload["capability_summary"]["capability_count"], 1)
        self.assertEqual(payload["results"][0]["scenario_id"], "customer-status")
        self.assertEqual(payload["results"][1]["response_kind"], "ambiguous")

    def test_tour_renders_pretty_summary(self):
        args = argparse.Namespace(
            format="pretty",
            scenario_ids=["customer-status", "partial-billing-answer"],
        )
        buffer = io.StringIO()
        with mock.patch("sys.stdout", buffer):
            exit_code = useful_workflows.cmd_tour(args)

        self.assertEqual(exit_code, 0)
        output = buffer.getvalue()
        self.assertIn("PECR Product Tour", output)
        self.assertIn("Customer status and plan lookup", output)
        self.assertIn("Partial billing answer with unresolved remainder", output)
        self.assertIn("Takeaways", output)


if __name__ == "__main__":
    unittest.main()
