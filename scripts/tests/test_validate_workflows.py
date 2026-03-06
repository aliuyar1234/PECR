import importlib.util
import sys
import tempfile
import textwrap
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


class WorkflowValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module("validate_workflows", "scripts/validate_workflows.py")

    def test_validate_uses_value_accepts_pinned_and_local_refs(self):
        self.assertIsNone(
            self.mod.validate_uses_value("actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5")
        )
        self.assertIsNone(self.mod.validate_uses_value("./.github/workflows/reusable.yml"))
        self.assertIsNone(self.mod.validate_uses_value("docker://alpine:3.20"))

    def test_validate_uses_value_rejects_floating_refs(self):
        error = self.mod.validate_uses_value("actions/checkout@v4")
        self.assertIsNotNone(error)
        self.assertIn("40-character commit SHA", error)

    def test_validate_workflow_file_reports_invalid_uses_entries(self):
        with tempfile.TemporaryDirectory(prefix="pecr-workflow-test-") as temp_dir:
            root = Path(temp_dir)
            workflow = root / "ci.yml"
            workflow.write_text(
                textwrap.dedent(
                    """
                    name: ci
                    jobs:
                      test:
                        runs-on: ubuntu-latest
                        steps:
                          - uses: actions/checkout@v4
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            errors = self.mod.validate_workflow_file(workflow)
            self.assertEqual(len(errors), 1)
            self.assertIn("actions/checkout@v4", errors[0])

    def test_validate_workflow_tree_accepts_valid_workflows(self):
        with tempfile.TemporaryDirectory(prefix="pecr-workflow-tree-") as temp_dir:
            root = Path(temp_dir)
            (root / "ci.yml").write_text(
                textwrap.dedent(
                    """
                    name: ci
                    jobs:
                      test:
                        uses: owner/repo/.github/workflows/reusable.yml@34e114876b0b11c390a56381ad16ebd13914f8d5
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            errors = self.mod.validate_workflow_tree(root)
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
