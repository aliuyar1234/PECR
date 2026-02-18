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


class SyncVendorRlmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sync_mod = load_module("sync_vendor_rlm", "scripts/rlm/sync_vendor_rlm.py")
        cls.verify_mod = load_module("verify_vendor_rlm", "scripts/rlm/verify_vendor_rlm.py")

    def test_parse_ls_remote_output_extracts_commit(self):
        commit = "76abb9c93ae314db96bae411bf4cd88a17349aad"
        raw = f"{commit}\trefs/heads/main\n"
        self.assertEqual(self.sync_mod.parse_ls_remote_output(raw), commit)

    def test_parse_ls_remote_output_rejects_invalid_line(self):
        with self.assertRaises(SystemExit) as ctx:
            self.sync_mod.parse_ls_remote_output("not-a-sha refs/heads/main\n")
        self.assertIn("unexpected git ls-remote output line", str(ctx.exception))

    def test_update_decisions_pin_text_rewrites_commit(self):
        old_commit = "37f6d0b26b9661ebb7d6f333740a354fc030e6c4"
        new_commit = "76abb9c93ae314db96bae411bf4cd88a17349aad"
        text = (
            "# Header\n"
            f"- Vendored upstream `alexzhang13/rlm` at commit `{old_commit}` into `vendor/rlm`.\n"
        )
        updated = self.sync_mod.update_decisions_pin_text(text, new_commit)
        self.assertIn(new_commit, updated)
        self.assertNotIn(old_commit, updated)

    def test_parse_pinned_commit_extracts_commit(self):
        commit = "76abb9c93ae314db96bae411bf4cd88a17349aad"
        text = (
            "## D-0001\n"
            f"- Vendored upstream `alexzhang13/rlm` at commit `{commit}` into `vendor/rlm`.\n"
        )
        self.assertEqual(self.verify_mod.parse_pinned_commit(text), commit)

    def test_collect_missing_paths_reports_missing(self):
        present = ROOT / "README.md"
        missing = ROOT / "this_path_should_not_exist_12345.txt"
        result = self.verify_mod.collect_missing_paths([present, missing])
        self.assertEqual(result, [missing])


if __name__ == "__main__":
    unittest.main()
