import importlib.util
import sys
import tempfile
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


class ContractLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check_lock = load_module(
            "check_contract_lock", "scripts/contracts/check_contract_lock.py"
        )
        cls.update_lock = load_module(
            "update_contract_lock", "scripts/contracts/update_contract_lock.py"
        )

    def test_sha256_file_normalizes_text_line_endings(self):
        with tempfile.TemporaryDirectory(prefix="pecr-contract-lock-") as tmp_dir:
            temp_path = Path(tmp_dir)
            lf_path = temp_path / "sample.json"
            crlf_path = temp_path / "sample-crlf.json"

            lf_path.write_bytes(b'{\n  "hello": "world"\n}\n')
            crlf_path.write_bytes(b'{\r\n  "hello": "world"\r\n}\r\n')

            self.assertEqual(
                self.check_lock.sha256_file(lf_path),
                self.check_lock.sha256_file(crlf_path),
            )
            self.assertEqual(
                self.update_lock.sha256_file(lf_path),
                self.update_lock.sha256_file(crlf_path),
            )
            self.assertEqual(
                self.check_lock.sha256_file(lf_path),
                self.update_lock.sha256_file(lf_path),
            )
