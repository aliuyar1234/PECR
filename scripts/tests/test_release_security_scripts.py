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


class ReleaseSmokeCheckParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module(
            "release_smoke_check",
            "scripts/security/release_smoke_check.py",
        )

    def test_parse_tarball_filenames_reads_checksums_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            checksums = Path(tmp_dir) / "SHA256SUMS.txt"
            checksums.write_text(
                "abc123  pecr-gateway_v1.0.0_linux_amd64.tar.gz\n"
                "def456 *pecr-controller_v1.0.0_linux_amd64.tar.gz\n",
                encoding="utf-8",
            )
            names = self.mod.parse_tarball_filenames(checksums)
            self.assertEqual(
                names,
                [
                    "pecr-gateway_v1.0.0_linux_amd64.tar.gz",
                    "pecr-controller_v1.0.0_linux_amd64.tar.gz",
                ],
            )

    def test_parse_tarball_filenames_rejects_invalid_line(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            checksums = Path(tmp_dir) / "SHA256SUMS.txt"
            checksums.write_text("invalid-line-without-space\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.mod.parse_tarball_filenames(checksums)

    def test_parse_image_refs_requires_digest_pinned_gateway_and_controller(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = Path(tmp_dir) / "image-digests.txt"
            manifest.write_text(
                "tag=v1.0.0\n"
                "gateway=ghcr.io/example/pecr-gateway@sha256:"
                + ("a" * 64)
                + "\n"
                "controller=ghcr.io/example/pecr-controller@sha256:"
                + ("b" * 64)
                + "\n",
                encoding="utf-8",
            )
            refs = self.mod.parse_image_refs(manifest)
            self.assertEqual(len(refs), 2)
            self.assertIn("ghcr.io/example/pecr-gateway@sha256:" + ("a" * 64), refs)
            self.assertIn("ghcr.io/example/pecr-controller@sha256:" + ("b" * 64), refs)

    def test_parse_image_refs_rejects_missing_controller_entry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = Path(tmp_dir) / "image-digests.txt"
            manifest.write_text(
                "gateway=ghcr.io/example/pecr-gateway@sha256:" + ("a" * 64) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                self.mod.parse_image_refs(manifest)


class VerifyReleaseAttestationsParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module(
            "verify_release_attestations",
            "scripts/security/verify_release_attestations.py",
        )

    def test_parse_image_refs_rejects_non_digest_reference(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = Path(tmp_dir) / "image-digests.txt"
            manifest.write_text(
                "gateway=ghcr.io/example/pecr-gateway:latest\n"
                "controller=ghcr.io/example/pecr-controller@sha256:"
                + ("b" * 64)
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                self.mod.parse_image_refs(manifest)

    def test_parse_image_refs_rejects_invalid_entry_format(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest = Path(tmp_dir) / "image-digests.txt"
            manifest.write_text(
                "gateway=ghcr.io/example/pecr-gateway@sha256:" + ("a" * 64) + "\n"
                "controller ghcr.io/example/pecr-controller@sha256:" + ("b" * 64) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                self.mod.parse_image_refs(manifest)


if __name__ == "__main__":
    unittest.main()
