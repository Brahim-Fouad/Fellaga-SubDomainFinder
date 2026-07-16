from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS))

from redact import environment_secrets, redact_path, redact_text


class RedactionTests(unittest.TestCase):
    def test_environment_secrets_include_full_and_composite_values(self) -> None:
        secrets = environment_secrets(
            {
                "SERVICE_API_KEY": "alpha:bravo",
                "ACCOUNT_SECRET": "charlie",
                "CENSYS_API_ID": "censys-identifier",
                "NORMAL_SETTING": "visible",
                "TINY_TOKEN": "abc",
            }
        )
        self.assertIn("alpha:bravo", secrets)
        self.assertIn("alpha", secrets)
        self.assertIn("bravo", secrets)
        self.assertIn("charlie", secrets)
        self.assertIn("censys-identifier", secrets)
        self.assertNotIn("visible", secrets)
        self.assertNotIn("abc", secrets)

    def test_longest_values_are_redacted_first(self) -> None:
        self.assertEqual(
            redact_text("token alpha:bravo alpha", ["alpha:bravo", "alpha"]),
            "token [REDACTED] [REDACTED]",
        )

    def test_directory_redaction_skips_binary_capture_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            text = root / "tool.stderr"
            capture = root / "traffic.pcapng"
            text.write_text("credential censys-identifier", encoding="utf-8")
            capture.write_bytes(b"\x00censys-identifier")
            redact_path(root, ["censys-identifier"])
            self.assertEqual(text.read_text(encoding="utf-8"), "credential [REDACTED]")
            self.assertEqual(capture.read_bytes(), b"\x00censys-identifier")


if __name__ == "__main__":
    unittest.main()
