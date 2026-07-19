from __future__ import annotations

import pathlib
import os
import sys
import tempfile
import unittest
from unittest import mock


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

    def test_streaming_redaction_handles_a_chunk_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "large.log"
            secret = "boundary-secret"
            prefix = "x" * (1024 * 1024 - 4)
            path.write_text(prefix + secret + " tail", encoding="utf-8")
            redact_path(path, [secret])
            payload = path.read_text(encoding="utf-8")
        self.assertNotIn(secret, payload)
        self.assertTrue(payload.endswith("[REDACTED] tail"))

    def test_source_is_closed_before_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "tool.stderr"
            path.write_text("credential boundary-secret", encoding="utf-8")
            source_handles = []
            original_open = pathlib.Path.open
            original_replace = os.replace

            def tracked_open(candidate, *args, **kwargs):
                handle = original_open(candidate, *args, **kwargs)
                if candidate == path and args and args[0] == "rb":
                    source_handles.append(handle)
                return handle

            def checked_replace(source, destination):
                self.assertTrue(source_handles)
                self.assertTrue(source_handles[0].closed)
                original_replace(source, destination)

            with mock.patch.object(pathlib.Path, "open", tracked_open), mock.patch(
                "redact.os.replace", checked_replace
            ):
                redact_path(path, ["boundary-secret"])

            self.assertEqual(
                path.read_text(encoding="utf-8"), "credential [REDACTED]"
            )

    @unittest.skipIf(os.name == "nt", "symbolic-link permissions vary on Windows")
    def test_directory_redaction_never_follows_a_symbolic_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = pathlib.Path(directory)
            target = pathlib.Path(outside) / "outside.txt"
            target.write_text("boundary-secret", encoding="utf-8")
            (root / "linked.txt").symlink_to(target)
            redact_path(root, ["boundary-secret"])
            self.assertEqual(target.read_text(encoding="utf-8"), "boundary-secret")


if __name__ == "__main__":
    unittest.main()
