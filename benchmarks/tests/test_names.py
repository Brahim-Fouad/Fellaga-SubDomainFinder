from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS))

import names as benchmark_names
from names import NameError, normalize_domain, normalize_fqdn, read_name_file


class NameNormalizationTests(unittest.TestCase):
    def test_domain_is_canonicalized(self) -> None:
        self.assertEqual(normalize_domain(" EXAMPLE.COM. "), "example.com")
        self.assertEqual(normalize_domain("täst.example"), "xn--tst-qla.example")

    def test_domain_rejects_shell_text_and_invalid_labels(self) -> None:
        for value in ("example.com;id", "$(id).example.com", "-bad.example", "localhost"):
            with self.subTest(value=value), self.assertRaises(NameError):
                normalize_domain(value)

    def test_fqdn_enforces_a_label_boundary_and_strips_wildcard(self) -> None:
        self.assertEqual(
            normalize_fqdn("*.API.Example.COM.", "example.com"),
            "api.example.com",
        )
        for value in ("example.com", "notexample.com", "api.example.com.evil.test"):
            with self.subTest(value=value), self.assertRaises(NameError):
                normalize_fqdn(value, "example.com")

    def test_name_file_filters_off_scope_and_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "names.txt"
            path.write_text(
                "api.example.com\n*.cdn.example.com.\nexample.com\nevil.test\napi.example.com extra\n",
                encoding="utf-8",
            )
            names, rejected = read_name_file(path, "example.com")
        self.assertEqual(names, {"api.example.com", "cdn.example.com"})
        self.assertEqual(rejected, 2)

    def test_normalize_cli_preserves_valid_names_but_fails_on_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "names.txt"
            path.write_text(
                "api.example.com\noffscope.test\napi.example.com extra\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "names.py"),
                    "normalize",
                    "example.com",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stdout, "api.example.com\n")
        self.assertIn("rejected 2", completed.stderr)

    def test_observational_normalizer_excludes_wildcard_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "names.txt"
            path.write_text(
                "api.example.com\n*.cdn.example.com\n*.example.com\n"
                "offscope.test\napi.example.com extra\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "names.py"),
                    "normalize-observational",
                    "example.com",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "api.example.com\n")
        self.assertIn("excluded_wildcards=2", completed.stderr)
        self.assertIn("excluded_invalid_or_out_of_scope=2", completed.stderr)

    def test_observational_name_limit_is_fatal_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "names.txt"
            path.write_text(
                "a.example.com\nb.example.com\nc.example.com\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(benchmark_names, "MAX_OBSERVATIONAL_NAMES", 2),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = benchmark_names.main(
                    ["normalize-observational", "example.com", str(path)]
                )

        self.assertEqual(result, 4)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("exceeds 2 unique names", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_observational_name_limit_applies_across_input_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
            second.write_text("c.example.com\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(benchmark_names, "MAX_OBSERVATIONAL_NAMES", 2),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = benchmark_names.main(
                    [
                        "normalize-observational",
                        "example.com",
                        str(first),
                        str(second),
                    ]
                )

        self.assertEqual(result, 4)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("exceeds 2 unique names", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_bbot_observational_parser_counts_exclusions_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "output.json").write_text(
                "\n".join(
                    [
                        json.dumps({"type": "DNS_NAME", "data": "api.example.com"}),
                        json.dumps({"type": "DNS_NAME", "data": "*.cdn.example.com"}),
                        json.dumps({"type": "DNS_NAME", "data": "offscope.test"}),
                        json.dumps({"type": "DNS_NAME", "data": 7}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "names.py"),
                    "bbot-observational",
                    "example.com",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "api.example.com\n")
        self.assertIn("excluded_wildcards=1", completed.stderr)
        self.assertIn("excluded_invalid_or_out_of_scope=2", completed.stderr)

    def test_bbot_observational_name_limit_is_fatal_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "output.json").write_text(
                "\n".join(
                    json.dumps(
                        {"type": "DNS_NAME", "data": f"{label}.example.com"}
                    )
                    for label in ("a", "b", "c")
                )
                + "\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(benchmark_names, "MAX_OBSERVATIONAL_NAMES", 2),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = benchmark_names.main(
                    ["bbot-observational", "example.com", str(root)]
                )

        self.assertEqual(result, 4)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("exceeds 2 unique names", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_fellaga_parser_fails_closed_on_malformed_and_off_scope_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "fellaga.json"
            metadata = root / "metadata.json"
            source.write_text(
                json.dumps(
                    {
                        "findings": [
                            {"fqdn": "api.example.com", "state": "live"},
                            {"fqdn": "offscope.test", "state": "live"},
                            {"fqdn": 7, "state": "live"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "names.py"),
                    "fellaga",
                    "example.com",
                    str(source),
                    "--metadata",
                    str(metadata),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            metadata_value = json.loads(metadata.read_text(encoding="utf-8"))
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stdout, "api.example.com\n")
        self.assertEqual(metadata_value["rejected_names"], 2)

    def test_bbot_parser_fails_closed_on_invalid_dns_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "output.json").write_text(
                "\n".join(
                    [
                        json.dumps({"type": "DNS_NAME", "data": "api.example.com"}),
                        json.dumps({"type": "DNS_NAME", "data": "example.com"}),
                        json.dumps({"type": "DNS_NAME", "data": "offscope.test"}),
                        json.dumps({"type": "DNS_NAME", "data": 7}),
                        json.dumps({"type": "IP_ADDRESS", "data": "192.0.2.1"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "names.py"),
                    "bbot",
                    "example.com",
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(completed.stdout, "api.example.com\n")
        self.assertIn("rejected 2", completed.stderr)


if __name__ == "__main__":
    unittest.main()
