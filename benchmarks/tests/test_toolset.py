from __future__ import annotations

import copy
import json
import pathlib
import sys
import tempfile
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS))

from toolset import (  # noqa: E402
    ToolsetError,
    capture_identity,
    load_toolset,
    normalized_snapshot,
    render_argv,
    render_output,
    snapshot_hash,
)


EXAMPLE = BENCHMARKS / "toolset.example.json"


class ToolsetTests(unittest.TestCase):
    def test_example_is_strict_normalized_and_hash_stable(self) -> None:
        toolset = load_toolset(EXAMPLE)
        snapshot = normalized_snapshot(toolset)

        self.assertEqual(snapshot["subject"], "subject_cli")
        self.assertIn("active", snapshot["campaigns"])
        self.assertIn("passive-observational", snapshot["campaigns"])
        self.assertEqual(snapshot_hash(snapshot), snapshot_hash(toolset))
        self.assertEqual(len(snapshot_hash(snapshot)), 64)

    def test_rendering_is_argv_only_and_rejects_unknown_context(self) -> None:
        toolset = load_toolset(EXAMPLE)
        context = {
            "executable": "/tmp/alternate-cli",
            "domain": "example.test",
            "output_file": "/tmp/names.txt",
        }
        argv = render_argv(toolset, "alternate_cli", "active", context)
        self.assertEqual(
            argv,
            [
                "/tmp/alternate-cli",
                "--target",
                "example.test",
                "--output",
                "/tmp/names.txt",
            ],
        )
        self.assertEqual(
            render_output(toolset, "alternate_cli", "active", context),
            {"kind": "line_file", "path": "/tmp/names.txt"},
        )
        with self.assertRaises(ToolsetError):
            render_argv(
                toolset,
                "alternate_cli",
                "active",
                {**context, "undeclared": "value"},
            )

    def test_output_paths_are_rendered_without_shell_interpretation(self) -> None:
        toolset = load_toolset(EXAMPLE)
        context = {
            "executable": "/tmp/validation-cli",
            "domain": "example.test",
            "input_file": "/tmp/corpus words.txt",
            "output_dir": "/tmp/result $(ignored)",
            "resolvers_file": "/tmp/resolvers.txt",
        }
        context.pop("domain")
        output = render_output(toolset, "validation_cli", "validate", context)
        argv = render_argv(toolset, "validation_cli", "validate", context)

        self.assertEqual(output["path"], context["output_dir"])
        self.assertIn(context["output_dir"], argv)
        self.assertNotIn("sh", argv)

    def test_duplicate_json_keys_and_unsafe_placeholders_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = pathlib.Path(directory) / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1}', encoding="utf-8"
            )
            with self.assertRaises(ToolsetError):
                load_toolset(duplicate)

            invalid = copy.deepcopy(load_toolset(EXAMPLE))
            invalid["tools"]["alternate_cli"]["commands"]["active"]["argv"].append(
                "{domain.__class__}"
            )
            path = pathlib.Path(directory) / "invalid.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(ToolsetError):
                load_toolset(path)

    def test_identity_uses_the_configured_executable_without_a_shell(self) -> None:
        toolset = copy.deepcopy(load_toolset(EXAMPLE))
        toolset["tools"]["validation_cli"]["executable"] = sys.executable
        identity = capture_identity(toolset, "validation_cli")

        self.assertEqual(identity["version_probe_status"], "success")
        self.assertEqual(len(identity["sha256"]), 64)
        self.assertTrue(identity["version"])


if __name__ == "__main__":
    unittest.main()
