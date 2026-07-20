import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / "check_release_consistency.py"
SPEC = importlib.util.spec_from_file_location("check_release_consistency", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseConsistencyTests(unittest.TestCase):
    def test_current_repository_is_consistent(self):
        root = Path(__file__).parents[2]
        self.assertEqual(MODULE.check_repository(root), [])

    def test_parses_only_the_closed_final_asset_array(self):
        workflow = """
          expected=(
            "one"
            "two"
          )
        """
        self.assertEqual(MODULE.shell_array(workflow, "expected"), {"one", "two"})

    def test_missing_documented_token_is_reported(self):
        self.assertEqual(
            MODULE.require_tokens("README.md", "release v1.0.0", ["v1.0.1"]),
            ["README.md: missing 'v1.0.1'"],
        )

    def test_forbidden_token_is_reported(self):
        self.assertEqual(
            MODULE.forbid_tokens("workflow", 'curl > "response.json"', ['> "response.json"']),
            ['workflow: forbidden \'> "response.json"\''],
        )

    def test_unexpected_occurrence_count_is_reported(self):
        self.assertEqual(
            MODULE.require_occurrences("workflow", "upload upload", "upload", 1),
            ["workflow: expected 1 occurrences of 'upload', found 2"],
        )


if __name__ == "__main__":
    unittest.main()
