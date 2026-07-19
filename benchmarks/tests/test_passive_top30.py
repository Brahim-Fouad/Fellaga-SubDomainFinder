from __future__ import annotations

import json
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
RUNNER = BENCHMARKS / "run-passive-top30.sh"
REPORT = BENCHMARKS / "passive_top30_report.py"
SOURCE_MANIFEST = BENCHMARKS / "data" / "tranco-74J5X-top30.json"
sys.path.insert(0, str(BENCHMARKS))

from passive_top30_report import (  # noqa: E402
    _no_key_environment,
    build_report,
    enforce_campaign_quota,
    prepare_campaign,
    record_run,
    validate_source_manifest,
    verify_campaign_tool,
    write_tree_manifest,
)
from toolset import load_toolset, normalized_snapshot, snapshot_hash  # noqa: E402


PASSIVE_POLICY = {
    "target_contact": "prohibited",
    "direct_dns": False,
    "direct_http_or_tls": False,
}


def tool_definition(
    executable: pathlib.Path,
    *,
    preflight: bool = False,
    output_kind: str = "line_stdout",
) -> dict[str, object]:
    required_context = ["domain"]
    output: dict[str, object] = {"kind": output_kind}
    argv = ["{executable}", "{domain}"]
    if output_kind in {"line_file", "finding_json"}:
        required_context.append("output_file")
        output["path"] = "{output_file}"
        argv.extend(["{output_file}"])
    elif output_kind == "dns_event_tree":
        required_context.append("output_directory")
        output["path"] = "{output_directory}"
        argv.extend(["{output_directory}"])
    value: dict[str, object] = {
        "executable": str(executable),
        "identity": {
            "version_argv": ["{executable}", "--version"],
            "extra_kind": "none",
        },
        "dns_controls": [],
        "parameters": {},
        "commands": {
            "active": {
                "argv": ["{executable}", "{domain}"],
                "required_context": ["domain"],
                "output": {"kind": "line_stdout"},
            },
            "validate": {
                "argv": ["{executable}", "{input_file}", "{output_file}"],
                "required_context": ["input_file", "output_file"],
                "output": {"kind": "line_file", "path": "{output_file}"},
            },
            "passive-observational": {
                "argv": argv,
                "required_context": required_context,
                "output": output,
            }
        },
        "passive_policy": dict(PASSIVE_POLICY),
    }
    if preflight:
        value["preflight"] = {
            "argv": ["{executable}", "--preflight"],
            "required_context": [],
            "required_literals": ["PASSIVE-SAFE"],
            "forbidden_regexes": ["contact policy disabled"],
        }
    return value


def write_toolset(
    path: pathlib.Path,
    executables: dict[str, pathlib.Path],
    *,
    subject: str = "subject",
    preflight: bool = False,
) -> pathlib.Path:
    document = {
        "schema_version": 1,
        "subject": subject,
        "campaigns": {
            "active": {
                "discoverers": list(executables),
                "validator": subject,
                "capacity_guard": subject,
                "provenance_only": [],
                "credential_participants": [],
            },
            "passive-observational": {"discoverers": list(executables)}
        },
        "tools": {
            tool: tool_definition(executable, preflight=preflight)
            for tool, executable in executables.items()
        },
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    load_toolset(path)
    return path


def write_completion_evidence(campaign: pathlib.Path) -> None:
    for action in ("cleanup", "redaction"):
        (campaign / f"{action}.status").write_text("complete\n", encoding="utf-8")
        (campaign / f"{action}.timing.json").write_text(
            json.dumps(
                {
                    "status": "success",
                    "exit_code": 0,
                    "duration_seconds": 0.01,
                    "max_rss_kib": 0,
                    "timeout_seconds": 60,
                    "grace_seconds": 5,
                    "max_file_bytes": 268435456,
                }
            )
            + "\n",
            encoding="utf-8",
        )


class PassiveTop30SourceTests(unittest.TestCase):
    def test_pinned_source_has_exact_ranks_domains_and_hashes(self) -> None:
        source, ranked = validate_source_manifest(SOURCE_MANIFEST)
        self.assertEqual(source["list_id"], "74J5X")
        self.assertEqual(source["generated_on"], "2026-07-17")
        self.assertEqual([rank for rank, _domain in ranked], list(range(1, 31)))
        self.assertEqual(ranked[0], (1, "google.com"))
        self.assertEqual(ranked[-1], (30, "bing.com"))
        self.assertEqual(len({domain for _rank, domain in ranked}), 30)
        self.assertEqual(
            source["retrieval"]["top30_csv_sha256"],
            "245ac9b15356107a52cb3a2e1ed7555481aad323bc71fe903e20d8ed7a798d5f",
        )

    def test_data_notice_does_not_claim_the_repository_license(self) -> None:
        source, _ranked = validate_source_manifest(SOURCE_MANIFEST)
        licensing = source["licensing"]
        self.assertIs(licensing["aggregate_license_asserted"], False)
        self.assertIs(licensing["fellaga_mit_license_applies_to_excerpt"], False)
        self.assertIn("not represented as covered", licensing["notice"])


class PassiveTop30PolicyTests(unittest.TestCase):
    def test_no_key_environment_uses_a_strict_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            "os.environ",
            {
                "FELLAGA_CONFIG": "/private/config.json",
                "CUSTOM_PASSWORD": "secret",
                "SAFE_VALUE": "must-not-survive",
            },
            clear=True,
        ):
            root = pathlib.Path(directory)
            environment = _no_key_environment(root)

        self.assertNotIn("FELLAGA_CONFIG", environment)
        self.assertNotIn("CUSTOM_PASSWORD", environment)
        self.assertNotIn("SAFE_VALUE", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertEqual(environment["HOME"], str(root / "home"))
        self.assertEqual(environment["TZ"], "UTC")
        self.assertEqual(
            set(environment),
            {
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "PATH",
                "TZ",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
            },
        )

    def test_runner_is_dynamic_and_uses_nul_argv_without_shell_eval(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")
        for fragment in (
            "FELLAGA_PASSIVE_TOP30_TOOLSET",
            "tool-list --toolset",
            "snapshot-toolset --toolset",
            "render-argv --toolset",
            "output-contract --toolset",
            "preflight-check",
            "mapfile -d '' -t",
            "passive-observational",
            "env -i",
            '"HOME=$isolation/home"',
            "[passive-top30] start",
            "[passive-top30] complete",
            'cleanup-run "$OUT"',
            'quota-check "$OUT"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)
        self.assertNotIn("eval ", script)
        self.assertNotIn('case "$tool"', script)
        self.assertNotIn("_BIN", script)
        self.assertNotIn("python_distribution", script)

    def test_tool_list_and_rendering_follow_the_local_toolset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            toolset = write_toolset(
                root / "tools.json",
                {"subject": pathlib.Path(sys.executable), "observer": pathlib.Path(sys.executable)},
            )
            listed = subprocess.run(
                [sys.executable, str(REPORT), "tool-list", "--toolset", str(toolset)],
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")
            rendered = subprocess.run(
                [
                    sys.executable,
                    str(REPORT),
                    "render-argv",
                    "--toolset",
                    str(toolset),
                    "observer",
                    "passive-observational",
                    "--context",
                    f"executable={sys.executable}",
                    "--context",
                    "domain=example.invalid",
                    "--context",
                    "output_file=/ignored/file",
                ],
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")

        self.assertEqual(listed[:-1], [b"subject", b"observer"])
        self.assertEqual(
            [value.decode() for value in rendered[:-1]],
            [sys.executable, "example.invalid"],
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "runner requires Linux")
    def test_runner_fail_closes_with_isolated_toolset_driven_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "campaign"
            executables: dict[str, pathlib.Path] = {}
            captures: dict[str, pathlib.Path] = {}
            for tool in ("subject", "observer"):
                executable = root / tool
                capture = root / f"{tool}.capture"
                captures[tool] = capture
                executable.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"capture={shlex.quote(str(capture))}\n"
                    f"tool={shlex.quote(tool)}\n"
                    "if [[ \"${1-}\" == --version ]]; then echo \"$tool 1.0\"; exit 0; fi\n"
                    "if [[ \"${1-}\" == --preflight ]]; then echo PASSIVE-SAFE; exit 0; fi\n"
                    "printf '%s\\n' \"$*\" >> \"$capture.args\"\n"
                    "env | sort > \"$capture.env\"\n"
                    "printf 'api.%s\\n' \"${1-}\"\n"
                    "exit 7\n",
                    encoding="utf-8",
                )
                executable.chmod(0o755)
                executables[tool] = executable
            toolset = write_toolset(
                root / "tools.json", executables, preflight=True
            )
            environment = dict(os.environ)
            environment.update(
                {
                    "AWS_SECRET_ACCESS_KEY": "must-not-leak",
                    "CUSTOM_TOKEN": "must-not-leak",
                    "HTTP_PROXY": "http://secret.invalid",
                    "FELLAGA_PASSIVE_TOP30_TOOLSET": str(toolset),
                    "FELLAGA_PASSIVE_TOP30_OUT": str(output),
                    "FELLAGA_PASSIVE_TOP30_TIMEOUT": "5",
                    "FELLAGA_PASSIVE_TOP30_PREFLIGHT_TIMEOUT": "5",
                    "FELLAGA_PASSIVE_TOP30_MAX_RUNTIME": "60",
                    "FELLAGA_PASSIVE_TOP30_COOLDOWN": "1",
                    "FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD": "1",
                }
            )
            completed = subprocess.run(
                ["bash", str(RUNNER)],
                cwd=BENCHMARKS.parent,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            captured_environments = {
                tool: captures[tool].with_suffix(".capture.env").read_text()
                for tool in captures
            }

        self.assertEqual(
            completed.returncode,
            3,
            msg=f"stdout={completed.stdout}\nstderr={completed.stderr}",
        )
        self.assertEqual(
            report["summary"]["recorded_runs"],
            2,
            msg=f"stdout={completed.stdout}\nstderr={completed.stderr}\nreport={report}",
        )
        self.assertEqual(report["summary"]["runnable_tools"], ["subject", "observer"])
        self.assertEqual(report["subject"], "subject")
        self.assertIn("circuit breaker", completed.stderr)
        self.assertEqual(manifest["toolset"]["subject"], "subject")
        self.assertEqual(
            manifest["toolset"]["sha256"],
            snapshot_hash(manifest["toolset"]["snapshot"]),
        )
        for child_environment in captured_environments.values():
            self.assertNotIn("must-not-leak", child_environment)
            self.assertNotIn("HTTP_PROXY", child_environment)


class PassiveTop30ReportTests(unittest.TestCase):
    def _prepare(self, campaign: pathlib.Path) -> dict[str, object]:
        toolset = write_toolset(
            campaign / "local-tools.json",
            {
                "subject": pathlib.Path(sys.executable),
                "observer": pathlib.Path(sys.executable),
            },
        )
        manifest = prepare_campaign(
            campaign,
            repetitions=1,
            runnable={"subject": sys.executable},
            missing={"observer": "executable_not_found"},
            skipped={},
            toolset_path=toolset,
        )
        write_completion_evidence(campaign)
        return manifest

    def _empty_raw_tree(self, campaign: pathlib.Path) -> pathlib.Path:
        root = campaign / "raw-tree-root"
        root.mkdir(exist_ok=True)
        manifest = campaign / "raw-tree.json"
        write_tree_manifest(campaign, root, manifest)
        return manifest

    def _run_artifacts(
        self, campaign: pathlib.Path, domain: str = "google.com"
    ) -> tuple[pathlib.Path, ...]:
        timing = campaign / "timing.json"
        names = campaign / "names.txt"
        stdout = campaign / "stdout.txt"
        stderr = campaign / "stderr.txt"
        parser_stderr = campaign / "parser-stderr.txt"
        timing.write_text(
            json.dumps(
                {
                    "status": "success",
                    "exit_code": 0,
                    "duration_seconds": 1,
                    "max_rss_kib": 0,
                    "timeout_seconds": 900,
                    "grace_seconds": 5,
                    "max_file_bytes": 268435456,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        names.write_text(f"www.{domain}\n", encoding="utf-8")
        for path in (stdout, stderr, parser_stderr):
            path.write_text("", encoding="utf-8")
        return timing, names, stdout, stderr, parser_stderr, self._empty_raw_tree(campaign)

    def test_manifest_binds_normalized_toolset_and_dynamic_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            manifest = self._prepare(campaign)
            snapshot_file = json.loads(
                (campaign / "toolset.snapshot.json").read_text(encoding="utf-8")
            )

        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["toolset"]["subject"], "subject")
        self.assertEqual(manifest["toolset"]["campaign"], "passive-observational")
        self.assertEqual(manifest["toolset"]["snapshot"], snapshot_file)
        self.assertEqual(
            manifest["toolset"]["sha256"], snapshot_hash(snapshot_file)
        )
        self.assertEqual(list(manifest["tools"]), ["subject", "observer"])
        self.assertNotIn("command_policy", manifest)

    def test_missing_tool_remains_descriptive_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            report = build_report(campaign)

        summary = report["summary"]
        self.assertIs(summary["qualification_eligible"], False)
        self.assertIs(summary["best_tool_claim_allowed"], False)
        self.assertEqual(summary["missing_tools"], ["observer"])
        self.assertEqual(report["subject"], "subject")
        self.assertEqual(set(report["tools"]), {"subject", "observer"})

    def test_record_and_report_use_dynamic_tool_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing, names, stdout, stderr, parser_stderr, raw_tree = self._run_artifacts(campaign)
            row = record_run(
                campaign,
                tool="subject",
                domain="google.com",
                rank=1,
                repetition=1,
                timing_path=timing,
                names_path=names,
                stdout_path=stdout,
                stderr_path=stderr,
                parser_stderr_path=parser_stderr,
                raw_tree_path=raw_tree,
                parse_status="success",
            )
            report = build_report(campaign)

        self.assertEqual(row["schema_version"], 2)
        self.assertEqual(row["tool"], "subject")
        self.assertEqual(report["tools"]["subject"]["successful_runs"], 1)
        self.assertEqual(report["tools"]["subject"]["unique_domain_name_pairs"], 1)

    def test_report_rejects_relaxed_contact_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            manifest_path = campaign / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["contact_policy"]["direct_dns_resolution"] = True
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contact policy"):
                build_report(campaign)

    def test_report_rejects_changed_toolset_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            artifact = campaign / "toolset.snapshot.json"
            snapshot = json.loads(artifact.read_text(encoding="utf-8"))
            snapshot["subject"] = "observer"
            artifact.write_text(json.dumps(snapshot) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "toolset artifact changed"):
                build_report(campaign)

    def test_report_rejects_changed_embedded_toolset_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            manifest_path = campaign / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["toolset"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "snapshot hash"):
                build_report(campaign)

    def test_record_rejects_out_of_scope_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing, names, stdout, stderr, parser_stderr, raw_tree = self._run_artifacts(campaign)
            names.write_text("outside.invalid\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                record_run(
                    campaign,
                    tool="subject",
                    domain="google.com",
                    rank=1,
                    repetition=1,
                    timing_path=timing,
                    names_path=names,
                    stdout_path=stdout,
                    stderr_path=stderr,
                    parser_stderr_path=parser_stderr,
                    raw_tree_path=raw_tree,
                    parse_status="success",
                )

    def test_campaign_quota_counts_all_retained_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            (campaign / "one.txt").write_text("one", encoding="utf-8")
            (campaign / "two.txt").write_text("two", encoding="utf-8")
            manifest = {
                "execution_limits": {
                    "campaign_max_files": 1,
                    "campaign_max_bytes": 1024,
                }
            }
            with self.assertRaisesRegex(ValueError, "file-count"):
                enforce_campaign_quota(campaign, manifest)

    def test_pre_run_identity_check_rejects_changed_binary_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            manifest_path = campaign / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["tools"]["subject"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed during the campaign"):
                verify_campaign_tool(campaign, "subject")


if __name__ == "__main__":
    unittest.main()
