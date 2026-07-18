from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import sys
import tempfile
import unittest
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
RUNNER = BENCHMARKS / "run-passive-top30.sh"
SOURCE_MANIFEST = BENCHMARKS / "data" / "tranco-74J5X-top30.json"
sys.path.insert(0, str(BENCHMARKS))

from passive_top30_report import (  # noqa: E402
    COMMAND_TEMPLATES,
    TOOLS,
    _no_key_environment,
    build_report,
    enforce_campaign_quota,
    prepare_campaign,
    record_run,
    validate_source_manifest,
    verify_campaign_tool,
    write_tree_manifest,
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
            source["retrieval"]["source_csv_sha256"],
            "9d8bd78b8d291ba18ac1f91758515d2d7013b83b42d0c73d751d79f5b1475f43",
        )
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
        self.assertEqual(
            source["retrieval"]["permanent_csv"],
            "https://tranco-list.eu/download/74J5X/1000000",
        )


class PassiveTop30PolicyTests(unittest.TestCase):
    def test_no_key_environment_uses_a_strict_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            "os.environ",
            {
                "FELLAGA_CONFIG": "/private/config.json",
                "SECURITYTRAILS_API_KEY": "secret-value",
                "CUSTOM_PASSWORD": "another-secret",
                "SAFE_VALUE": "preserved",
            },
            clear=True,
        ):
            root = pathlib.Path(directory)
            environment = _no_key_environment(root)

        self.assertNotIn("FELLAGA_CONFIG", environment)
        self.assertNotIn("SECURITYTRAILS_API_KEY", environment)
        self.assertNotIn("CUSTOM_PASSWORD", environment)
        self.assertNotIn("SAFE_VALUE", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("AWS_ACCESS_KEY_ID", environment)
        self.assertEqual(environment["HOME"], str(root / "home"))
        self.assertEqual(environment["XDG_CONFIG_HOME"], str(root / "config"))
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

    def test_runner_contains_only_no_target_contact_command_modes(self) -> None:
        script = RUNNER.read_text(encoding="utf-8")

        for fragment in (
            "scan --profile passive --no-target-contact",
            "--no-target-contact --all-sources",
            "--passive-zone-concurrency 1 --show",
            "-silent -duc -all -rl",
            "enum -passive -config /dev/null -d",
            "normalize-observational",
            "bbot-observational",
            "-f subdomain-enum -rf passive",
            "-c dns.disable=true speculate=false",
            "--dry-run",
            '"HOME=$isolation/home"',
            '"XDG_CONFIG_HOME=$isolation/config"',
            '"XDG_DATA_HOME=$isolation/data"',
            '"XDG_CACHE_HOME=$isolation/cache"',
            "env -i",
            "(rank - 1 + repetition - 1) % tool_count",
            "bbot=no_dns_preflight_semantic_error",
            "[passive-top30] start",
            "[passive-top30] complete",
            'cleanup-run "$OUT"',
            'quota-check "$OUT"',
            ".posix-mode-probe",
            "output must be on a POSIX-permission filesystem",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, script)

        for forbidden in (
            "dnsx",
            "puredns",
            "massdns",
            "--active",
            "--resolvers",
            "--force",
            "benchmarks/run.sh",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, script)
        self.assertIsNone(
            re.search(
                r"tool_bins\[subfinder\][^\n]*(?<!\S)-rL?(?=\s)",
                script,
            )
        )
        self.assertRegex(
            script,
            r"grep -Eiq .*\\\[ERRR\\\].*dnsresolve",
        )

    def test_recorded_command_templates_are_descriptive_and_safe(self) -> None:
        self.assertEqual(set(COMMAND_TEMPLATES), set(TOOLS))
        flattened = {
            tool: " ".join(arguments) for tool, arguments in COMMAND_TEMPLATES.items()
        }

        self.assertIn("--no-target-contact", flattened["fellaga"])
        self.assertIn("--all-sources", flattened["fellaga"])
        self.assertIn("--profile passive", flattened["fellaga"])
        self.assertNotIn("--active", flattened["subfinder"])
        self.assertNotIn("--resolvers", flattened["subfinder"])
        self.assertIn("-duc", flattened["subfinder"])
        self.assertIn("-all", flattened["subfinder"])
        self.assertIn("enum -passive", flattened["amass"])
        self.assertIn("-config /dev/null", flattened["amass"])
        self.assertIn("dns.disable=true", flattened["bbot"])
        self.assertIn("speculate=false", flattened["bbot"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "runner requires Linux")
    def test_runner_fail_closes_with_isolated_fake_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "campaign"
            binaries: dict[str, pathlib.Path] = {}
            captures: dict[str, pathlib.Path] = {}
            for tool in TOOLS:
                executable = root / tool
                capture = root / f"{tool}.capture"
                captures[tool] = capture
                executable.write_text(
                    "#!/usr/bin/env bash\n"
                    "set -eu\n"
                    f"capture={shlex.quote(str(capture))}\n"
                    f"tool={shlex.quote(tool)}\n"
                    "if [[ \"$tool\" == fellaga && \"$*\" == \"scan --help\" ]]; then\n"
                    "  echo --profile --no-target-contact --all-sources --show --passive-concurrency\n"
                    "  exit 0\n"
                    "fi\n"
                    "if [[ \"$tool\" == subfinder && \"$*\" == \"-duc -h\" ]]; then\n"
                    "  echo -duc -all -rl -d\n"
                    "  exit 0\n"
                    "fi\n"
                    "if [[ \"$tool\" == amass && \"$*\" == \"enum -h\" ]]; then\n"
                    "  echo -passive -config -d\n"
                    "  exit 0\n"
                    "fi\n"
                    "if [[ \"$*\" == \"--version\" || \"$*\" == \"-version\" ]]; then\n"
                    "  echo \"$tool fake-1.0\"\n"
                    "  exit 0\n"
                    "fi\n"
                    "if [[ \"$tool\" == bbot && \" $* \" == *\" --dry-run \"* ]]; then\n"
                    "  echo '[ERRR] dnsresolve is required but disabled' >&2\n"
                    "  exit 0\n"
                    "fi\n"
                    "printf '%s\\n' \"$*\" >> \"$capture.args\"\n"
                    "env | sort > \"$capture.env\"\n"
                    "domain=${!#}\n"
                    "printf 'api.%s\\n' \"$domain\"\n"
                    "exit 7\n",
                    encoding="utf-8",
                )
                executable.chmod(0o755)
                binaries[tool] = executable

            environment = dict(os.environ)
            environment.update(
                {
                    "AWS_SECRET_ACCESS_KEY": "must-not-leak",
                    "CUSTOM_TOKEN": "must-not-leak",
                    "HTTP_PROXY": "http://secret.invalid",
                    "KUBECONFIG": "/private/kubeconfig",
                    "FELLAGA_PASSIVE_TOP30_OUT": str(output),
                    "FELLAGA_PASSIVE_TOP30_TIMEOUT": "5",
                    "FELLAGA_PASSIVE_TOP30_BBOT_PREFLIGHT_TIMEOUT": "5",
                    "FELLAGA_PASSIVE_TOP30_MAX_RUNTIME": "60",
                    "FELLAGA_PASSIVE_TOP30_COOLDOWN": "1",
                    "FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD": "1",
                    "FELLAGA_PASSIVE_TOP30_FELLAGA_BIN": str(binaries["fellaga"]),
                    "FELLAGA_PASSIVE_TOP30_SUBFINDER_BIN": str(binaries["subfinder"]),
                    "FELLAGA_PASSIVE_TOP30_AMASS_BIN": str(binaries["amass"]),
                    "FELLAGA_PASSIVE_TOP30_BBOT_BIN": str(binaries["bbot"]),
                }
            )
            completed = __import__("subprocess").run(
                ["bash", str(RUNNER)],
                cwd=BENCHMARKS.parent,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            redaction_status = (output / "redaction.status").read_text().strip()
            cleanup_status = (output / "cleanup.status").read_text().strip()
            captured_arguments = {
                tool: captures[tool]
                .with_suffix(".capture.args")
                .read_text(encoding="utf-8")
                for tool in ("fellaga", "subfinder", "amass")
            }
            captured_environments = {
                tool: captures[tool]
                .with_suffix(".capture.env")
                .read_text(encoding="utf-8")
                for tool in ("fellaga", "subfinder", "amass")
            }

        self.assertEqual(completed.returncode, 3)
        self.assertEqual(report["summary"]["recorded_runs"], 3)
        self.assertFalse(report["summary"]["campaign_complete"])
        self.assertEqual(report["summary"]["skipped_tools"], ["bbot"])
        self.assertIn("circuit breaker", completed.stderr)
        self.assertEqual(redaction_status, "complete")
        self.assertEqual(cleanup_status, "complete")
        self.assertFalse((output / "isolation").exists())
        self.assertFalse((output / "state").exists())
        self.assertIn("--no-target-contact", captured_arguments["fellaga"])
        self.assertIn("--all-sources", captured_arguments["fellaga"])
        self.assertIn("--passive-concurrency 4", captured_arguments["fellaga"])
        self.assertIn("-duc -all -rl 5", captured_arguments["subfinder"])
        self.assertIn("-config /dev/null", captured_arguments["amass"])
        for tool in ("fellaga", "subfinder", "amass"):
            child_environment = captured_environments[tool]
            self.assertNotIn("must-not-leak", child_environment)
            self.assertNotIn("HTTP_PROXY", child_environment)
            self.assertNotIn("KUBECONFIG", child_environment)


class PassiveTop30ReportTests(unittest.TestCase):
    def _prepare(self, campaign: pathlib.Path) -> dict[str, object]:
        manifest = prepare_campaign(
            campaign,
            repetitions=1,
            runnable={"fellaga": sys.executable},
            missing={
                "subfinder": "executable_not_found",
                "amass": "executable_not_found",
            },
            skipped={"bbot": "no_dns_preflight_failed"},
        )
        (campaign / "redaction.status").write_text("complete\n", encoding="utf-8")
        (campaign / "cleanup.status").write_text("complete\n", encoding="utf-8")
        (campaign / "cleanup.timing.json").write_text(
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
        (campaign / "redaction.timing.json").write_text(
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
        return manifest

    def _empty_raw_tree(self, campaign: pathlib.Path) -> pathlib.Path:
        root = campaign / "raw-tree-root"
        root.mkdir(exist_ok=True)
        manifest = campaign / "raw-tree.json"
        write_tree_manifest(campaign, root, manifest)
        return manifest

    def test_missing_and_skipped_tools_can_never_qualify_or_win(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            report = build_report(campaign)
            manifest = json.loads(
                (campaign / "manifest.json").read_text(encoding="utf-8")
            )

        summary = report["summary"]
        self.assertIs(summary["qualification_eligible"], False)
        self.assertIs(summary["qualification_passed"], False)
        self.assertIs(summary["best_tool_claim_allowed"], False)
        self.assertEqual(summary["missing_tools"], ["subfinder", "amass"])
        self.assertEqual(summary["skipped_tools"], ["bbot"])
        self.assertIn("missing_tools", summary["qualification_failures"])
        self.assertIn("skipped_tools", summary["qualification_failures"])
        self.assertNotIn("best_tool", report)
        self.assertEqual(manifest["credential_policy"]["mode"], "no-key")
        self.assertEqual(
            manifest["source_selection_policy"],
            {
                "fellaga_request": "all_registered_sources",
                "subfinder_request": "all_registered_sources",
                "selection_mode_symmetric": True,
                "provider_catalog_comparable": False,
                "runtime_availability_comparable": False,
            },
        )
        self.assertIs(manifest["credential_policy"]["isolated_per_run"], True)
        self.assertEqual(
            manifest["credential_policy"]["environment_mode"], "allowlist"
        )
        self.assertIs(
            manifest["credential_policy"]["inherited_environment"], False
        )
        self.assertEqual(len(manifest["tools"]["fellaga"]["sha256"]), 64)
        self.assertIsNotNone(manifest["tools"]["fellaga"]["version"])

    def test_complete_runnable_subset_remains_descriptive_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            manifest = self._prepare(campaign)
            logs = campaign / "logs"
            names_directory = campaign / "names"
            logs.mkdir()
            names_directory.mkdir()
            stdout = logs / "stdout.txt"
            stderr = logs / "stderr.txt"
            parser_stderr = logs / "parser-stderr.txt"
            raw_tree = self._empty_raw_tree(campaign)
            timing = logs / "timing.json"
            for path in (stdout, stderr, parser_stderr):
                path.write_text("", encoding="utf-8")
            timing.write_text(
                json.dumps(
                    {
                        "status": "success",
                        "exit_code": 0,
                        "duration_seconds": 0.25,
                        "max_rss_kib": 100,
                        "timeout_seconds": 900,
                        "grace_seconds": 5,
                        "max_file_bytes": 268435456,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            for entry in manifest["domains"]:  # type: ignore[index]
                domain = entry["domain"]
                names = names_directory / f"{entry['rank']:02d}.txt"
                names.write_text(f"www.{domain}\n", encoding="utf-8")
                record_run(
                    campaign,
                    tool="fellaga",
                    domain=domain,
                    rank=entry["rank"],
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

        summary = report["summary"]
        self.assertIs(summary["runnable_subset_complete"], True)
        self.assertIs(summary["campaign_complete"], False)
        self.assertEqual(summary["expected_runs"], 30)
        self.assertEqual(summary["recorded_runs"], 30)
        self.assertIs(summary["qualification_passed"], False)
        self.assertIs(summary["best_tool_claim_allowed"], False)
        self.assertEqual(report["tools"]["fellaga"]["successful_runs"], 30)
        self.assertEqual(report["tools"]["fellaga"]["unique_domain_name_pairs"], 30)

    def test_record_rejects_an_out_of_scope_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing = campaign / "timing.json"
            names = campaign / "names.txt"
            empty = campaign / "empty.txt"
            timing.write_text(
                '{"status":"success","exit_code":0,"duration_seconds":1,'
                '"max_rss_kib":0,"timeout_seconds":900,"grace_seconds":5,'
                '"max_file_bytes":268435456}\n',
                encoding="utf-8",
            )
            names.write_text("outside.invalid\n", encoding="utf-8")
            empty.write_text("", encoding="utf-8")
            raw_tree = self._empty_raw_tree(campaign)

            with self.assertRaises(ValueError):
                record_run(
                    campaign,
                    tool="fellaga",
                    domain="google.com",
                    rank=1,
                    repetition=1,
                    timing_path=timing,
                    names_path=names,
                    stdout_path=empty,
                    stderr_path=empty,
                    parser_stderr_path=empty,
                    raw_tree_path=raw_tree,
                    parse_status="success",
                )

    def test_record_and_report_preserve_parser_exclusion_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing = campaign / "timing.json"
            names = campaign / "names.txt"
            empty = campaign / "empty.txt"
            parser_stderr = campaign / "parser-stderr.txt"
            timing.write_text(
                '{"status":"success","exit_code":0,"duration_seconds":1,'
                '"max_rss_kib":0,"timeout_seconds":900,"grace_seconds":5,'
                '"max_file_bytes":268435456}\n',
                encoding="utf-8",
            )
            names.write_text("www.google.com\n", encoding="utf-8")
            empty.write_text("", encoding="utf-8")
            parser_stderr.write_text(
                "excluded_wildcards=2\n"
                "excluded_invalid_or_out_of_scope=3\n",
                encoding="utf-8",
            )
            raw_tree = self._empty_raw_tree(campaign)

            row = record_run(
                campaign,
                tool="fellaga",
                domain="google.com",
                rank=1,
                repetition=1,
                timing_path=timing,
                names_path=names,
                stdout_path=empty,
                stderr_path=empty,
                parser_stderr_path=parser_stderr,
                raw_tree_path=raw_tree,
                parse_status="success",
            )
            report = build_report(campaign)

        self.assertEqual(row["excluded_wildcard_patterns"], 2)
        self.assertEqual(row["excluded_invalid_or_out_of_scope"], 3)
        self.assertEqual(report["summary"]["recorded_runs"], 1)
        self.assertEqual(report["tools"]["fellaga"]["excluded_wildcard_patterns"], 2)
        self.assertEqual(
            report["tools"]["fellaga"]["excluded_invalid_or_out_of_scope"], 3
        )

    def test_failed_run_names_do_not_contribute_to_coverage_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing = campaign / "timing.json"
            names = campaign / "names.txt"
            empty = campaign / "empty.txt"
            timing.write_text(
                '{"status":"timeout","exit_code":124,"duration_seconds":1,'
                '"max_rss_kib":0,"timeout_seconds":900,"grace_seconds":5,'
                '"max_file_bytes":268435456}\n',
                encoding="utf-8",
            )
            names.write_text("www.google.com\n", encoding="utf-8")
            empty.write_text("", encoding="utf-8")
            raw_tree = self._empty_raw_tree(campaign)
            record_run(
                campaign,
                tool="fellaga",
                domain="google.com",
                rank=1,
                repetition=1,
                timing_path=timing,
                names_path=names,
                stdout_path=empty,
                stderr_path=empty,
                parser_stderr_path=empty,
                raw_tree_path=raw_tree,
                parse_status="success",
            )

            report = build_report(campaign)

        summary = report["tools"]["fellaga"]
        self.assertEqual(summary["unique_domain_name_pairs"], 0)
        self.assertIsNone(summary["median_names_per_run"])
        self.assertIsNone(summary["median_duration_seconds"])
        self.assertEqual(summary["attempt_duration_seconds_total"], 1.0)

    def test_report_rejects_a_names_artifact_modified_after_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            timing = campaign / "timing.json"
            names = campaign / "names.txt"
            empty = campaign / "empty.txt"
            timing.write_text(
                '{"status":"success","exit_code":0,"duration_seconds":1,'
                '"max_rss_kib":0,"timeout_seconds":900,"grace_seconds":5,'
                '"max_file_bytes":268435456}\n',
                encoding="utf-8",
            )
            names.write_text("www.google.com\n", encoding="utf-8")
            empty.write_text("", encoding="utf-8")
            raw_tree = self._empty_raw_tree(campaign)
            record_run(
                campaign,
                tool="fellaga",
                domain="google.com",
                rank=1,
                repetition=1,
                timing_path=timing,
                names_path=names,
                stdout_path=empty,
                stderr_path=empty,
                parser_stderr_path=empty,
                raw_tree_path=raw_tree,
                parse_status="success",
            )
            names.write_text(
                "admin.google.com\nwww.google.com\n", encoding="utf-8"
            )

            report = build_report(campaign)

        self.assertEqual(report["summary"]["recorded_runs"], 0)
        self.assertIn(
            "invalid_run_or_artifact:1", report["summary"]["integrity_issues"]
        )
        self.assertEqual(
            report["tools"]["fellaga"]["unique_domain_name_pairs"], 0
        )

    def test_report_rejects_a_relaxed_contact_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            path = campaign / "manifest.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["contact_policy"]["direct_dns_resolution"] = True
            path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "contact policy"):
                build_report(campaign)

    def test_report_rejects_preflight_evidence_added_after_prepare(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            preflight = campaign / "preflight"
            preflight.mkdir(exist_ok=True)
            (preflight / "unexpected.txt").write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "preflight evidence changed"):
                build_report(campaign)

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

    def test_pre_run_tool_identity_check_fails_before_changed_binary_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = pathlib.Path(directory)
            self._prepare(campaign)
            manifest_path = campaign / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["tools"]["fellaga"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "changed during the campaign"):
                verify_campaign_tool(campaign, "fellaga")


if __name__ == "__main__":
    unittest.main()
