from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
RUN_SH = BENCHMARKS / "run.sh"


@unittest.skipUnless(os.name == "posix", "benchmark campaign smoke test requires POSIX")
@unittest.skipUnless(
    all(shutil.which(command) for command in ("bash", "jq", "timeout")),
    "benchmark campaign smoke test requires bash, jq, and timeout",
)
class RunScriptTests(unittest.TestCase):
    def _write_toolset(
        self, root: pathlib.Path, executables: dict[str, pathlib.Path]
    ) -> pathlib.Path:
        identity = {
            "version_argv": ["{executable}", "--version"],
            "extra_kind": "none",
        }

        def tool(
            name: str,
            commands: dict[str, object],
            controls: list[str] | None = None,
        ) -> dict[str, object]:
            return {
                "executable": str(executables[name]),
                "identity": identity,
                "dns_controls": controls or [],
                "commands": commands,
            }

        active_context = [
            "domain",
            "output_path",
            "database_path",
            "config_path",
            "profile",
            "resolvers_csv",
            "max_runtime",
            "active_max_runtime",
            "dns_rate",
            "dns_concurrency",
        ]
        document = {
            "schema_version": 1,
            "subject": "subject_engine",
            "campaigns": {
                "active": {
                    "discoverers": [
                        "subject_engine",
                        "finder_stdout",
                        "finder_tree",
                        "capacity_probe",
                    ],
                    "validator": "validator",
                    "capacity_guard": "capacity_probe",
                    "provenance_only": ["transport_helper"],
                    "credential_participants": [
                        "subject_engine",
                        "finder_stdout",
                        "finder_tree",
                    ],
                },
                "passive-observational": {"discoverers": ["subject_engine"]},
            },
            "tools": {
                "subject_engine": tool(
                    "subject_engine",
                    {
                        "active": {
                            "argv": [
                                "{executable}",
                                "active",
                                "--domain",
                                "{domain}",
                                "--database",
                                "{database_path}",
                                "--config-file",
                                "{config_path}",
                                "--profile",
                                "{profile}",
                                "--max-runtime",
                                "{max_runtime}",
                                "--active-max-runtime",
                                "{active_max_runtime}",
                                "--dns-rate",
                                "{dns_rate}",
                                "--dns-concurrency",
                                "{dns_concurrency}",
                                "--resolvers-csv",
                                "{resolvers_csv}",
                                "--output",
                                "{output_path}",
                            ],
                            "required_context": active_context,
                            "output": {
                                "kind": "finding_json",
                                "path": "{output_path}",
                            },
                        },
                        "passive-observational": {
                            "argv": [
                                "{executable}",
                                "passive-observational",
                                "--domain",
                                "{domain}",
                            ],
                            "required_context": ["domain"],
                            "output": {"kind": "line_stdout"},
                        },
                    },
                    ["resolver_list", "trusted_resolver_list", "rate_limit", "concurrency"],
                ),
                "finder_stdout": tool(
                    "finder_stdout",
                    {
                        "active": {
                            "argv": ["{executable}", "active", "--domain", "{domain}"],
                            "required_context": ["domain"],
                            "output": {"kind": "line_stdout"},
                        }
                    },
                    ["resolver_list"],
                ),
                "finder_tree": tool(
                    "finder_tree",
                    {
                        "active": {
                            "argv": [
                                "{executable}",
                                "active",
                                "--domain",
                                "{domain}",
                                "--output-dir",
                                "{output_dir}",
                            ],
                            "required_context": ["domain", "output_dir"],
                            "output": {
                                "kind": "dns_event_tree",
                                "path": "{output_dir}",
                            },
                        }
                    },
                    ["resolver_list", "concurrency"],
                ),
                "capacity_probe": tool(
                    "capacity_probe",
                    {
                        "active": {
                            "argv": [
                                "{executable}",
                                "active",
                                "--domain",
                                "{domain}",
                                "--output",
                                "{output_path}",
                                "--corpus",
                                "{corpus}",
                            ],
                            "required_context": ["domain", "output_path", "corpus"],
                            "output": {
                                "kind": "line_file",
                                "path": "{output_path}",
                            },
                        }
                    },
                    [
                        "resolver_list",
                        "trusted_resolver_list",
                        "rate_limit",
                        "trusted_rate_limit",
                    ],
                ),
                "validator": tool(
                    "validator",
                    {
                        "validate": {
                            "argv": [
                                "{executable}",
                                "validate",
                                "--input",
                                "{input_path}",
                                "--output",
                                "{output_path}",
                            ],
                            "required_context": ["input_path", "output_path"],
                            "output": {
                                "kind": "line_file",
                                "path": "{output_path}",
                            },
                        }
                    },
                    ["resolver_list", "rate_limit", "concurrency"],
                ),
                "transport_helper": tool("transport_helper", {}),
            },
        }
        document["tools"]["subject_engine"]["passive_policy"] = {
            "target_contact": "prohibited",
            "direct_dns": False,
            "direct_http_or_tls": False,
        }
        path = root / "toolset.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def _early_policy_environment(
        self, root: pathlib.Path, campaign: pathlib.Path
    ) -> tuple[dict[str, str], pathlib.Path, pathlib.Path]:
        fake_bin = root / "policy-bin"
        fake_bin.mkdir()
        true_binary = pathlib.Path(shutil.which("true") or "/bin/true")
        tool_names = (
            "subject_engine",
            "finder_stdout",
            "finder_tree",
            "capacity_probe",
            "validator",
            "transport_helper",
        )
        executables: dict[str, pathlib.Path] = {}
        for command in (*tool_names, "zstd"):
            target = fake_bin / command
            shutil.copyfile(true_binary, target)
            target.chmod(0o755)
            if command in tool_names:
                executables[command] = target
        zstd = fake_bin / "zstd"
        zstd.write_text("#!/bin/sh\nprintf 'one\\ntwo\\n'\n", encoding="utf-8")
        zstd.chmod(0o755)
        domains = root / "domains.txt"
        domains.write_text("example.test\n", encoding="utf-8")
        resolvers = root / "resolvers.txt"
        resolvers.write_text("1.1.1.1\n", encoding="utf-8")
        toolset = self._write_toolset(root, executables)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "BENCH_OUT": str(campaign),
                "FELLAGA_BENCH_AUTHORIZED": "YES",
                "FELLAGA_BENCH_RESOLVERS_FILE": str(resolvers),
                "FELLAGA_BENCH_TOOLSET": str(toolset),
                "FELLAGA_BENCH_PIPELINE_BYTES_PER_CANDIDATE": "1",
                "FELLAGA_BENCH_PIPELINE_FIXED_BYTES": "0",
                "FELLAGA_BENCH_PIPELINE_DISK_MARGIN_PERCENT": "100",
            }
        )
        return environment, domains, resolvers

    def test_equal_keys_rejects_an_empty_provider_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            campaign = root / "campaign"
            environment, domains, _ = self._early_policy_environment(root, campaign)
            manifest = root / "keys.json"
            manifest.write_text(
                json.dumps({"policy": "same-provider-keys", "providers": []}),
                encoding="utf-8",
            )
            environment["KEYS_MANIFEST"] = str(manifest)
            completed = subprocess.run(
                ["bash", str(RUN_SH), "equal-keys", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 5)
            self.assertIn("invalid equal-keys manifest", completed.stderr)

    def test_existing_output_is_rejected_before_stale_artifacts_are_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "candidate-pipeline.json").write_text(
                '{"status":"success"}\n', encoding="utf-8"
            )
            environment, domains, _ = self._early_policy_environment(root, campaign)
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 6)
            self.assertIn("benchmark output already exists", completed.stderr)

    def test_pipeline_size_and_transport_sample_fail_early(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            environment, domains, _ = self._early_policy_environment(
                root, root / "campaign-a"
            )
            environment["FELLAGA_BENCH_PIPELINE_CANDIDATES"] = "10000001"
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("exactly 10000000 candidates", completed.stderr)

            environment["BENCH_OUT"] = str(root / "campaign-b")
            environment["FELLAGA_BENCH_PIPELINE_CANDIDATES"] = "10000000"
            environment["FELLAGA_BENCH_RESOLVER_QUERIES"] = "99999"
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("at least 100000 queries", completed.stderr)

            environment["BENCH_OUT"] = str(root / "campaign-c")
            environment["FELLAGA_BENCH_RESOLVER_QUERIES"] = "100000"
            environment["FELLAGA_BENCH_PROFILE_BASELINES"] = "deep,fast"
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("comma-separated subset", completed.stderr)

    def test_pipeline_disk_preflight_rejects_insufficient_space(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            campaign = root / "campaign"
            environment, domains, _ = self._early_policy_environment(root, campaign)
            environment["FELLAGA_BENCH_PIPELINE_FIXED_BYTES"] = str(10**18)
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 6)
            self.assertIn("disk preflight failed", completed.stderr)
            evidence = json.loads(
                (campaign / "disk-preflight.json").read_text(encoding="utf-8")
            )
            self.assertEqual(evidence["status"], "insufficient")
            self.assertGreater(evidence["shortfall_bytes"], 0)

    def test_active_runtime_must_be_a_non_negative_integer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            campaign = root / "campaign"
            environment, domains, _ = self._early_policy_environment(root, campaign)
            environment["FELLAGA_BENCH_ACTIVE_MAX_RUNTIME"] = "-1"
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("non-negative integers", completed.stderr)

    def test_capacity_guard_preflight_rejects_impossible_qps_timeout_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            campaign = root / "campaign"
            environment, domains, _ = self._early_policy_environment(root, campaign)
            environment.update(
                {
                    "FELLAGA_BENCH_MAX_RUNTIME": "1",
                    "FELLAGA_BENCH_DISCOVERY_TIMEOUT": "1",
                    "FELLAGA_BENCH_DNS_RATE": "1",
                    "FELLAGA_BENCH_CAPACITY_GUARD_HEADROOM_PERCENT": "100",
                }
            )
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            self.assertEqual(completed.returncode, 8, completed.stderr)
            self.assertIn("capacity-guard preflight failed", completed.stderr)
            evidence = json.loads(
                (campaign / "capacity-guard-preflight.json").read_text(encoding="utf-8")
            )
            self.assertEqual(evidence["status"], "incoherent")
            self.assertEqual(evidence["minimum_coherent_rate_qps"], 2)

    def test_campaign_is_fresh_bounded_and_does_not_validate_failed_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            dispatcher = fake_bin / "dispatcher"
            dispatcher.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import hashlib
                    import json
                    import os
                    import pathlib
                    import shutil
                    import sys

                    tool = pathlib.Path(sys.argv[0]).name
                    args = sys.argv[1:]
                    if "--version" in args:
                        print(f"{tool} test-version")
                        raise SystemExit(0)

                    def value(flag):
                        return args[args.index(flag) + 1]

                    if tool == "zstd":
                        print("api")
                    elif tool == "subject_engine" and "benchmark" in args and "candidate-pipeline" in args:
                        wordlist = pathlib.Path(value("--wordlist"))
                        wordlist.write_text("bench-fixture\\n", encoding="utf-8")
                        wordlist_sha256 = hashlib.sha256(wordlist.read_bytes()).hexdigest()
                        binary_sha256 = hashlib.sha256(pathlib.Path(sys.argv[0]).read_bytes()).hexdigest()
                        requested = int(value("--candidates"))
                        pathlib.Path(value("--output")).write_text(
                            json.dumps({
                                "schema_version": 1,
                                "benchmark": "candidate_pipeline",
                                "engine": "subject_core",
                                "campaign_id": value("--campaign-id"),
                                "wordlist_sha256": wordlist_sha256,
                                "binary_sha256": binary_sha256,
                                "requested_candidates": requested,
                                "loaded_candidates": requested,
                                "persisted_candidates": requested,
                                "scheduled_candidates": requested,
                                "dns_dispatched_candidates": requested,
                                "processed_candidates": requested,
                                "positive_candidates": 0,
                                "definitive_negative_candidates": requested,
                                "indeterminate_candidates": 0,
                            }),
                            encoding="utf-8",
                        )
                    elif tool == "subject_engine" and args[:2] == ["resolvers", "benchmark"]:
                        pathlib.Path(value("--output")).write_text(
                            json.dumps({
                                "queries": int(value("--queries")),
                                "queries_per_second": 30000,
                                "loss_rate": 0.0,
                            }),
                            encoding="utf-8",
                        )
                    elif tool == "subject_engine" and args[:1] == ["active"]:
                        database = pathlib.Path(value("--database"))
                        config = pathlib.Path(value("--config-file"))
                        if not database.parent.is_dir() or not config.parent.is_dir():
                            raise SystemExit(20)
                        database.write_text("fresh", encoding="utf-8")
                        config.write_text("{}", encoding="utf-8")
                        with pathlib.Path(os.environ["MOCK_SUBJECT_PATHS"]).open("a", encoding="utf-8") as log:
                            log.write(json.dumps([
                                str(database), str(config), value("--profile"),
                                value("--max-runtime"), value("--active-max-runtime")
                            ]) + "\\n")
                        domain = value("--domain")
                        pathlib.Path(value("--output")).write_text(json.dumps({
                            "findings": [{"fqdn": f"api.{domain}", "state": "live"}],
                            "resolver_metrics": [],
                        }), encoding="utf-8")
                    elif tool == "finder_stdout" and args[:1] == ["active"]:
                        print(f"provider rejected {os.environ.get('MOCK_SECRET', 'credential-cleared')}", file=sys.stderr)
                        raise SystemExit(7)
                    elif tool == "finder_tree" and args[:1] == ["active"]:
                        output = pathlib.Path(value("--output-dir"))
                        output.mkdir(parents=True, exist_ok=True)
                        domain = value("--domain")
                        (output / "output.json").write_text(
                            json.dumps({"type": "DNS_NAME", "data": domain}) + "\\n" +
                            json.dumps({"type": "DNS_NAME", "data": f"api.{domain}"}) + "\\n",
                            encoding="utf-8",
                        )
                    elif tool == "capacity_probe" and args[:1] == ["active"]:
                        domain = value("--domain")
                        pathlib.Path(value("--output")).write_text(
                            f"api.{domain}\\n", encoding="utf-8"
                        )
                    elif tool == "validator" and args[:1] == ["validate"]:
                        source = pathlib.Path(value("--input"))
                        output = pathlib.Path(value("--output"))
                        shutil.copyfile(source, output)
                        with pathlib.Path(os.environ["MOCK_VALIDATOR_CALLS"]).open("a", encoding="utf-8") as log:
                            log.write(f"{source}\\n")
                    else:
                        raise SystemExit(f"unexpected mock invocation: {tool} {args}")
                    """
                ),
                encoding="utf-8",
            )
            dispatcher.chmod(0o755)
            tool_names = (
                "subject_engine",
                "finder_stdout",
                "finder_tree",
                "capacity_probe",
                "validator",
                "transport_helper",
            )
            executables: dict[str, pathlib.Path] = {}
            for tool in (*tool_names, "zstd"):
                target = fake_bin / tool
                shutil.copyfile(dispatcher, target)
                target.chmod(0o755)
                if tool in tool_names:
                    executables[tool] = target
            toolset = self._write_toolset(root, executables)

            domains = root / "domains.txt"
            domains.write_text("example.test\n", encoding="utf-8")
            resolvers = root / "resolvers.txt"
            resolvers.write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")
            campaign = root / "campaign with spaces;literal"
            paths_log = root / "subject-paths.txt"
            validator_log = root / "validator-calls.txt"
            secret = "benchmark-secret-must-not-enter-summary"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "BENCH_OUT": str(campaign),
                    "FELLAGA_BENCH_AUTHORIZED": "YES",
                    "FELLAGA_BENCH_MAX_RUNTIME": "1",
                    "FELLAGA_BENCH_DISCOVERY_TIMEOUT": "3",
                    "FELLAGA_BENCH_VALIDATION_TIMEOUT": "3",
                    "FELLAGA_BENCH_DNS_ENGINE_TIMEOUT": "3",
                    "FELLAGA_BENCH_TIMEOUT_GRACE": "1",
                    "FELLAGA_BENCH_RESOLVER_QUERIES": "100000",
                    "FELLAGA_BENCH_REPETITIONS": "3",
                    "FELLAGA_BENCH_RESOLVERS_FILE": str(resolvers),
                    "FELLAGA_BENCH_TOOLSET": str(toolset),
                    "FELLAGA_BENCH_REQUIRE_PASS": "0",
                    "FELLAGA_BENCH_PIPELINE_BYTES_PER_CANDIDATE": "1",
                    "FELLAGA_BENCH_PIPELINE_FIXED_BYTES": "0",
                    "FELLAGA_BENCH_PIPELINE_DISK_MARGIN_PERCENT": "100",
                    "FELLAGA_BENCH_PROFILE_BASELINES": "all",
                    "MOCK_SUBJECT_PATHS": str(paths_log),
                    "MOCK_VALIDATOR_CALLS": str(validator_log),
                    "MOCK_SECRET": secret,
                }
            )
            completed = subprocess.run(
                ["bash", str(RUN_SH), "no-key", str(domains)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            subject_paths = [
                json.loads(line)
                for line in paths_log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(subject_paths), 12)
            databases = {line[0] for line in subject_paths}
            configs = {line[1] for line in subject_paths}
            profiles = [line[2] for line in subject_paths]
            hard_runtimes = [line[3] for line in subject_paths]
            active_runtimes = [line[4] for line in subject_paths]
            self.assertEqual(len(databases), 12)
            self.assertEqual(len(configs), 12)
            self.assertEqual(
                {profile: profiles.count(profile) for profile in set(profiles)},
                {"deep": 3, "balanced": 3, "passive": 3, "turbo": 3},
            )
            self.assertEqual(set(hard_runtimes), {"1"})
            self.assertEqual(set(active_runtimes), {"1"})
            self.assertTrue(all(pathlib.Path(path).is_file() for path in databases))
            self.assertTrue(all(pathlib.Path(path).is_file() for path in configs))

            validator_inputs = validator_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(validator_inputs), 18)
            self.assertFalse(any(".finder_stdout." in path for path in validator_inputs))

            summary_text = (campaign / "summary.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret, summary_text)
            finder_log = campaign / "logs" / "example.test.finder_stdout.r1.discovery.stderr"
            self.assertNotIn(secret, finder_log.read_text(encoding="utf-8"))
            self.assertIn("credential-cleared", finder_log.read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in summary_text.splitlines()]
            self.assertEqual(len(rows), 12)
            subject_rows = [row for row in rows if row["tool"] == "subject_engine"]
            self.assertTrue(all(row["profile"] == "deep" for row in subject_rows))
            self.assertTrue(
                all(row["benchmark_kind"] == "qualification" for row in rows)
            )
            baseline_rows = [
                json.loads(line)
                for line in (campaign / "subject-profile-baselines.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(baseline_rows), 12)
            self.assertEqual(
                {row["profile"] for row in baseline_rows},
                {"deep", "balanced", "passive", "turbo"},
            )
            self.assertTrue(
                all(
                    row["benchmark_kind"] == "subject_profile_baseline"
                    and row["tool"] == "subject_engine"
                    for row in baseline_rows
                )
            )
            manifest = json.loads((campaign / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["configuration"]["dns_transport_timeout_seconds"], 3
            )
            self.assertEqual(
                manifest["configuration"]["candidate_pipeline_timeout_seconds"],
                5_400,
            )
            self.assertEqual(
                manifest["configuration"]["candidate_pipeline_candidates"],
                10_000_000,
            )
            self.assertEqual(
                manifest["configuration"]["subject_active_max_runtime_seconds"],
                1,
            )
            self.assertEqual(
                manifest["provenance"]["inputs"]["active_corpus_candidates"],
                1,
            )
            self.assertEqual(
                manifest["configuration"]["subject_profile_baselines"],
                ["deep", "balanced", "passive", "turbo"],
            )
            self.assertEqual(
                manifest["preflight"]["candidate_pipeline_disk"]["status"],
                "sufficient",
            )
            self.assertEqual(
                manifest["preflight"]["capacity_guard"]["status"],
                "coherent",
            )
            self.assertEqual(
                manifest["preflight"]["capacity_guard"]["corpus_candidates"],
                manifest["provenance"]["inputs"]["active_corpus_candidates"],
            )
            failed_rows = [row for row in rows if row["tool"] == "finder_stdout"]
            self.assertTrue(
                all(row["validation_status"] == "skipped" for row in failed_rows)
            )
            self.assertTrue(
                all("validation_error_log" in row for row in rows)
            )


if __name__ == "__main__":
    unittest.main()
