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
    def _early_policy_environment(
        self, root: pathlib.Path, campaign: pathlib.Path
    ) -> tuple[dict[str, str], pathlib.Path, pathlib.Path]:
        fake_bin = root / "policy-bin"
        fake_bin.mkdir()
        true_binary = pathlib.Path(shutil.which("true") or "/bin/true")
        for command in (
            "fellaga",
            "subfinder",
            "amass",
            "bbot",
            "puredns",
            "massdns",
            "dnsx",
            "zstd",
        ):
            target = fake_bin / command
            shutil.copyfile(true_binary, target)
            target.chmod(0o755)
        domains = root / "domains.txt"
        domains.write_text("example.test\n", encoding="utf-8")
        resolvers = root / "resolvers.txt"
        resolvers.write_text("1.1.1.1\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                "BENCH_OUT": str(campaign),
                "FELLAGA_BENCH_AUTHORIZED": "YES",
                "FELLAGA_BENCH_RESOLVERS_FILE": str(resolvers),
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
                    elif tool == "fellaga" and "benchmark" in args and "candidate-pipeline" in args:
                        wordlist = pathlib.Path(value("--wordlist"))
                        wordlist.write_text("bench-fixture\\n", encoding="utf-8")
                        wordlist_sha256 = hashlib.sha256(wordlist.read_bytes()).hexdigest()
                        binary_sha256 = hashlib.sha256(pathlib.Path(sys.argv[0]).read_bytes()).hexdigest()
                        requested = int(value("--candidates"))
                        pathlib.Path(value("--output")).write_text(
                            json.dumps({
                                "schema_version": 1,
                                "benchmark": "candidate_pipeline",
                                "engine": "fellaga_core",
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
                    elif tool == "fellaga" and args[:2] == ["resolvers", "benchmark"]:
                        pathlib.Path(value("--output")).write_text(
                            json.dumps({
                                "queries": int(value("--queries")),
                                "queries_per_second": 30000,
                                "loss_rate": 0.0,
                            }),
                            encoding="utf-8",
                        )
                    elif tool == "fellaga":
                        database = pathlib.Path(value("--db"))
                        config = pathlib.Path(value("--config"))
                        if not database.parent.is_dir() or not config.parent.is_dir():
                            raise SystemExit(20)
                        database.write_text("fresh", encoding="utf-8")
                        config.write_text("{}", encoding="utf-8")
                        with pathlib.Path(os.environ["MOCK_FELLAGA_PATHS"]).open("a", encoding="utf-8") as log:
                            log.write(f"{database} {config}\\n")
                        domain = args[args.index("scan") + 1]
                        print(json.dumps({
                            "findings": [{"fqdn": f"api.{domain}", "state": "live"}],
                            "resolver_metrics": [],
                        }))
                    elif tool == "subfinder":
                        pathlib.Path(value("-o")).write_text(
                            f"api.{value('-d')}\\n", encoding="utf-8"
                        )
                    elif tool == "amass":
                        print(f"provider rejected {os.environ.get('MOCK_SECRET', 'credential-cleared')}", file=sys.stderr)
                        raise SystemExit(7)
                    elif tool == "bbot":
                        output = pathlib.Path(value("-o"))
                        output.mkdir(parents=True, exist_ok=True)
                        domain = value("-t")
                        (output / "output.json").write_text(
                            json.dumps({"type": "DNS_NAME", "data": domain}) + "\\n" +
                            json.dumps({"type": "DNS_NAME", "data": f"api.{domain}"}) + "\\n",
                            encoding="utf-8",
                        )
                    elif tool == "puredns":
                        domain = args[args.index("bruteforce") + 2]
                        pathlib.Path(value("--write")).write_text(
                            f"api.{domain}\\n", encoding="utf-8"
                        )
                    elif tool == "dnsx":
                        source = pathlib.Path(value("-l"))
                        output = pathlib.Path(value("-o"))
                        shutil.copyfile(source, output)
                        with pathlib.Path(os.environ["MOCK_DNSX_CALLS"]).open("a", encoding="utf-8") as log:
                            log.write(f"{source}\\n")
                    else:
                        raise SystemExit(f"unexpected mock invocation: {tool} {args}")
                    """
                ),
                encoding="utf-8",
            )
            dispatcher.chmod(0o755)
            for tool in (
                "fellaga",
                "subfinder",
                "amass",
                "bbot",
                "puredns",
                "massdns",
                "dnsx",
                "zstd",
            ):
                target = fake_bin / tool
                shutil.copyfile(dispatcher, target)
                target.chmod(0o755)

            domains = root / "domains.txt"
            domains.write_text("example.test\n", encoding="utf-8")
            resolvers = root / "resolvers.txt"
            resolvers.write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")
            campaign = root / "campaign"
            paths_log = root / "fellaga-paths.txt"
            dnsx_log = root / "dnsx-calls.txt"
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
                    "FELLAGA_BENCH_REQUIRE_PASS": "0",
                    "MOCK_FELLAGA_PATHS": str(paths_log),
                    "MOCK_DNSX_CALLS": str(dnsx_log),
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

            fellaga_paths = paths_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(fellaga_paths), 3)
            databases = {line.split()[0] for line in fellaga_paths}
            configs = {line.split()[1] for line in fellaga_paths}
            self.assertEqual(len(databases), 3)
            self.assertEqual(len(configs), 3)
            self.assertTrue(all(pathlib.Path(path).is_file() for path in databases))
            self.assertTrue(all(pathlib.Path(path).is_file() for path in configs))

            dnsx_inputs = dnsx_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(dnsx_inputs), 12)
            self.assertFalse(any(".amass." in path for path in dnsx_inputs))

            summary_text = (campaign / "summary.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(secret, summary_text)
            amass_log = campaign / "logs" / "example.test.amass.r1.discovery.stderr"
            self.assertNotIn(secret, amass_log.read_text(encoding="utf-8"))
            self.assertIn("credential-cleared", amass_log.read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in summary_text.splitlines()]
            self.assertEqual(len(rows), 15)
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
            amass_rows = [row for row in rows if row["tool"] == "amass"]
            self.assertTrue(
                all(row["validation_status"] == "skipped" for row in amass_rows)
            )
            self.assertTrue(
                all("validation_error_log" in row for row in rows)
            )


if __name__ == "__main__":
    unittest.main()
