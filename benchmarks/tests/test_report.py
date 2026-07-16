from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS))

from report import (
    DNS_CONTROL_REQUIREMENTS,
    REQUIRED_TOOLS,
    build_report,
    main as report_main,
)


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.campaign = root / "benchmarks" / "results" / "campaign"
        self.truth = root / "benchmarks" / "ground-truth"
        (self.campaign / "live").mkdir(parents=True)
        self.truth.mkdir(parents=True)
        self.domains = [f"d{index:02d}.example" for index in range(30)]
        self.campaign_id = "campaign-test-0001"
        self.fellaga_sha256 = "a" * 64
        self.pipeline_sha256 = "b" * 64
        versions = {tool: f"{tool} test-version" for tool in (*REQUIRED_TOOLS, "massdns", "dnsx")}
        executables = {
            tool: {
                "version": version,
                "sha256": self.fellaga_sha256 if tool == "fellaga" else "c" * 64,
            }
            for tool, version in versions.items()
        }
        (self.campaign / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "campaign_id": self.campaign_id,
                    "mode": "no-key",
                    "authorized_domains": self.domains,
                    "repetitions": 3,
                    "versions": versions,
                    "configuration": {
                        "required_repetitions": 3,
                        "fellaga_active_max_runtime_seconds": 1_800,
                        "discovery_timeout_seconds": 1_860,
                        "validation_timeout_seconds": 300,
                        "dns_transport_timeout_seconds": 900,
                        "candidate_pipeline_timeout_seconds": 5_400,
                        "dns_rate_limit": 1_000,
                        "dns_concurrency": 100,
                        "dns_transport_queries": 100_000,
                        "dns_transport_concurrency": 128,
                        "candidate_pipeline_candidates": 10_000_000,
                        "candidate_pipeline_batch": 4_096,
                        "candidate_pipeline_concurrency": 128,
                        "candidate_pipeline_bytes_per_candidate": 2_048,
                        "candidate_pipeline_fixed_bytes": 2_147_483_648,
                        "candidate_pipeline_disk_margin_percent": 125,
                        "puredns_headroom_percent": 125,
                        "fellaga_profile_baselines": [],
                    },
                    "provenance": {
                        "repository": {"commit": "d" * 40, "dirty": False},
                        "executables": executables,
                        "inputs": {
                            "domains_sha256": "e" * 64,
                            "active_corpus_archive_sha256": "f" * 64,
                            "active_corpus_sha256": "1" * 64,
                            "active_corpus_candidates": 1_000_000,
                            "pipeline_corpus_sha256": self.pipeline_sha256,
                            "resolvers_sha256": "2" * 64,
                            "keys_manifest_sha256": None,
                        },
                    },
                    "credentials": {
                        "mode": "no-key",
                        "isolated_home": True,
                        "policy": "no-credentials",
                        "providers": [],
                    },
                    "preflight": {
                        "candidate_pipeline_disk": {
                            "schema_version": 1,
                            "check": "candidate_pipeline_disk",
                            "status": "sufficient",
                            "candidates": 10_000_000,
                            "bytes_per_candidate": 2_048,
                            "fixed_bytes": 2_147_483_648,
                            "estimated_payload_bytes": 22_627_483_648,
                            "margin_percent": 125,
                            "required_free_bytes": 28_284_354_560,
                            "available_free_bytes": 40_000_000_000,
                            "shortfall_bytes": 0,
                        },
                        "puredns_capacity": {
                            "schema_version": 1,
                            "check": "puredns_capacity",
                            "status": "coherent",
                            "corpus_candidates": 1_000_000,
                            "rate_limit_qps": 1_000,
                            "timeout_seconds": 1_860,
                            "headroom_percent": 125,
                            "estimated_minimum_seconds": 1_250,
                            "minimum_coherent_rate_qps": 673,
                            "capacity_candidates": 1_488_000,
                        },
                    },
                    "dns_fairness": {
                        "rate_limit_qps": 1_000,
                        "concurrency": 100,
                        "resolver_count": 3,
                        "resolvers_sha256": "2" * 64,
                        "controls": {
                            tool: sorted(controls)
                            for tool, controls in DNS_CONTROL_REQUIREMENTS.items()
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.campaign / "dns-transport.json").write_text(
            json.dumps(
                {
                    "status": "success",
                    "exit_code": 0,
                    "campaign_id": self.campaign_id,
                    "fellaga_sha256": self.fellaga_sha256,
                    "queries": 100_000,
                    "queries_per_second": 30_000,
                    "loss_rate": 0.0,
                    "max_rss_kib": 500_000,
                }
            ),
            encoding="utf-8",
        )
        (self.campaign / "candidate-pipeline.json").write_text(
            json.dumps(
                {
                    "status": "success",
                    "engine_status": "success",
                    "exit_code": 0,
                    "schema_version": 1,
                    "benchmark": "candidate_pipeline",
                    "engine": "fellaga_core",
                    "campaign_id": self.campaign_id,
                    "fellaga_sha256": self.fellaga_sha256,
                    "binary_sha256": self.fellaga_sha256,
                    "corpus_sha256": self.pipeline_sha256,
                    "wordlist_sha256": self.pipeline_sha256,
                    "candidates": 10_000_000,
                    "requested_candidates": 10_000_000,
                    "loaded_candidates": 10_000_000,
                    "persisted_candidates": 10_000_000,
                    "scheduled_candidates": 10_000_000,
                    "dns_dispatched_candidates": 10_000_000,
                    "processed_candidates": 10_000_000,
                    "positive_candidates": 0,
                    "definitive_negative_candidates": 10_000_000,
                    "indeterminate_candidates": 0,
                    "max_rss_kib": 500_000,
                }
            ),
            encoding="utf-8",
        )
        self.rows: list[dict[str, object]] = []
        for domain in self.domains:
            truth_names = [f"a.{domain}", f"b.{domain}"]
            (self.truth / f"{domain}.txt").write_text(
                "\n".join(truth_names) + "\n", encoding="utf-8"
            )
            for repetition in range(1, 4):
                for tool in REQUIRED_TOOLS:
                    found = truth_names if tool == "fellaga" else truth_names[:1]
                    (self.campaign / "live" / f"{domain}.{tool}.r{repetition}.txt").write_text(
                        "\n".join(found) + "\n", encoding="utf-8"
                    )
                    duration = 1.5 if tool == "fellaga" else 1.0
                    self.rows.append(
                        {
                            "campaign_id": self.campaign_id,
                            "domain": domain,
                            "tool": tool,
                            "repetition": repetition,
                            "status": 0,
                            "discovery_status": "success",
                            "validation_status": "success",
                            "discovery_duration_seconds": duration * 0.8,
                            "validation_duration_seconds": duration * 0.2,
                            "end_to_end_duration_seconds": duration,
                            "duration_seconds": duration,
                        }
                    )
        self.write_rows()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_rows(self) -> None:
        (self.campaign / "summary.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8"
        )

    def test_complete_campaign_passes_and_uses_correct_formulas(self) -> None:
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertTrue(summary["qualification_passed"])
        self.assertEqual(summary["ranked_domains"], 30)
        self.assertEqual(summary["fellaga_wins"], 30)
        self.assertEqual(summary["true_positives"], 60)
        self.assertEqual(summary["false_positives"], 0)
        self.assertEqual(summary["false_negatives"], 0)
        self.assertEqual(summary["precision"], 1.0)
        self.assertEqual(summary["recall"], 1.0)
        self.assertEqual(summary["false_discovery_rate"], 0.0)

    def test_qualification_requires_complete_aggregate_ground_truth_recall(self) -> None:
        for domain in self.domains:
            truth_path = self.truth / f"{domain}.txt"
            truth_path.write_text(
                truth_path.read_text(encoding="utf-8") + f"c.{domain}\n",
                encoding="utf-8",
            )

        report = build_report(self.campaign, self.truth)
        summary = report["summary"]

        self.assertEqual(summary["recall"], 2 / 3)
        self.assertEqual(summary["false_negatives"], 30)
        self.assertEqual(summary["fellaga_win_rate"], 1.0)
        self.assertEqual(summary["validated_gain"], 1.0)
        self.assertEqual(summary["false_discovery_rate"], 0.0)
        self.assertTrue(summary["deep_within_2x_best_coverage"])
        self.assertFalse(summary["qualification_passed"])
        self.assertEqual(
            summary["qualification_failures"],
            [
                "aggregate_ground_truth_recall_below_100_percent",
                "fellaga_run_ground_truth_recall_below_100_percent",
            ],
        )

    def test_tp_fp_fn_precision_recall_and_false_discovery_rate(self) -> None:
        domain = self.domains[0]
        path = self.campaign / "live" / f"{domain}.fellaga.r1.txt"
        path.write_text(f"a.{domain}\nfalse.{domain}\n", encoding="utf-8")
        report = build_report(self.campaign, self.truth)
        row = next(
            row
            for row in report["results"]
            if row.get("domain") == domain
            and row.get("tool") == "fellaga"
            and row.get("repetition") == 1
        )
        self.assertEqual(row["true_positives"], 1)
        self.assertEqual(row["false_positives"], 1)
        self.assertEqual(row["false_negatives"], 1)
        self.assertEqual(row["precision"], 0.5)
        self.assertEqual(row["recall"], 0.5)
        self.assertEqual(row["false_discovery_rate"], 0.5)
        self.assertFalse(report["summary"]["qualification_passed"])

    def test_failed_validation_fails_closed_and_is_not_ranked(self) -> None:
        failed = self.rows[0]
        failed["validation_status"] = "timeout"
        self.write_rows()
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("failed_or_timed_out_validation_runs", summary["qualification_failures"])
        self.assertEqual(summary["ranked_domains"], 29)
        result = next(
            row
            for row in report["results"]
            if row.get("domain") == failed["domain"]
            and row.get("tool") == failed["tool"]
            and row.get("repetition") == failed["repetition"]
        )
        self.assertFalse(result["eligible_for_ranking"])
        self.assertIsNone(result["exclusive_validated"])

    def test_skipped_validation_after_failed_discovery_fails_closed(self) -> None:
        failed = self.rows[0]
        failed["discovery_status"] = "timeout"
        failed["validation_status"] = "skipped"
        self.write_rows()
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn(
            "failed_or_timed_out_discovery_runs", summary["qualification_failures"]
        )
        self.assertIn(
            "failed_or_timed_out_validation_runs", summary["qualification_failures"]
        )

    def test_transport_only_cannot_satisfy_pipeline_gate(self) -> None:
        (self.campaign / "candidate-pipeline.json").unlink()
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn(
            "missing_candidate_pipeline_benchmark",
            summary["qualification_failures"],
        )
        self.assertNotIn("false_positive_rate", summary)

    def test_transport_status_must_be_explicitly_successful(self) -> None:
        transport = json.loads(
            (self.campaign / "dns-transport.json").read_text(encoding="utf-8")
        )
        transport.pop("status")
        (self.campaign / "dns-transport.json").write_text(
            json.dumps(transport), encoding="utf-8"
        )
        report = build_report(self.campaign, self.truth)
        self.assertFalse(report["summary"]["qualification_passed"])
        self.assertIn(
            "dns_transport_benchmark_failed",
            report["summary"]["qualification_failures"],
        )

    def test_invalid_authorized_domain_manifest_fails_closed(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["authorized_domains"] = "not-a-list"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("missing_or_invalid_manifest", summary["qualification_failures"])
        self.assertIn("invalid_authorized_domains", summary["manifest_issues"])

    def test_missing_repetition_and_truth_fail_closed(self) -> None:
        removed = self.rows.pop()
        self.write_rows()
        (self.truth / f"{self.domains[0]}.txt").unlink()
        report = build_report(self.campaign, self.truth)
        summary = report["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("missing_required_runs", summary["qualification_failures"])
        self.assertIn("missing_ground_truth", summary["qualification_failures"])
        expected_label = (
            f"{removed['domain']}/{removed['tool']}/r{removed['repetition']}"
        )
        self.assertIn(expected_label, summary["missing_required_runs"])

    def test_each_fellaga_repetition_requires_full_recall(self) -> None:
        domain = self.domains[0]
        (self.campaign / "live" / f"{domain}.fellaga.r1.txt").write_text(
            f"a.{domain}\n", encoding="utf-8"
        )
        (self.campaign / "live" / f"{domain}.fellaga.r2.txt").write_text(
            f"b.{domain}\n", encoding="utf-8"
        )
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertEqual(summary["recall"], 1.0)
        self.assertIn(
            "fellaga_run_ground_truth_recall_below_100_percent",
            summary["qualification_failures"],
        )
        self.assertEqual(
            summary["incomplete_fellaga_ground_truth_runs"],
            [f"{domain}/fellaga/r1", f"{domain}/fellaga/r2"],
        )

    def test_missing_or_inconsistent_timing_fails_closed(self) -> None:
        self.rows[0].pop("discovery_duration_seconds")
        self.rows[1]["end_to_end_duration_seconds"] = 99
        self.write_rows()
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertIn(
            "missing_or_inconsistent_timing_evidence",
            summary["qualification_failures"],
        )
        self.assertEqual(len(summary["invalid_timing_runs"]), 2)

    def test_invalid_candidate_pipeline_json_is_reported_without_exception(self) -> None:
        (self.campaign / "candidate-pipeline.json").write_text("{", encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn(
            "invalid_candidate_pipeline_json", summary["qualification_failures"]
        )

    def test_candidate_pipeline_rejects_processed_above_requested(self) -> None:
        path = self.campaign / "candidate-pipeline.json"
        pipeline = json.loads(path.read_text(encoding="utf-8"))
        pipeline["processed_candidates"] = 10_000_001
        path.write_text(json.dumps(pipeline), encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertIn(
            "candidate_pipeline_loss_at_or_above_1_percent",
            summary["qualification_failures"],
        )
        self.assertIn(
            "candidate_pipeline_incomplete_stage_counts",
            summary["qualification_failures"],
        )

    def test_extra_repetition_is_unexpected(self) -> None:
        extra = dict(self.rows[0])
        extra["repetition"] = 4
        self.rows.append(extra)
        domain = str(extra["domain"])
        tool = str(extra["tool"])
        (self.campaign / "live" / f"{domain}.{tool}.r4.txt").write_text(
            f"a.{domain}\nb.{domain}\n", encoding="utf-8"
        )
        self.write_rows()
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertIn(f"{domain}/{tool}/r4", summary["unexpected_runs"])
        self.assertIn(
            "invalid_benchmark_rows_or_domains", summary["qualification_failures"]
        )

    def test_false_positives_do_not_improve_win_ranking(self) -> None:
        for domain in self.domains:
            for repetition in range(1, 4):
                path = self.campaign / "live" / f"{domain}.subfinder.r{repetition}.txt"
                false_names = "".join(
                    f"false-{index}.{domain}\n" for index in range(20)
                )
                path.write_text(f"a.{domain}\n{false_names}", encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertEqual(summary["fellaga_wins"], 30)
        self.assertEqual(summary["best_competitor_true_positive_total"], 30)

    def test_artifacts_must_match_campaign_and_binary(self) -> None:
        path = self.campaign / "candidate-pipeline.json"
        pipeline = json.loads(path.read_text(encoding="utf-8"))
        pipeline["campaign_id"] = "different-campaign"
        pipeline["fellaga_sha256"] = "9" * 64
        path.write_text(json.dumps(pipeline), encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertIn(
            "candidate_pipeline_provenance_mismatch",
            summary["qualification_failures"],
        )

    def test_equal_keys_requires_non_secret_provider_evidence(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["mode"] = "equal-keys"
        manifest["provenance"]["inputs"]["keys_manifest_sha256"] = "3" * 64
        manifest["credentials"] = {
            "mode": "equal-keys",
            "isolated_home": True,
            "policy": "same-provider-keys",
            "providers": [
                {
                    "name": "provider",
                    "fellaga_env": "PROVIDER_API_KEY",
                    "configured_tools": [
                        "fellaga",
                        "subfinder",
                        "amass",
                        "bbot",
                    ],
                }
            ],
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertTrue(build_report(self.campaign, self.truth)["summary"]["qualification_passed"])

        manifest["credentials"]["providers"] = []
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("invalid_equal_keys_policy", summary["manifest_issues"])

    def test_missing_version_hash_and_dns_fairness_fail_manifest(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["versions"]["massdns"] = ""
        manifest["provenance"]["executables"]["fellaga"]["sha256"] = "bad"
        manifest["dns_fairness"]["resolvers_sha256"] = "9" * 64
        manifest["configuration"]["dns_transport_queries"] = 99_999
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("missing_version:massdns", summary["manifest_issues"])
        self.assertIn("invalid_executable_hash:fellaga", summary["manifest_issues"])
        self.assertIn("dns_resolver_hash_mismatch", summary["manifest_issues"])
        self.assertIn(
            "invalid_configuration:dns_transport_queries",
            summary["manifest_issues"],
        )

    def test_schema_two_capacity_preflights_fail_closed(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["preflight"]["candidate_pipeline_disk"][
            "available_free_bytes"
        ] = 1
        manifest["preflight"]["puredns_capacity"][
            "estimated_minimum_seconds"
        ] = 1
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("invalid_disk_preflight", summary["manifest_issues"])
        self.assertIn("invalid_puredns_preflight", summary["manifest_issues"])

    def test_puredns_preflight_must_match_manifest_corpus_count(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["provenance"]["inputs"]["active_corpus_candidates"] = 999_999
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertFalse(summary["qualification_passed"])
        self.assertIn("invalid_puredns_preflight", summary["manifest_issues"])

    def test_schema_one_campaign_remains_compatible(self) -> None:
        manifest_path = self.campaign / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema_version"] = 1
        manifest.pop("preflight")
        for field in (
            "fellaga_active_max_runtime_seconds",
            "candidate_pipeline_bytes_per_candidate",
            "candidate_pipeline_fixed_bytes",
            "candidate_pipeline_disk_margin_percent",
            "puredns_headroom_percent",
            "fellaga_profile_baselines",
        ):
            manifest["configuration"].pop(field)
        manifest["provenance"]["inputs"].pop("active_corpus_candidates")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        summary = build_report(self.campaign, self.truth)["summary"]
        self.assertTrue(summary["qualification_passed"])

    def test_require_pass_returns_nonzero_for_failed_qualification(self) -> None:
        self.assertEqual(
            report_main(
                [str(self.campaign), "--truth-root", str(self.truth), "--require-pass"]
            ),
            0,
        )
        (self.campaign / "candidate-pipeline.json").unlink()
        self.assertEqual(
            report_main(
                [str(self.campaign), "--truth-root", str(self.truth), "--require-pass"]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
