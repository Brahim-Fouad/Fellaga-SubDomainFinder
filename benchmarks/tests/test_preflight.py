from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
PREFLIGHT = BENCHMARKS / "preflight.py"
sys.path.insert(0, str(BENCHMARKS))

from preflight import (
    active_resolver_capacity_evidence,
    disk_evidence,
    estimate_disk_bytes,
)


class PreflightTests(unittest.TestCase):
    def test_disk_estimate_includes_fixed_cost_and_margin(self) -> None:
        estimated, required = estimate_disk_bytes(10, 200, 500, 125)
        self.assertEqual(estimated, 2_500)
        self.assertEqual(required, 3_125)

    @mock.patch("preflight.shutil.disk_usage")
    def test_disk_check_fails_closed_when_space_is_insufficient(self, usage) -> None:
        usage.return_value = mock.Mock(free=999)
        result = disk_evidence(pathlib.Path("."), 10, 100, 0, 100)
        self.assertEqual(result["status"], "insufficient")
        self.assertEqual(result["required_free_bytes"], 1_000)
        self.assertEqual(result["shortfall_bytes"], 1)

    def test_active_resolver_capacity_reports_required_rate(self) -> None:
        result = active_resolver_capacity_evidence(1_000_000, 100, 1_860, 125)
        self.assertEqual(result["status"], "incoherent")
        self.assertEqual(result["estimated_minimum_seconds"], 12_500)
        self.assertEqual(result["minimum_coherent_rate_qps"], 673)

        coherent = active_resolver_capacity_evidence(1_000_000, 1_000, 1_860, 125)
        self.assertEqual(coherent["status"], "coherent")
        self.assertEqual(coherent["estimated_minimum_seconds"], 1_250)

    def test_cli_persists_incoherent_capacity_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            corpus = root / "corpus.txt"
            corpus.write_text("one\ntwo\n", encoding="utf-8")
            output = root / "evidence.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PREFLIGHT),
                    "active-resolver",
                    "--corpus",
                    str(corpus),
                    "--rate-qps",
                    "1",
                    "--timeout-seconds",
                    "1",
                    "--headroom-percent",
                    "100",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "incoherent")
            self.assertEqual(evidence["check"], "active_resolver_capacity")
            self.assertEqual(evidence["corpus_candidates"], 2)

    def test_cli_records_filesystem_inspection_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "evidence.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PREFLIGHT),
                    "disk",
                    "--path",
                    str(root / "missing"),
                    "--candidates",
                    "10000000",
                    "--bytes-per-candidate",
                    "384",
                    "--fixed-bytes",
                    "2147483648",
                    "--margin-percent",
                    "125",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "error")


if __name__ == "__main__":
    unittest.main()
