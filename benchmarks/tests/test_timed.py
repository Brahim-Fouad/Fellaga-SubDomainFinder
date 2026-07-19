from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest


BENCHMARKS = pathlib.Path(__file__).resolve().parents[1]
TIMED = BENCHMARKS / "timed.py"
sys.path.insert(0, str(BENCHMARKS))

from timed import LINGERING_PROCESS_EXIT_CODE, run_bounded


def process_is_alive(pid: int) -> bool:
    if os.name == "posix":
        stat = pathlib.Path(f"/proc/{pid}/stat")
        if stat.exists():
            fields = stat.read_text(encoding="utf-8").split()
            if len(fields) > 2 and fields[2] == "Z":
                return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class TimedRunnerTests(unittest.TestCase):
    def test_success_and_error_statuses_are_distinct(self) -> None:
        success = run_bounded([sys.executable, "-c", "pass"], 5, 0.1)
        error = run_bounded([sys.executable, "-c", "raise SystemExit(7)"], 5, 0.1)
        self.assertEqual(success["status"], "success")
        self.assertEqual(success["exit_code"], 0)
        self.assertEqual(error["status"], "error")
        self.assertEqual(error["exit_code"], 7)

    @unittest.skipUnless(os.name == "posix", "process-group assertion requires POSIX")
    def test_successful_leader_with_lingering_child_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = root / "helper.py"
            child_pid_file = root / "child-pid.txt"
            helper.write_text(
                "import pathlib, signal, subprocess, sys\n"
                "child_code = 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)'\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code])\n"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')\n",
                encoding="utf-8",
            )

            result = run_bounded(
                [sys.executable, str(helper), str(child_pid_file)], 5, 0.2
            )

            self.assertEqual(result["status"], "error")
            self.assertEqual(result["exit_code"], LINGERING_PROCESS_EXIT_CODE)
            self.assertTrue(result["interrupted"])
            self.assertIn("descendants", result["error"])
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and process_is_alive(child_pid):
                time.sleep(0.05)
            self.assertFalse(process_is_alive(child_pid))

    @unittest.skipUnless(os.name == "posix", "process-group assertion requires POSIX")
    def test_timeout_forces_complete_process_group_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = root / "helper.py"
            pids = root / "pids.txt"
            metrics = root / "metrics.json"
            helper.write_text(
                "import os, pathlib, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                "child_code = 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)'\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code])\n"
                "pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}', encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(TIMED),
                    "--timeout",
                    "0.5",
                    "--grace",
                    "0.2",
                    str(metrics),
                    "--",
                    sys.executable,
                    str(helper),
                    str(pids),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 124)
            result = json.loads(metrics.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "timeout")
            self.assertTrue(result["interrupted"])
            self.assertTrue(result["forced_kill"])
            recorded_pids = [int(value) for value in pids.read_text().split()]
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                process_is_alive(pid) for pid in recorded_pids
            ):
                time.sleep(0.05)
            self.assertFalse(any(process_is_alive(pid) for pid in recorded_pids))

    @unittest.skipUnless(os.name == "posix", "process-group assertion requires POSIX")
    def test_lingering_child_is_killed_after_leader_accepts_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = root / "helper.py"
            pids = root / "pids.txt"
            metrics = root / "metrics.json"
            helper.write_text(
                "import os, pathlib, subprocess, sys, time\n"
                "child_code = 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)'\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code])\n"
                "pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}', encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(TIMED),
                    "--timeout",
                    "0.5",
                    "--grace",
                    "0.5",
                    str(metrics),
                    "--",
                    sys.executable,
                    str(helper),
                    str(pids),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 124)
            result = json.loads(metrics.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "timeout")
            self.assertTrue(result["forced_kill"])
            recorded_pids = [int(value) for value in pids.read_text().split()]
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                process_is_alive(pid) for pid in recorded_pids
            ):
                time.sleep(0.05)
            self.assertFalse(any(process_is_alive(pid) for pid in recorded_pids))

    @unittest.skipUnless(os.name == "posix", "signal forwarding assertion requires POSIX")
    def test_external_sigterm_writes_metrics_and_reaps_child_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            helper = root / "helper.py"
            pids = root / "pids.txt"
            metrics = root / "metrics.json"
            helper.write_text(
                "import os, pathlib, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                "child_code = 'import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)'\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code])\n"
                "pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()} {child.pid}', encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            wrapper = subprocess.Popen(
                [
                    sys.executable,
                    str(TIMED),
                    "--timeout",
                    "30",
                    "--grace",
                    "0.2",
                    str(metrics),
                    "--",
                    sys.executable,
                    str(helper),
                    str(pids),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not pids.exists():
                time.sleep(0.02)
            self.assertTrue(pids.exists())
            os.kill(wrapper.pid, signal.SIGTERM)
            self.assertEqual(wrapper.wait(timeout=5), 128 + signal.SIGTERM)
            result = json.loads(metrics.read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "interrupted")
            self.assertEqual(result["exit_code"], 128 + signal.SIGTERM)
            self.assertTrue(result["interrupted"])
            recorded_pids = [int(value) for value in pids.read_text().split()]
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                process_is_alive(pid) for pid in recorded_pids
            ):
                time.sleep(0.05)
            self.assertFalse(any(process_is_alive(pid) for pid in recorded_pids))


if __name__ == "__main__":
    unittest.main()
