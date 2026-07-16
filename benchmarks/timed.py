#!/usr/bin/env python3
"""Run one benchmark command with a hard wall-clock deadline.

The child starts in its own process group. On timeout the complete group first
receives an interrupt, then a forced termination if it does not exit within the
grace period. Metrics are written even when spawning or execution fails.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Any

try:
    import resource
except ImportError:  # pragma: no cover - Windows compatibility
    resource = None  # type: ignore[assignment]


TIMEOUT_EXIT_CODE = 124
SPAWN_ERROR_EXIT_CODE = 126


class ExternalInterruption(Exception):
    """Raised by the CLI signal handler so the child group can be reaped."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"received signal {signum}")
        self.signum = signum


def _peak_rss_kib() -> int:
    if resource is None:
        return 0
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    value = int(usage.ru_maxrss)
    # macOS reports bytes while Linux and the benchmark schema use KiB.
    return value // 1024 if sys.platform == "darwin" else value


def _interrupt_group(process: subprocess.Popen[Any]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        return

    # CREATE_NEW_PROCESS_GROUP allows CTRL_BREAK_EVENT on Windows. Some hosts
    # do not attach a console; terminate() is the safe fallback there.
    try:  # pragma: no cover - exercised on Windows only
        process.send_signal(signal.CTRL_BREAK_EVENT)
    except (AttributeError, OSError):
        try:
            process.terminate()
        except OSError:
            pass


def _kill_group(process: subprocess.Popen[Any]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return

    # taskkill is the only standard Windows mechanism that reliably terminates
    # descendants. Fall back to Popen.kill if it is unavailable.
    try:  # pragma: no cover - exercised on Windows only
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass


def _group_still_exists(process: subprocess.Popen[Any]) -> bool:
    if os.name != "posix":  # pragma: no cover - descendants checked by taskkill
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_group(process: subprocess.Popen[Any], grace: float) -> bool:
    """Interrupt, kill if needed, and reap a complete child process group."""

    forced = False
    _interrupt_group(process)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        forced = True
        _kill_group(process)
    else:
        # The group leader may exit while a descendant ignores the interrupt.
        if _group_still_exists(process):
            forced = True
            _kill_group(process)
    try:
        process.wait(timeout=max(grace, 1.0))
    except subprocess.TimeoutExpired:
        forced = True
        process.kill()
        process.wait()
    return forced


def run_bounded(command: list[str], timeout: float, grace: float) -> dict[str, Any]:
    if not command:
        raise ValueError("a command is required")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if grace < 0:
        raise ValueError("grace must not be negative")

    started = time.monotonic()
    process: subprocess.Popen[Any] | None = None
    status = "error"
    exit_code = SPAWN_ERROR_EXIT_CODE
    interrupted = False
    forced = False
    error: str | None = None

    try:
        popen_options: dict[str, Any] = {}
        if os.name == "posix":
            popen_options["start_new_session"] = True
        else:  # pragma: no cover - exercised on Windows only
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        process = subprocess.Popen(command, **popen_options)
        try:
            exit_code = process.wait(timeout=timeout)
            status = "success" if exit_code == 0 else "error"
        except subprocess.TimeoutExpired:
            status = "timeout"
            exit_code = TIMEOUT_EXIT_CODE
            interrupted = True
            forced = _stop_group(process, grace)
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"
    except (ExternalInterruption, KeyboardInterrupt) as exc:
        signum = exc.signum if isinstance(exc, ExternalInterruption) else signal.SIGINT
        status = "interrupted"
        exit_code = 128 + int(signum)
        interrupted = True
        error = f"received signal {int(signum)}"
        if process is not None:
            forced = _stop_group(process, grace)
    finally:
        elapsed = time.monotonic() - started

    return {
        "status": status,
        "exit_code": exit_code,
        "duration_seconds": round(elapsed, 6),
        "max_rss_kib": _peak_rss_kib(),
        "timeout_seconds": timeout,
        "grace_seconds": grace,
        "interrupted": interrupted,
        "forced_kill": forced,
        "error": error,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a command with a process-group wall timeout"
    )
    parser.add_argument("--timeout", type=float, default=1800.0)
    parser.add_argument("--grace", type=float, default=5.0)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.grace < 0:
        parser.error("--grace must not be negative")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    handled_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        handled_signals.append(signal.SIGHUP)
    previous_handlers: dict[int, Any] = {}

    def raise_interruption(signum: int, _frame: Any) -> None:
        # Ignore repeats while cleanup runs; the first signal determines the
        # conventional 128+signal exit code written to the timing artifact.
        signal.signal(signum, signal.SIG_IGN)
        raise ExternalInterruption(signum)

    for signum in handled_signals:
        previous_handlers[int(signum)] = signal.getsignal(signum)
        signal.signal(signum, raise_interruption)
    try:
        result = run_bounded(args.command, args.timeout, args.grace)
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
