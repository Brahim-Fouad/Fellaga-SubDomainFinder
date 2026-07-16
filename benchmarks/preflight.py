#!/usr/bin/env python3
"""Fail-closed capacity checks for benchmark campaigns."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import sys
import tempfile
from typing import Any


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _non_negative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def _percentage(value: str) -> int:
    parsed = int(value)
    if parsed < 100:
        raise argparse.ArgumentTypeError("must be at least 100")
    return parsed


def estimate_disk_bytes(
    candidates: int,
    bytes_per_candidate: int,
    fixed_bytes: int,
    margin_percent: int,
) -> tuple[int, int]:
    """Return the estimated payload and required free space."""

    if candidates <= 0 or bytes_per_candidate <= 0:
        raise ValueError("candidates and bytes_per_candidate must be positive")
    if fixed_bytes < 0:
        raise ValueError("fixed_bytes must not be negative")
    if margin_percent < 100:
        raise ValueError("margin_percent must be at least 100")
    estimated = candidates * bytes_per_candidate + fixed_bytes
    required = (estimated * margin_percent + 99) // 100
    return estimated, required


def disk_evidence(
    path: pathlib.Path,
    candidates: int,
    bytes_per_candidate: int,
    fixed_bytes: int,
    margin_percent: int,
) -> dict[str, Any]:
    estimated, required = estimate_disk_bytes(
        candidates, bytes_per_candidate, fixed_bytes, margin_percent
    )
    free = int(shutil.disk_usage(path).free)
    status = "sufficient" if free >= required else "insufficient"
    return {
        "schema_version": 1,
        "check": "candidate_pipeline_disk",
        "status": status,
        "candidates": candidates,
        "bytes_per_candidate": bytes_per_candidate,
        "fixed_bytes": fixed_bytes,
        "estimated_payload_bytes": estimated,
        "margin_percent": margin_percent,
        "required_free_bytes": required,
        "available_free_bytes": free,
        "shortfall_bytes": max(0, required - free),
    }


def count_corpus_candidates(path: pathlib.Path) -> int:
    with path.open("rb") as corpus:
        return sum(1 for line in corpus if line.strip())


def puredns_evidence(
    corpus_candidates: int,
    rate_qps: int,
    timeout_seconds: int,
    headroom_percent: int,
) -> dict[str, Any]:
    if corpus_candidates <= 0:
        raise ValueError("the PureDNS corpus must contain at least one candidate")
    if rate_qps <= 0 or timeout_seconds <= 0:
        raise ValueError("rate_qps and timeout_seconds must be positive")
    if headroom_percent < 100:
        raise ValueError("headroom_percent must be at least 100")

    weighted_candidates = corpus_candidates * headroom_percent
    rate_denominator = rate_qps * 100
    timeout_denominator = timeout_seconds * 100
    estimated_seconds = (weighted_candidates + rate_denominator - 1) // rate_denominator
    minimum_rate = (weighted_candidates + timeout_denominator - 1) // timeout_denominator
    capacity = (rate_qps * timeout_seconds * 100) // headroom_percent
    status = "coherent" if estimated_seconds <= timeout_seconds else "incoherent"
    return {
        "schema_version": 1,
        "check": "puredns_capacity",
        "status": status,
        "corpus_candidates": corpus_candidates,
        "rate_limit_qps": rate_qps,
        "timeout_seconds": timeout_seconds,
        "headroom_percent": headroom_percent,
        "estimated_minimum_seconds": estimated_seconds,
        "minimum_coherent_rate_qps": minimum_rate,
        "capacity_candidates": capacity,
    }


def _write_atomic(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="check", required=True)

    disk = subparsers.add_parser("disk", help="check candidate-pipeline disk space")
    disk.add_argument("--path", type=pathlib.Path, required=True)
    disk.add_argument("--candidates", type=_positive, required=True)
    disk.add_argument("--bytes-per-candidate", type=_positive, required=True)
    disk.add_argument("--fixed-bytes", type=_non_negative, required=True)
    disk.add_argument("--margin-percent", type=_percentage, required=True)
    disk.add_argument("--output", type=pathlib.Path, required=True)

    puredns = subparsers.add_parser(
        "puredns", help="check that corpus, QPS, and timeout are coherent"
    )
    puredns.add_argument("--corpus", type=pathlib.Path, required=True)
    puredns.add_argument("--rate-qps", type=_positive, required=True)
    puredns.add_argument("--timeout-seconds", type=_positive, required=True)
    puredns.add_argument("--headroom-percent", type=_percentage, required=True)
    puredns.add_argument("--output", type=pathlib.Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.check == "disk":
            if not args.path.is_dir():
                raise ValueError("disk inspection path must be an existing directory")
            result = disk_evidence(
                args.path,
                args.candidates,
                args.bytes_per_candidate,
                args.fixed_bytes,
                args.margin_percent,
            )
            passed = result["status"] == "sufficient"
        else:
            result = puredns_evidence(
                count_corpus_candidates(args.corpus),
                args.rate_qps,
                args.timeout_seconds,
                args.headroom_percent,
            )
            passed = result["status"] == "coherent"
    except (OSError, ValueError) as exc:
        result = {
            "schema_version": 1,
            "check": args.check,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }
        passed = False

    try:
        _write_atomic(args.output, result)
    except OSError as exc:
        print(f"unable to write preflight evidence: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
