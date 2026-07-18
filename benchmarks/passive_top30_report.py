#!/usr/bin/env python3
"""Build descriptive reports for the no-target-contact Tranco top-30 run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import pathlib
import platform
import shlex
import shutil
import statistics
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from names import NameError as BenchmarkNameError
from names import MAX_OBSERVATIONAL_NAMES, normalize_candidate, normalize_domain


BENCHMARKS = pathlib.Path(__file__).resolve().parent
REPOSITORY = BENCHMARKS.parent
DEFAULT_SOURCE_MANIFEST = BENCHMARKS / "data" / "tranco-74J5X-top30.json"
TOOLS = ("fellaga", "subfinder", "amass", "bbot")
CAMPAIGN_KIND = "passive-top30-observational"
RAW_TREE_MAX_FILES = 10_000
PREFLIGHT_MAX_FILES = 500
PREFLIGHT_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_CAMPAIGN_MAX_FILES = 50_000
DEFAULT_CAMPAIGN_MAX_BYTES = 2 * 1024 * 1024 * 1024

ISOLATED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ISOLATED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "NO_COLOR": "1",
    "PATH": ISOLATED_PATH,
    "TZ": "UTC",
}
ARTIFACT_KEYS = (
    "timing",
    "names",
    "stdout",
    "stderr",
    "parser_stderr",
    "raw_tree",
)
HARNESS_FILES = {
    "names.py": BENCHMARKS / "names.py",
    "passive_top30_report.py": pathlib.Path(__file__).resolve(),
    "redact.py": BENCHMARKS / "redact.py",
    "run-passive-top30.sh": BENCHMARKS / "run-passive-top30.sh",
    "timed.py": BENCHMARKS / "timed.py",
    "data/tranco-74J5X-top30.csv": BENCHMARKS
    / "data"
    / "tranco-74J5X-top30.csv",
    "data/tranco-74J5X-top30.json": DEFAULT_SOURCE_MANIFEST,
    "data/tranco-74J5X-top30.txt": BENCHMARKS
    / "data"
    / "tranco-74J5X-top30.txt",
}
VERSION_ARGUMENTS = {
    "fellaga": ["--version"],
    "subfinder": ["-version"],
    "amass": ["-version"],
    "bbot": ["--version"],
}

COMMAND_TEMPLATES: dict[str, list[str]] = {
    "fellaga": [
        "fellaga",
        "--db",
        "{state_db}",
        "scan",
        "--profile",
        "passive",
        "--no-target-contact",
        "--passive-concurrency",
        "{fellaga_passive_concurrency}",
        "--passive-zone-concurrency",
        "1",
        "--show",
        "{domain}",
    ],
    "subfinder": [
        "subfinder",
        "-silent",
        "-duc",
        "-all",
        "-rl",
        "{subfinder_rate_limit}",
        "-d",
        "{domain}",
    ],
    "amass": [
        "amass",
        "enum",
        "-passive",
        "-config",
        "/dev/null",
        "-d",
        "{domain}",
    ],
    "bbot": [
        "bbot",
        "-y",
        "-t",
        "{domain}",
        "-f",
        "subdomain-enum",
        "-rf",
        "passive",
        "-c",
        "dns.disable=true",
        "speculate=false",
        "-om",
        "json",
        "-o",
        "{output_directory}",
    ],
}

BASE_QUALIFICATION_FAILURES = [
    "passive_observational_corpus_has_no_ground_truth",
    "direct_target_validation_is_prohibited",
    "descriptive_counts_are_not_accuracy_measurements",
    "source_health_is_not_normalized_across_tools",
    "network_controls_are_tool_specific",
]


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def _write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _manifest_file(base: pathlib.Path, value: Any, field: str) -> pathlib.Path:
    if not isinstance(value, str) or not value or pathlib.Path(value).name != value:
        raise ValueError(f"source manifest field {field} must be a local file name")
    return base / value


def validate_source_manifest(
    path: pathlib.Path = DEFAULT_SOURCE_MANIFEST,
) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    """Verify the pinned excerpt and return its manifest and ranked domains."""

    source = _read_json(path)
    if source.get("schema_version") != 1 or source.get("list_id") != "74J5X":
        raise ValueError("unexpected Tranco source manifest schema or list ID")

    retrieval = source.get("retrieval")
    if not isinstance(retrieval, dict):
        raise ValueError("source manifest is missing retrieval metadata")
    base = path.parent
    csv_path = _manifest_file(base, retrieval.get("top30_csv_path"), "top30_csv_path")
    domains_path = _manifest_file(
        base, retrieval.get("top30_domains_path"), "top30_domains_path"
    )
    for data_path, hash_field in (
        (csv_path, "top30_csv_sha256"),
        (domains_path, "top30_domains_sha256"),
    ):
        expected_hash = retrieval.get(hash_field)
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ValueError(f"source manifest has an invalid {hash_field}")
        if not data_path.is_file() or _sha256(data_path) != expected_hash:
            raise ValueError(f"source data hash mismatch: {data_path}")

    ranked: list[tuple[int, str]] = []
    try:
        with csv_path.open("r", encoding="utf-8", errors="strict", newline="") as handle:
            for row in csv.reader(handle):
                if len(row) != 2:
                    raise ValueError("ranked source rows must contain exactly two columns")
                rank = int(row[0])
                domain = normalize_domain(row[1])
                if row[1] != domain:
                    raise ValueError("ranked source domains must already be canonical")
                ranked.append((rank, domain))
    except (OSError, UnicodeError, csv.Error, BenchmarkNameError) as exc:
        raise ValueError(f"cannot parse ranked source data: {exc}") from exc

    if [rank for rank, _domain in ranked] != list(range(1, 31)):
        raise ValueError("ranked source data must contain ranks 1 through 30 exactly once")
    csv_domains = [domain for _rank, domain in ranked]
    if len(set(csv_domains)) != 30:
        raise ValueError("ranked source data contains duplicate domains")

    try:
        listed_domains = domains_path.read_text(
            encoding="utf-8", errors="strict"
        ).splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot parse domain source data: {exc}") from exc
    if listed_domains != csv_domains:
        raise ValueError("ranked CSV and domain-only source data disagree")

    licensing = source.get("licensing")
    if not isinstance(licensing, dict):
        raise ValueError("source manifest is missing its licensing notice")
    if licensing.get("aggregate_license_asserted") is not False:
        raise ValueError("the source manifest must not assert an aggregate license")
    if licensing.get("fellaga_mit_license_applies_to_excerpt") is not False:
        raise ValueError("the source manifest must exclude the excerpt from Fellaga's MIT license")
    if not isinstance(licensing.get("notice"), str) or not licensing["notice"].strip():
        raise ValueError("source manifest is missing a licensing notice")

    return source, ranked


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = result.stdout.strip()
    return commit if len(commit) == 40 else None


def _git_worktree_clean() -> bool | None:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
            cwd=REPOSITORY,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return not result.stdout


def _platform_metadata() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def _no_key_environment(isolation_root: pathlib.Path) -> dict[str, str]:
    environment = dict(ISOLATED_ENVIRONMENT)
    home = isolation_root / "home"
    config = isolation_root / "config"
    data = isolation_root / "data"
    cache = isolation_root / "cache"
    state = isolation_root / "state"
    for directory in (home, config, data, cache, state):
        directory.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_DATA_HOME": str(data),
            "XDG_CACHE_HOME": str(cache),
            "XDG_STATE_HOME": str(state),
        }
    )
    return environment


def _snapshot_harness(campaign: pathlib.Path) -> dict[str, dict[str, str]]:
    snapshot: dict[str, dict[str, str]] = {}
    for name, source in HARNESS_FILES.items():
        if not source.is_file():
            raise ValueError(f"benchmark harness file is missing: {source}")
        destination = campaign / "harness" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        source_hash = _sha256(source)
        if _sha256(destination) != source_hash:
            raise ValueError(f"benchmark harness snapshot failed: {source}")
        snapshot[name] = {
            "path": destination.relative_to(campaign).as_posix(),
            "sha256": source_hash,
        }
    return snapshot


def write_tree_manifest(
    campaign: pathlib.Path, root: pathlib.Path, output: pathlib.Path
) -> None:
    campaign_root = campaign.resolve()
    tree_root = root.resolve()
    try:
        tree_root.relative_to(campaign_root)
        output.resolve().relative_to(campaign_root)
    except ValueError as exc:
        raise ValueError("raw tree manifest paths must remain inside the campaign") from exc
    if not tree_root.is_dir():
        raise ValueError("raw tree root is not a directory")
    campaign_manifest = _read_json(campaign / "manifest.json")
    maximum_bytes = int(campaign_manifest["execution_limits"]["max_file_bytes"])
    files: list[dict[str, str]] = []
    total_bytes = 0
    for path in sorted(tree_root.rglob("*")):
        if path.is_symlink():
            raise ValueError("raw tree contains a symbolic link")
        if not path.is_file():
            continue
        if len(files) >= RAW_TREE_MAX_FILES:
            raise ValueError("raw tree exceeds its file-count limit")
        resolved = path.resolve()
        try:
            resolved.relative_to(tree_root)
        except ValueError as exc:
            raise ValueError("raw tree file escapes its directory") from exc
        total_bytes += resolved.stat().st_size
        if total_bytes > maximum_bytes:
            raise ValueError("raw tree exceeds its cumulative size limit")
        files.append(
            {
                "path": resolved.relative_to(campaign_root).as_posix(),
                "sha256": _sha256(resolved),
            }
        )
    _write_json(
        output,
        {
            "schema_version": 1,
            "root": tree_root.relative_to(campaign_root).as_posix(),
            "files": files,
        },
    )


def _validate_tree_manifest(campaign: pathlib.Path, path: pathlib.Path) -> None:
    document = _read_json(path)
    files = document.get("files")
    root_value = document.get("root")
    if (
        set(document) != {"schema_version", "root", "files"}
        or document.get("schema_version") != 1
        or not isinstance(root_value, str)
        or not root_value
        or pathlib.Path(root_value).is_absolute()
        or not isinstance(files, list)
    ):
        raise ValueError("raw tree manifest schema is invalid")
    campaign_root = campaign.resolve()
    tree_root = (campaign / root_value).resolve()
    try:
        tree_root.relative_to(campaign_root)
    except ValueError as exc:
        raise ValueError("raw tree root escapes the campaign") from exc
    if not tree_root.is_dir():
        raise ValueError("raw tree root is missing")
    previous = ""
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("raw tree manifest entry is invalid")
        relative = entry.get("path")
        expected_hash = entry.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or relative in seen
            or relative <= previous
            or pathlib.Path(relative).is_absolute()
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
        ):
            raise ValueError("raw tree manifest entry is invalid")
        candidate = (campaign / relative).resolve()
        try:
            candidate.relative_to(campaign_root)
        except ValueError as exc:
            raise ValueError("raw tree artifact escapes the campaign") from exc
        if not candidate.is_file() or _sha256(candidate) != expected_hash:
            raise ValueError("raw tree artifact hash mismatch")
        previous = relative
        seen.add(relative)
    current: dict[str, str] = {}
    total_bytes = 0
    campaign_manifest = _read_json(campaign / "manifest.json")
    maximum_bytes = int(campaign_manifest["execution_limits"]["max_file_bytes"])
    for candidate in sorted(tree_root.rglob("*")):
        if candidate.is_symlink():
            raise ValueError("raw tree contains a symbolic link")
        if not candidate.is_file():
            continue
        if len(current) >= RAW_TREE_MAX_FILES:
            raise ValueError("raw tree exceeds its file-count limit")
        resolved = candidate.resolve()
        try:
            resolved.relative_to(tree_root)
        except ValueError as exc:
            raise ValueError("raw tree artifact escapes its root") from exc
        total_bytes += resolved.stat().st_size
        if total_bytes > maximum_bytes:
            raise ValueError("raw tree exceeds its cumulative size limit")
        current[resolved.relative_to(campaign_root).as_posix()] = _sha256(resolved)
    declared = {str(entry["path"]): str(entry["sha256"]) for entry in files}
    if current != declared:
        raise ValueError("raw tree contents do not match its manifest")


def _safe_remove_tree(campaign: pathlib.Path, path: pathlib.Path) -> None:
    campaign_root = campaign.resolve()
    absolute = pathlib.Path(os.path.abspath(path))
    try:
        absolute.relative_to(campaign_root)
    except ValueError as exc:
        raise ValueError("cleanup path escapes the campaign") from exc
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(campaign_root)
        except ValueError as exc:
            raise ValueError("cleanup target escapes the campaign") from exc
        shutil.rmtree(resolved)


def cleanup_preflight(campaign: pathlib.Path) -> None:
    preflight = campaign / "preflight"
    if not preflight.exists():
        return
    if preflight.is_symlink() or not preflight.is_dir():
        raise ValueError("preflight path is unsafe")
    for tool_directory in list(preflight.iterdir()):
        if tool_directory.name == "identities":
            _safe_remove_tree(campaign, tool_directory)
            continue
        if tool_directory.is_symlink():
            raise ValueError("preflight tool path is a symbolic link")
        if not tool_directory.is_dir():
            continue
        for name in ("home", "config", "data", "cache", "state", "output"):
            _safe_remove_tree(campaign, tool_directory / name)


def cleanup_run(
    campaign: pathlib.Path, isolation: pathlib.Path, state_prefix: pathlib.Path
) -> None:
    campaign_root = campaign.resolve()
    expected_isolation_parent = pathlib.Path(os.path.abspath(campaign / "isolation"))
    expected_state_parent = pathlib.Path(os.path.abspath(campaign / "state"))
    if pathlib.Path(os.path.abspath(isolation)).parent != expected_isolation_parent:
        raise ValueError("run isolation cleanup path is invalid")
    if pathlib.Path(os.path.abspath(state_prefix)).parent != expected_state_parent:
        raise ValueError("run state cleanup path is invalid")
    _safe_remove_tree(campaign, isolation)
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = pathlib.Path(str(state_prefix) + suffix)
        if candidate.is_symlink():
            candidate.unlink()
        elif candidate.exists():
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(campaign_root)
            except ValueError as exc:
                raise ValueError("run state cleanup path escapes the campaign") from exc
            if not resolved.is_file():
                raise ValueError("run state cleanup target is not a file")
            resolved.unlink()


def cleanup_all_ephemeral(campaign: pathlib.Path) -> None:
    cleanup_preflight(campaign)
    _safe_remove_tree(campaign, campaign / "isolation")
    _safe_remove_tree(campaign, campaign / "state")
    _safe_remove_tree(campaign, campaign / "identity-check")


def _ephemeral_paths(campaign: pathlib.Path) -> list[pathlib.Path]:
    paths = [
        campaign / "isolation",
        campaign / "state",
        campaign / "identity-check",
        campaign / "preflight" / "identities",
    ]
    preflight = campaign / "preflight"
    if preflight.is_symlink():
        paths.append(preflight)
    elif preflight.exists() and preflight.is_dir():
        for tool_directory in preflight.iterdir():
            if tool_directory.name == "identities":
                continue
            if tool_directory.is_symlink():
                paths.append(tool_directory)
                continue
            if not tool_directory.is_dir():
                continue
            paths.extend(
                tool_directory / name
                for name in ("home", "config", "data", "cache", "state", "output")
            )
    return paths


def campaign_usage(campaign: pathlib.Path) -> dict[str, int]:
    campaign_root = campaign.resolve()
    file_count = 0
    total_bytes = 0
    for path in campaign.rglob("*"):
        if path.is_symlink():
            raise ValueError("campaign contains a symbolic link")
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(campaign_root)
        except ValueError as exc:
            raise ValueError("campaign artifact escapes its root") from exc
        file_count += 1
        total_bytes += resolved.stat().st_size
    return {"file_count": file_count, "total_bytes": total_bytes}


def enforce_campaign_quota(
    campaign: pathlib.Path, manifest: dict[str, Any] | None = None
) -> dict[str, int]:
    if manifest is None:
        manifest = _read_json(campaign / "manifest.json")
    limits = manifest.get("execution_limits")
    if not isinstance(limits, dict):
        raise ValueError("campaign execution limits are missing")
    usage = campaign_usage(campaign)
    maximum_files = limits.get("campaign_max_files")
    maximum_bytes = limits.get("campaign_max_bytes")
    if type(maximum_files) is not int or type(maximum_bytes) is not int:
        raise ValueError("campaign cumulative limits are invalid")
    if usage["file_count"] > maximum_files:
        raise ValueError("campaign exceeds its cumulative file-count limit")
    if usage["total_bytes"] > maximum_bytes:
        raise ValueError("campaign exceeds its cumulative size limit")
    return usage


def _preflight_evidence(campaign: pathlib.Path) -> dict[str, str]:
    preflight = campaign / "preflight"
    evidence: dict[str, str] = {}
    total = 0
    if not preflight.exists():
        return evidence
    for path in sorted(preflight.rglob("*")):
        if path.is_symlink():
            raise ValueError("preflight evidence contains a symbolic link")
        if not path.is_file():
            continue
        if len(evidence) >= PREFLIGHT_MAX_FILES:
            raise ValueError("preflight evidence exceeds its file-count limit")
        total += path.stat().st_size
        if total > PREFLIGHT_MAX_BYTES:
            raise ValueError("preflight evidence exceeds its size limit")
        evidence[path.resolve().relative_to(campaign.resolve()).as_posix()] = _sha256(path)
    return evidence


def _validate_preflight_evidence(
    campaign: pathlib.Path, manifest: dict[str, Any]
) -> None:
    expected = manifest.get("preflight_evidence")
    if not isinstance(expected, dict) or not all(
        isinstance(path, str) and isinstance(value, str) and len(value) == 64
        for path, value in expected.items()
    ):
        raise ValueError("campaign preflight evidence manifest is invalid")
    if _preflight_evidence(campaign) != expected:
        raise ValueError("campaign preflight evidence changed")


def _validate_harness(campaign: pathlib.Path, manifest: dict[str, Any]) -> None:
    harness = manifest.get("harness")
    if not isinstance(harness, dict) or set(harness) != set(HARNESS_FILES):
        raise ValueError("campaign harness manifest is invalid")
    campaign_root = campaign.resolve()
    for name, source in HARNESS_FILES.items():
        metadata = harness.get(name)
        if not isinstance(metadata, dict):
            raise ValueError("campaign harness entry is invalid")
        relative = metadata.get("path")
        expected_hash = metadata.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or pathlib.Path(relative).is_absolute()
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
        ):
            raise ValueError("campaign harness entry is invalid")
        snapshot = (campaign / relative).resolve()
        try:
            snapshot.relative_to(campaign_root)
        except ValueError as exc:
            raise ValueError("campaign harness snapshot escapes its directory") from exc
        if (
            not snapshot.is_file()
            or _sha256(snapshot) != expected_hash
            or not source.is_file()
            or _sha256(source) != expected_hash
        ):
            raise ValueError(f"campaign harness changed: {name}")


def _tool_identity(
    campaign: pathlib.Path, tool: str, executable: str
) -> dict[str, Any]:
    path = pathlib.Path(executable).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"runnable tool does not resolve to a file: {tool}")
    identity: dict[str, Any] = {
        "executable": str(path),
        "sha256": _sha256(path),
        "version": None,
        "version_probe_status": "error",
    }
    probe_root = campaign / "preflight" / "identities" / tool
    environment = _no_key_environment(probe_root)
    timing_path = probe_root / "version.timing.json"
    stdout_path = probe_root / "version.stdout.txt"
    stderr_path = probe_root / "version.stderr.txt"
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(
                [
                    sys.executable,
                    str(BENCHMARKS / "timed.py"),
                    "--timeout",
                    "10",
                    "--grace",
                    "1",
                    "--max-file-bytes",
                    str(1024 * 1024),
                    str(timing_path),
                    "--",
                    str(path),
                    *VERSION_ARGUMENTS[tool],
                ],
                check=False,
                stdout=stdout,
                stderr=stderr,
                env=environment,
            )
    except OSError:
        return identity
    try:
        timing = _read_json(timing_path)
        output = " ".join(
            (
                stdout_path.read_text(encoding="utf-8", errors="replace")
                + "\n"
                + stderr_path.read_text(encoding="utf-8", errors="replace")
            ).split()
        )[:512]
    except (OSError, ValueError):
        return identity
    identity["version"] = output or None
    probe_status = timing.get("status")
    if probe_status == "timeout":
        identity["version_probe_status"] = "timeout"
    elif result.returncode == 0 and probe_status == "success":
        identity["version_probe_status"] = "success"
    else:
        identity["version_probe_status"] = "error"
    if tool == "bbot":
        identity["python_distribution"] = _python_distribution_identity(
            path, environment, "bbot"
        )
        if identity["python_distribution"].get("status") != "success":
            raise ValueError("BBOT Python distribution identity is unavailable")
    return identity


def _python_distribution_identity(
    executable: pathlib.Path, environment: dict[str, str], distribution: str
) -> dict[str, Any]:
    identity: dict[str, Any] = {"status": "unavailable"}
    try:
        first_line = executable.open("rb").readline(4096).decode("utf-8").strip()
        if not first_line.startswith("#!"):
            return identity
        command = shlex.split(first_line[2:])
        if not command or not pathlib.Path(command[0]).is_absolute():
            return identity
        launcher = pathlib.Path(command[0])
        if not launcher.is_file():
            return identity
        resolved_interpreter = launcher.resolve(strict=True)
    except (OSError, UnicodeError, ValueError):
        return identity
    script = r'''
import hashlib
import importlib.metadata
import json
import pathlib
import sys

distribution = importlib.metadata.distribution(sys.argv[1])
digest = hashlib.sha256()
count = 0
total = 0
for relative in sorted(distribution.files or [], key=str):
    path = pathlib.Path(distribution.locate_file(relative))
    if not path.is_file():
        continue
    payload_size = path.stat().st_size
    count += 1
    total += payload_size
    if count > 10000 or total > 536870912:
        raise RuntimeError("distribution identity limit exceeded")
    digest.update(str(relative).encode("utf-8"))
    digest.update(b"\0")
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1048576), b""):
            digest.update(block)
print(json.dumps({
    "status": "success",
    "version": distribution.version,
    "location": str(distribution.locate_file("")),
    "file_count": count,
    "total_bytes": total,
    "tree_sha256": digest.hexdigest(),
}, sort_keys=True))
'''
    try:
        completed = subprocess.run(
            [str(launcher), *command[1:], "-c", script, distribution],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return identity
    if completed.returncode != 0:
        return identity
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return identity
    if not isinstance(value, dict) or value.get("status") != "success":
        return identity
    value["interpreter_launcher"] = str(launcher)
    value["interpreter_resolved"] = str(resolved_interpreter)
    value["interpreter_sha256"] = _sha256(resolved_interpreter)
    return value


def _verify_tool_identity(
    campaign: pathlib.Path, tool: str, metadata: dict[str, Any]
) -> None:
    executable = metadata.get("executable")
    executable_hash = metadata.get("sha256")
    if (
        not isinstance(executable, str)
        or not isinstance(executable_hash, str)
        or len(executable_hash) != 64
    ):
        raise ValueError(f"tool identity is invalid in this campaign: {tool}")
    executable_path = pathlib.Path(executable)
    if not executable_path.is_file() or _sha256(executable_path) != executable_hash:
        raise ValueError(f"tool executable changed during the campaign: {tool}")
    if tool == "bbot":
        expected = metadata.get("python_distribution")
        identity_root = campaign / "identity-check"
        try:
            environment = _no_key_environment(identity_root / tool)
            observed = _python_distribution_identity(executable_path, environment, "bbot")
        finally:
            shutil.rmtree(identity_root, ignore_errors=True)
        if not isinstance(expected, dict) or observed != expected:
            raise ValueError("BBOT Python distribution changed during the campaign")


def verify_campaign_tool(campaign: pathlib.Path, tool: str) -> None:
    manifest = _read_json(campaign / "manifest.json")
    if manifest.get("campaign_kind") != CAMPAIGN_KIND:
        raise ValueError("not a passive top-30 campaign")
    _validate_campaign_policy(manifest)
    _validate_harness(campaign, manifest)
    _validate_preflight_evidence(campaign, manifest)
    metadata = manifest.get("tools", {}).get(tool)
    if not isinstance(metadata, dict) or metadata.get("status") != "runnable":
        raise ValueError(f"tool is not runnable in this campaign: {tool}")
    _verify_tool_identity(campaign, tool, metadata)


def prepare_campaign(
    campaign: pathlib.Path,
    repetitions: int,
    runnable: dict[str, str],
    missing: dict[str, str],
    skipped: dict[str, str],
    source_manifest: pathlib.Path = DEFAULT_SOURCE_MANIFEST,
    discovery_timeout_seconds: float = 900.0,
    timeout_grace_seconds: float = 5.0,
    preflight_timeout_seconds: float = 60.0,
    campaign_max_runtime_seconds: float = 7200.0,
    cooldown_seconds: float = 1.0,
    consecutive_failure_threshold: int = 3,
    subfinder_rate_limit: int = 5,
    fellaga_passive_concurrency: int = 4,
    cleanup_timeout_seconds: int = 60,
    redaction_timeout_seconds: int = 60,
    max_file_bytes: int = 268_435_456,
    campaign_max_files: int = DEFAULT_CAMPAIGN_MAX_FILES,
    campaign_max_bytes: int = DEFAULT_CAMPAIGN_MAX_BYTES,
) -> dict[str, Any]:
    if not 1 <= repetitions <= 10:
        raise ValueError("repetitions must be between 1 and 10")
    for label, value in (
        ("discovery timeout", discovery_timeout_seconds),
        ("timeout grace", timeout_grace_seconds),
        ("preflight timeout", preflight_timeout_seconds),
        ("campaign maximum runtime", campaign_max_runtime_seconds),
        ("inter-run cooldown", cooldown_seconds),
    ):
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{label} must be finite and greater than zero")
    for label, value, minimum, maximum in (
        ("consecutive failure threshold", consecutive_failure_threshold, 1, 10),
        ("Subfinder rate limit", subfinder_rate_limit, 1, 20),
        ("Fellaga passive concurrency", fellaga_passive_concurrency, 1, 8),
        ("cleanup timeout", cleanup_timeout_seconds, 1, 60),
        ("redaction timeout", redaction_timeout_seconds, 1, 60),
        ("maximum file bytes", max_file_bytes, 1_048_576, 1_073_741_824),
        ("campaign maximum files", campaign_max_files, 1_000, 1_000_000),
        (
            "campaign maximum bytes",
            campaign_max_bytes,
            64 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ),
    ):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{label} must be between {minimum} and {maximum}")
    classifications = [set(runnable), set(missing), set(skipped)]
    if any(left & right for index, left in enumerate(classifications) for right in classifications[index + 1 :]):
        raise ValueError("each tool must have exactly one status")
    if set().union(*classifications) != set(TOOLS):
        raise ValueError("all supported tools must have an explicit status")

    source, ranked = validate_source_manifest(source_manifest)
    harness = _snapshot_harness(campaign)
    tool_status: dict[str, dict[str, Any]] = {}
    for tool in TOOLS:
        if tool in runnable:
            identity = _tool_identity(campaign, tool, runnable[tool])
            tool_status[tool] = {"status": "runnable", "reason": None, **identity}
        elif tool in missing:
            tool_status[tool] = {
                "status": "missing",
                "executable": None,
                "reason": missing[tool],
            }
        else:
            tool_status[tool] = {
                "status": "skipped",
                "executable": None,
                "reason": skipped[tool],
            }
    cleanup_preflight(campaign)
    preflight_evidence = _preflight_evidence(campaign)

    manifest = {
        "schema_version": 1,
        "campaign_kind": CAMPAIGN_KIND,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repository_commit": _git_commit(),
        "repository_worktree_clean": _git_worktree_clean(),
        "platform": _platform_metadata(),
        "repetitions": repetitions,
        "execution_limits": {
            "discovery_timeout_seconds": discovery_timeout_seconds,
            "timeout_grace_seconds": timeout_grace_seconds,
            "preflight_timeout_seconds": preflight_timeout_seconds,
            "campaign_max_runtime_seconds": campaign_max_runtime_seconds,
            "cooldown_seconds": cooldown_seconds,
            "consecutive_failure_threshold": consecutive_failure_threshold,
            "subfinder_rate_limit": subfinder_rate_limit,
            "fellaga_passive_concurrency": fellaga_passive_concurrency,
            "cleanup_timeout_seconds": cleanup_timeout_seconds,
            "redaction_timeout_seconds": redaction_timeout_seconds,
            "max_file_bytes": max_file_bytes,
            "raw_tree_max_files": RAW_TREE_MAX_FILES,
            "campaign_max_files": campaign_max_files,
            "campaign_max_bytes": campaign_max_bytes,
        },
        "harness": harness,
        "preflight_evidence": preflight_evidence,
        "source": {
            "list_id": source["list_id"],
            "generated_on": source["generated_on"],
            "permanent_list_page": source["retrieval"]["permanent_list_page"],
            "permanent_csv": source["retrieval"]["permanent_csv"],
            "source_csv_sha256": source["retrieval"]["source_csv_sha256"],
            "top30_csv_sha256": source["retrieval"]["top30_csv_sha256"],
            "top30_domains_sha256": source["retrieval"]["top30_domains_sha256"],
            "attribution": source["attribution"],
            "licensing": source["licensing"],
        },
        "domains": [{"rank": rank, "domain": domain} for rank, domain in ranked],
        "tools": tool_status,
        "command_policy": COMMAND_TEMPLATES,
        "contact_policy": {
            "target_contact": "prohibited",
            "direct_dns_resolution": False,
            "direct_http_or_tls": False,
            "third_party_passive_provider_requests": True,
            "bbot_requires_no_dns_preflight": True,
            "bbot_dns_fallback_allowed": False,
        },
        "credential_policy": {
            "mode": "no-key",
            "isolated_per_run": True,
            "isolated_home": True,
            "isolated_xdg_config": True,
            "isolated_xdg_data": True,
            "isolated_xdg_cache": True,
            "credential_environment_cleared": True,
            "inherited_tool_configuration": False,
            "environment_mode": "allowlist",
            "inherited_environment": False,
            "environment_allowlist": sorted(
                [*ISOLATED_ENVIRONMENT, "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]
            ),
            "proxy_environment_inherited": False,
        },
        "execution_order_policy": "rotate-left-by-domain-and-repetition",
        "claims": {
            "qualification_eligible": False,
            "qualification_passed": False,
            "best_tool_claim_allowed": False,
            "reason_codes": BASE_QUALIFICATION_FAILURES,
        },
    }
    manifest_path = campaign / "manifest.json"
    if manifest_path.exists():
        raise ValueError(f"campaign manifest already exists: {manifest_path}")
    _write_json(manifest_path, manifest)
    return manifest


def _campaign_relative(campaign: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(campaign.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"artifact is outside the campaign: {path}") from exc


def _validate_campaign_policy(manifest: dict[str, Any]) -> None:
    if manifest.get("command_policy") != COMMAND_TEMPLATES:
        raise ValueError("campaign command policy does not match the passive allowlist")
    contact = manifest.get("contact_policy")
    if not isinstance(contact, dict) or any(
        (
            contact.get("target_contact") != "prohibited",
            contact.get("direct_dns_resolution") is not False,
            contact.get("direct_http_or_tls") is not False,
            contact.get("third_party_passive_provider_requests") is not True,
            contact.get("bbot_requires_no_dns_preflight") is not True,
            contact.get("bbot_dns_fallback_allowed") is not False,
        )
    ):
        raise ValueError("campaign contact policy is not fail-closed")
    credentials = manifest.get("credential_policy")
    if not isinstance(credentials, dict) or any(
        (
            credentials.get("mode") != "no-key",
            credentials.get("isolated_per_run") is not True,
            credentials.get("isolated_home") is not True,
            credentials.get("isolated_xdg_config") is not True,
            credentials.get("isolated_xdg_data") is not True,
            credentials.get("isolated_xdg_cache") is not True,
            credentials.get("credential_environment_cleared") is not True,
            credentials.get("inherited_tool_configuration") is not False,
            credentials.get("environment_mode") != "allowlist",
            credentials.get("inherited_environment") is not False,
            credentials.get("proxy_environment_inherited") is not False,
        )
    ):
        raise ValueError("campaign credential policy is not isolated no-key mode")
    if manifest.get("execution_order_policy") != "rotate-left-by-domain-and-repetition":
        raise ValueError("campaign execution-order policy is invalid")
    limits = manifest.get("execution_limits")
    if not isinstance(limits, dict):
        raise ValueError("campaign execution limits are missing")
    for field in (
        "discovery_timeout_seconds",
        "timeout_grace_seconds",
        "preflight_timeout_seconds",
        "campaign_max_runtime_seconds",
        "cooldown_seconds",
    ):
        value = limits.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ValueError("campaign execution limits are invalid")
    for field, minimum, maximum in (
        ("consecutive_failure_threshold", 1, 10),
        ("subfinder_rate_limit", 1, 20),
        ("fellaga_passive_concurrency", 1, 8),
        ("cleanup_timeout_seconds", 1, 60),
        ("redaction_timeout_seconds", 1, 60),
        ("max_file_bytes", 1_048_576, 1_073_741_824),
        ("campaign_max_files", 1_000, 1_000_000),
        ("campaign_max_bytes", 64 * 1024 * 1024, 100 * 1024 * 1024 * 1024),
    ):
        value = limits.get(field)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("campaign execution limits are invalid")
    if limits.get("raw_tree_max_files") != RAW_TREE_MAX_FILES:
        raise ValueError("campaign execution limits are invalid")
    claims = manifest.get("claims")
    if not isinstance(claims, dict) or any(
        (
            claims.get("qualification_eligible") is not False,
            claims.get("qualification_passed") is not False,
            claims.get("best_tool_claim_allowed") is not False,
        )
    ):
        raise ValueError("campaign claim policy is not descriptive-only")


def _canonical_names(path: pathlib.Path, domain: str) -> list[str]:
    names: list[str] = []
    previous: str | None = None
    try:
        handle = path.open("r", encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read normalized names from {path}: {exc}") from exc
    try:
        with handle:
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")
                if not line:
                    raise ValueError(f"normalized names contain a blank row: {path}")
                try:
                    normalized = normalize_candidate(line, domain)
                except BenchmarkNameError as exc:
                    raise ValueError(f"invalid normalized name in {path}: {exc}") from exc
                if normalized is None or normalized != line:
                    raise ValueError(f"normalized names are not canonical: {path}")
                if previous is not None and line <= previous:
                    raise ValueError(f"normalized names are not sorted and unique: {path}")
                if len(names) >= MAX_OBSERVATIONAL_NAMES:
                    raise ValueError(f"normalized names exceed the campaign limit: {path}")
                names.append(line)
                previous = line
    except UnicodeError as exc:
        raise ValueError(f"cannot decode normalized names from {path}: {exc}") from exc
    return names


def _parser_diagnostic_count(path: pathlib.Path, key: str) -> int:
    count = 0
    seen = False
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read parser diagnostics from {path}: {exc}") from exc
    for line in lines:
        prefix = f"{key}="
        if not line.startswith(prefix):
            continue
        if seen:
            raise ValueError(f"parser diagnostics contain duplicate {key} counts")
        seen = True
        value = line.removeprefix(prefix)
        if not value.isdigit():
            raise ValueError(f"parser diagnostics contain an invalid {key} count")
        count = int(value)
    return count


def _excluded_wildcard_count(path: pathlib.Path) -> int:
    return _parser_diagnostic_count(path, "excluded_wildcards")


def _excluded_invalid_count(path: pathlib.Path) -> int:
    return _parser_diagnostic_count(path, "excluded_invalid_or_out_of_scope")


def _validated_discovery_timing(
    timing: dict[str, Any], execution_limits: dict[str, Any]
) -> tuple[str, int, float, int]:
    status = timing.get("status")
    if status not in {"success", "error", "timeout", "interrupted"}:
        raise ValueError("timing status is invalid")
    exit_code = timing.get("exit_code")
    if type(exit_code) is not int:
        raise ValueError("timing exit code is invalid")
    duration = timing.get("duration_seconds")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or float(duration) < 0
    ):
        raise ValueError("timing duration is invalid")
    max_rss = timing.get("max_rss_kib")
    if type(max_rss) is not int or max_rss < 0:
        raise ValueError("timing maximum RSS is invalid")
    timeout = timing.get("timeout_seconds")
    grace = timing.get("grace_seconds")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or float(timeout) <= 0
        or float(timeout) > float(execution_limits["discovery_timeout_seconds"])
        or isinstance(grace, bool)
        or not isinstance(grace, (int, float))
        or float(grace) != float(execution_limits["timeout_grace_seconds"])
    ):
        raise ValueError("timing limits do not match the campaign")
    if timing.get("max_file_bytes") != execution_limits["max_file_bytes"]:
        raise ValueError("timing file-size limit does not match the campaign")
    return status, exit_code, float(duration), max_rss


def record_run(
    campaign: pathlib.Path,
    *,
    tool: str,
    domain: str,
    rank: int,
    repetition: int,
    timing_path: pathlib.Path,
    names_path: pathlib.Path,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    parser_stderr_path: pathlib.Path,
    raw_tree_path: pathlib.Path,
    parse_status: str,
) -> dict[str, Any]:
    manifest = _read_json(campaign / "manifest.json")
    if manifest.get("campaign_kind") != CAMPAIGN_KIND:
        raise ValueError("not a passive top-30 campaign")
    _validate_campaign_policy(manifest)
    _validate_harness(campaign, manifest)
    _validate_preflight_evidence(campaign, manifest)
    enforce_campaign_quota(campaign, manifest)
    if tool not in TOOLS or manifest["tools"].get(tool, {}).get("status") != "runnable":
        raise ValueError(f"tool is not runnable in this campaign: {tool}")
    tool_metadata = manifest["tools"][tool]
    _verify_tool_identity(campaign, tool, tool_metadata)
    expected_ranks = {entry["domain"]: entry["rank"] for entry in manifest["domains"]}
    if expected_ranks.get(domain) != rank:
        raise ValueError(f"domain/rank pair is not in the pinned source: {domain}")
    if not 1 <= repetition <= int(manifest["repetitions"]):
        raise ValueError("repetition is outside the campaign range")
    if parse_status not in {"success", "error"}:
        raise ValueError("parse status must be success or error")

    timing = _read_json(timing_path)
    timing_status, exit_code, duration, max_rss = _validated_discovery_timing(
        timing, manifest["execution_limits"]
    )
    names = _canonical_names(names_path, domain)
    excluded_wildcards = _excluded_wildcard_count(parser_stderr_path)
    excluded_invalid = _excluded_invalid_count(parser_stderr_path)
    status = timing_status if timing_status != "success" else parse_status

    artifact_paths = {
        "timing": timing_path,
        "names": names_path,
        "stdout": stdout_path,
        "stderr": stderr_path,
        "parser_stderr": parser_stderr_path,
        "raw_tree": raw_tree_path,
    }
    row = {
        "schema_version": 1,
        "tool": tool,
        "domain": domain,
        "rank": rank,
        "repetition": repetition,
        "status": status,
        "discovery_status": timing_status,
        "parse_status": parse_status,
        "exit_code": exit_code,
        "duration_seconds": duration,
        "max_rss_kib": max_rss,
        "name_count": len(names),
        "excluded_wildcard_patterns": excluded_wildcards,
        "excluded_invalid_or_out_of_scope": excluded_invalid,
        "source_health": "unknown" if status == "success" else "failed",
        "names_sha256": _sha256(names_path),
        "artifacts": {
            name: _campaign_relative(campaign, path)
            for name, path in artifact_paths.items()
        },
        "artifact_sha256": {
            name: _sha256(path) for name, path in artifact_paths.items()
        },
    }
    with (campaign / "runs.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def _load_rows(path: pathlib.Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], []
    rows: list[dict[str, Any]] = []
    issues: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            issues.append(f"blank_run_row:{number}")
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            issues.append(f"invalid_run_json:{number}")
            continue
        if not isinstance(row, dict):
            issues.append(f"invalid_run_row:{number}")
            continue
        rows.append(row)
    return rows, issues


def _redaction_integrity_issues(
    campaign: pathlib.Path, manifest: dict[str, Any]
) -> list[str]:
    issues: list[str] = []
    status_path = campaign / "redaction.status"
    timing_path = campaign / "redaction.timing.json"
    try:
        status = status_path.read_text(encoding="utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        status = "missing"
    if status != "complete":
        issues.append("redaction_not_complete")
    try:
        timing = _read_json(timing_path)
    except ValueError:
        issues.append("redaction_timing_invalid")
        return issues
    limits = manifest["execution_limits"]
    duration = timing.get("duration_seconds")
    if any(
        (
            timing.get("status") != "success",
            type(timing.get("exit_code")) is not int,
            timing.get("exit_code") != 0,
            isinstance(duration, bool),
            not isinstance(duration, (int, float)),
            isinstance(duration, (int, float))
            and (not math.isfinite(float(duration)) or float(duration) < 0),
            timing.get("timeout_seconds") != limits["redaction_timeout_seconds"],
            timing.get("grace_seconds") != limits["timeout_grace_seconds"],
            timing.get("max_file_bytes") != limits["max_file_bytes"],
        )
    ):
        issues.append("redaction_timing_invalid")
    return issues


def _cleanup_integrity_issues(
    campaign: pathlib.Path, manifest: dict[str, Any]
) -> list[str]:
    issues: list[str] = []
    try:
        status = (campaign / "cleanup.status").read_text(
            encoding="utf-8", errors="strict"
        ).strip()
    except (OSError, UnicodeError):
        status = "missing"
    if status != "complete":
        issues.append("cleanup_not_complete")
    try:
        timing = _read_json(campaign / "cleanup.timing.json")
    except ValueError:
        issues.append("cleanup_timing_invalid")
    else:
        duration = timing.get("duration_seconds")
        limits = manifest["execution_limits"]
        if any(
            (
                timing.get("status") != "success",
                type(timing.get("exit_code")) is not int,
                timing.get("exit_code") != 0,
                isinstance(duration, bool),
                not isinstance(duration, (int, float)),
                isinstance(duration, (int, float))
                and (not math.isfinite(float(duration)) or float(duration) < 0),
                timing.get("timeout_seconds") != limits["cleanup_timeout_seconds"],
                timing.get("grace_seconds") != limits["timeout_grace_seconds"],
                timing.get("max_file_bytes") != limits["max_file_bytes"],
            )
        ):
            issues.append("cleanup_timing_invalid")
    if any(path.exists() or path.is_symlink() for path in _ephemeral_paths(campaign)):
        issues.append("ephemeral_artifacts_remain")
    return issues


def _quota_integrity_issues(
    campaign: pathlib.Path, manifest: dict[str, Any]
) -> tuple[list[str], dict[str, int] | None]:
    try:
        return [], enforce_campaign_quota(campaign, manifest)
    except (OSError, ValueError):
        return ["campaign_quota_exceeded_or_invalid"], None


def _verified_names_for_row(
    campaign: pathlib.Path,
    row: dict[str, Any],
    expected_rank: int,
    execution_limits: dict[str, Any],
) -> set[str]:
    if (
        type(row.get("schema_version")) is not int
        or row.get("schema_version") != 1
        or type(row.get("rank")) is not int
        or row.get("rank") != expected_rank
    ):
        raise ValueError("run schema or rank is invalid")
    discovery_status = row.get("discovery_status")
    parse_status = row.get("parse_status")
    status = row.get("status")
    if discovery_status not in {"success", "error", "timeout", "interrupted"}:
        raise ValueError("run discovery status is invalid")
    if parse_status not in {"success", "error"}:
        raise ValueError("run parser status is invalid")
    expected_status = discovery_status if discovery_status != "success" else parse_status
    if status != expected_status:
        raise ValueError("run combined status is inconsistent")
    duration = row.get("duration_seconds")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or float(duration) < 0
    ):
        raise ValueError("run duration is invalid")
    name_count = row.get("name_count")
    if isinstance(name_count, bool) or not isinstance(name_count, int) or name_count < 0:
        raise ValueError("run name count is invalid")
    excluded_wildcards = row.get("excluded_wildcard_patterns")
    if (
        isinstance(excluded_wildcards, bool)
        or not isinstance(excluded_wildcards, int)
        or excluded_wildcards < 0
    ):
        raise ValueError("run excluded wildcard count is invalid")
    excluded_invalid = row.get("excluded_invalid_or_out_of_scope")
    if (
        isinstance(excluded_invalid, bool)
        or not isinstance(excluded_invalid, int)
        or excluded_invalid < 0
    ):
        raise ValueError("run excluded invalid-name count is invalid")
    expected_source_health = "unknown" if status == "success" else "failed"
    if row.get("source_health") != expected_source_health:
        raise ValueError("run source health classification is invalid")

    artifacts = row.get("artifacts")
    hashes = row.get("artifact_sha256")
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != set(ARTIFACT_KEYS)
        or not isinstance(hashes, dict)
        or set(hashes) != set(ARTIFACT_KEYS)
    ):
        raise ValueError("run artifact manifest is invalid")
    resolved_artifacts: dict[str, pathlib.Path] = {}
    campaign_root = campaign.resolve()
    for name in ARTIFACT_KEYS:
        relative = artifacts.get(name)
        expected_hash = hashes.get(name)
        if not isinstance(relative, str) or not relative or pathlib.Path(relative).is_absolute():
            raise ValueError("run artifact path is invalid")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ValueError("run artifact hash is invalid")
        path = (campaign / relative).resolve()
        try:
            path.relative_to(campaign_root)
        except ValueError as exc:
            raise ValueError("run artifact escapes the campaign") from exc
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError("run artifact hash mismatch")
        resolved_artifacts[name] = path
    if row.get("names_sha256") != hashes["names"]:
        raise ValueError("run names hash is inconsistent")
    names = _canonical_names(resolved_artifacts["names"], str(row.get("domain", "")))
    if len(names) != name_count:
        raise ValueError("run name count does not match its artifact")
    if _excluded_wildcard_count(resolved_artifacts["parser_stderr"]) != excluded_wildcards:
        raise ValueError("run wildcard count does not match parser diagnostics")
    if _excluded_invalid_count(resolved_artifacts["parser_stderr"]) != excluded_invalid:
        raise ValueError("run invalid-name count does not match parser diagnostics")
    _validate_tree_manifest(campaign, resolved_artifacts["raw_tree"])
    timing = _read_json(resolved_artifacts["timing"])
    timing_status, timing_exit, timing_duration, timing_rss = _validated_discovery_timing(
        timing, execution_limits
    )
    if (
        discovery_status != timing_status
        or type(row.get("exit_code")) is not int
        or row.get("exit_code") != timing_exit
        or float(duration) != timing_duration
        or type(row.get("max_rss_kib")) is not int
        or row.get("max_rss_kib") != timing_rss
    ):
        raise ValueError("run row does not match its timing artifact")
    return set(names)


def build_report(campaign: pathlib.Path) -> dict[str, Any]:
    manifest = _read_json(campaign / "manifest.json")
    if manifest.get("campaign_kind") != CAMPAIGN_KIND:
        raise ValueError("not a passive top-30 campaign")
    _validate_campaign_policy(manifest)
    _validate_harness(campaign, manifest)
    _validate_preflight_evidence(campaign, manifest)
    source, ranked = validate_source_manifest(DEFAULT_SOURCE_MANIFEST)
    if manifest.get("source", {}).get("list_id") != source["list_id"]:
        raise ValueError("campaign source does not match the pinned Tranco source")
    for field in ("source_csv_sha256", "top30_csv_sha256", "top30_domains_sha256"):
        if manifest.get("source", {}).get(field) != source["retrieval"].get(field):
            raise ValueError(f"campaign {field} does not match the pinned source")

    rows, issues = _load_rows(campaign / "runs.jsonl")
    issues.extend(_redaction_integrity_issues(campaign, manifest))
    issues.extend(_cleanup_integrity_issues(campaign, manifest))
    quota_issues, campaign_usage_summary = _quota_integrity_issues(campaign, manifest)
    issues.extend(quota_issues)
    repetitions = int(manifest.get("repetitions", 0))
    runnable_tools = [
        tool for tool in TOOLS if manifest["tools"].get(tool, {}).get("status") == "runnable"
    ]
    expected = {
        (tool, domain, repetition)
        for tool in runnable_tools
        for _rank, domain in ranked
        for repetition in range(1, repetitions + 1)
    }
    observed: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    valid_rows: list[dict[str, Any]] = []
    verified_names: dict[tuple[Any, Any, Any], set[str]] = {}
    expected_ranks = {domain: rank for rank, domain in ranked}
    for number, row in enumerate(rows, start=1):
        row_tool = row.get("tool")
        row_domain = row.get("domain")
        row_repetition = row.get("repetition")
        if (
            not isinstance(row_tool, str)
            or not isinstance(row_domain, str)
            or isinstance(row_repetition, bool)
            or not isinstance(row_repetition, int)
        ):
            issues.append(f"invalid_run_shape:{number}")
            continue
        key = (row_tool, row_domain, row_repetition)
        if key not in expected:
            issues.append(f"unexpected_run:{number}")
            continue
        if key in observed:
            issues.append(f"duplicate_run:{number}")
            continue
        try:
            row_names = _verified_names_for_row(
                campaign,
                row,
                expected_ranks[str(row.get("domain"))],
                manifest["execution_limits"],
            )
        except (KeyError, ValueError):
            issues.append(f"invalid_run_or_artifact:{number}")
            continue
        observed[key] = row
        valid_rows.append(row)
        verified_names[key] = row_names

    missing_runs = sorted(expected - set(observed))
    if missing_runs:
        issues.append("missing_runs")
    failed_runs = [row for row in valid_rows if row.get("status") != "success"]
    if failed_runs:
        issues.append("failed_runs")

    summaries: dict[str, dict[str, Any]] = {}
    for tool in TOOLS:
        tool_meta = manifest["tools"].get(tool, {})
        tool_rows = [row for row in valid_rows if row.get("tool") == tool]
        successful_rows = [row for row in tool_rows if row.get("status") == "success"]
        durations = [float(row["duration_seconds"]) for row in successful_rows]
        attempt_durations = [float(row["duration_seconds"]) for row in tool_rows]
        counts = Counter(str(row.get("status")) for row in tool_rows)
        domain_name_pairs = {
            (str(row.get("domain")), name)
            for row in successful_rows
            for name in verified_names[
                (row.get("tool"), row.get("domain"), row.get("repetition"))
            ]
        }
        summaries[tool] = {
            "availability": tool_meta.get("status"),
            "availability_reason": tool_meta.get("reason"),
            "runs_expected": 30 * repetitions if tool in runnable_tools else 0,
            "runs_recorded": len(tool_rows),
            "successful_runs": counts.get("success", 0),
            "process_successful_runs": counts.get("success", 0),
            "failed_runs": len(tool_rows) - counts.get("success", 0),
            "status_counts": dict(sorted(counts.items())),
            "median_duration_seconds": statistics.median(durations) if durations else None,
            "attempt_duration_seconds_total": sum(attempt_durations),
            "excluded_wildcard_patterns": sum(
                int(row.get("excluded_wildcard_patterns", 0)) for row in tool_rows
            ),
            "excluded_invalid_or_out_of_scope": sum(
                int(row.get("excluded_invalid_or_out_of_scope", 0))
                for row in tool_rows
            ),
            "empty_successful_runs": sum(
                1 for row in successful_rows if int(row.get("name_count", 0)) == 0
            ),
            "source_health": "unknown",
            "median_names_per_run": statistics.median(
                [int(row.get("name_count", 0)) for row in successful_rows]
            )
            if successful_rows
            else None,
            "unique_domain_name_pairs": len(domain_name_pairs),
        }

    missing_tools = [
        tool for tool in TOOLS if manifest["tools"].get(tool, {}).get("status") == "missing"
    ]
    skipped_tools = [
        tool for tool in TOOLS if manifest["tools"].get(tool, {}).get("status") == "skipped"
    ]
    qualification_failures = list(BASE_QUALIFICATION_FAILURES)
    if missing_tools:
        qualification_failures.append("missing_tools")
    if skipped_tools:
        qualification_failures.append("skipped_tools")
    if missing_runs:
        qualification_failures.append("missing_runs")
    if failed_runs:
        qualification_failures.append("failed_runs")
    if issues:
        qualification_failures.append("campaign_integrity_issues")

    runnable_subset_complete = (
        bool(runnable_tools) and not missing_runs and not failed_runs and not issues
    )
    report = {
        "schema_version": 1,
        "campaign_kind": CAMPAIGN_KIND,
        "source": manifest["source"],
        "summary": {
            "descriptive_only": True,
            "timing_comparable": False,
            "source_health_comparable": False,
            "qualification_eligible": False,
            "qualification_passed": False,
            "best_tool_claim_allowed": False,
            "qualification_failures": list(dict.fromkeys(qualification_failures)),
            "runnable_subset_complete": runnable_subset_complete,
            "campaign_complete": (
                runnable_subset_complete and not missing_tools and not skipped_tools
            ),
            "runnable_tools": runnable_tools,
            "missing_tools": missing_tools,
            "skipped_tools": skipped_tools,
            "expected_runs": len(expected),
            "recorded_runs": len(valid_rows),
            "integrity_issues": sorted(set(issues)),
            "campaign_usage": campaign_usage_summary,
        },
        "tools": summaries,
    }
    return report


def _mapping(values: list[str], option: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, detail = value.partition("=")
        if not separator or name not in TOOLS or not detail:
            raise ValueError(f"{option} requires TOOL=VALUE for a supported tool")
        if name in result:
            raise ValueError(f"duplicate {option} value for {name}")
        result[name] = detail
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    verify = subparsers.add_parser("verify-source")
    verify.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_SOURCE_MANIFEST)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("campaign", type=pathlib.Path)
    prepare.add_argument("--repetitions", type=int, required=True)
    prepare.add_argument("--discovery-timeout", type=float, required=True)
    prepare.add_argument("--timeout-grace", type=float, required=True)
    prepare.add_argument("--preflight-timeout", type=float, required=True)
    prepare.add_argument("--campaign-max-runtime", type=float, required=True)
    prepare.add_argument("--cooldown", type=float, required=True)
    prepare.add_argument("--failure-threshold", type=int, required=True)
    prepare.add_argument("--subfinder-rate-limit", type=int, required=True)
    prepare.add_argument("--fellaga-passive-concurrency", type=int, required=True)
    prepare.add_argument("--cleanup-timeout", type=int, required=True)
    prepare.add_argument("--redaction-timeout", type=int, required=True)
    prepare.add_argument("--max-file-bytes", type=int, required=True)
    prepare.add_argument("--campaign-max-files", type=int, required=True)
    prepare.add_argument("--campaign-max-bytes", type=int, required=True)
    prepare.add_argument("--runnable", action="append", default=[])
    prepare.add_argument("--missing", action="append", default=[])
    prepare.add_argument("--skipped", action="append", default=[])

    record = subparsers.add_parser("record")
    record.add_argument("campaign", type=pathlib.Path)
    record.add_argument("--tool", required=True, choices=TOOLS)
    record.add_argument("--domain", required=True)
    record.add_argument("--rank", required=True, type=int)
    record.add_argument("--repetition", required=True, type=int)
    record.add_argument("--timing", required=True, type=pathlib.Path)
    record.add_argument("--names", required=True, type=pathlib.Path)
    record.add_argument("--stdout", required=True, type=pathlib.Path)
    record.add_argument("--stderr", required=True, type=pathlib.Path)
    record.add_argument("--parser-stderr", required=True, type=pathlib.Path)
    record.add_argument("--raw-tree", required=True, type=pathlib.Path)
    record.add_argument("--parse-status", required=True, choices=("success", "error"))

    report = subparsers.add_parser("report")
    report.add_argument("campaign", type=pathlib.Path)
    report.add_argument("--output", type=pathlib.Path)
    report.add_argument("--require-complete", action="store_true")

    tree = subparsers.add_parser("tree-manifest")
    tree.add_argument("campaign", type=pathlib.Path)
    tree.add_argument("root", type=pathlib.Path)
    tree.add_argument("output", type=pathlib.Path)

    cleanup_run_parser = subparsers.add_parser("cleanup-run")
    cleanup_run_parser.add_argument("campaign", type=pathlib.Path)
    cleanup_run_parser.add_argument("isolation", type=pathlib.Path)
    cleanup_run_parser.add_argument("state_prefix", type=pathlib.Path)

    cleanup_all_parser = subparsers.add_parser("cleanup-all")
    cleanup_all_parser.add_argument("campaign", type=pathlib.Path)

    quota = subparsers.add_parser("quota-check")
    quota.add_argument("campaign", type=pathlib.Path)

    verify_tool = subparsers.add_parser("verify-tool")
    verify_tool.add_argument("campaign", type=pathlib.Path)
    verify_tool.add_argument("tool", choices=TOOLS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.action == "verify-source":
            source, ranked = validate_source_manifest(args.manifest)
            print(
                json.dumps(
                    {
                        "list_id": source["list_id"],
                        "domains": len(ranked),
                        "top30_csv_sha256": source["retrieval"]["top30_csv_sha256"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.action == "prepare":
            prepare_campaign(
                args.campaign,
                args.repetitions,
                _mapping(args.runnable, "--runnable"),
                _mapping(args.missing, "--missing"),
                _mapping(args.skipped, "--skipped"),
                discovery_timeout_seconds=args.discovery_timeout,
                timeout_grace_seconds=args.timeout_grace,
                preflight_timeout_seconds=args.preflight_timeout,
                campaign_max_runtime_seconds=args.campaign_max_runtime,
                cooldown_seconds=args.cooldown,
                consecutive_failure_threshold=args.failure_threshold,
                subfinder_rate_limit=args.subfinder_rate_limit,
                fellaga_passive_concurrency=args.fellaga_passive_concurrency,
                cleanup_timeout_seconds=args.cleanup_timeout,
                redaction_timeout_seconds=args.redaction_timeout,
                max_file_bytes=args.max_file_bytes,
                campaign_max_files=args.campaign_max_files,
                campaign_max_bytes=args.campaign_max_bytes,
            )
            return 0
        if args.action == "record":
            record_run(
                args.campaign,
                tool=args.tool,
                domain=normalize_domain(args.domain),
                rank=args.rank,
                repetition=args.repetition,
                timing_path=args.timing,
                names_path=args.names,
                stdout_path=args.stdout,
                stderr_path=args.stderr,
                parser_stderr_path=args.parser_stderr,
                raw_tree_path=args.raw_tree,
                parse_status=args.parse_status,
            )
            return 0
        if args.action == "tree-manifest":
            write_tree_manifest(args.campaign, args.root, args.output)
            return 0
        if args.action == "cleanup-run":
            cleanup_run(args.campaign, args.isolation, args.state_prefix)
            return 0
        if args.action == "cleanup-all":
            cleanup_all_ephemeral(args.campaign)
            return 0
        if args.action == "quota-check":
            print(json.dumps(enforce_campaign_quota(args.campaign), sort_keys=True))
            return 0
        if args.action == "verify-tool":
            verify_campaign_tool(args.campaign, args.tool)
            return 0
        report = build_report(args.campaign)
        output = args.output or (args.campaign / "report.json")
        _write_json(output, report)
        print(output)
        if args.require_complete and not report["summary"]["campaign_complete"]:
            return 3
        return 0
    except (ValueError, BenchmarkNameError) as exc:
        print(f"passive top-30 report error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
