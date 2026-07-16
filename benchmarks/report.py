#!/usr/bin/env python3
"""Build strict, fail-closed metrics from a Fellaga benchmark campaign."""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import statistics
import sys
from collections import defaultdict
from typing import Any

try:
    from .names import NameError, normalize_domain, read_name_file
except ImportError:  # Direct script execution.
    from names import NameError, normalize_domain, read_name_file


REQUIRED_TOOLS = ("fellaga", "subfinder", "amass", "bbot", "puredns")
PROVENANCE_TOOLS = REQUIRED_TOOLS + ("massdns", "dnsx")
CREDENTIAL_TOOLS = {"fellaga", "subfinder", "amass", "bbot"}
MINIMUM_DOMAINS = 30
MINIMUM_REPETITIONS = 3
SAFE_TOOL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SAFE_CAMPAIGN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")
DNS_CONTROL_REQUIREMENTS = {
    "fellaga": {"resolver_list", "trusted_resolver_list", "rate_limit", "concurrency"},
    "subfinder": {"resolver_list"},
    "amass": {"resolver_list", "concurrency"},
    "bbot": {"concurrency", "bruteforce_resolver_list", "no_strict_qps_cli"},
    "puredns": {
        "resolver_list",
        "trusted_resolver_list",
        "rate_limit",
        "trusted_rate_limit",
    },
    "dnsx": {"resolver_list", "rate_limit", "concurrency"},
}


def _finite_number(document: dict[str, Any], key: str, default: float) -> float:
    value = document.get(key)
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _load_json_object(path: pathlib.Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "invalid_json"
    if not isinstance(value, dict):
        return None, "not_an_object"
    return value, None


def _timing_evidence(row: dict[str, Any]) -> tuple[float, float, float] | None:
    values: list[float] = []
    for key in (
        "discovery_duration_seconds",
        "validation_duration_seconds",
        "end_to_end_duration_seconds",
    ):
        if key not in row or isinstance(row[key], bool):
            return None
        try:
            value = float(row[key])
        except (TypeError, ValueError):
            return None
        if not math.isfinite(value) or value < 0:
            return None
        values.append(value)
    discovery, validation, end_to_end = values
    combined = discovery + validation
    tolerance = max(0.001, max(combined, end_to_end) * 0.001)
    if abs(end_to_end - combined) > tolerance:
        return None
    legacy = row.get("duration_seconds")
    if legacy is not None:
        try:
            legacy_value = float(legacy)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(legacy_value) or abs(legacy_value - end_to_end) > tolerance:
            return None
    return discovery, validation, end_to_end


def _manifest_evidence_issues(manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if manifest.get("schema_version") not in {1, 2}:
        issues.append("invalid_manifest_schema")
    campaign_id = manifest.get("campaign_id")
    if not isinstance(campaign_id, str) or not SAFE_CAMPAIGN.fullmatch(campaign_id):
        issues.append("invalid_campaign_id")
    mode = manifest.get("mode")
    if mode not in {"no-key", "equal-keys"}:
        issues.append("invalid_mode")

    versions = manifest.get("versions")
    if not isinstance(versions, dict):
        issues.append("missing_versions")
        versions = {}
    for tool in PROVENANCE_TOOLS:
        if not isinstance(versions.get(tool), str) or not versions[tool].strip():
            issues.append(f"missing_version:{tool}")

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        issues.append("missing_provenance")
        return issues
    repository = provenance.get("repository")
    if not isinstance(repository, dict):
        issues.append("missing_repository_provenance")
    else:
        commit = repository.get("commit")
        if not isinstance(commit, str) or not GIT_COMMIT.fullmatch(commit):
            issues.append("invalid_repository_commit")
        if repository.get("dirty") is not False:
            issues.append("repository_not_clean")

    executables = provenance.get("executables")
    if not isinstance(executables, dict):
        issues.append("missing_executable_provenance")
        executables = {}
    for tool in PROVENANCE_TOOLS:
        evidence = executables.get(tool)
        if not isinstance(evidence, dict):
            issues.append(f"missing_executable:{tool}")
            continue
        version = evidence.get("version")
        digest = evidence.get("sha256")
        if version != versions.get(tool):
            issues.append(f"version_mismatch:{tool}")
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            issues.append(f"invalid_executable_hash:{tool}")

    inputs = provenance.get("inputs")
    required_inputs = (
        "domains_sha256",
        "active_corpus_archive_sha256",
        "active_corpus_sha256",
        "pipeline_corpus_sha256",
        "resolvers_sha256",
    )
    if not isinstance(inputs, dict):
        issues.append("missing_input_provenance")
        inputs = {}
    for name in required_inputs:
        digest = inputs.get(name)
        if not isinstance(digest, str) or not HEX_SHA256.fullmatch(digest):
            issues.append(f"invalid_input_hash:{name}")
    keys_digest = inputs.get("keys_manifest_sha256")
    if mode == "equal-keys":
        if not isinstance(keys_digest, str) or not HEX_SHA256.fullmatch(keys_digest):
            issues.append("invalid_input_hash:keys_manifest_sha256")
    elif keys_digest is not None:
        issues.append("unexpected_keys_manifest_hash")

    credentials = manifest.get("credentials")
    if not isinstance(credentials, dict):
        issues.append("missing_credential_evidence")
    else:
        if credentials.get("mode") != mode or credentials.get("isolated_home") is not True:
            issues.append("invalid_credential_isolation")
        providers = credentials.get("providers")
        if not isinstance(providers, list):
            issues.append("invalid_credential_providers")
        elif mode == "no-key":
            if providers:
                issues.append("unexpected_no_key_providers")
            if credentials.get("policy") != "no-credentials":
                issues.append("invalid_no_key_policy")
        elif mode == "equal-keys":
            if credentials.get("policy") != "same-provider-keys" or not providers:
                issues.append("invalid_equal_keys_policy")
            seen_names: set[str] = set()
            seen_env: set[str] = set()
            for provider in providers:
                if not isinstance(provider, dict):
                    issues.append("invalid_equal_keys_provider")
                    continue
                name = provider.get("name")
                variable = provider.get("fellaga_env")
                tools = provider.get("configured_tools")
                if (
                    not isinstance(name, str)
                    or not name
                    or name in seen_names
                    or not isinstance(variable, str)
                    or not variable
                    or variable in seen_env
                    or not isinstance(tools, list)
                    or any(not isinstance(tool, str) for tool in tools)
                    or not CREDENTIAL_TOOLS.issubset(
                        {tool for tool in tools if isinstance(tool, str)}
                    )
                ):
                    issues.append("invalid_equal_keys_provider")
                if isinstance(name, str):
                    seen_names.add(name)
                if isinstance(variable, str):
                    seen_env.add(variable)

    fairness = manifest.get("dns_fairness")
    if not isinstance(fairness, dict):
        issues.append("missing_dns_fairness_evidence")
    else:
        if _finite_number(fairness, "rate_limit_qps", 0) <= 0:
            issues.append("invalid_dns_rate_limit")
        if _finite_number(fairness, "concurrency", 0) <= 0:
            issues.append("invalid_dns_concurrency")
        if _finite_number(fairness, "resolver_count", 0) <= 0:
            issues.append("invalid_dns_resolver_count")
        resolver_hash = fairness.get("resolvers_sha256")
        if (
            not isinstance(resolver_hash, str)
            or not HEX_SHA256.fullmatch(resolver_hash)
            or resolver_hash != inputs.get("resolvers_sha256")
        ):
            issues.append("dns_resolver_hash_mismatch")
        controls = fairness.get("controls")
        if not isinstance(controls, dict):
            issues.append("missing_dns_tool_controls")
        else:
            for tool, required in DNS_CONTROL_REQUIREMENTS.items():
                documented = controls.get(tool)
                if (
                    not isinstance(documented, list)
                    or any(not isinstance(value, str) for value in documented)
                    or not required.issubset(set(documented))
                ):
                    issues.append(f"missing_dns_tool_controls:{tool}")
    return issues


def _integer(document: dict[str, Any], key: str) -> int | None:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _capacity_preflight_issues(
    manifest: dict[str, Any], configuration: dict[str, Any]
) -> list[str]:
    """Validate schema-v2 capacity evidence and its internal calculations."""

    issues: list[str] = []
    provenance = manifest.get("provenance")
    inputs = provenance.get("inputs") if isinstance(provenance, dict) else None
    active_corpus_candidates = (
        _integer(inputs, "active_corpus_candidates")
        if isinstance(inputs, dict)
        else None
    )
    preflight = manifest.get("preflight")
    if not isinstance(preflight, dict):
        return ["missing_capacity_preflight"]

    disk = preflight.get("candidate_pipeline_disk")
    if not isinstance(disk, dict):
        issues.append("missing_disk_preflight")
    else:
        candidates = _integer(disk, "candidates")
        bytes_per_candidate = _integer(disk, "bytes_per_candidate")
        fixed_bytes = _integer(disk, "fixed_bytes")
        margin = _integer(disk, "margin_percent")
        estimated = _integer(disk, "estimated_payload_bytes")
        required = _integer(disk, "required_free_bytes")
        available = _integer(disk, "available_free_bytes")
        shortfall = _integer(disk, "shortfall_bytes")
        expected_estimated = (
            candidates * bytes_per_candidate + fixed_bytes
            if candidates is not None
            and candidates > 0
            and bytes_per_candidate is not None
            and bytes_per_candidate > 0
            and fixed_bytes is not None
            and fixed_bytes >= 0
            else None
        )
        expected_required = (
            (expected_estimated * margin + 99) // 100
            if expected_estimated is not None and margin is not None and margin >= 100
            else None
        )
        if (
            disk.get("schema_version") != 1
            or disk.get("check") != "candidate_pipeline_disk"
            or disk.get("status") != "sufficient"
            or candidates != _integer(configuration, "candidate_pipeline_candidates")
            or bytes_per_candidate
            != _integer(configuration, "candidate_pipeline_bytes_per_candidate")
            or fixed_bytes != _integer(configuration, "candidate_pipeline_fixed_bytes")
            or margin
            != _integer(configuration, "candidate_pipeline_disk_margin_percent")
            or estimated != expected_estimated
            or required != expected_required
            or available is None
            or required is None
            or available < required
            or shortfall != 0
        ):
            issues.append("invalid_disk_preflight")

    puredns = preflight.get("puredns_capacity")
    if not isinstance(puredns, dict):
        issues.append("missing_puredns_preflight")
    else:
        corpus = _integer(puredns, "corpus_candidates")
        rate = _integer(puredns, "rate_limit_qps")
        timeout = _integer(puredns, "timeout_seconds")
        headroom = _integer(puredns, "headroom_percent")
        estimated_seconds = _integer(puredns, "estimated_minimum_seconds")
        minimum_rate = _integer(puredns, "minimum_coherent_rate_qps")
        capacity = _integer(puredns, "capacity_candidates")
        valid_inputs = (
            corpus is not None
            and corpus > 0
            and rate is not None
            and rate > 0
            and timeout is not None
            and timeout > 0
            and headroom is not None
            and headroom >= 100
        )
        expected_seconds = (
            (corpus * headroom + rate * 100 - 1) // (rate * 100)
            if valid_inputs
            else None
        )
        expected_rate = (
            (corpus * headroom + timeout * 100 - 1) // (timeout * 100)
            if valid_inputs
            else None
        )
        expected_capacity = (
            rate * timeout * 100 // headroom if valid_inputs else None
        )
        if (
            puredns.get("schema_version") != 1
            or puredns.get("check") != "puredns_capacity"
            or puredns.get("status") != "coherent"
            or corpus != active_corpus_candidates
            or rate != _integer(configuration, "dns_rate_limit")
            or timeout != _integer(configuration, "discovery_timeout_seconds")
            or headroom != _integer(configuration, "puredns_headroom_percent")
            or estimated_seconds != expected_seconds
            or minimum_rate != expected_rate
            or capacity != expected_capacity
            or estimated_seconds is None
            or timeout is None
            or estimated_seconds > timeout
        ):
            issues.append("invalid_puredns_preflight")

    profiles = configuration.get("fellaga_profile_baselines")
    allowed_profiles = {"deep", "balanced", "passive", "turbo"}
    if (
        not isinstance(profiles, list)
        or any(not isinstance(profile, str) for profile in profiles)
        or len(profiles) != len(set(profiles))
        or not set(profiles).issubset(allowed_profiles)
    ):
        issues.append("invalid_fellaga_profile_baselines")
    return issues


def _status(row: dict[str, Any], field: str) -> str:
    value = row.get(field)
    if value in {"success", "timeout", "error", "skipped", "interrupted"}:
        exit_field = (
            "discovery_exit_code" if field == "discovery_status" else "validation_exit_code"
        )
        exit_code = row.get(exit_field)
        if value == "success" and exit_code is not None and exit_code != 0:
            return "error"
        return str(value)
    if field == "discovery_status" and "status" in row:
        return "success" if row.get("status") == 0 else "error"
    # Old rows never recorded validation status. They remain readable but
    # cannot satisfy the fail-closed qualification gate.
    return "unknown"


def _live_path(
    root: pathlib.Path, domain: str, tool: str, repetition: int
) -> pathlib.Path:
    repeated = root / "live" / f"{domain}.{tool}.r{repetition}.txt"
    if repeated.exists() or repetition != 1:
        return repeated
    return root / "live" / f"{domain}.{tool}.txt"


def _load_rows(root: pathlib.Path) -> list[dict[str, Any]]:
    path = root / "summary.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"summary.jsonl line {number} is not an object")
        rows.append(value)
    return rows


def _metric_counts(found: set[str], truth: set[str]) -> dict[str, Any]:
    true_positives = len(found & truth)
    false_positives = len(found - truth)
    false_negatives = len(truth - found)
    predicted = true_positives + false_positives
    expected = true_positives + false_negatives
    precision = true_positives / predicted if predicted else None
    recall = true_positives / expected if expected else 1.0
    false_discovery_rate = false_positives / predicted if predicted else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and precision + recall > 0
        else None
    )
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_discovery_rate": false_discovery_rate,
    }


def build_report(
    root: pathlib.Path, truth_root: pathlib.Path | None = None
) -> dict[str, Any]:
    root = root.resolve()
    truth_root = (
        truth_root.resolve()
        if truth_root is not None
        else (root.parent.parent / "ground-truth").resolve()
    )
    manifest_path = root / "manifest.json"
    manifest, manifest_load_error = _load_json_object(manifest_path)
    manifest = manifest or {}
    rows = _load_rows(root)
    manifest_issues: list[str] = []
    if manifest_load_error == "missing":
        manifest_issues.append("missing_manifest")
    elif manifest_load_error is not None:
        manifest_issues.append("invalid_manifest_json")
    else:
        manifest_issues.extend(_manifest_evidence_issues(manifest))
    configuration = manifest.get("configuration", {})
    if not isinstance(configuration, dict):
        manifest_issues.append("invalid_configuration")
        configuration = {}
    if manifest.get("schema_version") == 2:
        manifest_issues.extend(_capacity_preflight_issues(manifest, configuration))
    requested_repetitions = configuration.get(
        "required_repetitions", manifest.get("repetitions", MINIMUM_REPETITIONS)
    )
    try:
        required_repetitions = max(MINIMUM_REPETITIONS, int(requested_repetitions))
    except (TypeError, ValueError):
        manifest_issues.append("invalid_required_repetitions")
        required_repetitions = MINIMUM_REPETITIONS
    for field in (
        "discovery_timeout_seconds",
        "validation_timeout_seconds",
        "dns_transport_timeout_seconds",
        "candidate_pipeline_timeout_seconds",
        "dns_rate_limit",
        "dns_concurrency",
        "dns_transport_queries",
        "dns_transport_concurrency",
        "candidate_pipeline_batch",
        "candidate_pipeline_concurrency",
    ):
        if _finite_number(configuration, field, 0) <= 0:
            manifest_issues.append(f"invalid_configuration:{field}")
    if _finite_number(configuration, "candidate_pipeline_candidates", 0) != 10_000_000:
        manifest_issues.append("invalid_configuration:candidate_pipeline_candidates")
    if _finite_number(configuration, "dns_transport_queries", 0) < 100_000:
        manifest_issues.append("invalid_configuration:dns_transport_queries")
    if manifest.get("schema_version") == 2:
        active_max_runtime = _integer(
            configuration, "fellaga_active_max_runtime_seconds"
        )
        if active_max_runtime is None or active_max_runtime < 0:
            manifest_issues.append(
                "invalid_configuration:fellaga_active_max_runtime_seconds"
            )

    manifest_domains = manifest.get("authorized_domains", [])
    domain_errors: list[str] = []
    domains: set[str] = set()
    if "authorized_domains" in manifest:
        if isinstance(manifest_domains, list):
            domain_values = manifest_domains
            if not manifest_domains:
                manifest_issues.append("empty_authorized_domains")
        else:
            domain_values = []
            manifest_issues.append("invalid_authorized_domains")
    else:
        manifest_issues.append("missing_authorized_domains")
        domain_values = [row.get("domain") for row in rows]
    for value in domain_values:
        if not isinstance(value, str):
            domain_errors.append(repr(value))
            continue
        try:
            domains.add(normalize_domain(value))
        except NameError:
            domain_errors.append(value)
    ordered_domains = sorted(domains)

    truth_by_domain: dict[str, set[str]] = {}
    missing_truth: list[str] = []
    empty_truth: list[str] = []
    invalid_truth_names: dict[str, int] = {}
    for domain in ordered_domains:
        path = truth_root / f"{domain}.txt"
        if not path.exists():
            missing_truth.append(domain)
            continue
        truth, rejected = read_name_file(path, domain)
        truth_by_domain[domain] = truth
        if rejected:
            invalid_truth_names[domain] = rejected
        if not truth:
            empty_truth.append(domain)

    processed_rows: list[dict[str, Any]] = []
    rows_by_key: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    found_by_row: dict[int, set[str]] = {}
    invalid_rows = 0
    unexpected_runs: list[str] = []
    invalid_timing_runs: list[str] = []
    campaign_mismatch_runs: list[str] = []
    campaign_id = manifest.get("campaign_id")
    for source in rows:
        row = dict(source)
        try:
            domain = normalize_domain(str(row.get("domain", "")))
            tool = str(row.get("tool", "")).lower()
            repetition = int(row.get("repetition", 1))
            if not SAFE_TOOL.fullmatch(tool) or repetition < 1:
                raise ValueError("invalid tool or repetition")
        except (NameError, TypeError, ValueError):
            row["eligible_for_ranking"] = False
            row["row_error"] = "invalid domain, tool, or repetition"
            invalid_rows += 1
            processed_rows.append(row)
            continue

        row["domain"] = domain
        row["tool"] = tool
        row["repetition"] = repetition
        row["discovery_status"] = _status(row, "discovery_status")
        row["validation_status"] = _status(row, "validation_status")
        label = f"{domain}/{tool}/r{repetition}"
        expected_run = (
            domain in domains
            and tool in REQUIRED_TOOLS
            and repetition <= required_repetitions
        )
        if not expected_run:
            unexpected_runs.append(label)
        timing = _timing_evidence(row)
        if timing is None:
            invalid_timing_runs.append(label)
            row["timing_evidence_valid"] = False
        else:
            row["timing_evidence_valid"] = True
            row["discovery_duration_seconds"] = timing[0]
            row["validation_duration_seconds"] = timing[1]
            row["end_to_end_duration_seconds"] = timing[2]
        campaign_matches = (
            isinstance(campaign_id, str) and row.get("campaign_id") == campaign_id
        )
        if not campaign_matches:
            campaign_mismatch_runs.append(label)
        path = _live_path(root, domain, tool, repetition)
        found, rejected = read_name_file(path, domain)
        output_exists = path.exists()
        row["live_names"] = len(found)
        row["invalid_live_names"] = rejected
        row["live_output_present"] = output_exists
        eligible = bool(
            row["discovery_status"] == "success"
            and row["validation_status"] == "success"
            and output_exists
            and rejected == 0
            and expected_run
            and timing is not None
            and campaign_matches
            and domain in truth_by_domain
        )
        row["eligible_for_ranking"] = eligible
        if domain in truth_by_domain:
            row.update(_metric_counts(found, truth_by_domain[domain]))
        else:
            row.update(
                {
                    "true_positives": None,
                    "false_positives": None,
                    "false_negatives": None,
                    "precision": None,
                    "recall": None,
                    "f1": None,
                    "false_discovery_rate": None,
                }
            )
        found_by_row[id(row)] = found
        rows_by_key[(domain, tool, repetition)].append(row)
        processed_rows.append(row)

    # Exclusives are compared only against successful validation runs from the
    # same domain and repetition. Failed outputs never affect ranking.
    for row in processed_rows:
        if not row.get("eligible_for_ranking"):
            row["exclusive_validated"] = None
            continue
        found = found_by_row[id(row)]
        others: set[str] = set()
        for candidate in processed_rows:
            if (
                candidate.get("eligible_for_ranking")
                and candidate.get("domain") == row["domain"]
                and candidate.get("repetition") == row["repetition"]
                and candidate.get("tool") != row["tool"]
            ):
                others.update(found_by_row[id(candidate)])
        row["exclusive_validated"] = len(found - others)

    missing_runs: list[str] = []
    duplicate_runs: list[str] = []
    failed_discovery_runs: list[str] = []
    failed_validation_runs: list[str] = []
    invalid_output_runs: list[str] = []
    for domain in ordered_domains:
        for tool in REQUIRED_TOOLS:
            for repetition in range(1, required_repetitions + 1):
                key = (domain, tool, repetition)
                candidates = rows_by_key.get(key, [])
                label = f"{domain}/{tool}/r{repetition}"
                if not candidates:
                    missing_runs.append(label)
                    continue
                if len(candidates) != 1:
                    duplicate_runs.append(label)
                    continue
                row = candidates[0]
                if row["discovery_status"] != "success":
                    failed_discovery_runs.append(label)
                if row["validation_status"] != "success":
                    failed_validation_runs.append(label)
                if not row["live_output_present"] or row["invalid_live_names"]:
                    invalid_output_runs.append(label)

    aggregates: dict[tuple[str, str], dict[str, float]] = {}
    for domain in ordered_domains:
        for tool in REQUIRED_TOOLS:
            tool_rows: list[dict[str, Any]] = []
            for repetition in range(1, required_repetitions + 1):
                candidates = rows_by_key.get((domain, tool, repetition), [])
                if len(candidates) != 1 or not candidates[0]["eligible_for_ranking"]:
                    tool_rows = []
                    break
                tool_rows.append(candidates[0])
            if not tool_rows:
                continue
            counts = [float(row["true_positives"]) for row in tool_rows]
            durations = [float(row["end_to_end_duration_seconds"]) for row in tool_rows]
            aggregates[(domain, tool)] = {
                "median_true_positives": statistics.median(counts),
                "median_end_to_end_seconds": statistics.median(durations),
            }

    wins = 0
    fellaga_total = 0.0
    best_competitor_total = 0.0
    coverage_duration_ok = True
    ranked_domains = 0
    for domain in ordered_domains:
        fellaga = aggregates.get((domain, "fellaga"))
        competitors = [
            aggregates[(domain, tool)]
            for tool in REQUIRED_TOOLS
            if tool != "fellaga" and (domain, tool) in aggregates
        ]
        if fellaga is None or len(competitors) != len(REQUIRED_TOOLS) - 1:
            continue
        ranked_domains += 1
        best = max(
            competitors,
            key=lambda value: (
                value["median_true_positives"],
                -value["median_end_to_end_seconds"],
            ),
        )
        fellaga_total += fellaga["median_true_positives"]
        best_competitor_total += best["median_true_positives"]
        if fellaga["median_true_positives"] > best["median_true_positives"]:
            wins += 1
        coverage_duration_ok = bool(
            coverage_duration_ok
            and fellaga["median_end_to_end_seconds"]
            <= 2 * max(best["median_end_to_end_seconds"], 0.001)
        )

    aggregate_found: set[tuple[str, str]] = set()
    aggregate_truth: set[tuple[str, str]] = set()
    for domain in ordered_domains:
        truth = truth_by_domain.get(domain)
        if truth is None:
            continue
        aggregate_truth.update((domain, name) for name in truth)
        fellaga_rows = [
            rows_by_key[(domain, "fellaga", repetition)][0]
            for repetition in range(1, required_repetitions + 1)
            if len(rows_by_key.get((domain, "fellaga", repetition), [])) == 1
            and rows_by_key[(domain, "fellaga", repetition)][0][
                "eligible_for_ranking"
            ]
        ]
        for row in fellaga_rows:
            aggregate_found.update((domain, name) for name in found_by_row[id(row)])
    aggregate_metrics = _metric_counts(
        {f"{domain}\0{name}" for domain, name in aggregate_found},
        {f"{domain}\0{name}" for domain, name in aggregate_truth},
    )
    incomplete_fellaga_ground_truth_runs: list[str] = []
    for domain in ordered_domains:
        if domain not in truth_by_domain:
            continue
        for repetition in range(1, required_repetitions + 1):
            candidates = rows_by_key.get((domain, "fellaga", repetition), [])
            if len(candidates) != 1 or not candidates[0].get("eligible_for_ranking"):
                continue
            row = candidates[0]
            if row.get("recall") != 1.0 or row.get("false_negatives") != 0:
                incomplete_fellaga_ground_truth_runs.append(
                    f"{domain}/fellaga/r{repetition}"
                )

    win_rate = wins / ranked_domains if ranked_domains else 0.0
    validated_gain = (
        (fellaga_total - best_competitor_total) / best_competitor_total
        if best_competitor_total > 0
        else None
    )
    dns_transport_path = root / "dns-transport.json"
    dns_transport, dns_transport_error = _load_json_object(dns_transport_path)
    if dns_transport_error == "missing" and (root / "dns-engine.json").exists():
        # Legacy data remains readable, but it lacks the required binding.
        dns_transport, _ = _load_json_object(root / "dns-engine.json")
        dns_transport_error = "legacy_unbound"
    candidate_pipeline_path = root / "candidate-pipeline.json"
    candidate_pipeline, candidate_pipeline_error = _load_json_object(
        candidate_pipeline_path
    )

    provenance = manifest.get("provenance", {})
    executables = provenance.get("executables", {}) if isinstance(provenance, dict) else {}
    inputs = provenance.get("inputs", {}) if isinstance(provenance, dict) else {}
    fellaga_evidence = (
        executables.get("fellaga", {}) if isinstance(executables, dict) else {}
    )
    expected_fellaga_hash = (
        fellaga_evidence.get("sha256") if isinstance(fellaga_evidence, dict) else None
    )
    expected_pipeline_hash = (
        inputs.get("pipeline_corpus_sha256") if isinstance(inputs, dict) else None
    )

    reasons: list[str] = []
    if len(ordered_domains) < MINIMUM_DOMAINS:
        reasons.append("fewer_than_30_authorized_domains")
    if manifest_issues:
        reasons.append("missing_or_invalid_manifest")
    if domain_errors or invalid_rows or unexpected_runs:
        reasons.append("invalid_benchmark_rows_or_domains")
    if invalid_timing_runs:
        reasons.append("missing_or_inconsistent_timing_evidence")
    if campaign_mismatch_runs:
        reasons.append("row_campaign_id_mismatch")
    if missing_runs:
        reasons.append("missing_required_runs")
    if duplicate_runs:
        reasons.append("duplicate_required_runs")
    if failed_discovery_runs:
        reasons.append("failed_or_timed_out_discovery_runs")
    if failed_validation_runs:
        reasons.append("failed_or_timed_out_validation_runs")
    if invalid_output_runs:
        reasons.append("missing_or_invalid_validation_outputs")
    if missing_truth:
        reasons.append("missing_ground_truth")
    if empty_truth or invalid_truth_names:
        reasons.append("empty_or_invalid_ground_truth")
    if ranked_domains != len(ordered_domains):
        reasons.append("incomplete_ranked_domains")
    if win_rate < 0.80:
        reasons.append("win_rate_below_80_percent")
    if validated_gain is None or validated_gain < 0.10:
        reasons.append("validated_gain_below_10_percent")
    false_discovery_rate = aggregate_metrics["false_discovery_rate"]
    if false_discovery_rate is None or false_discovery_rate >= 0.005:
        reasons.append("false_discovery_rate_not_below_0_5_percent")
    aggregate_recall = aggregate_metrics["recall"]
    if aggregate_recall != 1.0 or aggregate_metrics["false_negatives"] != 0:
        reasons.append("aggregate_ground_truth_recall_below_100_percent")
    if incomplete_fellaga_ground_truth_runs:
        reasons.append("fellaga_run_ground_truth_recall_below_100_percent")
    if not coverage_duration_ok:
        reasons.append("deep_profile_exceeds_2x_best_coverage_duration")
    if dns_transport_error == "missing":
        reasons.append("missing_dns_transport_benchmark")
    elif dns_transport_error is not None:
        reasons.append("invalid_or_unbound_dns_transport_benchmark")
    if not isinstance(dns_transport, dict):
        if dns_transport_error != "missing":
            reasons.append("invalid_or_unbound_dns_transport_benchmark")
    else:
        if dns_transport.get("status") != "success" or dns_transport.get("exit_code") != 0:
            reasons.append("dns_transport_benchmark_failed")
        if (
            dns_transport.get("campaign_id") != campaign_id
            or dns_transport.get("fellaga_sha256") != expected_fellaga_hash
        ):
            reasons.append("dns_transport_provenance_mismatch")
        transport_queries = _finite_number(dns_transport, "queries", 0)
        transport_qps = _finite_number(dns_transport, "queries_per_second", 0)
        transport_loss = _finite_number(dns_transport, "loss_rate", 1)
        if transport_queries < 100_000:
            reasons.append("dns_transport_fewer_than_100k_queries")
        if transport_qps < 25_000:
            reasons.append("dns_transport_below_25k_qps")
        if not 0 <= transport_loss < 0.01:
            reasons.append("dns_transport_loss_at_or_above_1_percent")
    if candidate_pipeline_error == "missing":
        reasons.append("missing_candidate_pipeline_benchmark")
    elif candidate_pipeline_error is not None:
        reasons.append("invalid_candidate_pipeline_json")
    if not isinstance(candidate_pipeline, dict):
        if candidate_pipeline_error != "missing":
            reasons.append("invalid_candidate_pipeline_json")
    else:
        if (
            candidate_pipeline.get("status") != "success"
            or candidate_pipeline.get("exit_code") != 0
            or candidate_pipeline.get("engine_status") != "success"
        ):
            reasons.append("candidate_pipeline_benchmark_failed")
        if (
            candidate_pipeline.get("schema_version") != 1
            or candidate_pipeline.get("benchmark") != "candidate_pipeline"
            or candidate_pipeline.get("engine") != "fellaga_core"
        ):
            reasons.append("invalid_candidate_pipeline_schema")
        if (
            candidate_pipeline.get("campaign_id") != campaign_id
            or candidate_pipeline.get("fellaga_sha256") != expected_fellaga_hash
            or candidate_pipeline.get("binary_sha256") != expected_fellaga_hash
            or candidate_pipeline.get("corpus_sha256") != expected_pipeline_hash
            or candidate_pipeline.get("wordlist_sha256") != expected_pipeline_hash
        ):
            reasons.append("candidate_pipeline_provenance_mismatch")
        candidates = _finite_number(
            candidate_pipeline,
            "requested_candidates",
            _finite_number(candidate_pipeline, "candidates", 0),
        )
        processed = _finite_number(candidate_pipeline, "processed_candidates", 0)
        if candidates < 10_000_000:
            reasons.append("candidate_pipeline_fewer_than_10m_candidates")
        if candidates <= 0 or processed > candidates or processed / candidates < 0.99:
            reasons.append("candidate_pipeline_loss_at_or_above_1_percent")
        stage_names = (
            "loaded_candidates",
            "persisted_candidates",
            "scheduled_candidates",
            "dns_dispatched_candidates",
            "processed_candidates",
        )
        stage_counts = [
            _finite_number(candidate_pipeline, name, -1) for name in stage_names
        ]
        if (
            not candidates.is_integer()
            or any(not count.is_integer() or count != candidates for count in stage_counts)
        ):
            reasons.append("candidate_pipeline_incomplete_stage_counts")
        definitive = _finite_number(
            candidate_pipeline, "definitive_negative_candidates", -1
        )
        indeterminate = _finite_number(
            candidate_pipeline, "indeterminate_candidates", -1
        )
        positive = _finite_number(candidate_pipeline, "positive_candidates", -1)
        dispatched = _finite_number(
            candidate_pipeline, "dns_dispatched_candidates", -1
        )
        if (
            definitive < 0
            or indeterminate < 0
            or positive < 0
            or not definitive.is_integer()
            or not indeterminate.is_integer()
            or not positive.is_integer()
            or positive != 0
            or indeterminate != 0
            or positive + definitive != processed
            or processed + indeterminate != dispatched
        ):
            reasons.append("candidate_pipeline_invalid_outcome_counts")
        pipeline_rss = _finite_number(
            candidate_pipeline, "max_rss_kib", 1_048_577
        )
        if not 0 <= pipeline_rss < 1_048_576:
            reasons.append("candidate_pipeline_memory_at_or_above_1_gib")

    # Keep reasons stable and compact for automation.
    reasons = list(dict.fromkeys(reasons))
    summary: dict[str, Any] = {
        "authorized_domains": len(ordered_domains),
        "required_repetitions": required_repetitions,
        "ranked_domains": ranked_domains,
        "fellaga_wins": wins,
        "fellaga_win_rate": win_rate,
        "fellaga_live_total": fellaga_total,
        "best_competitor_live_total": best_competitor_total,
        "fellaga_true_positive_total": fellaga_total,
        "best_competitor_true_positive_total": best_competitor_total,
        "validated_gain": validated_gain,
        "true_positives": aggregate_metrics["true_positives"],
        "false_positives": aggregate_metrics["false_positives"],
        "false_negatives": aggregate_metrics["false_negatives"],
        "precision": aggregate_metrics["precision"],
        "recall": aggregate_metrics["recall"],
        "f1": aggregate_metrics["f1"],
        "false_discovery_rate": false_discovery_rate,
        "deep_within_2x_best_coverage": coverage_duration_ok,
        "dns_transport": dns_transport,
        "candidate_pipeline": candidate_pipeline,
        "qualification_passed": not reasons,
        "qualification_failures": reasons,
        "missing_required_runs": missing_runs,
        "duplicate_required_runs": duplicate_runs,
        "failed_discovery_runs": failed_discovery_runs,
        "failed_validation_runs": failed_validation_runs,
        "invalid_output_runs": invalid_output_runs,
        "invalid_timing_runs": invalid_timing_runs,
        "campaign_mismatch_runs": campaign_mismatch_runs,
        "incomplete_fellaga_ground_truth_runs": incomplete_fellaga_ground_truth_runs,
        "unexpected_runs": unexpected_runs,
        "missing_ground_truth": missing_truth,
        "empty_ground_truth": empty_truth,
        "invalid_ground_truth_names": invalid_truth_names,
        "manifest_issues": manifest_issues,
    }
    return {"summary": summary, "results": processed_rows}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("--truth-root", type=pathlib.Path)
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="exit non-zero when any qualification gate fails",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = build_report(args.root, args.truth_root)
    output = args.root / "report.json"
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"rows": len(report["results"]), "report": str(output)}))
    if args.require_pass and not report["summary"]["qualification_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
