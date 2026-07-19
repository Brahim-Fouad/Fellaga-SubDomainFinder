#!/usr/bin/env python3
"""Strict, product-neutral benchmark tool adapters."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import pathlib
import re
import shutil
import string
import subprocess
import sys
from collections.abc import Mapping
from typing import Any


DEFAULT_TOOLSET = pathlib.Path(__file__).with_name("toolset.local.json")
ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
OUTPUT_KINDS = {"line_stdout", "line_file", "finding_json", "dns_event_tree"}
MAX_TOOLSET_BYTES = 1024 * 1024


class ToolsetError(ValueError):
    """Raised when an adapter document or rendering request is unsafe."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolsetError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _keys(value: Any, required: set[str], optional: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolsetError(f"{where} must be an object")
    actual = set(value)
    if missing := required - actual:
        raise ToolsetError(f"{where} is missing: {', '.join(sorted(missing))}")
    if extra := actual - required - optional:
        raise ToolsetError(f"{where} has unknown fields: {', '.join(sorted(extra))}")
    return value


def _text(value: Any, where: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or "\0" in value or (identifier and not ID.fullmatch(value)):
        raise ToolsetError(f"{where} must be a safe string")
    return value


def _file_hash(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ids(value: Any, where: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ToolsetError(f"{where} must be a{' non-empty' if nonempty else ''} list")
    result = [_text(item, f"{where}[]", identifier=True) for item in value]
    if len(result) != len(set(result)):
        raise ToolsetError(f"{where} contains duplicates")
    return result


def _placeholders(template: str, where: str) -> set[str]:
    fields: set[str] = set()
    try:
        for _, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            if spec or conversion or not ID.fullmatch(name):
                raise ToolsetError(f"{where} has an unsafe placeholder")
            fields.add(name)
    except ValueError as exc:
        raise ToolsetError(f"{where} has invalid braces") from exc
    return fields


def _argv(value: Any, allowed: set[str], where: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ToolsetError(f"{where} must be a non-empty command array")
    result: list[str] = []
    for index, item in enumerate(value):
        item = _text(item, f"{where}[{index}]")
        unknown = _placeholders(item, f"{where}[{index}]") - allowed
        if unknown:
            raise ToolsetError(f"{where}[{index}] uses undeclared placeholders: {', '.join(sorted(unknown))}")
        result.append(item)
    if result[0] != "{executable}":
        raise ToolsetError(f"{where} must start with {{executable}}")
    return result


def _command(value: Any, parameters: set[str], where: str) -> None:
    value = _keys(value, {"argv", "output"}, {"required_context"}, where)
    context = set(_ids(value.get("required_context", []), f"{where}.required_context"))
    allowed = {"executable"} | parameters | context
    argv = _argv(value["argv"], allowed, f"{where}.argv")
    output = _keys(value["output"], {"kind"}, {"path"}, f"{where}.output")
    kind = _text(output["kind"], f"{where}.output.kind")
    if kind not in OUTPUT_KINDS:
        raise ToolsetError(f"{where}.output.kind is unsupported")
    path = output.get("path")
    if (kind == "line_stdout") != (path is None):
        raise ToolsetError(f"{where}.output.path is required only for file/tree output")
    used = set().union(*(_placeholders(item, f"{where}.argv") for item in argv))
    if path is not None:
        path = _text(path, f"{where}.output.path")
        fields = _placeholders(path, f"{where}.output.path")
        if unknown := fields - allowed:
            raise ToolsetError(f"{where}.output.path uses undeclared placeholders: {', '.join(sorted(unknown))}")
        used |= fields
    if missing := context - used:
        raise ToolsetError(f"{where} declares unused context: {', '.join(sorted(missing))}")


def validate_toolset(document: Any) -> dict[str, Any]:
    root = _keys(document, {"schema_version", "subject", "campaigns", "tools"}, set(), "toolset")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ToolsetError("toolset.schema_version must be 1")
    subject = _text(root["subject"], "toolset.subject", identifier=True)
    tools = root["tools"]
    if not isinstance(tools, dict) or not tools:
        raise ToolsetError("toolset.tools must be a non-empty object")
    for tool_id, tool in tools.items():
        _text(tool_id, "tool id", identifier=True)
        tool = _keys(tool, {"executable", "identity", "dns_controls", "commands"}, {"parameters", "preflight", "passive_policy"}, f"tools.{tool_id}")
        _text(tool["executable"], f"tools.{tool_id}.executable")
        parameters = tool.get("parameters", {})
        if not isinstance(parameters, dict):
            raise ToolsetError(f"tools.{tool_id}.parameters must be an object")
        for key, value in parameters.items():
            _text(key, f"tools.{tool_id}.parameters key", identifier=True)
            _text(value, f"tools.{tool_id}.parameters.{key}")
        identity = _keys(tool["identity"], {"version_argv", "extra_kind"}, {"distribution"}, f"tools.{tool_id}.identity")
        _argv(identity["version_argv"], {"executable"} | set(parameters), f"tools.{tool_id}.identity.version_argv")
        extra = _text(identity["extra_kind"], f"tools.{tool_id}.identity.extra_kind")
        if extra not in {"none", "python_distribution"}:
            raise ToolsetError(f"tools.{tool_id}.identity.extra_kind is unsupported")
        if (extra == "python_distribution") != ("distribution" in identity):
            raise ToolsetError(f"tools.{tool_id}.identity.distribution does not match extra_kind")
        if "distribution" in identity:
            _text(identity["distribution"], f"tools.{tool_id}.identity.distribution")
        _ids(tool["dns_controls"], f"tools.{tool_id}.dns_controls")
        commands = tool["commands"]
        if not isinstance(commands, dict):
            raise ToolsetError(f"tools.{tool_id}.commands must be an object")
        for phase, command in commands.items():
            _text(phase, f"tools.{tool_id}.commands phase", identifier=True)
            _command(command, set(parameters), f"tools.{tool_id}.commands.{phase}")
        if "preflight" in tool:
            preflight = _keys(tool["preflight"], {"argv", "required_literals", "forbidden_regexes"}, {"required_context"}, f"tools.{tool_id}.preflight")
            context = set(_ids(preflight.get("required_context", []), f"tools.{tool_id}.preflight.required_context"))
            argv = _argv(preflight["argv"], {"executable"} | set(parameters) | context, f"tools.{tool_id}.preflight.argv")
            used = set().union(*(_placeholders(item, "preflight argv") for item in argv))
            if missing := context - used:
                raise ToolsetError(f"tools.{tool_id}.preflight declares unused context: {', '.join(sorted(missing))}")
            for field in ("required_literals", "forbidden_regexes"):
                values = preflight[field]
                if not isinstance(values, list):
                    raise ToolsetError(f"tools.{tool_id}.preflight.{field} must be a list")
                for item in values:
                    item = _text(item, f"tools.{tool_id}.preflight.{field}[]")
                    if field == "forbidden_regexes":
                        try:
                            re.compile(item)
                        except re.error as exc:
                            raise ToolsetError(f"tools.{tool_id}.preflight has an invalid regex") from exc
        if "passive_policy" in tool:
            policy = _keys(tool["passive_policy"], {"target_contact", "direct_dns", "direct_http_or_tls"}, set(), f"tools.{tool_id}.passive_policy")
            if (
                policy["target_contact"] != "prohibited"
                or type(policy["direct_dns"]) is not bool
                or policy["direct_dns"]
                or type(policy["direct_http_or_tls"]) is not bool
                or policy["direct_http_or_tls"]
            ):
                raise ToolsetError(f"tools.{tool_id}.passive_policy must be fail-closed")
    if subject not in tools:
        raise ToolsetError("toolset.subject is not defined in tools")
    campaigns = _keys(root["campaigns"], {"active", "passive-observational"}, set(), "toolset.campaigns")
    active = _keys(campaigns["active"], {"discoverers", "validator", "capacity_guard", "provenance_only", "credential_participants"}, set(), "campaigns.active")
    discoverers = _ids(active["discoverers"], "campaigns.active.discoverers", nonempty=True)
    validator = _text(active["validator"], "campaigns.active.validator", identifier=True)
    capacity = _text(active["capacity_guard"], "campaigns.active.capacity_guard", identifier=True)
    references = discoverers + [validator, capacity] + _ids(active["provenance_only"], "campaigns.active.provenance_only") + _ids(active["credential_participants"], "campaigns.active.credential_participants")
    passive = _keys(campaigns["passive-observational"], {"discoverers"}, set(), "campaigns.passive-observational")
    passive_discoverers = _ids(passive["discoverers"], "campaigns.passive-observational.discoverers", nonempty=True)
    references += passive_discoverers
    if unknown := set(references) - set(tools):
        raise ToolsetError(f"campaigns reference unknown tools: {', '.join(sorted(unknown))}")
    if subject not in discoverers or subject not in passive_discoverers:
        raise ToolsetError("toolset.subject must participate in both campaigns")
    if capacity not in discoverers:
        raise ToolsetError("campaigns.active.capacity_guard must be an active discoverer")
    for tool_id in discoverers:
        if "active" not in tools[tool_id]["commands"]:
            raise ToolsetError(f"active discoverer {tool_id} has no active command")
    if "validate" not in tools[validator]["commands"]:
        raise ToolsetError("active validator has no validate command")
    for tool_id in passive_discoverers:
        tool = tools[tool_id]
        if "passive-observational" not in tool["commands"]:
            raise ToolsetError(f"passive discoverer {tool_id} has no passive-observational command")
        if tool.get("passive_policy") != {"target_contact": "prohibited", "direct_dns": False, "direct_http_or_tls": False}:
            raise ToolsetError(f"passive discoverer {tool_id} lacks a fail-closed policy")
    return root


def load_toolset(path: pathlib.Path | str = DEFAULT_TOOLSET) -> dict[str, Any]:
    path = pathlib.Path(path)
    try:
        if path.stat().st_size > MAX_TOOLSET_BYTES:
            raise ToolsetError("toolset file exceeds the size limit")
        document = json.loads(path.read_text(encoding="utf-8", errors="strict"), object_pairs_hook=_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolsetError(f"cannot read toolset: {exc}") from exc
    return validate_toolset(document)


def normalized_snapshot(toolset: Mapping[str, Any]) -> dict[str, Any]:
    validate_toolset(toolset)
    return json.loads(json.dumps(toolset, sort_keys=True, separators=(",", ":")))


def snapshot_hash(toolset: Mapping[str, Any]) -> str:
    data = json.dumps(normalized_snapshot(toolset), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def campaign_roles(toolset: Mapping[str, Any], name: str) -> dict[str, Any]:
    validate_toolset(toolset)
    if name not in {"active", "passive-observational"}:
        raise ToolsetError("unknown campaign")
    return json.loads(json.dumps(toolset["campaigns"][name], sort_keys=True))


def resolve_executable(toolset: Mapping[str, Any], tool_id: str, search_path: str | None = None) -> pathlib.Path:
    validate_toolset(toolset)
    if tool_id not in toolset["tools"]:
        raise ToolsetError(f"unknown tool: {tool_id}")
    configured = os.path.expanduser(toolset["tools"][tool_id]["executable"])
    found = shutil.which(configured, path=search_path) if pathlib.Path(configured).name == configured else configured
    if not found:
        raise ToolsetError(f"executable not found: {tool_id}")
    path = pathlib.Path(found).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ToolsetError(f"executable is not runnable: {tool_id}")
    return path


def _argument_value(value: Any) -> str:
    if isinstance(value, str):
        result = value
    elif value is None:
        result = "null"
    elif type(value) is bool:
        result = "true" if value else "false"
    elif type(value) is int:
        result = str(value)
    elif type(value) is float and math.isfinite(value):
        result = json.dumps(value, allow_nan=False)
    else:
        raise ToolsetError("render context values must be finite JSON scalars")
    if "\0" in result:
        raise ToolsetError("render context values must not contain NUL")
    return result


def _render(toolset: Mapping[str, Any], tool_id: str, phase: str, context: Mapping[str, Any] | None, *, preflight: bool = False) -> tuple[list[str], dict[str, Any] | None]:
    validate_toolset(toolset)
    if tool_id not in toolset["tools"]:
        raise ToolsetError(f"unknown tool: {tool_id}")
    tool = toolset["tools"][tool_id]
    item = tool.get("preflight") if preflight else tool["commands"].get(phase)
    if item is None:
        raise ToolsetError(f"undefined {'preflight' if preflight else 'phase'} for {tool_id}")
    supplied = {} if context is None else dict(context)
    if any(not isinstance(key, str) or not ID.fullmatch(key) for key in supplied):
        raise ToolsetError("render context keys must be safe identifiers")
    context_values = {key: _argument_value(value) for key, value in supplied.items()}
    required = set(item.get("required_context", []))
    parameters = dict(tool.get("parameters", {}))
    if missing := required - set(context_values):
        raise ToolsetError(f"missing render context: {', '.join(sorted(missing))}")
    if unknown := set(context_values) - required - set(parameters) - {"executable"}:
        raise ToolsetError(f"unknown render context: {', '.join(sorted(unknown))}")
    executable = context_values.get("executable") or str(resolve_executable(toolset, tool_id))
    values = parameters | context_values | {"executable": executable}
    argv = [part.format_map(values) for part in item["argv"]]
    return argv, None if preflight else item["output"]


def render_argv(toolset: Mapping[str, Any], tool_id: str, phase: str, context: Mapping[str, Any] | None = None) -> list[str]:
    return _render(toolset, tool_id, phase, context)[0]


def render_output(toolset: Mapping[str, Any], tool_id: str, phase: str, context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    _, output = _render(toolset, tool_id, phase, context)
    assert output is not None
    result = {"kind": output["kind"]}
    if "path" in output:
        tool = toolset["tools"][tool_id]
        supplied = {key: _argument_value(value) for key, value in dict(context or {}).items()}
        executable = supplied.get("executable") or str(resolve_executable(toolset, tool_id))
        values = dict(tool.get("parameters", {})) | supplied | {"executable": executable}
        result["path"] = output["path"].format_map(values)
    return result


def render_preflight_argv(toolset: Mapping[str, Any], tool_id: str, context: Mapping[str, Any] | None = None) -> list[str]:
    return _render(toolset, tool_id, "preflight", context, preflight=True)[0]


def capture_identity(toolset: Mapping[str, Any], tool_id: str, timeout_seconds: float = 10.0, env: Mapping[str, str] | None = None, search_path: str | None = None) -> dict[str, Any]:
    if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ToolsetError("identity timeout must be finite and positive")
    path = resolve_executable(toolset, tool_id, search_path)
    tool = toolset["tools"][tool_id]
    values = dict(tool.get("parameters", {})) | {"executable": str(path)}
    argv = [part.format_map(values) for part in tool["identity"]["version_argv"]]
    digest = _file_hash(path)
    status, version = "error", None
    try:
        completed = subprocess.run(argv, shell=False, check=False, capture_output=True, timeout=timeout_seconds, env=None if env is None else dict(env))
        output = b" ".join((completed.stdout + b"\n" + completed.stderr).split()).decode("utf-8", "replace")[:512]
        version = output or None
        status = "success" if completed.returncode == 0 and version else "error"
    except subprocess.TimeoutExpired:
        status = "timeout"
    except OSError:
        status = "error"
    identity = {"executable": str(path), "sha256": digest, "version": version, "version_probe_status": status, "extra": {"kind": "none"}}
    spec = tool["identity"]
    if spec["extra_kind"] == "python_distribution":
        try:
            distribution = importlib.metadata.distribution(spec["distribution"])
        except importlib.metadata.PackageNotFoundError as exc:
            raise ToolsetError(f"configured Python distribution is unavailable: {tool_id}") from exc
        identity["extra"] = {"kind": "python_distribution", "distribution": spec["distribution"], "version": distribution.version}
    return identity


def _context(value: str) -> dict[str, str]:
    if value.startswith("@"):
        value = pathlib.Path(value[1:]).read_text(encoding="utf-8")
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ToolsetError("context JSON must be an object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "snapshot"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", type=pathlib.Path, default=DEFAULT_TOOLSET)
        if name == "snapshot":
            sub.add_argument("--output", type=pathlib.Path)
    roles = commands.add_parser("roles")
    roles.add_argument("--config", type=pathlib.Path, default=DEFAULT_TOOLSET)
    roles.add_argument("campaign", choices=("active", "passive-observational"))
    listing = commands.add_parser("list")
    listing.add_argument("--config", type=pathlib.Path, default=DEFAULT_TOOLSET)
    listing.add_argument("--campaign", choices=("active", "passive-observational"))
    listing.add_argument("--null", action="store_true")
    render = commands.add_parser("render")
    render.add_argument("--config", type=pathlib.Path, default=DEFAULT_TOOLSET)
    render.add_argument("tool")
    render.add_argument("phase")
    render.add_argument("--context-json", default="{}")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        toolset = load_toolset(args.config)
        if args.command == "validate":
            print(json.dumps({"schema_version": 1, "status": "valid", "sha256": snapshot_hash(toolset)}, sort_keys=True))
        elif args.command == "roles":
            print(json.dumps(campaign_roles(toolset, args.campaign), sort_keys=True))
        elif args.command == "list":
            names = sorted(toolset["tools"])
            if args.campaign:
                roles_value = campaign_roles(toolset, args.campaign)
                names = sorted(set(roles_value.get("discoverers", [])) | {value for key, value in roles_value.items() if key in {"validator", "capacity_guard"}} | set(roles_value.get("provenance_only", [])))
            separator, ending = ("\0", "\0") if args.null else ("\n", "\n")
            sys.stdout.write(separator.join(names) + ending)
        elif args.command == "render":
            rendered = render_argv(toolset, args.tool, args.phase, _context(args.context_json))
            sys.stdout.buffer.write(b"\0".join(part.encode() for part in rendered) + b"\0")
        else:
            normalized = normalized_snapshot(toolset)
            result = {"schema_version": 1, "sha256": snapshot_hash(toolset), "toolset": normalized}
            encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.write_text(encoded, encoding="utf-8")
            else:
                sys.stdout.write(encoded)
    except (OSError, ToolsetError, json.JSONDecodeError) as exc:
        print(f"toolset: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
