"""Load terraform show -json plan and state documents."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

from .model import UNKNOWN, Resource, normalize_address


class PlanLoadError(Exception):
    """Raised when the --plan-json input cannot be read as Terraform JSON."""


def _unknown_paths(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if value is True:
        if prefix:
            paths.add(prefix)
        return paths
    if isinstance(value, dict):
        for key, child in value.items():
            paths |= _unknown_paths(child, f"{prefix}.{key}".strip("."))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths |= _unknown_paths(child, f"{prefix}.{index}".strip("."))
    return paths


def _mark_unknown(value: Any, unknown: Any) -> Any:
    if unknown is True:
        return UNKNOWN
    if isinstance(unknown, dict) and isinstance(value, dict):
        return {k: _mark_unknown(v, unknown.get(k)) for k, v in value.items()}
    if isinstance(unknown, list) and isinstance(value, list):
        return [
            _mark_unknown(v, unknown[i] if i < len(unknown) else None) for i, v in enumerate(value)
        ]
    return value


_MISSING = object()
_EXPRESSION_KEYS = {"constant_value", "references", "traversal", "function"}


def _configured_paths(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _EXPRESSION_KEYS:
                continue
            path = f"{prefix}.{key}".strip(".")
            paths.add(path)
            paths.update(_configured_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.update(_configured_paths(child, prefix))
    return paths


def _unknown_is_configured(path: str, configured_paths: set[str]) -> bool:
    normalized = ".".join(part for part in path.split(".") if not part.isdigit())
    return any(
        normalized == configured
        or normalized.startswith(configured + ".")
        or configured.startswith(normalized + ".")
        for configured in configured_paths
    )


def _filter_unknown(value: Any, prefix: str, configured_paths: set[str]) -> Any:
    if value is True:
        return True if _unknown_is_configured(prefix, configured_paths) else _MISSING
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            filtered = _filter_unknown(
                child,
                f"{prefix}.{key}".strip("."),
                configured_paths,
            )
            if filtered is not _MISSING:
                result[key] = filtered
        return result if result else _MISSING
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            filtered = _filter_unknown(
                child,
                f"{prefix}.{index}".strip("."),
                configured_paths,
            )
            result.append(filtered if filtered is not _MISSING else None)
        return result if any(item is not None for item in result) else _MISSING
    return _MISSING


def _configuration_resources(module: dict[str, Any], prefix: str = "") -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in module.get("resources", []):
        address = item.get("address", "")
        qualified = ".".join(x for x in (prefix, address) if x)
        result[normalize_address(qualified)] = item
    for child in module.get("child_modules", []):
        child_address = child.get("address", "")
        child_prefix = ".".join(x for x in (prefix, child_address) if x)
        result.update(_configuration_resources(child, child_prefix))
    for name, call in (module.get("module_calls") or {}).items():
        child = call.get("module") or {}
        child_address = call.get("address") or f"module.{name}"
        child_prefix = ".".join(x for x in (prefix, child_address) if x)
        result.update(_configuration_resources(child, child_prefix))
    return result


def _resource(
    item: dict[str, Any],
    module_path: str = "",
    unknown: dict[str, Any] | None = None,
    configured_paths: set[str] | None = None,
) -> Resource:
    address = item.get("address", "")
    values = item.get("values") or {}
    unknown = unknown if unknown is not None else item.get("after_unknown") or {}
    if configured_paths is not None:
        filtered = _filter_unknown(unknown, "", configured_paths)
        unknown = filtered if filtered is not _MISSING else {}
    return Resource(
        address=address,
        type=item.get("type", ""),
        name=item.get("name", address.rsplit(".", 1)[-1]),
        values=_mark_unknown(values, unknown),
        module_path=module_path,
        provider=item.get("provider_name") or item.get("provider"),
        mode=item.get("mode", "managed"),
        unknown_paths=_unknown_paths(unknown),
        configured_paths=configured_paths,
    )


def _walk_module(
    module: dict[str, Any],
    path: str = "",
    unknown_by_address: dict[str, dict[str, Any]] | None = None,
    configuration_by_address: dict[str, dict[str, Any]] | None = None,
) -> Iterable[Resource]:
    for item in module.get("resources", []):
        address = item.get("address", "")
        config = (configuration_by_address or {}).get(normalize_address(address))
        configured = _configured_paths(config.get("expressions", {})) if config else None
        yield _resource(
            item,
            path,
            (unknown_by_address or {}).get(address),
            configured,
        )
    for child in module.get("child_modules", []):
        child_path = child.get("address", "")
        yield from _walk_module(
            child,
            child_path,
            unknown_by_address,
            configuration_by_address,
        )


def _resource_changes(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    changes: dict[str, dict[str, Any]] = {}
    for change in document.get("resource_changes", []):
        address = change.get("address", "")
        details = change.get("change") or {}
        if address and details.get("after_unknown"):
            changes[address] = details["after_unknown"]
    return changes


def load_document(document: dict[str, Any]) -> tuple[list[Resource], dict[str, Any]]:
    """Return resources and the original configuration graph source."""
    root = document.get("planned_values", {}).get("root_module")
    if root is None:
        root = document.get("values", {}).get("root_module", {})
    configuration = document.get("configuration", {})
    configuration_by_address = _configuration_resources(configuration.get("root_module", {}))
    resources = list(
        _walk_module(
            root or {},
            unknown_by_address=_resource_changes(document),
            configuration_by_address=configuration_by_address,
        )
    )
    return resources, configuration


_NOT_JSON_HINT = (
    "expected Terraform plan or state JSON. If this is a binary plan file "
    "(e.g. the output of `terraform plan -out`), convert it first with "
    "`terraform show -json <plan> > plan.json`."
)


def _parse_json(raw: str, source: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanLoadError(f"{source}: {_NOT_JSON_HINT}") from exc


def load_plan(path: str | Path) -> tuple[list[Resource], dict[str, Any]]:
    if str(path) == "-":
        raw = sys.stdin.buffer.read()
        source = "<stdin>"
    else:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise PlanLoadError(f"{path}: {exc.strerror or exc}") from exc
        source = str(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PlanLoadError(f"{source}: {_NOT_JSON_HINT}") from exc
    return load_document(_parse_json(text, source))
