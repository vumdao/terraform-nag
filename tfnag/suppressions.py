"""JSON suppressions and the restricted legacy YAML suppression format."""

from __future__ import annotations

import fnmatch
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from .registry import INVENTORY, discover

CONFIG_ERROR_EXIT = 3
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_INSTANCE_RE = re.compile(r"\[[^]]*\]")


class SuppressionConfigError(ValueError):
    """A suppression file cannot be interpreted safely."""


def suppression_path(explicit: str | Path | None = None) -> Path | None:
    """Resolve the default JSON-first suppression file lookup."""
    if explicit is not None:
        return Path(explicit)
    json_path = Path.cwd() / ".tfnag.json"
    if json_path.exists():
        return json_path
    yaml_path = Path.cwd() / ".tfnag.yml"
    if yaml_path.exists():
        return yaml_path
    return None


def _problem(path: Path, index: int | None, message: str) -> SuppressionConfigError:
    location = f"entry {index}" if index is not None else "file"
    return SuppressionConfigError(f"{path}: {location}: {message}")


def _validate_date(path: Path, index: int, value: Any) -> str:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise _problem(path, index, "expires must be a YYYY-MM-DD date")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise _problem(path, index, "expires must be a YYYY-MM-DD date") from exc
    return value


def _validate_entry(
    path: Path,
    index: int,
    item: Any,
    *,
    json_format: bool,
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise _problem(path, index, "entry must be an object")
    allowed = (
        {"id", "resources", "reason", "expires"}
        if json_format
        else {"id", "rule", "resources", "address", "reason", "expires"}
    )
    unknown = sorted(set(item) - allowed)
    if unknown and json_format:
        raise _problem(path, index, f"unknown key(s): {', '.join(unknown)}")
    rule_id = item.get("id", item.get("rule"))
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise _problem(path, index, "id is required")
    rule_id = rule_id.strip()
    discover()
    if rule_id not in INVENTORY and not (not json_format and rule_id == "*"):
        raise _problem(path, index, f"unknown rule ID {rule_id!r}")

    if json_format:
        resources = item.get("resources")
        if not isinstance(resources, list) or not resources:
            raise _problem(path, index, "resources must be a non-empty array")
    else:
        resources = item.get("resources")
        if resources is None:
            resources = [item.get("address", "*")]
        elif not isinstance(resources, list) or not resources:
            raise _problem(path, index, "resources must be a non-empty array")
    if any(not isinstance(resource, str) or not resource.strip() for resource in resources):
        raise _problem(path, index, "resources must contain non-empty strings")
    resources = [resource.strip() for resource in resources]

    reason = item.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise _problem(path, index, "reason is required and must be non-empty")
    normalized = {
        "id": rule_id,
        "resources": resources,
        "reason": reason.strip(),
        "_index": index,
        "_matched": False,
    }
    if "expires" in item:
        normalized["expires"] = _validate_date(path, index, item["expires"])
    return normalized


def _read_yaml(path: Path) -> list[Any]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current is not None:
                rows.append(current)
            current = {}
            stripped = stripped[2:].strip()
        if ":" in stripped and current is not None:
            key, value = stripped.split(":", 1)
            current[key.strip()] = value.strip().strip("\"'")
    if current is not None:
        rows.append(current)
    return rows


def load_suppressions(path: str | Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    file_path = Path(path)
    if not file_path.exists():
        raise SuppressionConfigError(f"{file_path}: file does not exist")
    json_format = file_path.suffix.lower() == ".json"
    if file_path.suffix.lower() not in {".yml", ".yaml", ".json"}:
        prefix = file_path.read_text(encoding="utf-8").lstrip()[:1]
        json_format = prefix in {"[", "{"}
    if json_format:
        try:
            document = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SuppressionConfigError(f"{file_path}: malformed JSON: {exc}") from exc
        if isinstance(document, list):
            rows = document
        elif isinstance(document, dict):
            if set(document) != {"suppressions"}:
                unknown = sorted(set(document) - {"suppressions"})
                message = (
                    f"unknown top-level key(s): {', '.join(unknown)}"
                    if unknown
                    else "object must contain a suppressions array"
                )
                raise _problem(file_path, None, message)
            rows = document["suppressions"]
        else:
            raise _problem(file_path, None, "top level must be an array or object")
        if not isinstance(rows, list):
            raise _problem(file_path, None, "suppressions must be an array")
    else:
        try:
            rows = _read_yaml(file_path)
        except OSError as exc:
            raise SuppressionConfigError(f"{file_path}: cannot read file: {exc}") from exc
    return [
        _validate_entry(file_path, index, item, json_format=json_format)
        for index, item in enumerate(rows)
    ]


def _segment_parts(segment: str) -> tuple[str, list[str]]:
    keys = [key[1:-1] for key in _INSTANCE_RE.findall(segment)]
    return segment.split("[", 1)[0], keys


def _segment_matches(pattern: str, candidate: str) -> bool:
    pattern_base, pattern_keys = _segment_parts(pattern)
    candidate_base, candidate_keys = _segment_parts(candidate)
    if not fnmatch.fnmatchcase(candidate_base, pattern_base):
        return False
    if not pattern_keys:
        return True
    return len(pattern_keys) == len(candidate_keys) and all(
        fnmatch.fnmatchcase(candidate_key, pattern_key)
        for pattern_key, candidate_key in zip(pattern_keys, candidate_keys)
    )


def address_matches(pattern: str, address: str) -> bool:
    """Match a suffix on Terraform address segments, including instance keys."""
    if pattern == "*":
        return True
    pattern_parts = pattern.split(".")
    address_parts = address.split(".")
    if len(pattern_parts) > len(address_parts):
        return False
    return all(
        _segment_matches(pattern_part, address_part)
        for pattern_part, address_part in zip(pattern_parts, address_parts[-len(pattern_parts) :])
    )


def _entry_matches(item: dict[str, Any], rule_id: str, address: str) -> bool:
    item_id = item.get("id", item.get("rule"))
    resources = item.get("resources")
    if resources is None:
        resources = [item.get("address", "*")]
    if item_id not in (rule_id, "*"):
        return False
    return any(address_matches(resource, address) for resource in resources)


def suppression_for(
    suppressions: list[dict[str, Any]], rule_id: str, address: str, strict: bool = False
) -> str | None:
    status = suppression_status(suppressions, rule_id, address, strict)
    return status[1] if status and status[0] == "suppressed" else None


def suppression_status(
    suppressions: list[dict[str, Any]], rule_id: str, address: str, strict: bool = False
) -> tuple[str, str] | None:
    if strict:
        return None
    expired: tuple[str, str] | None = None
    for item in suppressions:
        if not _entry_matches(item, rule_id, address):
            continue
        item["_matched"] = True
        item["_last_match"] = (rule_id, address)
        reason = str(item["reason"])
        expires = item.get("expires")
        if expires and date.fromisoformat(expires) < date.today():
            expired = ("expired", reason)
            continue
        return ("suppressed", reason)
    return expired


def dead_suppressions(
    suppressions: list[dict[str, Any]], strict: bool = False
) -> list[dict[str, Any]]:
    if strict:
        return []
    return [item for item in suppressions if not item.get("_matched", False)]
