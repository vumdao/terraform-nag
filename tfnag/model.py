"""The small, provider-neutral model passed to rules."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Compliance(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class Level(str, Enum):
    ERROR = "ERROR"
    WARN = "WARN"


class _Unknown:
    def __repr__(self) -> str:
        return "(known after apply)"


UNKNOWN = _Unknown()
_INSTANCE_KEY_RE = re.compile(r"\[[^]]*\]")


def normalize_address(address: str) -> str:
    """Remove count/for_each instance keys from a Terraform address."""
    return _INSTANCE_KEY_RE.sub("", address)


@dataclass
class Resource:
    address: str
    type: str
    name: str
    values: dict[str, Any] = field(default_factory=dict)
    module_path: str = ""
    provider: str | None = None
    mode: str = "managed"
    unknown_paths: set[str] = field(default_factory=set)
    configured_paths: set[str] | None = None

    def get(self, path: str, default: Any = None) -> Any:
        """Read dotted Terraform attributes, preserving unknown markers."""
        parts = path.split(".")
        value: Any = self.values
        consumed: list[str] = []
        position = 0
        while position < len(parts):
            part = parts[position]
            prefix = ".".join(consumed + [part])
            if self.has_unknown(prefix) or self._has_unknown_list_path(prefix):
                return UNKNOWN
            if isinstance(value, dict) and part in value:
                value = value[part]
                consumed.append(part)
                position += 1
                continue
            if isinstance(value, list):
                if part.isdigit():
                    index = int(part)
                    if index >= len(value):
                        return default
                    value = value[index]
                    consumed.append(part)
                    position += 1
                    continue
                if len(value) == 1:
                    value = value[0]
                    continue
            return default
        return value

    def _has_unknown_list_path(self, path: str) -> bool:
        normalized = re.sub(r"\.\d+(?=\.|$)", "", path)
        return any(
            re.sub(r"\.\d+(?=\.|$)", "", unknown) == normalized
            or normalized.startswith(re.sub(r"\.\d+(?=\.|$)", "", unknown) + ".")
            for unknown in self.unknown_paths
        )

    def has_unknown(self, path: str = "") -> bool:
        return any(p == path or path.startswith(p + ".") for p in self.unknown_paths)

    def is_configured(self, path: str) -> bool:
        """Return whether configuration expressions include this attribute."""
        if self.configured_paths is None:
            return True
        normalized = re.sub(r"\.\d+(?=\.|$)", "", path)
        return any(
            normalized == configured
            or normalized.startswith(configured + ".")
            or configured.startswith(normalized + ".")
            for configured in self.configured_paths
        )


@dataclass
class Finding:
    rule_id: str
    level: Level
    address: str
    message: str
    compliance: Compliance
    cfn_origin: str = ""
    suppression: str | None = None
    details: list[str] = field(default_factory=list)
    suppression_entry: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level.value,
            "address": self.address,
            "message": self.message,
            "compliance": self.compliance.value,
            "cfn_origin": self.cfn_origin,
            "suppression": self.suppression,
            "suppression_entry": self.suppression_entry,
            "details": self.details,
        }
