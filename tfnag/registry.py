"""Rule decorator, registry, inventory seeding, and auto-discovery."""

from __future__ import annotations

import importlib
import json
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .model import Compliance, Level, Resource


@dataclass
class Rule:
    id: str
    level: Level
    resource_types: tuple[str, ...]
    cfn_origin: str
    info: str
    check: Callable[[Resource, object], Compliance]
    explanation: str = ""
    attributes: dict[str, tuple[str, ...]] = field(default_factory=dict)


RULES: dict[str, Rule] = {}
INVENTORY: dict[str, dict] = {}


def rule(
    id: str,
    level: Level,
    resource_types: tuple[str, ...],
    cfn_origin: str,
    info: str = "",
    attributes: dict[str, tuple[str, ...]] | None = None,
):
    def decorate(check):
        RULES[id] = Rule(
            id,
            level,
            resource_types,
            cfn_origin,
            info,
            check,
            attributes=attributes or {resource_type: () for resource_type in resource_types},
        )
        return check

    return decorate


def seed_inventory() -> None:
    if INVENTORY:
        return
    path = Path(__file__).parent / "data" / "aws_solutions_pack.json"
    INVENTORY.update({f"AwsSolutions-{item['id']}": item for item in json.loads(path.read_text())})


def discover() -> None:
    seed_inventory()
    import tfnag.rules as package

    for module in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if not module.ispkg:
            importlib.import_module(module.name)
    for rule_id, registered in RULES.items():
        item = INVENTORY.get(rule_id, {})
        if not registered.info:
            registered.info = item.get("info", "")
        registered.explanation = item.get("explanation", registered.info)


def status(rule_id: str) -> str:
    if INVENTORY.get(rule_id, {}).get("not_applicable_terraform"):
        return "not-applicable-to-terraform"
    return "implemented" if rule_id in RULES else "not-implemented"
