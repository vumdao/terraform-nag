"""Rule execution and unknown/suppression policy."""

from __future__ import annotations

from dataclasses import dataclass

from .graph import ResourceGraph
from .model import Compliance, Finding, Level
from .registry import RULES, discover
from .suppressions import suppression_status


@dataclass
class Context:
    graph: ResourceGraph
    unknown_as: str = "warn"


def scan(
    resources, configuration, unknown_as="warn", suppressions=None, strict=False
) -> list[Finding]:
    discover()
    context = Context(ResourceGraph(resources, configuration), unknown_as)
    findings: list[Finding] = []
    for rule in RULES.values():
        for resource in context.graph.resources:
            if resource.mode != "managed":
                continue
            if resource.type not in rule.resource_types:
                continue
            result = rule.check(resource, context)
            if result in (Compliance.COMPLIANT, Compliance.NOT_APPLICABLE):
                continue
            level = rule.level
            if result == Compliance.UNKNOWN:
                if unknown_as == "ignore":
                    continue
                level = Level.ERROR if unknown_as == "error" else Level.WARN
            suppression = suppression_status(suppressions or [], rule.id, resource.address, strict)
            suppression_entry = None
            if suppression:
                for item in suppressions or []:
                    if item.get("_last_match") == (rule.id, resource.address):
                        suppression_entry = item.get("_index")
                        break
            details: list[str] = []
            message = rule.info
            if suppression and suppression[0] == "suppressed":
                details.append(f"Suppressed: {suppression[1]}")
            elif suppression and suppression[0] == "expired":
                details.append(f"Suppression expired: {suppression[1]}")
                message = f"{rule.info} (suppression expired: {suppression[1]})"
            if suppression and suppression[0] == "expired":
                level = Level.WARN
            findings.append(
                Finding(
                    rule.id,
                    level,
                    resource.address,
                    message,
                    result,
                    rule.cfn_origin,
                    suppression=(
                        suppression[1] if suppression and suppression[0] == "suppressed" else None
                    ),
                    details=details,
                    suppression_entry=suppression_entry,
                )
            )
    return findings
