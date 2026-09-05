"""Refresh the pruned AWS provider schema snapshot.

`tfnag/schema.py` validates that every rule's Terraform attribute path really
exists in the provider, so the snapshot has to track provider releases. The full
`terraform providers schema -json` output is tens of megabytes, so only the
resource types the rules actually touch are kept.
"""

from __future__ import annotations

from typing import Any

from .report import SyncReport

PROVIDER = "registry.terraform.io/hashicorp/aws"


def wanted_resource_types(rules: dict[str, Any]) -> set[str]:
    """Resource types the registered rules target or read attributes from."""
    types: set[str] = set()
    for rule in rules.values():
        types.update(rule.resource_types or ())
        types.update(rule.attributes or {})
    return types


def prune(schema: dict[str, Any], resource_types: set[str]) -> dict[str, Any]:
    """Keep only ``resource_types`` of the AWS provider's resource schemas."""
    provider = schema.get("provider_schemas", {}).get(PROVIDER)
    if not provider or not provider.get("resource_schemas"):
        raise ValueError(f"terraform schema output has no resource schemas for {PROVIDER}")
    resources = provider["resource_schemas"]
    return {
        "format_version": schema.get("format_version", "1.0"),
        "provider_schemas": {
            PROVIDER: {
                "resource_schemas": {
                    name: resources[name] for name in sorted(resource_types & resources.keys())
                }
            }
        },
    }


def diff(current: dict[str, Any], pruned: dict[str, Any]) -> SyncReport:
    report = SyncReport(source="Terraform AWS provider schema")
    before = current["provider_schemas"][PROVIDER]["resource_schemas"]
    after = pruned["provider_schemas"][PROVIDER]["resource_schemas"]
    for name in sorted(after.keys() - before.keys()):
        report.changes.append(f"`{name}` schema added")
    for name in sorted(before.keys() - after.keys()):
        report.warnings.append(
            f"`{name}` is no longer in the provider schema; a rule referencing it will fail "
            "validation"
        )
    changed = [name for name in sorted(before.keys() & after.keys()) if before[name] != after[name]]
    if changed:
        report.changes.append(
            f"{len(changed)} resource schema(s) updated: "
            + ", ".join(f"`{name}`" for name in changed[:10])
            + (", ..." if len(changed) > 10 else "")
        )
    return report
