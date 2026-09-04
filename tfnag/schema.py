"""Validation helpers for rule Terraform attribute metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).parent / "data" / "provider_schema.json"


def load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open(encoding="utf-8") as stream:
        return json.load(stream)


def _block_for_path(block: dict[str, Any], path: str) -> bool:
    current = block
    for component in path.split("."):
        if component.isdigit():
            continue
        attributes = current.get("attributes", {})
        if component in attributes:
            current = attributes[component]
            continue
        nested = current.get("block_types", {}).get(component)
        if nested is None:
            return False
        current = nested.get("block", {})
    return True


def path_exists(schema: dict[str, Any], resource_type: str, path: str) -> bool:
    resources = schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"][
        "resource_schemas"
    ]
    if resource_type not in resources:
        return False
    return _block_for_path(resources[resource_type]["block"], path)


def validate_rule_metadata(rules: dict[str, Any]) -> list[str]:
    schema = load_schema()
    errors: list[str] = []
    for rule_id, registered in rules.items():
        if not registered.attributes:
            errors.append(f"{rule_id}: no Terraform attribute metadata")
            continue
        for resource_type, paths in registered.attributes.items():
            for path in paths:
                if not path_exists(schema, resource_type, path):
                    errors.append(
                        f"{rule_id}: {resource_type}.{path} is absent from provider schema"
                    )
    return errors
