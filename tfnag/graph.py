"""Reference and companion queries used by Terraform rules."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .model import UNKNOWN, Resource, normalize_address


def _walk_config(module: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
    result = []
    for resource in module.get("resources", []):
        item = dict(resource)
        address = resource.get("address", "")
        item["address"] = normalize_address(
            f"{prefix}.{address}" if prefix and address else address or prefix
        )
        result.append(item)
    for child in module.get("child_modules", []):
        child_address = child.get("address", "")
        child_prefix = ".".join(x for x in (prefix, child_address) if x)
        result.extend(_walk_config(child, child_prefix))
    for name, call in (module.get("module_calls") or {}).items():
        child = call.get("module") or {}
        child_address = call.get("address") or f"module.{name}"
        child_prefix = ".".join(x for x in (prefix, child_address) if x)
        result.extend(_walk_config(child, child_prefix))
    return result


def _normalize_reference(reference: str) -> str:
    value = re.sub(r"\[[^]]*\]", "", reference)
    parts = value.split(".")
    resource_index = next(
        (
            index
            for index, part in enumerate(parts)
            if part.startswith(("aws_", "azurerm_", "google_", "random_", "tls_"))
        ),
        None,
    )
    if resource_index is None or resource_index + 1 >= len(parts):
        return value
    start = resource_index
    if resource_index and parts[resource_index - 1] == "data":
        start -= 1
    return ".".join(parts[:start] + parts[start : resource_index + 2])


def _instance_keys(address: str) -> list[str]:
    return re.findall(r"\[[^]]*\]", address)


def _module_scope(address: str) -> str:
    parts = address.split(".")
    resource_index = next(
        (
            index
            for index, part in enumerate(parts)
            if part.startswith(("aws_", "azurerm_", "google_", "random_", "tls_"))
        ),
        len(parts),
    )
    scope = parts[:resource_index]
    if scope and scope[-1] == "data":
        scope.pop()
    return ".".join(scope)


def _walk_expression(value: Any) -> list[str]:
    if isinstance(value, dict):
        references = value.get("references", [])
        result = [ref for ref in references if isinstance(ref, str)]
        for key, child in value.items():
            if key != "references":
                result.extend(_walk_expression(child))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for child in value:
            result.extend(_walk_expression(child))
        return result
    return []


def _qualify_reference(source: str, reference: str) -> str:
    normalized = _normalize_reference(reference)
    if normalized.startswith("module."):
        return normalized
    source_parts = source.split(".")
    source_resource = next(
        (
            index
            for index, part in enumerate(source_parts)
            if part.startswith(("aws_", "azurerm_", "google_", "random_", "tls_"))
        ),
        len(source_parts),
    )
    prefix = ".".join(source_parts[:source_resource])
    return ".".join(x for x in (prefix, normalized) if x)


def _references(configuration: dict[str, Any]) -> dict[str, set[str]]:
    root = configuration.get("root_module", {})
    edges: dict[str, set[str]] = defaultdict(set)
    for resource in _walk_config(root):
        source = resource.get("address", "")
        for ref in _walk_expression(resource.get("expressions") or {}):
            edges[source].add(_qualify_reference(source, ref))
    return edges


class ResourceGraph:
    def __init__(self, resources: list[Resource], configuration: dict[str, Any] | None = None):
        self.resources = resources
        self.by_address = {r.address: r for r in resources}
        self.by_type: dict[str, list[Resource]] = defaultdict(list)
        for resource in resources:
            self.by_type[resource.type].append(resource)
        configured_edges = _references(configuration or {})
        instances: dict[str, list[str]] = defaultdict(list)
        for resource in resources:
            instances[normalize_address(resource.address)].append(resource.address)
        self.edges: dict[str, set[str]] = defaultdict(set)
        for source, targets in configured_edges.items():
            source_instances = instances.get(source, [source])
            for source_instance in source_instances:
                for target in targets:
                    target_instances = instances.get(target, [target])
                    source_scope = _module_scope(source_instance)
                    if source_scope:
                        scoped = [
                            candidate
                            for candidate in target_instances
                            if _module_scope(candidate) == source_scope
                        ]
                        if scoped:
                            target_instances = scoped
                    source_keys = _instance_keys(source_instance)
                    if source_keys:
                        keyed = [
                            candidate
                            for candidate in target_instances
                            if _instance_keys(candidate) == source_keys
                        ]
                        if keyed:
                            target_instances = keyed
                    self.edges[source_instance].update(target_instances)
        self.reverse: dict[str, set[str]] = defaultdict(set)
        for source, targets in self.edges.items():
            for target in targets:
                self.reverse[target].add(source)

    def referrers(self, resource: Resource, type: str | None = None) -> list[Resource]:
        items = [
            self.by_address[a]
            for a in self.reverse.get(resource.address, set())
            if a in self.by_address
        ]
        return [r for r in items if type is None or r.type == type]

    def companions(self, resource: Resource, type: str, key: str | None = None) -> list[Resource]:
        direct = [
            r
            for r in self.by_type.get(type, [])
            if resource.address in self.edges.get(r.address, set())
        ]
        if direct:
            return direct
        matches: list[Resource] = []
        candidates = self.by_type.get(type, [])
        identifiers = {
            resource.name,
            resource.address,
            *(
                resource.get(identifier)
                for identifier in ("bucket", "id", "arn", "name", "queue_url")
                if isinstance(resource.get(identifier), str)
            ),
        }
        for candidate in candidates:
            if _module_scope(candidate.address) != _module_scope(resource.address):
                continue
            if key and candidate.name == resource.name:
                matches.append(candidate)
                continue
            if not key or key not in candidate.values:
                continue
            value = candidate.values[key]
            values = value if isinstance(value, list) else [value]
            if any(
                isinstance(item, str)
                and (_normalize_reference(item) in identifiers or item in identifiers)
                for item in values
            ):
                matches.append(candidate)
        return matches

    def policy_documents_for(self, resource: Resource) -> list[Any]:
        policies: list[Any] = []
        identifiers = {
            resource.name,
            resource.address,
            *(
                resource.get(identifier)
                for identifier in ("bucket", "id", "arn", "name", "queue_url", "topic_arn")
                if isinstance(resource.get(identifier), str)
            ),
        }
        for candidate in self.resources:
            if "policy" not in candidate.type and not candidate.address.startswith(
                "data.aws_iam_policy_document."
            ):
                continue
            linked = resource.address in self.edges.get(candidate.address, set())
            linked = linked or candidate.address in self.edges.get(resource.address, set())
            if not linked and _module_scope(candidate.address) == _module_scope(resource.address):
                linked = any(
                    isinstance(candidate.get(key), str) and candidate.get(key) in identifiers
                    for key in ("bucket", "queue_arn", "topic_arn", "resource", "target_resource")
                )
            if linked:
                body = (
                    candidate.get("policy")
                    or candidate.get("policy_document")
                    or candidate.get("json")
                    or candidate.get("rendered")
                )
                if body is UNKNOWN:
                    policies.append(UNKNOWN)
                elif body is not None:
                    policies.append(body)
        return policies

    def references(self, resource: Resource) -> list[Resource]:
        return [
            self.by_address[a]
            for a in self.edges.get(resource.address, set())
            if a in self.by_address
        ]
