"""Small predicates shared by rule modules."""

from __future__ import annotations

import json
from typing import Any

from ..model import UNKNOWN, Compliance, Resource


def check(value: Any, *, missing: Compliance) -> Compliance:
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    if value is None:
        return missing
    return Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT


def any_unknown(resource: Resource, *paths: str) -> bool:
    return any(resource.has_unknown(path) for path in paths)


def text(value: Any) -> str:
    return "" if value is None or value is UNKNOWN else str(value)


def json_text(value: Any) -> str:
    return json.dumps(value, default=str)


def json_value(value: Any) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return UNKNOWN
    return value


def unknown_value(value: Any) -> bool:
    if value is UNKNOWN:
        return True
    if isinstance(value, dict):
        return any(unknown_value(item) for item in value.values())
    if isinstance(value, list):
        return any(unknown_value(item) for item in value)
    return False


def required(
    resource: Resource,
    path: str,
    predicate,
    *,
    missing: Compliance = Compliance.NON_COMPLIANT,
) -> Compliance:
    value = resource.get(path)
    if unknown_value(value) or resource.has_unknown(path):
        return Compliance.UNKNOWN
    if value is None:
        return missing
    return Compliance.COMPLIANT if predicate(value) else Compliance.NON_COMPLIANT


def documents(ctx: Any, resource: Resource) -> list[dict[str, Any]]:
    result = []
    own = [
        resource.get(path)
        for path in (
            "policy",
            "inline_policy",
            "policy_document",
            "assume_role_policy",
            "access_policies",
        )
    ]
    for document in [value for value in own if value is not None]:
        if document is UNKNOWN:
            result.append(UNKNOWN)
            continue
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except json.JSONDecodeError:
                result.append(UNKNOWN)
                continue
        if isinstance(document, dict):
            result.append(document)
    for document in ctx.graph.policy_documents_for(resource):
        if document is UNKNOWN:
            result.append(UNKNOWN)
            continue
        if isinstance(document, str):
            try:
                document = json.loads(document)
            except json.JSONDecodeError:
                result.append(UNKNOWN)
                continue
        if isinstance(document, dict):
            result.append(document)
    return result


def policy_bodies(ctx: Any, resource: Resource) -> list[Any]:
    values: list[Any] = []
    for path in (
        "policy",
        "inline_policy",
        "policy_document",
        "assume_role_policy",
        "access_policies",
    ):
        body = resource.get(path)
        if body is not None:
            values.append(body)
    if ctx is not None:
        values.extend(ctx.graph.policy_documents_for(resource))
    return values


def wildcard_policy(ctx: Any, resource: Resource) -> Compliance:
    bodies = policy_bodies(ctx, resource)
    if not bodies:
        return Compliance.COMPLIANT
    for body in bodies:
        parsed = json_value(body)
        if parsed is UNKNOWN:
            return Compliance.UNKNOWN
        statements_value = parsed.get("Statement", []) if isinstance(parsed, dict) else []
        statements_list = (
            statements_value if isinstance(statements_value, list) else [statements_value]
        )
        for statement in statements_list:
            if not isinstance(statement, dict):
                continue
            if str(statement.get("Effect", "")).lower() != "allow":
                continue
            action = statement.get("Action", statement.get("actions", []))
            resource_value = statement.get("Resource", statement.get("resources", []))
            actions = action if isinstance(action, list) else [action]
            resources = resource_value if isinstance(resource_value, list) else [resource_value]
            if any(isinstance(item, str) and "*" in item for item in actions + resources):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


def statements(ctx: Any, resource: Resource) -> list[dict[str, Any]]:
    result = []
    for document in documents(ctx, resource):
        if document is UNKNOWN:
            continue
        value = document.get("Statement", [])
        result.extend(value if isinstance(value, list) else [value])
    return [s for s in result if isinstance(s, dict)]


def secure_transport_policy(ctx: Any, resource: Resource, service: str) -> Compliance:
    found = False
    unknown = False
    policy_documents = documents(ctx, resource)
    if not policy_documents:
        return Compliance.NON_COMPLIANT
    raw_identifiers = (resource.get("arn"), resource.get("id"), resource.get("name"))
    unknown = any(value is UNKNOWN for value in raw_identifiers)
    resource_arns = {value for value in raw_identifiers if isinstance(value, str)}
    for statement in statements(ctx, resource):
        condition = statement.get("Condition") or statement.get("condition") or {}
        bools = (
            next(
                (
                    value
                    for key, value in condition.items()
                    if str(key).lower() == "bool" and isinstance(value, dict)
                ),
                {},
            )
            if isinstance(condition, dict)
            else {}
        )
        secure = next(
            (value for key, value in bools.items() if str(key).lower() == "aws:securetransport"),
            None,
        )
        action = statement.get("actions", statement.get("Action", "*"))
        principal = statement.get("principals", statement.get("Principal", "*"))
        resource_value = statement.get("Resource", statement.get("resources", "*"))
        actions = action if isinstance(action, list) else [action]
        principals = principal if isinstance(principal, list) else [principal]
        statement_resources = (
            resource_value if isinstance(resource_value, list) else [resource_value]
        )
        if any(value is UNKNOWN for value in (secure, action, principal, resource_value)):
            unknown = True
            continue
        if (
            str(secure).lower() == "false"
            and str(statement.get("Effect", statement.get("effect", ""))).lower() == "deny"
        ):
            all_principals = any(
                p == "*" or (isinstance(p, dict) and p.get("AWS") == "*") for p in principals
            )
            all_actions = any(a == "*" or str(a).lower() == f"{service}:*" for a in actions)
            if service == "s3" and resource_arns:
                direct = any(item in resource_arns for item in statement_resources)
                wildcard = any(
                    str(item).endswith("/*") and str(item).removesuffix("/*") in resource_arns
                    for item in statement_resources
                )
                resource_match = any(item == "*" for item in statement_resources) or (
                    direct and wildcard
                )
            else:
                resource_match = not resource_arns or any(
                    item == "*" or item in resource_arns or str(item).endswith("/*")
                    for item in statement_resources
                )
            if all_actions and all_principals and resource_match:
                found = True
    if any(document is UNKNOWN for document in policy_documents):
        unknown = True
    if found:
        return Compliance.COMPLIANT
    if unknown:
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT
