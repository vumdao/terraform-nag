"""Amazon OpenSearch AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import documents, required


@rule(
    "AwsSolutions-OS1",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchInVPCOnly",
    attributes={"aws_opensearch_domain": ("vpc_options",)},
)
def os1(res, ctx):
    """VPCOptions maps to vpc_options; domains without VPC options are public."""
    return required(res, "vpc_options", bool)


@rule(
    "AwsSolutions-OS2",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchNodeToNodeEncryption",
    attributes={"aws_opensearch_domain": ("node_to_node_encryption.0.enabled",)},
)
def os2(res, ctx):
    """NodeToNodeEncryptionOptions.Enabled maps to node_to_node_encryption.enabled; provider default is false."""
    return required(res, "node_to_node_encryption.enabled", lambda value: value is True)


@rule(
    "AwsSolutions-OS3",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchAllowlistedIPs",
    attributes={"aws_opensearch_domain": ("access_policies",)},
)
def os3(res, ctx):
    """AccessPolicies maps to access_policies; every Allow statement requires an aws:sourceIp allow-list."""
    policy_documents = documents(ctx, res)
    if not policy_documents:
        return Compliance.NON_COMPLIANT
    for document in policy_documents:
        if document is UNKNOWN:
            return Compliance.UNKNOWN
        statements = document.get("Statement", []) if isinstance(document, dict) else []
        statements = statements if isinstance(statements, list) else [statements]
        for statement in statements:
            if (
                not isinstance(statement, dict)
                or str(statement.get("Effect", "")).lower() != "allow"
            ):
                continue
            condition = statement.get("Condition", {})
            ip = condition.get("IpAddress", {}) if isinstance(condition, dict) else {}
            if not any(str(key).lower() == "aws:sourceip" and value for key, value in ip.items()):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-OS4",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchDedicatedMasterNode",
    attributes={"aws_opensearch_domain": ("cluster_config.0.dedicated_master_enabled",)},
)
def os4(res, ctx):
    """DedicatedMasterEnabled maps to cluster_config.dedicated_master_enabled; false is non-compliant."""
    return required(res, "cluster_config.dedicated_master_enabled", lambda value: value is True)


@rule(
    "AwsSolutions-OS5",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchNoUnsignedOrAnonymousAccess",
    attributes={"aws_opensearch_domain": ("access_policies",)},
)
def os5(res, ctx):
    """AccessPolicies maps to access_policies; wildcard principals on Allow statements are non-compliant."""
    policy_documents = documents(ctx, res)
    if not policy_documents:
        return Compliance.NON_COMPLIANT
    for document in policy_documents:
        if document is UNKNOWN:
            return Compliance.UNKNOWN
        statements = document.get("Statement", []) if isinstance(document, dict) else []
        statements = statements if isinstance(statements, list) else [statements]
        for statement in statements:
            if (
                not isinstance(statement, dict)
                or str(statement.get("Effect", "")).lower() != "allow"
            ):
                continue
            if "*" in str(statement.get("Principal", "")):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-OS7",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchZoneAwareness",
    attributes={"aws_opensearch_domain": ("cluster_config.0.zone_awareness_enabled",)},
)
def os7(res, ctx):
    """ZoneAwarenessEnabled maps to cluster_config.zone_awareness_enabled; false is non-compliant."""
    return required(res, "cluster_config.zone_awareness_enabled", lambda value: value is True)


@rule(
    "AwsSolutions-OS8",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchEncryptedAtRest",
    attributes={"aws_opensearch_domain": ("encrypt_at_rest.0.enabled",)},
)
def os8(res, ctx):
    """EncryptionAtRestOptions.Enabled maps to encrypt_at_rest.enabled; provider default is false."""
    return required(res, "encrypt_at_rest.enabled", lambda value: value is True)


@rule(
    "AwsSolutions-OS9",
    Level.ERROR,
    ("aws_opensearch_domain",),
    "OpenSearchSlowLogsToCloudWatch",
    attributes={"aws_opensearch_domain": ("log_publishing_options",)},
)
def os9(res, ctx):
    """LogPublishingOptions maps to log_publishing_options; slow/search/index logs require CloudWatch destinations."""
    value = res.get("log_publishing_options")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    required_types = {"INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS"}
    found = {
        item.get("log_type")
        for item in (value or [])
        if isinstance(item, dict) and item.get("cloudwatch_log_group_arn")
    }
    return Compliance.COMPLIANT if required_types <= found else Compliance.NON_COMPLIANT
