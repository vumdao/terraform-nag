"""EC2 mappings: SecurityGroupIngress→inline ingress or aws_vpc_security_group_ingress_rule/
aws_security_group_rule; EBS encrypted→encrypted, and monitoring/termination properties map
to Terraform equivalents on aws_instance, aws_launch_template, aws_launch_configuration, and
aws_ebs_volume.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import check, text


def ingress_rules(res, ctx):
    inline = res.get("ingress")
    result = list(inline) if isinstance(inline, list) else []
    result += [
        r
        for r in ctx.graph.referrers(res)
        if r.type in ("aws_vpc_security_group_ingress_rule", "aws_security_group_rule")
    ]
    return result


@rule(
    "AwsSolutions-EC23",
    Level.ERROR,
    ("aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_security_group_rule"),
    "EC2RestrictedInbound",
    attributes={
        "aws_security_group": ("ingress",),
        "aws_vpc_security_group_ingress_rule": ("cidr_ipv4", "cidr_ipv6"),
        "aws_security_group_rule": ("cidr_blocks", "ipv6_cidr_blocks"),
    },
)
def ec23(res, ctx):
    if res.type != "aws_security_group":
        rules = [res]
    else:
        inline = res.get("ingress")
        if inline is UNKNOWN:
            return Compliance.UNKNOWN
        rules = [item for item in (inline or []) if isinstance(item, dict)]
    for item in rules:
        for key in ("cidr_ipv4", "cidr_ipv6", "cidr_blocks", "ipv6_cidr_blocks"):
            value = item.get(key) if hasattr(item, "get") else None
            values = value if isinstance(value, list) else [value]
            if any(v is UNKNOWN for v in values):
                return Compliance.UNKNOWN
            if any("/0" in text(v) for v in values):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-EC26",
    Level.ERROR,
    ("aws_ebs_volume", "aws_instance", "aws_launch_configuration", "aws_launch_template"),
    "EC2EBSVolumeEncrypted",
    attributes={
        "aws_ebs_volume": ("encrypted",),
        "aws_instance": ("ebs_block_device", "root_block_device"),
        "aws_launch_configuration": ("ebs_block_device", "root_block_device"),
        "aws_launch_template": ("block_device_mappings",),
    },
)
def ec26(res, ctx):
    if res.type == "aws_ebs_volume":
        return check(res.get("encrypted"), missing=Compliance.NON_COMPLIANT)
    collections = []
    for path in (
        "ebs_block_device",
        "root_block_device",
        "block_device_mapping",
        "block_device_mappings",
    ):
        value = res.get(path)
        if value is UNKNOWN:
            return Compliance.UNKNOWN
        if value is not None:
            collections.extend(value if isinstance(value, list) else [value])
    if not collections:
        return (
            Compliance.NON_COMPLIANT
            if res.type in ("aws_launch_configuration", "aws_launch_template")
            else Compliance.COMPLIANT
        )
    for block in collections:
        if res.type == "aws_launch_template" and isinstance(block, dict):
            block = block.get("ebs") or block
        encrypted = block.get("encrypted") if isinstance(block, dict) else None
        if encrypted is UNKNOWN:
            return Compliance.UNKNOWN
        if encrypted is not True:
            return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-EC27",
    Level.ERROR,
    ("aws_security_group",),
    "EC2SecurityGroupDescription",
    attributes={"aws_security_group": ("description",)},
)
def ec27(res, ctx):
    description = res.get("description")
    if description is UNKNOWN:
        return Compliance.UNKNOWN
    return check(
        isinstance(description, str) and len(description) >= 2, missing=Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-EC28",
    Level.ERROR,
    ("aws_instance", "aws_launch_configuration"),
    "EC2InstanceDetailedMonitoringEnabled",
    attributes={
        "aws_instance": ("monitoring",),
        "aws_launch_configuration": ("enable_monitoring",),
    },
)
def ec28(res, ctx):
    value = res.get("monitoring") if res.type == "aws_instance" else res.get("enable_monitoring")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    if res.type == "aws_launch_configuration" and value is None:
        return Compliance.COMPLIANT
    return check(value, missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-EC29",
    Level.ERROR,
    ("aws_instance",),
    "EC2InstanceTerminationProtection",
    attributes={"aws_instance": ("disable_api_termination",)},
)
def ec29(res, ctx):
    return check(res.get("disable_api_termination"), missing=Compliance.NON_COMPLIANT)
