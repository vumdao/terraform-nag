"""Network mappings: NetworkAcl→aws_network_acl/aws_network_acl_rule; FlowLog
resource associations→aws_flow_log.vpc_id; FileSystem.encrypted→aws_efs_file_system;
KMS Key.enableKeyRotation→aws_kms_key.enable_key_rotation.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import check


@rule(
    "AwsSolutions-VPC3",
    Level.WARN,
    ("aws_network_acl", "aws_network_acl_rule"),
    "VPCNoNACLs",
    attributes={
        "aws_network_acl": ("vpc_id",),
        "aws_network_acl_rule": ("network_acl_id",),
    },
)
def vpc3(res, ctx):
    return Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-VPC7",
    Level.ERROR,
    ("aws_vpc",),
    "VPCFlowLogsEnabled",
    attributes={
        "aws_vpc": ("id",),
        "aws_flow_log": ("vpc_id",),
    },
)
def vpc7(res, ctx):
    logs = []
    for flow_log in ctx.graph.by_type.get("aws_flow_log", []):
        vpc_id = flow_log.get("vpc_id")
        if vpc_id is UNKNOWN:
            return Compliance.UNKNOWN
        if vpc_id == res.address or res.name in str(vpc_id):
            logs.append(flow_log)
    return Compliance.COMPLIANT if logs else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-EFS1",
    Level.ERROR,
    ("aws_efs_file_system",),
    "EFSEncrypted",
    attributes={"aws_efs_file_system": ("encrypted",)},
)
def efs1(res, ctx):
    value = res.get("encrypted")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT if value is not True else Compliance.COMPLIANT


@rule(
    "AwsSolutions-KMS5",
    Level.ERROR,
    ("aws_kms_key",),
    "KMSBackingKeyRotationEnabled",
    attributes={"aws_kms_key": ("customer_master_key_spec", "enable_key_rotation")},
)
def kms5(res, ctx):
    spec = res.get("customer_master_key_spec")
    if spec is UNKNOWN or res.get("enable_key_rotation") is UNKNOWN:
        return Compliance.UNKNOWN
    if spec and str(spec).upper() not in ("SYMMETRIC_DEFAULT", "SYMMETRIC"):
        return Compliance.COMPLIANT
    return check(res.get("enable_key_rotation"), missing=Compliance.NON_COMPLIANT)
