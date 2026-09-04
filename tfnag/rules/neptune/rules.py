"""Amazon Neptune AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-N1",
    Level.ERROR,
    ("aws_neptune_cluster",),
    "NeptuneClusterMultiAZ",
    attributes={"aws_neptune_cluster": ("neptune_subnet_group_name", "availability_zones")},
)
def n1(res, ctx):
    """DBSubnetGroupName/AvailabilityZones map to neptune_subnet_group_name/availability_zones; a subnet group is required."""
    subnet, zones = res.get("neptune_subnet_group_name"), res.get("availability_zones")
    if subnet is UNKNOWN or zones is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if subnet and (zones is None or len(zones) >= 2)
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-N2",
    Level.ERROR,
    ("aws_neptune_cluster_instance",),
    "NeptuneClusterAutomaticMinorVersionUpgrade",
    attributes={"aws_neptune_cluster_instance": ("auto_minor_version_upgrade",)},
)
def n2(res, ctx):
    """AutoMinorVersionUpgrade maps to auto_minor_version_upgrade; provider default is true."""
    return required(res, "auto_minor_version_upgrade", lambda value: value is True)


@rule(
    "AwsSolutions-N3",
    Level.ERROR,
    ("aws_neptune_cluster",),
    "NeptuneClusterBackupRetentionPeriod",
    attributes={"aws_neptune_cluster": ("backup_retention_period",)},
)
def n3(res, ctx):
    """BackupRetentionPeriod maps to backup_retention_period; at least seven days are required."""
    return required(res, "backup_retention_period", lambda value: value >= 7)


@rule(
    "AwsSolutions-N4",
    Level.ERROR,
    ("aws_neptune_cluster",),
    "NeptuneClusterEncryptionAtRest",
    attributes={"aws_neptune_cluster": ("storage_encrypted",)},
)
def n4(res, ctx):
    """StorageEncrypted maps to storage_encrypted; provider default is false."""
    return required(res, "storage_encrypted", lambda value: value is True)


@rule(
    "AwsSolutions-N5",
    Level.ERROR,
    ("aws_neptune_cluster",),
    "NeptuneClusterIAMAuth",
    attributes={"aws_neptune_cluster": ("iam_database_authentication_enabled",)},
)
def n5(res, ctx):
    """IamAuthEnabled maps to iam_database_authentication_enabled; provider default is false."""
    return required(res, "iam_database_authentication_enabled", lambda value: value is True)
