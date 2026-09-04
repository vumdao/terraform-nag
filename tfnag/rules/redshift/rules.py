"""Amazon Redshift AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


def _parameter_group(res, ctx, name: str) -> bool | object:
    if ctx is None:
        return UNKNOWN
    groups = [
        item for item in ctx.graph.references(res) if item.type == "aws_redshift_parameter_group"
    ]
    groups.extend(
        ctx.graph.companions(res, "aws_redshift_parameter_group", "cluster_parameter_group_name")
    )
    if not groups:
        return UNKNOWN
    for group in groups:
        parameters = group.get("parameter")
        if parameters is UNKNOWN:
            return UNKNOWN
        for parameter in parameters or []:
            if isinstance(parameter, dict) and str(parameter.get("name", "")).lower() == name:
                return str(parameter.get("value", "")).lower() == "true"
    return False


@rule(
    "AwsSolutions-RS1",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftRequireTlsSSL",
    attributes={
        "aws_redshift_cluster": ("cluster_parameter_group_name",),
        "aws_redshift_parameter_group": ("parameter",),
    },
)
def rs1(res, ctx):
    """require_ssl maps to aws_redshift_parameter_group.parameter; the referenced group must set true."""
    value = _parameter_group(res, ctx, "require_ssl")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value is True else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-RS2",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterInVPC",
    attributes={"aws_redshift_cluster": ("cluster_subnet_group_name",)},
)
def rs2(res, ctx):
    """DBSubnetGroupName maps to cluster_subnet_group_name; absent means public placement."""
    return required(res, "cluster_subnet_group_name", bool)


@rule(
    "AwsSolutions-RS3",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterNonDefaultUsername",
    attributes={"aws_redshift_cluster": ("master_username",)},
)
def rs3(res, ctx):
    """MasterUsername maps to master_username; the provider default admin is prohibited."""
    return required(
        res, "master_username", lambda value: str(value).lower() not in ("admin", "master")
    )


@rule(
    "AwsSolutions-RS4",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterNonDefaultPort",
    attributes={"aws_redshift_cluster": ("port",)},
)
def rs4(res, ctx):
    """Port maps to port; provider default 5439 is non-compliant."""
    return required(res, "port", lambda value: int(value) != 5439)


@rule(
    "AwsSolutions-RS5",
    Level.ERROR,
    ("aws_redshift_cluster", "aws_redshift_logging"),
    "RedshiftClusterAuditLogging",
    attributes={
        "aws_redshift_cluster": ("logging.enable",),
        "aws_redshift_logging": ("cluster_identifier", "log_destination_type"),
    },
)
def rs5(res, ctx):
    """LoggingProperties maps to aws_redshift_cluster.logging and aws_redshift_logging; a destination is required."""
    if res.type == "aws_redshift_logging":
        return Compliance.COMPLIANT if res.get("log_destination_type") else Compliance.NON_COMPLIANT
    return (
        Compliance.COMPLIANT
        if res.get("logging.enable") is True
        or ctx.graph.companions(res, "aws_redshift_logging", "cluster_identifier")
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-RS6",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterEncryptionAtRest",
    attributes={"aws_redshift_cluster": ("encrypted",)},
)
def rs6(res, ctx):
    """EncryptionAtRest maps to encrypted; provider default is false."""
    return required(res, "encrypted", lambda value: value is True)


@rule(
    "AwsSolutions-RS8",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterPublicAccess",
    attributes={"aws_redshift_cluster": ("publicly_accessible",)},
)
def rs8(res, ctx):
    """PubliclyAccessible maps to publicly_accessible; provider default is false."""
    return required(
        res, "publicly_accessible", lambda value: value is False, missing=Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-RS9",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterVersionUpgrade",
    attributes={"aws_redshift_cluster": ("allow_version_upgrade",)},
)
def rs9(res, ctx):
    """AllowVersionUpgrade maps to allow_version_upgrade; provider default true is compliant."""
    return required(
        res, "allow_version_upgrade", lambda value: value is True, missing=Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-RS10",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftBackupEnabled",
    attributes={"aws_redshift_cluster": ("automated_snapshot_retention_period",)},
)
def rs10(res, ctx):
    """AutomatedSnapshotRetentionPeriod maps to automated_snapshot_retention_period; zero disables backups."""
    return required(res, "automated_snapshot_retention_period", lambda value: value > 0)


@rule(
    "AwsSolutions-RS11",
    Level.ERROR,
    ("aws_redshift_cluster",),
    "RedshiftClusterUserActivityLogging",
    attributes={
        "aws_redshift_cluster": ("cluster_parameter_group_name",),
        "aws_redshift_parameter_group": ("parameter",),
    },
)
def rs11(res, ctx):
    """enable_user_activity_logging maps to aws_redshift_parameter_group.parameter; the referenced group must set true."""
    value = _parameter_group(res, ctx, "enable_user_activity_logging")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value is True else Compliance.NON_COMPLIANT
