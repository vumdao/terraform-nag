"""Amazon DocumentDB AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-DOC1",
    Level.ERROR,
    ("aws_docdb_cluster",),
    "DocumentDBClusterEncryptionAtRest",
    attributes={"aws_docdb_cluster": ("storage_encrypted",)},
)
def doc1(res, ctx):
    """StorageEncrypted maps to storage_encrypted; provider default is false."""
    return required(res, "storage_encrypted", lambda value: value is True)


@rule(
    "AwsSolutions-DOC2",
    Level.ERROR,
    ("aws_docdb_cluster",),
    "DocumentDBClusterNonDefaultPort",
    attributes={"aws_docdb_cluster": ("port",)},
)
def doc2(res, ctx):
    """Port maps to port; provider default 27017 is non-compliant."""
    return required(res, "port", lambda value: int(value) != 27017)


@rule(
    "AwsSolutions-DOC3",
    Level.ERROR,
    ("aws_docdb_cluster",),
    "DocumentDBCredentialsInSecretsManager",
    attributes={"aws_docdb_cluster": ("master_username", "master_password")},
)
def doc3(res, ctx):
    """MasterUsername/MasterUserPassword map to master_username/master_password; both must use secretsmanager dynamic references."""
    username, password = res.get("master_username"), res.get("master_password")
    if UNKNOWN in (username, password):
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if all(
            isinstance(value, str) and "{{resolve:secretsmanager" in value
            for value in (username, password)
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-DOC4",
    Level.ERROR,
    ("aws_docdb_cluster",),
    "DocumentDBClusterBackupRetentionPeriod",
    attributes={"aws_docdb_cluster": ("backup_retention_period",)},
)
def doc4(res, ctx):
    """BackupRetentionPeriod maps to backup_retention_period; at least seven days are required."""
    return required(res, "backup_retention_period", lambda value: value >= 7)


@rule(
    "AwsSolutions-DOC5",
    Level.ERROR,
    ("aws_docdb_cluster",),
    "DocumentDBClusterLogExports",
    attributes={"aws_docdb_cluster": ("enabled_cloudwatch_logs_exports",)},
)
def doc5(res, ctx):
    """EnableCloudwatchLogsExports maps to enabled_cloudwatch_logs_exports; empty exports are non-compliant."""
    return required(res, "enabled_cloudwatch_logs_exports", bool)
