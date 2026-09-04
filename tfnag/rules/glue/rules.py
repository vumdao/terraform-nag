"""AWS Glue AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import json_value


@rule(
    "AwsSolutions-GL1",
    Level.WARN,
    ("aws_glue_crawler", "aws_glue_job", "aws_glue_security_configuration"),
    "GlueEncryptedCloudWatchLogs",
    attributes={"aws_glue_security_configuration": ("encryption_configuration",)},
)
def gl1(res, ctx):
    """CloudWatchEncryption maps to aws_glue_security_configuration.encryption_configuration; KMS encryption is required."""
    value = json_value(res.get("encryption_configuration"))
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if isinstance(value, dict) and value.get("cloudwatch_encryption", {}).get("kms_key_arn")
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-GL3",
    Level.WARN,
    ("aws_glue_job", "aws_glue_security_configuration"),
    "GlueJobBookmarkEncrypted",
    attributes={"aws_glue_security_configuration": ("encryption_configuration",)},
)
def gl3(res, ctx):
    """JobBookmarksEncryption maps to aws_glue_security_configuration.encryption_configuration; KMS encryption is required."""
    value = json_value(res.get("encryption_configuration"))
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if isinstance(value, dict)
        and value.get("job_bookmarks_encryption", {}).get("job_bookmarks_encryption_mode")
        == "CSE-KMS"
        else Compliance.NON_COMPLIANT
    )
