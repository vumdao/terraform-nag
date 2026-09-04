"""Amazon Timestream AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-TS3",
    Level.WARN,
    ("aws_timestreamwrite_database",),
    "TimestreamDatabaseCustomerManagedKey",
    attributes={"aws_timestreamwrite_database": ("kms_key_id",)},
)
def ts3(res, ctx):
    """KmsKeyId maps to kms_key_id; absent means the AWS-owned key is used."""
    value = res.get("kms_key_id")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT
