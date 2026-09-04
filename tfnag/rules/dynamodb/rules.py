"""DynamoDB and DAX AWS Solutions rules."""

from ...model import Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-DDB3",
    Level.WARN,
    ("aws_dynamodb_table",),
    "DynamoDBPITREnabled",
    attributes={"aws_dynamodb_table": ("point_in_time_recovery.0.enabled",)},
)
def ddb3(res, ctx):
    """PointInTimeRecoverySpecification.Enabled maps to point_in_time_recovery.enabled; default is false."""
    return required(res, "point_in_time_recovery.enabled", lambda value: value is True)


@rule(
    "AwsSolutions-DDB4",
    Level.ERROR,
    ("aws_dax_cluster",),
    "DAXEncrypted",
    attributes={"aws_dax_cluster": ("server_side_encryption.0.enabled",)},
)
def ddb4(res, ctx):
    """SSEEnabled maps to aws_dax_cluster.server_side_encryption.enabled; default is false."""
    return required(res, "server_side_encryption.enabled", lambda value: value is True)
