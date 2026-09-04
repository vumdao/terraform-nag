"""AWS Secrets Manager AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-SMG4",
    Level.ERROR,
    ("aws_secretsmanager_secret", "aws_secretsmanager_secret_rotation"),
    "SecretsManagerRotationEnabled",
    attributes={
        "aws_secretsmanager_secret": ("arn",),
        "aws_secretsmanager_secret_rotation": ("secret_id", "rotation_lambda_arn"),
    },
)
def smg4(res, ctx):
    """RotationEnabled maps to aws_secretsmanager_secret_rotation; every secret requires a linked rotation resource."""
    if res.type == "aws_secretsmanager_secret_rotation":
        value = res.get("rotation_lambda_arn")
        return (
            Compliance.UNKNOWN
            if value is UNKNOWN
            else (Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT)
        )
    return (
        Compliance.COMPLIANT
        if ctx.graph.companions(res, "aws_secretsmanager_secret_rotation", "secret_id")
        else Compliance.NON_COMPLIANT
    )
