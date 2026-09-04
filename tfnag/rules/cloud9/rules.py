"""AWS Cloud9 AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-C91",
    Level.ERROR,
    ("aws_cloud9_environment_ec2",),
    "Cloud9InstanceNoIngressSystemsManager",
    attributes={"aws_cloud9_environment_ec2": ("connection_type",)},
)
def c91(res, ctx):
    """ConnectionType maps to connection_type; CONNECT_SSM is required."""
    value = res.get("connection_type")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (
            Compliance.COMPLIANT
            if str(value).upper() == "CONNECT_SSM"
            else Compliance.NON_COMPLIANT
        )
    )
