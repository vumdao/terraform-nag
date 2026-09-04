"""AWS Elemental MediaStore AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import secure_transport_policy


@rule(
    "AwsSolutions-MS3",
    Level.ERROR,
    ("aws_media_store_container_policy",),
    "MediaStoreContainerSSLRequestsOnly",
    attributes={"aws_media_store_container_policy": ("policy",)},
)
def ms3(res, ctx):
    """Policy Condition aws:SecureTransport maps to policy; insecure requests must be denied."""
    return secure_transport_policy(ctx, res, "mediastore")


@rule(
    "AwsSolutions-MS7",
    Level.WARN,
    ("aws_media_store_container", "aws_media_store_container_policy"),
    "MediaStoreContainerHasContainerPolicy",
    attributes={
        "aws_media_store_container": ("name",),
        "aws_media_store_container_policy": ("container_name",),
    },
)
def ms7(res, ctx):
    """ContainerPolicy maps to aws_media_store_container_policy.container_name; a matching policy is required."""
    if res.type == "aws_media_store_container_policy":
        return (
            Compliance.COMPLIANT
            if res.get("container_name") not in (None, UNKNOWN)
            else Compliance.NON_COMPLIANT
        )
    policies = ctx.graph.companions(res, "aws_media_store_container_policy", "container_name")
    return Compliance.COMPLIANT if policies else Compliance.NON_COMPLIANT
