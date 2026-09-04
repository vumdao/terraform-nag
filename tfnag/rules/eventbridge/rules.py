"""Amazon EventBridge AWS Solutions rules."""

from ...model import Level
from ...registry import rule
from ..common import wildcard_policy


@rule(
    "AwsSolutions-EVB1",
    Level.ERROR,
    ("aws_cloudwatch_event_bus_policy",),
    "EventBusOpenAccess",
    attributes={"aws_cloudwatch_event_bus_policy": ("policy",)},
)
def evb1(res, ctx):
    """Statement Principal/Action maps to aws_cloudwatch_event_bus_policy.policy; wildcard Allow access is prohibited."""
    return wildcard_policy(ctx, res)
