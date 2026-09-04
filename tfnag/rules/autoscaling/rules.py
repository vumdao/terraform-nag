"""Amazon Auto Scaling AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-AS1",
    Level.ERROR,
    ("aws_autoscaling_group",),
    "AutoScalingGroupCooldownPeriod",
    attributes={"aws_autoscaling_group": ("default_cooldown",)},
)
def as1(res, ctx):
    """Cooldown maps to default_cooldown; a positive cooldown is required."""
    value = res.get("default_cooldown")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value is not None and value > 0 else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-AS2",
    Level.ERROR,
    ("aws_autoscaling_group",),
    "AutoScalingGroupHealthCheck",
    attributes={"aws_autoscaling_group": ("health_check_type", "health_check_grace_period")},
)
def as2(res, ctx):
    """HealthCheckType/GracePeriod map to health_check_type/health_check_grace_period; ELB and a positive grace period are required."""
    health_type, grace = res.get("health_check_type"), res.get("health_check_grace_period")
    if UNKNOWN in (health_type, grace):
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT
        if health_type != "ELB" or grace is None or grace <= 0
        else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-AS3",
    Level.ERROR,
    ("aws_autoscaling_group", "aws_autoscaling_notification"),
    "AutoScalingGroupScalingNotifications",
    attributes={
        "aws_autoscaling_group": ("id",),
        "aws_autoscaling_notification": ("group_names", "notifications"),
    },
)
def as3(res, ctx):
    """NotificationConfiguration maps to aws_autoscaling_notification.notifications; all four scaling events are required."""
    required = {
        "autoscaling:EC2_INSTANCE_LAUNCH",
        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
        "autoscaling:EC2_INSTANCE_TERMINATE",
        "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
    }
    if res.type == "aws_autoscaling_notification":
        return (
            Compliance.COMPLIANT
            if required <= set(res.get("notifications") or [])
            else Compliance.NON_COMPLIANT
        )
    notices = ctx.graph.companions(res, "aws_autoscaling_notification", "group_names")
    events = {event for notice in notices for event in (notice.get("notifications") or [])}
    return Compliance.COMPLIANT if required <= events else Compliance.NON_COMPLIANT
