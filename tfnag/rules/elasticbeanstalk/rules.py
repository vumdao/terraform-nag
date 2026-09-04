"""Elastic Beanstalk AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-EB1",
    Level.ERROR,
    ("aws_elastic_beanstalk_environment",),
    "ElasticBeanstalkVPCSpecified",
    attributes={"aws_elastic_beanstalk_environment": ("setting",)},
)
def eb1(res, ctx):
    """VpcId/VPCId maps to aws_elastic_beanstalk_environment.setting."""
    settings = res.get("setting")
    if settings is None:
        return Compliance.NON_COMPLIANT
    settings = settings if isinstance(settings, list) else [settings]
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(item, dict)
            and item.get("namespace") == "aws:ec2:vpc"
            and item.get("name") == "VPCId"
            and item.get("value")
            for item in settings
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-EB3",
    Level.ERROR,
    ("aws_elastic_beanstalk_environment",),
    "ElasticBeanstalkManagedUpdatesEnabled",
    attributes={"aws_elastic_beanstalk_environment": ("setting",)},
)
def eb3(res, ctx):
    """ManagedActionsEnabled maps to aws_elastic_beanstalk_environment.setting; absent defaults false."""
    settings = res.get("setting")
    if settings is UNKNOWN:
        return Compliance.UNKNOWN
    settings = settings if isinstance(settings, list) else [settings or {}]
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(item, dict)
            and item.get("namespace") == "aws:elasticbeanstalk:managedactions"
            and item.get("name") == "ManagedActionsEnabled"
            and str(item.get("value")).lower() == "true"
            for item in settings
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-EB4",
    Level.WARN,
    ("aws_elastic_beanstalk_environment",),
    "ElasticBeanstalkEC2InstanceLogsToS3",
    attributes={"aws_elastic_beanstalk_environment": ("setting",)},
)
def eb4(res, ctx):
    """StreamLogs maps to aws_elastic_beanstalk_environment.setting; provider default is disabled."""
    settings = res.get("setting")
    if settings is UNKNOWN:
        return Compliance.UNKNOWN
    settings = settings if isinstance(settings, list) else [settings or {}]
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(item, dict)
            and item.get("namespace") == "aws:elasticbeanstalk:environment:logs"
            and item.get("name") == "StreamLogs"
            and str(item.get("value")).lower() == "true"
            for item in settings
        )
        else Compliance.NON_COMPLIANT
    )
