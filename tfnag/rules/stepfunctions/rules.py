"""AWS Step Functions AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-SF1",
    Level.ERROR,
    ("aws_sfn_state_machine",),
    "StepFunctionStateMachineAllLogsToCloudWatch",
    attributes={"aws_sfn_state_machine": ("logging_configuration.0.log_destination",)},
)
def sf1(res, ctx):
    """LoggingConfiguration.log_destination maps to logging_configuration; CloudWatch logging is required."""
    value = res.get("logging_configuration.log_destination")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT)
    )


@rule(
    "AwsSolutions-SF2",
    Level.ERROR,
    ("aws_sfn_state_machine",),
    "StepFunctionStateMachineXray",
    attributes={"aws_sfn_state_machine": ("tracing_configuration.0.enabled",)},
)
def sf2(res, ctx):
    """TracingConfiguration.enabled maps to tracing_configuration; X-Ray must be enabled."""
    value = res.get("tracing_configuration.enabled")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (Compliance.COMPLIANT if value is True else Compliance.NON_COMPLIANT)
    )
