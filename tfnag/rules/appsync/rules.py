"""AWS AppSync AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-ASC3",
    Level.ERROR,
    ("aws_appsync_graphql_api",),
    "AppSyncGraphQLRequestLogging",
    attributes={"aws_appsync_graphql_api": ("log_config.0.cloudwatch_logs_role_arn",)},
)
def asc3(res, ctx):
    """LogConfig.cloudwatch_logs_role_arn maps to log_config; request logging requires a role."""
    value = res.get("log_config.cloudwatch_logs_role_arn")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT)
    )
