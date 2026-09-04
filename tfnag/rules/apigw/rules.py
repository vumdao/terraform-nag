"""Amazon API Gateway AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-APIG1",
    Level.ERROR,
    ("aws_api_gateway_stage", "aws_apigatewayv2_stage"),
    "APIGWAccessLogging",
    attributes={
        "aws_api_gateway_stage": ("access_log_settings.0.destination_arn",),
        "aws_apigatewayv2_stage": ("access_log_settings.0.destination_arn",),
    },
)
def apig1(res, ctx):
    """AccessLogSetting maps to access_log_settings.destination_arn; absent disables access logging."""
    value = res.get("access_log_settings.destination_arn")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-APIG2",
    Level.ERROR,
    ("aws_api_gateway_rest_api", "aws_api_gateway_request_validator"),
    "APIGWRequestValidation",
    attributes={
        "aws_api_gateway_rest_api": ("id",),
        "aws_api_gateway_request_validator": (
            "rest_api_id",
            "validate_request_body",
            "validate_request_parameters",
        ),
    },
)
def apig2(res, ctx):
    """RequestValidator validates both body and parameters and is linked to the REST API by rest_api_id."""
    if res.type == "aws_api_gateway_request_validator":
        return (
            Compliance.COMPLIANT
            if res.get("validate_request_body") is True
            and res.get("validate_request_parameters") is True
            else Compliance.NON_COMPLIANT
        )
    validators = ctx.graph.companions(res, "aws_api_gateway_request_validator", "rest_api_id")
    return (
        Compliance.COMPLIANT
        if any(
            item.get("validate_request_body") is True
            and item.get("validate_request_parameters") is True
            for item in validators
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-APIG3",
    Level.WARN,
    ("aws_api_gateway_stage", "aws_wafv2_web_acl_association"),
    "APIGWAssociatedWithWAF",
    attributes={
        "aws_api_gateway_stage": ("rest_api_id", "stage_name"),
        "aws_wafv2_web_acl_association": ("resource_arn", "web_acl_arn"),
    },
)
def apig3(res, ctx):
    """WebACLAssociation.resource_arn maps to the API stage; a matching WAFv2 association is required."""
    if res.type == "aws_wafv2_web_acl_association":
        return (
            Compliance.COMPLIANT
            if res.get("resource_arn") and res.get("web_acl_arn")
            else Compliance.NON_COMPLIANT
        )
    associations = ctx.graph.companions(res, "aws_wafv2_web_acl_association", "resource_arn")
    return Compliance.COMPLIANT if associations else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-APIG4",
    Level.ERROR,
    ("aws_api_gateway_method", "aws_apigatewayv2_route"),
    "APIGWAuthorization",
    attributes={
        "aws_api_gateway_method": ("authorization",),
        "aws_apigatewayv2_route": ("authorization_type",),
    },
)
def apig4(res, ctx):
    """AuthorizationType maps to authorization/authorization_type; NONE is non-compliant."""
    value = (
        res.get("authorization_type")
        if res.type == "aws_apigatewayv2_route"
        else res.get("authorization")
    )
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT if str(value or "NONE").upper() == "NONE" else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-APIG6",
    Level.ERROR,
    ("aws_api_gateway_method_settings",),
    "APIGWExecutionLoggingEnabled",
    attributes={"aws_api_gateway_method_settings": ("settings.logging_level",)},
)
def apig6(res, ctx):
    """MethodSettings.settings.logging_level maps to settings; INFO or ERROR is required."""
    settings = res.get("settings")
    if settings is UNKNOWN:
        return Compliance.UNKNOWN
    if isinstance(settings, dict):
        settings = [settings]
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(item, dict)
            and str(item.get("logging_level", "")).upper() in ("INFO", "ERROR")
            for item in (settings or [])
        )
        else Compliance.NON_COMPLIANT
    )
