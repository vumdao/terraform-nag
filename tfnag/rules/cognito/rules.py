"""Amazon Cognito AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-COG1",
    Level.ERROR,
    ("aws_cognito_user_pool",),
    "CognitoUserPoolStrongPasswordPolicy",
    attributes={"aws_cognito_user_pool": ("password_policy.0",)},
)
def cog1(res, ctx):
    """PasswordPolicy maps to password_policy; minimum length 8 and all character classes are required."""
    policy = res.get("password_policy")
    if policy is UNKNOWN:
        return Compliance.UNKNOWN
    if isinstance(policy, list):
        policy = policy[0] if len(policy) == 1 else None
    if isinstance(policy, list):
        policy = policy[0] if len(policy) == 1 else None
    if not isinstance(policy, dict):
        return Compliance.NON_COMPLIANT
    return (
        Compliance.COMPLIANT
        if (
            policy.get("minimum_length", 0) >= 8
            and policy.get("require_lowercase", False)
            and policy.get("require_uppercase", False)
            and policy.get("require_numbers", False)
            and policy.get("require_symbols", False)
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-COG2",
    Level.WARN,
    ("aws_cognito_user_pool",),
    "CognitoUserPoolMFA",
    attributes={"aws_cognito_user_pool": ("mfa_configuration",)},
)
def cog2(res, ctx):
    """MfaConfiguration maps to mfa_configuration; OFF is non-compliant."""
    value = res.get("mfa_configuration")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT if str(value or "OFF").upper() == "OFF" else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-COG4",
    Level.ERROR,
    ("aws_api_gateway_method",),
    "CognitoUserPoolAPIGWAuthorizer",
    attributes={"aws_api_gateway_method": ("http_method", "authorization")},
)
def cog4(res, ctx):
    """AuthorizationType maps to authorization; every non-OPTIONS method must use COGNITO_USER_POOLS."""
    method, authorization = res.get("http_method"), res.get("authorization")
    if method is UNKNOWN or authorization is UNKNOWN:
        return Compliance.UNKNOWN
    if str(method).upper() == "OPTIONS":
        return Compliance.NOT_APPLICABLE
    return (
        Compliance.COMPLIANT
        if str(authorization).upper() == "COGNITO_USER_POOLS"
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-COG7",
    Level.ERROR,
    ("aws_cognito_identity_pool",),
    "CognitoUserPoolNoUnauthenticatedLogins",
    attributes={"aws_cognito_identity_pool": ("allow_unauthenticated_identities",)},
)
def cog7(res, ctx):
    """AllowUnauthenticatedIdentities maps to allow_unauthenticated_identities; true is non-compliant."""
    value = res.get("allow_unauthenticated_identities")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT if value is not False else Compliance.COMPLIANT


@rule(
    "AwsSolutions-COG8",
    Level.ERROR,
    ("aws_cognito_user_pool",),
    "CognitoUserPoolPlusTier",
    attributes={"aws_cognito_user_pool": ("user_pool_add_ons.0.advanced_security_mode",)},
)
def cog8(res, ctx):
    """AdvancedSecurityMode maps to user_pool_add_ons.advanced_security_mode; ENFORCED is required."""
    value = res.get("user_pool_add_ons.advanced_security_mode")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if str(value).upper() == "ENFORCED" else Compliance.NON_COMPLIANT
