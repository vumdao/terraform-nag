"""AWS IAM AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import wildcard_policy

IAM_ENTITY_TYPES = ("aws_iam_group", "aws_iam_role", "aws_iam_user")
IAM_POLICY_TYPES = (
    "aws_iam_group_policy",
    "aws_iam_managed_policy",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
)


@rule(
    "AwsSolutions-IAM4",
    Level.ERROR,
    IAM_ENTITY_TYPES
    + (
        "aws_iam_role_policy_attachment",
        "aws_iam_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
    ),
    "IAMNoManagedPolicies",
    attributes={
        "aws_iam_role": ("managed_policy_arns",),
        "aws_iam_role_policy_attachment": ("policy_arn",),
        "aws_iam_policy_attachment": ("policy_arn",),
        "aws_iam_user_policy_attachment": ("policy_arn",),
        "aws_iam_group_policy_attachment": ("policy_arn",),
    },
)
def iam4(res, ctx):
    """ManagedPolicyArns/policy_arn map to IAM entity and attachment resources; AWS-managed ARNs are non-compliant."""
    values = []
    if res.get("policy_arn") is UNKNOWN or res.get("managed_policy_arns") is UNKNOWN:
        return Compliance.UNKNOWN
    values.extend([res.get("policy_arn")])
    values.extend(res.get("managed_policy_arns") or [])
    return (
        Compliance.NON_COMPLIANT
        if any(isinstance(value, str) and ":iam::aws:policy/" in value for value in values)
        else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-IAM5",
    Level.ERROR,
    IAM_ENTITY_TYPES + IAM_POLICY_TYPES,
    "IAMNoWildcardPermissions",
    attributes={
        "aws_iam_group": ("id",),
        "aws_iam_role": ("assume_role_policy", "inline_policy"),
        "aws_iam_user": ("id",),
        "aws_iam_group_policy": ("policy",),
        "aws_iam_managed_policy": (),
        "aws_iam_policy": ("policy",),
        "aws_iam_role_policy": ("policy",),
        "aws_iam_user_policy": ("policy",),
    },
)
def iam5(res, ctx):
    """PolicyDocument Action/Resource wildcards map to IAM policy JSON; any wildcard on an Allow is non-compliant."""
    return wildcard_policy(ctx, res)
