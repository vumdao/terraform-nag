"""Amazon ECR AWS Solutions rules."""

import json

from ...model import Compliance, Level
from ...registry import rule
from ..common import statements


@rule(
    "AwsSolutions-ECR1",
    Level.ERROR,
    ("aws_ecr_repository", "aws_ecr_repository_policy", "aws_ecr_registry_policy"),
    "ECROpenAccess",
    attributes={
        "aws_ecr_repository_policy": ("repository", "policy"),
        "aws_ecr_registry_policy": ("policy",),
    },
)
def ecr1(res, ctx):
    """RepositoryPolicyText/Principal maps to aws_ecr_*_policy.policy; no Allow statement may grant *."""
    for statement in statements(ctx, res):
        if str(statement.get("Effect", "")).lower() == "allow" and "*" in json.dumps(
            statement.get("Principal", "")
        ):
            return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT
