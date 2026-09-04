"""Amazon SageMaker AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-SM1",
    Level.ERROR,
    ("aws_sagemaker_notebook_instance",),
    "SageMakerNotebookInVPC",
    attributes={
        "aws_sagemaker_notebook_instance": (
            "subnet_id",
            "security_groups",
        )
    },
)
def sm1(res, ctx):
    """SubnetId/SecurityGroups map to subnet_id/security_groups; both are required for VPC placement."""
    return (
        Compliance.COMPLIANT
        if res.get("subnet_id") and res.get("security_groups")
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-SM2",
    Level.ERROR,
    ("aws_sagemaker_notebook_instance",),
    "SageMakerNotebookInstanceKMSKeyConfigured",
    attributes={"aws_sagemaker_notebook_instance": ("kms_key_id",)},
)
def sm2(res, ctx):
    """KmsKeyId maps to kms_key_id; absent uses an AWS-managed key and is non-compliant."""
    value = res.get("kms_key_id")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT)
    )


@rule(
    "AwsSolutions-SM3",
    Level.ERROR,
    ("aws_sagemaker_notebook_instance",),
    "SageMakerNotebookNoDirectInternetAccess",
    attributes={"aws_sagemaker_notebook_instance": ("direct_internet_access",)},
)
def sm3(res, ctx):
    """DirectInternetAccess maps to direct_internet_access; provider default is enabled."""
    value = res.get("direct_internet_access")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT
        if value in (None, "Enabled", "DirectInternetAccess")
        else Compliance.COMPLIANT
    )
