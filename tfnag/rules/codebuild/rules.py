"""AWS CodeBuild AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-CB4",
    Level.ERROR,
    ("aws_codebuild_project",),
    "CodeBuildProjectKMSEncryptedArtifacts",
    attributes={"aws_codebuild_project": ("artifacts.0.encryption_disabled", "encryption_key")},
)
def cb4(res, ctx):
    """Artifacts.encryption_disabled and encryption_key map to CodeBuild artifact encryption; disabled artifacts are non-compliant."""
    disabled, key = res.get("artifacts.encryption_disabled"), res.get("encryption_key")
    if UNKNOWN in (disabled, key):
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT if disabled is True or not key else Compliance.COMPLIANT


@rule(
    "AwsSolutions-CB5",
    Level.WARN,
    ("aws_codebuild_project",),
    "CodeBuildProjectManagedImages",
    attributes={"aws_codebuild_project": ("environment.0.image",)},
)
def cb5(res, ctx):
    """Environment.image maps to environment.image; the AWS-managed CodeBuild image family is required."""
    value = res.get("environment.image")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if isinstance(value, str) and value.startswith("aws/codebuild/")
        else Compliance.NON_COMPLIANT
    )
