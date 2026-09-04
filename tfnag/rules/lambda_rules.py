"""Lambda mapping: CFN Function.runtime→aws_lambda_function.runtime.
Container-image functions and custom provided runtimes are not applicable.
"""

from ..model import UNKNOWN, Compliance, Level
from ..registry import rule

# Latest generally available managed runtime per language family.
# Source: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html (2026-08-27).
LATEST_RUNTIMES = {
    "python": "python3.14",
    "nodejs": "nodejs24.x",
    "java": "java25",
    "dotnet": "dotnet10",
    "ruby": "ruby4.0",
    "go": "provided.al2023",
}

# Public-preview runtimes are newer than the latest GA release, so they are accepted too.
PREVIEW_RUNTIMES = frozenset({"nodejs26.x", "python3.15"})


@rule(
    "AwsSolutions-L1",
    Level.ERROR,
    ("aws_lambda_function",),
    "LambdaLatestVersion",
    attributes={"aws_lambda_function": ("runtime",)},
)
def lambda_latest(res, ctx):
    runtime = res.get("runtime")
    if runtime is UNKNOWN:
        return Compliance.UNKNOWN
    if not runtime or str(runtime).startswith("provided"):
        return Compliance.NOT_APPLICABLE
    expected = next(
        (value for key, value in LATEST_RUNTIMES.items() if str(runtime).startswith(key)), None
    )
    return (
        Compliance.COMPLIANT
        if expected is None or runtime == expected or runtime in PREVIEW_RUNTIMES
        else Compliance.NON_COMPLIANT
    )
