"""Lambda mapping: CFN Function.runtime→aws_lambda_function.runtime.
Container-image functions and custom provided runtimes are not applicable.
"""

import json
from pathlib import Path

from ..model import UNKNOWN, Compliance, Level
from ..registry import rule

# Latest generally available managed runtime per language family, plus the
# public-preview runtimes that are newer than any GA release. The file is
# refreshed from the AWS documentation by scripts/sync_upstream.py.
RUNTIMES_PATH = Path(__file__).parent.parent / "data" / "lambda_runtimes.json"
_RUNTIMES = json.loads(RUNTIMES_PATH.read_text(encoding="utf-8"))
LATEST_RUNTIMES: dict[str, str] = _RUNTIMES["latest"]
PREVIEW_RUNTIMES: frozenset[str] = frozenset(_RUNTIMES["preview"])


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
