"""Amazon QuickSight AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-QS1",
    Level.ERROR,
    ("aws_quicksight_data_source",),
    "QuicksightSSLConnections",
    attributes={"aws_quicksight_data_source": ("ssl_properties",)},
)
def qs1(res, ctx):
    """SSLProperties maps to ssl_properties; disable_ssl is not permitted."""
    value = res.get("ssl_properties")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    return (
        Compliance.COMPLIANT
        if value and value.get("disable_ssl") is not True
        else Compliance.NON_COMPLIANT
    )
