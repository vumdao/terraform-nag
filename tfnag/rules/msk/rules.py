"""Amazon MSK AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-MSK2",
    Level.ERROR,
    ("aws_msk_cluster",),
    "MSKClientToBrokerTLS",
    attributes={"aws_msk_cluster": ("encryption_info.0.encryption_in_transit.0.client_broker",)},
)
def msk2(res, ctx):
    """ClientBroker maps to encryption_info.encryption_in_transit.client_broker; plaintext is non-compliant."""
    value = res.get("encryption_info.encryption_in_transit.client_broker")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if str(value).upper() == "TLS" else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-MSK3",
    Level.ERROR,
    ("aws_msk_cluster",),
    "MSKBrokerToBrokerTLS",
    attributes={"aws_msk_cluster": ("encryption_info.0.encryption_in_transit.0.in_cluster",)},
)
def msk3(res, ctx):
    """InCluster maps to encryption_info.encryption_in_cluster; false is non-compliant."""
    value = res.get("encryption_info.encryption_in_transit.in_cluster")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if value is True else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-MSK6",
    Level.ERROR,
    ("aws_msk_cluster",),
    "MSKBrokerLogging",
    attributes={"aws_msk_cluster": ("logging_info.0.broker_logs",)},
)
def msk6(res, ctx):
    """BrokerLogs destinations map to logging_info.broker_logs; at least one enabled destination is required."""
    logs = res.get("logging_info.broker_logs")
    if logs is UNKNOWN:
        return Compliance.UNKNOWN
    if not isinstance(logs, dict):
        return Compliance.NON_COMPLIANT
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(logs.get(key), dict) and logs[key].get("enabled") is True
            for key in ("s3", "cloudwatch_logs", "firehose")
        )
        else Compliance.NON_COMPLIANT
    )
