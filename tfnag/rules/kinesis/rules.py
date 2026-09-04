"""Amazon Kinesis AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-KDA3",
    Level.WARN,
    ("aws_kinesisanalyticsv2_application",),
    "KinesisDataAnalyticsFlinkCheckpointing",
    attributes={"aws_kinesisanalyticsv2_application": ("application_configuration",)},
)
def kda3(res, ctx):
    """CheckpointConfiguration maps to application_configuration; CUSTOM checkpointing is required."""
    value = res.get(
        "application_configuration.flink_application_configuration.checkpoint_configuration.configuration_type"
    )
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if str(value).upper() == "CUSTOM" else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-KDF1",
    Level.ERROR,
    ("aws_kinesis_firehose_delivery_stream",),
    "KinesisDataFirehoseSSE",
    attributes={"aws_kinesis_firehose_delivery_stream": ("server_side_encryption",)},
)
def kdf1(res, ctx):
    """SSE maps to server_side_encryption; KMS encryption is required."""
    value = res.get("server_side_encryption")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if isinstance(value, dict) and value.get("enabled") is True
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-KDS1",
    Level.ERROR,
    ("aws_kinesis_stream",),
    "KinesisDataStreamSSE",
    attributes={"aws_kinesis_stream": ("encryption_type",)},
)
def kds1(res, ctx):
    """StreamEncryption maps to encryption_type; KMS is required."""
    return required(res, "encryption_type", lambda value: str(value).upper() == "KMS")


@rule(
    "AwsSolutions-KDS3",
    Level.WARN,
    ("aws_kinesis_stream",),
    "KinesisDataStreamDefaultKeyWhenSSE",
    attributes={"aws_kinesis_stream": ("encryption_type", "kms_key_id")},
)
def kds3(res, ctx):
    """KmsKeyId maps to kms_key_id; KMS encryption must use a customer key rather than alias/aws/kinesis."""
    encryption, key = res.get("encryption_type"), res.get("kms_key_id")
    if UNKNOWN in (encryption, key):
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if str(encryption).upper() != "KMS" or key not in (None, "alias/aws/kinesis")
        else Compliance.NON_COMPLIANT
    )
