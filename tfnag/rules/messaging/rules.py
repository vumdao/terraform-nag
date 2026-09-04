"""SQS/SNS mappings: Queue/Topic security properties map to aws_sqs_queue and
aws_sns_topic; QueuePolicy/TopicPolicy map to aws_*_queue_policy/aws_*_topic_policy.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import secure_transport_policy, statements


@rule(
    "AwsSolutions-SQS2",
    Level.ERROR,
    ("aws_sqs_queue",),
    "SQSQueueSSE",
    attributes={"aws_sqs_queue": ("sqs_managed_sse_enabled", "kms_master_key_id")},
)
def sqs2(res, ctx):
    managed = res.get("sqs_managed_sse_enabled")
    kms = res.get("kms_master_key_id")
    if managed is UNKNOWN or kms is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if managed is True or kms else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-SQS3",
    Level.ERROR,
    ("aws_sqs_queue",),
    "SQSQueueDLQ",
    attributes={"aws_sqs_queue": ("redrive_policy",)},
)
def sqs3(res, ctx):
    redrive = res.get("redrive_policy")
    if redrive is UNKNOWN:
        return Compliance.UNKNOWN
    if redrive:
        return Compliance.COMPLIANT
    for candidate in ctx.graph.by_type.get("aws_sqs_queue", []):
        if candidate is not res:
            policy = candidate.get("redrive_policy")
            if isinstance(policy, dict) and (
                policy.get("dead_letter_target_arn") == res.address or res.name in str(policy)
            ):
                return Compliance.COMPLIANT
    for function in ctx.graph.by_type.get("aws_lambda_function", []):
        dead = function.get("dead_letter_config")
        if isinstance(dead, dict) and res.name in str(dead):
            return Compliance.COMPLIANT
    return Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-SQS4",
    Level.ERROR,
    ("aws_sqs_queue",),
    "SQSQueueSSLRequestsOnly",
    attributes={"aws_sqs_queue": ("arn", "id", "name")},
)
def sqs4(res, ctx):
    return secure_transport_policy(ctx, res, "sqs")


@rule(
    "AwsSolutions-SNS3",
    Level.ERROR,
    ("aws_sns_topic",),
    "SNSTopicSSLPublishOnly",
    attributes={"aws_sns_topic": ("arn", "id", "name", "kms_master_key_id")},
)
def sns3(res, ctx):
    if res.get("kms_master_key_id") is not None:
        return Compliance.COMPLIANT
    for statement in statements(ctx, res):
        effect = str(statement.get("Effect", statement.get("effect", ""))).lower()
        action = statement.get("Action", statement.get("actions", []))
        condition = statement.get("Condition", statement.get("condition", {}))
        secure = (
            (condition.get("Bool") or condition).get("aws:SecureTransport")
            if isinstance(condition, dict)
            else None
        )
        actions = action if isinstance(action, list) else [action]
        if (
            effect == "deny"
            and secure in (False, "false")
            and any(str(a).lower() in ("sns:publish", "*") for a in actions)
        ):
            return Compliance.COMPLIANT
    return Compliance.NON_COMPLIANT
