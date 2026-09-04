"""Amazon Lex AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-LEX4",
    Level.ERROR,
    ("aws_lex_bot_alias",),
    "LexBotAliasEncryptedConversationLogs",
    attributes={"aws_lex_bot_alias": ("conversation_logs",)},
)
def lex4(res, ctx):
    """ConversationLogSettings.destination maps to conversation_log_settings; enabled destinations require encryption."""
    value = res.get("conversation_logs")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    if not value:
        return Compliance.NON_COMPLIANT
    return (
        Compliance.COMPLIANT
        if any(
            isinstance(item, dict) and item.get("kms_key_arn")
            for item in (value if isinstance(value, list) else [value])
        )
        else Compliance.NON_COMPLIANT
    )
