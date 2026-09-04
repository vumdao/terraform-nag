"""S3 mappings: LoggingConfiguration→aws_s3_bucket_logging; PublicAccessBlockConfiguration→
aws_s3_bucket_public_access_block; BucketPolicy→aws_s3_bucket_policy. Legacy inline arguments
and provider 4+ split resources are both accepted.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import check, json_text, secure_transport_policy, statements


@rule(
    "AwsSolutions-S1",
    Level.ERROR,
    ("aws_s3_bucket",),
    "S3BucketLoggingEnabled",
    attributes={
        "aws_s3_bucket": ("logging",),
        "aws_s3_bucket_logging": ("bucket", "target_bucket", "target_prefix"),
    },
)
def s1(res, ctx):
    companions = ctx.graph.companions(res, "aws_s3_bucket_logging", "bucket")
    if companions:
        return Compliance.COMPLIANT
    logging = res.get("logging")
    if logging is UNKNOWN:
        return Compliance.UNKNOWN
    if isinstance(logging, list):
        logging = logging[0] if len(logging) == 1 else None
    if logging and (
        logging.get("target_bucket")
        or logging.get("target_prefix")
        or logging.get("target_object_key_format")
    ):
        return Compliance.COMPLIANT
    return Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-S2",
    Level.ERROR,
    ("aws_s3_bucket",),
    "S3BucketLevelPublicAccessProhibited",
    attributes={"aws_s3_bucket": ("acl",)},
)
def s2(res, ctx):
    companions = ctx.graph.companions(res, "aws_s3_bucket_public_access_block", "bucket")
    if companions:
        inline = companions[0].values
    else:
        inline = res.get("public_access_block")
    if isinstance(inline, list):
        inline = inline[0] if len(inline) == 1 else None
    if inline is UNKNOWN:
        return Compliance.UNKNOWN
    block = inline if isinstance(inline, dict) else None
    if block is None:
        return Compliance.NON_COMPLIANT
    keys = (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    )
    if any(block.get(k) is UNKNOWN for k in keys):
        return Compliance.UNKNOWN
    return check(all(block.get(k) is True for k in keys), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-S5",
    Level.ERROR,
    ("aws_s3_bucket",),
    "S3WebBucketOAIAccess",
    attributes={
        "aws_s3_bucket": ("website",),
        "aws_s3_bucket_website_configuration": ("bucket",),
    },
)
def s5(res, ctx):
    website_companions = ctx.graph.companions(res, "aws_s3_bucket_website_configuration", "bucket")
    if not res.is_configured("website") and not website_companions:
        return Compliance.NOT_APPLICABLE
    website = res.get("website")
    if website is UNKNOWN:
        return Compliance.UNKNOWN
    for statement in statements(ctx, res):
        effect = str(statement.get("Effect", statement.get("effect", ""))).lower()
        principal = statement.get("Principal", statement.get("principal"))
        actions = statement.get("Action", statement.get("actions", []))
        actions = actions if isinstance(actions, list) else [actions]
        principal_text = json_text(principal)
        if effect == "allow" and "*" in principal_text:
            return Compliance.NON_COMPLIANT
        if effect == "allow" and (
            "cloudfront origin access identity" in principal_text.lower()
            or "CanonicalUser" in principal_text
        ):
            if all(str(a).lower() in ("s3:getobject", "s3:putobject") for a in actions):
                return Compliance.COMPLIANT
    return Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-S10",
    Level.ERROR,
    ("aws_s3_bucket",),
    "S3BucketSSLRequestsOnly",
    attributes={"aws_s3_bucket": ("policy",)},
)
def s10(res, ctx):
    return secure_transport_policy(ctx, res, "s3")
