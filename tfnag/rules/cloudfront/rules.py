"""Amazon CloudFront AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-CFR1",
    Level.WARN,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionGeoRestrictions",
    attributes={
        "aws_cloudfront_distribution": ("restrictions.0.geo_restriction.0.restriction_type",)
    },
)
def cfr1(res, ctx):
    """GeoRestriction maps to restrictions.geo_restriction; whitelist/blacklist is required."""
    return required(
        res,
        "restrictions.geo_restriction.restriction_type",
        lambda value: str(value).lower() in ("whitelist", "blacklist"),
    )


@rule(
    "AwsSolutions-CFR2",
    Level.WARN,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionWAFIntegration",
    attributes={"aws_cloudfront_distribution": ("web_acl_id",)},
)
def cfr2(res, ctx):
    """WebACLId maps to web_acl_id; absent means no WAF integration."""
    return required(res, "web_acl_id", bool)


@rule(
    "AwsSolutions-CFR3",
    Level.ERROR,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionAccessLogging",
    attributes={"aws_cloudfront_distribution": ("logging_config.0.bucket",)},
)
def cfr3(res, ctx):
    """Logging maps to logging_config.bucket; absent disables access logging."""
    return required(res, "logging_config.bucket", bool)


@rule(
    "AwsSolutions-CFR4",
    Level.ERROR,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionHttpsViewerNoOutdatedSSL",
    attributes={
        "aws_cloudfront_distribution": ("default_cache_behavior.0.viewer_protocol_policy",)
    },
)
def cfr4(res, ctx):
    """ViewerProtocolPolicy maps to default_cache_behavior.viewer_protocol_policy; HTTPS-only is required."""
    return required(
        res,
        "default_cache_behavior.viewer_protocol_policy",
        lambda value: str(value).lower() in ("https-only", "redirect-to-https"),
    )


@rule(
    "AwsSolutions-CFR5",
    Level.ERROR,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionNoOutdatedSSL",
    attributes={
        "aws_cloudfront_distribution": (
            "origin.0.custom_origin_config.0.origin_protocol_policy",
            "origin.0.custom_origin_config.0.origin_ssl_protocols",
        )
    },
)
def cfr5(res, ctx):
    """CustomOriginConfig maps to origin_protocol_policy/origin_ssl_protocols; HTTPS-only without SSLv3/TLSv1 is required."""
    origins = res.get("origin")
    if origins is UNKNOWN:
        return Compliance.UNKNOWN
    for origin in origins or []:
        if not isinstance(origin, dict) or "custom_origin_config" not in origin:
            continue
        configs = origin.get("custom_origin_config") or []
        configs = configs if isinstance(configs, list) else [configs]
        for config in configs:
            if config is UNKNOWN or not isinstance(config, dict):
                return Compliance.UNKNOWN
            policy = config.get("origin_protocol_policy")
            protocols = config.get("origin_ssl_protocols")
            if UNKNOWN in (policy, protocols):
                return Compliance.UNKNOWN
            if (
                policy != "https-only"
                or not protocols
                or any(
                    str(value).lower()
                    in ("sslv3", "tlsv1", "tlsv1.1", "tlsv1_2016", "tlsv1.1_2016")
                    for value in protocols
                )
            ):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-CFR7",
    Level.ERROR,
    ("aws_cloudfront_distribution",),
    "CloudFrontDistributionS3OriginAccessControl",
    attributes={"aws_cloudfront_distribution": ("origin.0.origin_access_control_id",)},
)
def cfr7(res, ctx):
    """S3 origin OriginAccessControlId maps to origin.origin_access_control_id; every S3 origin must have one."""
    origins = res.get("origin")
    if origins is UNKNOWN:
        return Compliance.UNKNOWN
    for origin in origins or []:
        if not isinstance(origin, dict):
            continue
        s3_config = origin.get("s3_origin_config")
        if s3_config is UNKNOWN:
            return Compliance.UNKNOWN
        if s3_config and not origin.get("origin_access_control_id"):
            return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT
