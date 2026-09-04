"""ElastiCache AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import required


@rule(
    "AwsSolutions-AEC1",
    Level.ERROR,
    ("aws_elasticache_cluster", "aws_elasticache_replication_group"),
    "ElastiCacheClusterInVPC",
    attributes={
        "aws_elasticache_cluster": ("subnet_group_name",),
        "aws_elasticache_replication_group": ("subnet_group_name",),
    },
)
def aec1(res, ctx):
    """VpcSubnetGroup maps to subnet_group_name; absent means the default VPC placement and is non-compliant."""
    return required(res, "subnet_group_name", bool)


@rule(
    "AwsSolutions-AEC3",
    Level.ERROR,
    ("aws_elasticache_replication_group",),
    "ElastiCacheRedisClusterEncryption",
    attributes={
        "aws_elasticache_replication_group": (
            "at_rest_encryption_enabled",
            "transit_encryption_enabled",
        )
    },
)
def aec3(res, ctx):
    """AtRestEncryptionEnabled and TransitEncryptionEnabled map to matching attributes; provider defaults are false."""
    rest, transit = res.get("at_rest_encryption_enabled"), res.get("transit_encryption_enabled")
    if rest is UNKNOWN or transit is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.COMPLIANT if rest is True and transit is True else Compliance.NON_COMPLIANT


@rule(
    "AwsSolutions-AEC4",
    Level.ERROR,
    ("aws_elasticache_replication_group",),
    "ElastiCacheRedisClusterMultiAZ",
    attributes={"aws_elasticache_replication_group": ("multi_az_enabled",)},
)
def aec4(res, ctx):
    """MultiAZEnabled maps to multi_az_enabled; provider default is false."""
    return required(res, "multi_az_enabled", lambda value: value is True)


@rule(
    "AwsSolutions-AEC5",
    Level.ERROR,
    ("aws_elasticache_cluster", "aws_elasticache_replication_group"),
    "ElastiCacheClusterNonDefaultPort",
    attributes={
        "aws_elasticache_cluster": ("port", "engine"),
        "aws_elasticache_replication_group": ("port", "engine"),
    },
)
def aec5(res, ctx):
    """Port maps to port; the Redis/Memcached provider defaults 6379/11211 are non-compliant."""
    value = res.get("port")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    default = 6379 if "redis" in str(res.get("engine", "")).lower() else 11211
    return (
        Compliance.NON_COMPLIANT if value is None or int(value) == default else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-AEC6",
    Level.ERROR,
    ("aws_elasticache_replication_group",),
    "ElastiCacheRedisClusterRedisAuth",
    attributes={"aws_elasticache_replication_group": ("auth_token",)},
)
def aec6(res, ctx):
    """AuthToken maps to auth_token; absent means Redis AUTH is disabled."""
    return required(res, "auth_token", bool)
