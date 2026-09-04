"""RDS mappings: DBCluster/DBInstance properties map to aws_rds_cluster and
aws_db_instance attributes. Security group ingress is represented by inline ingress
or aws_vpc_security_group_ingress_rule/aws_security_group_rule.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import check, text
from ..ec2.rules import ingress_rules


def engine(res):
    value = res.get("engine")
    return value.lower() if isinstance(value, str) else value


@rule(
    "AwsSolutions-RDS2",
    Level.ERROR,
    ("aws_db_instance", "aws_rds_cluster"),
    "RDSStorageEncrypted",
    attributes={
        "aws_db_instance": ("engine", "storage_encrypted"),
        "aws_rds_cluster": ("engine", "storage_encrypted"),
    },
)
def rds2(res, ctx):
    encrypted = res.get("storage_encrypted")
    eng = engine(res)
    if res.type == "aws_db_instance" and isinstance(eng, str) and "aurora" in eng:
        return Compliance.COMPLIANT
    return check(encrypted, missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-RDS3",
    Level.ERROR,
    ("aws_db_instance",),
    "RDSMultiAZSupport",
    attributes={"aws_db_instance": ("engine", "multi_az")},
)
def rds3(res, ctx):
    eng = engine(res)
    if isinstance(eng, str) and "aurora" in eng:
        return Compliance.COMPLIANT
    return check(res.get("multi_az"), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-RDS6",
    Level.ERROR,
    ("aws_rds_cluster",),
    "AuroraMySQLPostgresIAMAuth",
    attributes={"aws_rds_cluster": ("engine", "iam_database_authentication_enabled")},
)
def rds6(res, ctx):
    eng = engine(res)
    if not isinstance(eng, str) or "aurora" not in eng:
        return Compliance.COMPLIANT
    return check(res.get("iam_database_authentication_enabled"), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-RDS8",
    Level.ERROR,
    ("aws_db_instance", "aws_rds_cluster"),
    "RDSRestrictedInbound",
    attributes={
        "aws_db_instance": ("vpc_security_group_ids",),
        "aws_rds_cluster": ("vpc_security_group_ids",),
        "aws_security_group": ("ingress",),
        "aws_security_group_rule": ("cidr_blocks", "ipv6_cidr_blocks"),
        "aws_vpc_security_group_ingress_rule": ("cidr_ipv4", "cidr_ipv6"),
    },
)
def rds8(res, ctx):
    groups = res.get("vpc_security_group_ids")
    if groups is UNKNOWN:
        return Compliance.UNKNOWN
    for group in ctx.graph.by_type.get("aws_security_group", []):
        if any(
            isinstance(g, str) and (g == group.address or g.endswith(group.name))
            for g in (groups or [])
        ):
            result = ingress_rules(group, ctx)
            if any(
                "/0" in text(rule.get("cidr_blocks") or rule.get("cidr_ipv4")) for rule in result
            ):
                return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-RDS10",
    Level.ERROR,
    ("aws_db_instance", "aws_rds_cluster"),
    "RDSInstanceDeletionProtectionEnabled",
    attributes={
        "aws_db_instance": ("engine", "deletion_protection"),
        "aws_rds_cluster": ("engine", "deletion_protection"),
    },
)
def rds10(res, ctx):
    eng = engine(res)
    if res.type == "aws_db_instance" and isinstance(eng, str) and "aurora" in eng:
        return Compliance.COMPLIANT
    return check(res.get("deletion_protection"), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-RDS11",
    Level.ERROR,
    ("aws_db_instance", "aws_rds_cluster"),
    "RDSNonDefaultPort",
    attributes={"aws_db_instance": ("engine", "port"), "aws_rds_cluster": ("engine", "port")},
)
def rds11(res, ctx):
    port = res.get("port")
    eng = engine(res)
    if port is UNKNOWN or eng is UNKNOWN:
        return Compliance.UNKNOWN
    if port is None:
        return (
            Compliance.NON_COMPLIANT
            if not (isinstance(eng, str) and "aurora" in eng)
            else Compliance.COMPLIANT
        )
    defaults = (
        ("3306",)
        if isinstance(eng, str) and ("mysql" in eng or eng in ("aurora", "aurora-mysql", "mariadb"))
        else ()
    )
    if isinstance(eng, str) and "postgres" in eng:
        defaults = ("5432",)
    if isinstance(eng, str) and "oracle" in eng:
        defaults = ("1521",)
    if isinstance(eng, str) and "sqlserver" in eng:
        defaults = ("1433",)
    return Compliance.NON_COMPLIANT if str(port) in defaults else Compliance.COMPLIANT


@rule(
    "AwsSolutions-RDS13",
    Level.ERROR,
    ("aws_db_instance",),
    "RDSInstanceBackupEnabled",
    attributes={"aws_db_instance": ("backup_retention_period",)},
)
def rds13(res, ctx):
    value = res.get("backup_retention_period")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    default = 1 if res.type == "aws_rds_cluster" else 0
    return (
        Compliance.NON_COMPLIANT
        if (value if value is not None else default) <= 0
        else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-RDS14",
    Level.ERROR,
    ("aws_rds_cluster",),
    "AuroraMySQLBacktrack",
    attributes={"aws_rds_cluster": ("engine", "backtrack_window")},
)
def rds14(res, ctx):
    eng = engine(res)
    if eng not in ("aurora", "aurora-mysql"):
        return Compliance.COMPLIANT
    value = res.get("backtrack_window")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT if not value else Compliance.COMPLIANT


@rule(
    "AwsSolutions-RDS16",
    Level.ERROR,
    ("aws_rds_cluster",),
    "AuroraMySQLLogging",
    attributes={"aws_rds_cluster": ("engine", "engine_mode", "enabled_cloudwatch_logs_exports")},
)
def rds16(res, ctx):
    eng, mode = engine(res), res.get("engine_mode")
    if eng not in ("aurora", "aurora-mysql") or mode != "serverless":
        return Compliance.COMPLIANT
    exports = res.get("enabled_cloudwatch_logs_exports")
    if exports is UNKNOWN:
        return Compliance.UNKNOWN
    return (
        Compliance.COMPLIANT
        if all(x in (exports or []) for x in ("audit", "error", "general", "slowquery"))
        else Compliance.NON_COMPLIANT
    )
