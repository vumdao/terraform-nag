"""Amazon EMR AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import json_value


def _security_config(res, ctx):
    groups = [
        item for item in ctx.graph.references(res) if item.type == "aws_emr_security_configuration"
    ]
    groups.extend(
        ctx.graph.companions(res, "aws_emr_security_configuration", "security_configuration")
    )
    if not groups:
        return None
    return json_value(groups[0].get("configuration"))


@rule(
    "AwsSolutions-EMR2",
    Level.ERROR,
    ("aws_emr_cluster",),
    "EMRS3AccessLogging",
    attributes={"aws_emr_cluster": ("log_uri",)},
)
def emr2(res, ctx):
    """LogUri maps to log_uri; absent means EMR logs are not delivered to S3."""
    value = res.get("log_uri")
    return (
        Compliance.UNKNOWN
        if value is UNKNOWN
        else (Compliance.COMPLIANT if value else Compliance.NON_COMPLIANT)
    )


@rule(
    "AwsSolutions-EMR4",
    Level.ERROR,
    ("aws_emr_cluster",),
    "EMRLocalDiskEncryption",
    attributes={
        "aws_emr_cluster": ("security_configuration",),
        "aws_emr_security_configuration": ("configuration",),
    },
)
def emr4(res, ctx):
    """LocalDiskEncryptionConfiguration maps to aws_emr_security_configuration.configuration JSON."""
    config = _security_config(res, ctx)
    if config is None:
        return Compliance.NON_COMPLIANT
    if config is UNKNOWN:
        return Compliance.UNKNOWN
    at_rest = config.get("AtRestEncryptionConfiguration", {})
    local = at_rest.get("LocalDiskEncryptionConfiguration", {})
    return (
        Compliance.COMPLIANT
        if config.get("EnableAtRestEncryption") is True and local.get("EncryptionKeyProviderType")
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-EMR5",
    Level.ERROR,
    ("aws_emr_cluster",),
    "EMREncryptionInTransit",
    attributes={
        "aws_emr_cluster": ("security_configuration",),
        "aws_emr_security_configuration": ("configuration",),
    },
)
def emr5(res, ctx):
    """TLSCertificateConfiguration maps to aws_emr_security_configuration.configuration JSON."""
    config = _security_config(res, ctx)
    if config is None:
        return Compliance.NON_COMPLIANT
    if config is UNKNOWN:
        return Compliance.UNKNOWN
    transit = config.get("InTransitEncryptionConfiguration", {})
    tls = transit.get("TLSCertificateConfiguration", {})
    return (
        Compliance.COMPLIANT
        if config.get("EnableInTransitEncryption") is True and tls.get("CertificateProviderType")
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-EMR6",
    Level.ERROR,
    ("aws_emr_cluster",),
    "EMRAuthEC2KeyPairOrKerberos",
    attributes={"aws_emr_cluster": ("kerberos_attributes", "ec2_attributes")},
)
def emr6(res, ctx):
    """KerberosAttributes or Ec2Attributes.KeyName maps to kerberos_attributes/ec2_attributes; either authentication method is sufficient."""
    if res.get("kerberos_attributes") is UNKNOWN or res.get("ec2_attributes") is UNKNOWN:
        return Compliance.UNKNOWN
    kerberos = bool(res.get("kerberos_attributes"))
    ec2 = res.get("ec2_attributes") or {}
    key = ec2.get("key_name") if isinstance(ec2, dict) else None
    return Compliance.COMPLIANT if kerberos or key else Compliance.NON_COMPLIANT
