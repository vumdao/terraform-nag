"""Amazon EKS AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule


@rule(
    "AwsSolutions-EKS1",
    Level.ERROR,
    ("aws_eks_cluster",),
    "EKSClusterNoEndpointPublicAccess",
    attributes={"aws_eks_cluster": ("vpc_config.0.endpoint_public_access",)},
)
def eks1(res, ctx):
    """EndpointPublicAccess maps to aws_eks_cluster.vpc_config.endpoint_public_access; provider default is true."""
    value = res.get("vpc_config.endpoint_public_access")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    return Compliance.NON_COMPLIANT if value is None or value is True else Compliance.COMPLIANT


@rule(
    "AwsSolutions-EKS2",
    Level.ERROR,
    ("aws_eks_cluster",),
    "EKSClusterControlPlaneLogs",
    attributes={"aws_eks_cluster": ("enabled_cluster_log_types",)},
)
def eks2(res, ctx):
    """Logging types map to aws_eks_cluster.enabled_cluster_log_types; empty defaults disable logs."""
    value = res.get("enabled_cluster_log_types")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
    return Compliance.COMPLIANT if required <= set(value or []) else Compliance.NON_COMPLIANT
