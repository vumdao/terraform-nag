"""ELB mappings: classic LoadBalancer properties map to aws_elb; V2 access-log
attributes map to aws_lb/aws_alb load_balancer_type and access_logs blocks.
"""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import check


def listeners(res, ctx):
    values = res.get("listener")
    return values if isinstance(values, list) else []


@rule(
    "AwsSolutions-ELB1",
    Level.ERROR,
    ("aws_elb",),
    "CLBNoInboundHttpHttps",
    attributes={"aws_elb": ("listener",)},
)
def elb1(res, ctx):
    for listener in listeners(res, ctx):
        protocol = listener.get("lb_protocol") or listener.get("protocol")
        if protocol is UNKNOWN:
            return Compliance.UNKNOWN
        if str(protocol).lower() in ("http", "https"):
            return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT


@rule(
    "AwsSolutions-ELB2",
    Level.ERROR,
    ("aws_elb", "aws_lb", "aws_alb"),
    "ELBLoggingEnabled",
    attributes={
        "aws_elb": ("access_logs",),
        "aws_lb": ("access_logs",),
        "aws_alb": ("access_logs",),
    },
)
def elb2(res, ctx):
    value = res.get("access_logs")
    if value is UNKNOWN:
        return Compliance.UNKNOWN
    if res.type == "aws_elb":
        value = res.get("access_logs") or res.get("access_logging_policy")
        return check(value, missing=Compliance.NON_COMPLIANT)
    return check(value, missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-ELB3",
    Level.ERROR,
    ("aws_elb",),
    "CLBConnectionDraining",
    attributes={"aws_elb": ("connection_draining",)},
)
def elb3(res, ctx):
    return check(res.get("connection_draining"), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-ELB4",
    Level.ERROR,
    ("aws_elb",),
    "ELBCrossZoneLoadBalancingEnabled",
    attributes={"aws_elb": ("availability_zones", "cross_zone_load_balancing")},
)
def elb4(res, ctx):
    zones = res.get("availability_zones")
    if zones is UNKNOWN or res.get("cross_zone_load_balancing") is UNKNOWN:
        return Compliance.UNKNOWN
    if len(zones or []) < 2:
        return Compliance.NON_COMPLIANT
    return check(res.get("cross_zone_load_balancing"), missing=Compliance.NON_COMPLIANT)


@rule(
    "AwsSolutions-ELB5",
    Level.ERROR,
    ("aws_elb",),
    "ELBTlsHttpsListenersOnly",
    attributes={"aws_elb": ("listener",)},
)
def elb5(res, ctx):
    for listener in listeners(res, ctx):
        protocol = listener.get("lb_protocol") or listener.get("protocol")
        if protocol is UNKNOWN:
            return Compliance.UNKNOWN
        if str(protocol).lower() not in ("https", "ssl", "tls"):
            return Compliance.NON_COMPLIANT
    return Compliance.COMPLIANT
