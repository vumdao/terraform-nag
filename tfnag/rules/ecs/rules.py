"""Amazon ECS AWS Solutions rules."""

from ...model import UNKNOWN, Compliance, Level
from ...registry import rule
from ..common import json_value


def _containers(res):
    value = json_value(res.get("container_definitions"))
    if value is UNKNOWN:
        return [], True
    if isinstance(value, dict):
        value = [value]
    return (
        ([item for item in value if isinstance(item, dict)], False)
        if isinstance(value, list)
        else ([], False)
    )


@rule(
    "AwsSolutions-ECS2",
    Level.ERROR,
    ("aws_ecs_task_definition",),
    "ECSTaskDefinitionNoEnvironmentVariables",
    attributes={"aws_ecs_task_definition": ("container_definitions",)},
)
def ecs2(res, ctx):
    """ContainerDefinitions.environment maps to aws_ecs_task_definition.container_definitions; non-empty vars are prohibited."""
    containers, unknown = _containers(res)
    if unknown:
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT
        if any(item.get("environment") for item in containers)
        else Compliance.COMPLIANT
    )


@rule(
    "AwsSolutions-ECS4",
    Level.ERROR,
    ("aws_ecs_cluster",),
    "ECSClusterCloudWatchContainerInsights",
    attributes={"aws_ecs_cluster": ("setting",)},
)
def ecs4(res, ctx):
    """ClusterSettings containerInsights maps to aws_ecs_cluster.setting; default is disabled."""
    settings = res.get("setting")
    if settings is UNKNOWN:
        return Compliance.UNKNOWN
    settings = settings if isinstance(settings, list) else [settings or {}]
    return (
        Compliance.COMPLIANT
        if any(
            item.get("name") == "containerInsights"
            and str(item.get("value")).lower() in ("enabled", "enhanced")
            for item in settings
            if isinstance(item, dict)
        )
        else Compliance.NON_COMPLIANT
    )


@rule(
    "AwsSolutions-ECS7",
    Level.ERROR,
    ("aws_ecs_task_definition",),
    "ECSTaskDefinitionContainerLogging",
    attributes={"aws_ecs_task_definition": ("container_definitions",)},
)
def ecs7(res, ctx):
    """ContainerDefinitions.logConfiguration maps to aws_ecs_task_definition.container_definitions; absent logging is non-compliant."""
    containers, unknown = _containers(res)
    if unknown:
        return Compliance.UNKNOWN
    return (
        Compliance.NON_COMPLIANT
        if any(not (item.get("logConfiguration") or {}).get("logDriver") for item in containers)
        else Compliance.COMPLIANT
    )
