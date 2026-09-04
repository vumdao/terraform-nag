from tfnag.graph import ResourceGraph
from tfnag.model import UNKNOWN, Compliance, Resource
from tfnag.registry import INVENTORY, RULES, discover
from tfnag.schema import validate_rule_metadata


def test_block_list_paths_and_numeric_indices():
    resource = Resource(
        "aws_dynamodb_table.example",
        "aws_dynamodb_table",
        "example",
        {"point_in_time_recovery": [{"enabled": True}]},
    )
    assert resource.get("point_in_time_recovery.enabled") is True
    assert resource.get("point_in_time_recovery.0.enabled") is True
    assert resource.get("point_in_time_recovery.1.enabled") is None


def test_block_list_unknown_paths_are_preserved():
    resource = Resource(
        "aws_dynamodb_table.example",
        "aws_dynamodb_table",
        "example",
        {"point_in_time_recovery": [{}]},
        unknown_paths={"point_in_time_recovery.0.enabled"},
    )
    assert resource.get("point_in_time_recovery.enabled") is UNKNOWN
    assert resource.get("point_in_time_recovery.0.enabled") is UNKNOWN


def test_unknown_nested_sibling_does_not_hide_known_block_attribute():
    resource = Resource(
        "aws_dynamodb_table.example",
        "aws_dynamodb_table",
        "example",
        {"point_in_time_recovery": [{"enabled": True}]},
        unknown_paths={"point_in_time_recovery.0.recovery_period_in_days"},
    )
    assert resource.get("point_in_time_recovery.enabled") is True


def test_all_inventory_rules_have_dedicated_implementations():
    discover()
    missing = [
        rule_id
        for rule_id, item in INVENTORY.items()
        if not item.get("not_applicable_terraform") and rule_id not in RULES
    ]
    assert not missing
    assert all(
        registered.check.__module__ != "tfnag.rules.remaining.rules"
        for registered in RULES.values()
    )
    assert len({registered.check for registered in RULES.values()}) == len(RULES)


def test_every_rule_metadata_path_exists_in_provider_schema():
    discover()
    assert validate_rule_metadata(RULES) == []


def test_compliant_dynamodb_block_is_compliant():
    discover()
    rule = RULES["AwsSolutions-DDB3"]
    resource = Resource(
        "aws_dynamodb_table.example",
        "aws_dynamodb_table",
        "example",
        {"point_in_time_recovery": [{"enabled": True}]},
    )
    assert rule.check(resource, None) is Compliance.COMPLIANT


def test_data_sources_remain_graph_targets_but_are_not_scanned():
    data = Resource(
        "data.aws_iam_policy_document.policy",
        "aws_iam_policy_document",
        "policy",
        {"json": '{"Statement": []}'},
        mode="data",
    )
    policy = Resource(
        "aws_iam_role_policy.example",
        "aws_iam_role_policy",
        "example",
        {"policy": data.values["json"]},
    )
    graph = ResourceGraph(
        [data, policy],
        {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_iam_role_policy.example",
                        "expressions": {"policy": {"references": [data.address]}},
                    }
                ]
            }
        },
    )
    assert graph.references(policy) == [data]
