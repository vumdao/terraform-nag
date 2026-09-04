import json
from pathlib import Path

import pytest

from tfnag.cli import main
from tfnag.engine import scan
from tfnag.model import Level, Resource
from tfnag.reporters import exit_code, render
from tfnag.suppressions import (
    SuppressionConfigError,
    address_matches,
    load_suppressions,
    suppression_path,
)

REAL_PLAN = Path(__file__).parent / "real-terraform" / "real-plan.json"


def test_suffix_matching_requires_whole_segments():
    nested = "module.vfl_svc.module.vfl_gw.aws_api_gateway_stage.vfl-gw-stage"
    assert address_matches("vfl_gw.aws_api_gateway_stage.vfl-gw-stage", nested)
    assert not address_matches("gw-stage", nested)
    assert not address_matches("stage.vfl-gw-stage", nested)
    assert not address_matches(nested, "vfl_gw.aws_api_gateway_stage.vfl-gw-stage")


def test_instance_key_matching_covers_unexpanded_and_expanded_addresses():
    assert address_matches("aws_sqs_queue.q", "aws_sqs_queue.q[0]")
    assert address_matches("aws_sqs_queue.q", 'aws_sqs_queue.q["a"]')
    assert address_matches('aws_sqs_queue.q["a"]', 'aws_sqs_queue.q["a"]')
    assert not address_matches('aws_sqs_queue.q["a"]', 'aws_sqs_queue.q["b"]')
    assert address_matches('module.web["*"].aws_sqs_queue.q', 'module.web["a"].aws_sqs_queue.q[0]')


def test_json_rule_wide_glob_and_suppression_reason(tmp_path):
    path = tmp_path / ".tfnag.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "AwsSolutions-EFS1",
                    "resources": ["*"],
                    "reason": "Handled by the platform baseline",
                }
            ]
        )
    )
    suppressions = load_suppressions(path)
    resource = Resource(
        "module.storage.aws_efs_file_system.files[0]",
        "aws_efs_file_system",
        "files",
        {"encrypted": False},
    )
    findings = scan([resource], {}, suppressions=suppressions)
    assert findings[0].suppression == "Handled by the platform baseline"
    assert json.loads(render(findings, "json"))[0]["suppression"] == (
        "Handled by the platform baseline"
    )
    assert exit_code(findings) == 0


def test_expired_entry_becomes_warn_with_message():
    resource = Resource(
        "aws_efs_file_system.files",
        "aws_efs_file_system",
        "files",
        {"encrypted": False},
    )
    findings = scan(
        [resource],
        {},
        suppressions=[
            {
                "id": "AwsSolutions-EFS1",
                "resources": ["aws_efs_file_system.files"],
                "reason": "Old exception",
                "expires": "2000-01-01",
            }
        ],
    )
    assert findings[0].level == Level.WARN
    assert findings[0].suppression is None
    assert "suppression expired" in findings[0].message


@pytest.mark.parametrize(
    ("document", "needle"),
    [
        ([{"id": "AwsSolutions-S1", "resources": ["*"]}], "reason"),
        ([{"id": "AwsSolutions-NOTREAL", "resources": ["*"], "reason": "x"}], "unknown rule ID"),
        ([{"id": "AwsSolutions-S1", "resources": ["*"], "reason": "x", "extra": 1}], "unknown key"),
        ([{"id": "AwsSolutions-S1", "resources": ["*"], "reason": " "}], "reason"),
        ([{"id": "AwsSolutions-S1", "reason": "x"}], "resources"),
        ([{"id": "AwsSolutions-S1", "resources": [], "reason": "x"}], "resources"),
        (
            [{"id": "AwsSolutions-S1", "resources": ["*"], "reason": "x", "expires": "tomorrow"}],
            "YYYY-MM-DD",
        ),
        (["not an object"], "entry 0"),
    ],
)
def test_json_configuration_errors_name_file_and_entry(tmp_path, document, needle):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(SuppressionConfigError, match=r"bad\.json"):
        load_suppressions(path)
    with pytest.raises(SuppressionConfigError) as error:
        load_suppressions(path)
    assert needle in str(error.value)


@pytest.mark.parametrize(
    ("document", "needle"),
    [
        ({"suppressions": "not an array"}, "suppressions must be an array"),
        ({"unexpected": []}, "unknown top-level key"),
        ("not an array or object", "top level must be an array or object"),
    ],
)
def test_json_top_level_configuration_errors(tmp_path, document, needle):
    path = tmp_path / "bad-top-level.json"
    path.write_text(json.dumps(document))
    with pytest.raises(SuppressionConfigError, match=r"bad-top-level\.json"):
        load_suppressions(path)
    with pytest.raises(SuppressionConfigError, match=needle):
        load_suppressions(path)


def test_json_yaml_precedence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".tfnag.json").write_text(
        '[{"id":"AwsSolutions-S1","resources":["*"],"reason":"json"}]'
    )
    (tmp_path / ".tfnag.yml").write_text(
        "- rule: AwsSolutions-S1\n  address: '*'\n  reason: yaml\n"
    )
    assert suppression_path() == tmp_path / ".tfnag.json"
    assert load_suppressions(suppression_path())[0]["reason"] == "json"


def test_explicit_suppression_path_overrides_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".tfnag.json").write_text(
        '[{"id":"AwsSolutions-S1","resources":["*"],"reason":"default"}]'
    )
    override = tmp_path / "override.json"
    override.write_text('[{"id":"AwsSolutions-S1","resources":["*"],"reason":"override"}]')
    assert load_suppressions(suppression_path(override))[0]["reason"] == "override"


def test_strict_ignores_suppressions():
    resource = Resource(
        "aws_efs_file_system.files",
        "aws_efs_file_system",
        "files",
        {"encrypted": False},
    )
    suppressions = [{"id": "AwsSolutions-EFS1", "resources": ["*"], "reason": "ignored"}]
    findings = scan([resource], {}, suppressions=suppressions, strict=True)
    assert findings[0].suppression is None
    assert exit_code(findings) == 1
    output = render(findings, "table", suppressions, strict=True)
    assert "SUPPRESSED" not in output
    assert "tf-nag:" not in output


def test_table_and_markdown_report_suppression_summary_and_dead_warning(tmp_path):
    resource = Resource(
        "aws_efs_file_system.files",
        "aws_efs_file_system",
        "files",
        {"encrypted": False},
    )
    path = tmp_path / ".tfnag.json"
    path.write_text(
        json.dumps(
            {
                "suppressions": [
                    {"id": "AwsSolutions-EFS1", "resources": ["*"], "reason": "accepted"},
                    {
                        "id": "AwsSolutions-EFS1",
                        "resources": ["aws_efs_file_system.never"],
                        "reason": "stale",
                    },
                ]
            }
        )
    )
    suppressions = load_suppressions(path)
    findings = scan([resource], {}, suppressions=suppressions)
    table = render(findings, "table", suppressions)
    markdown = render(findings, "markdown", suppressions)
    for output in (table, markdown):
        assert "1 findings suppressed by 1 suppression entries" in output
        assert "WARNING: suppression entry 1 matched no findings" in output


def test_real_plan_json_suppression_smoke(tmp_path, capsys):
    path = tmp_path / ".tfnag.json"
    path.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "id": "AwsSolutions-S2",
                        "resources": ["aws_s3_bucket.site"],
                        "reason": "Public access is reviewed centrally",
                    },
                    {
                        "id": "AwsSolutions-APIG1",
                        "resources": ["aws_api_gateway_stage.vfl-gw-stage"],
                        "reason": "Stale example",
                    },
                ]
            }
        )
    )
    result = main(
        [
            "scan",
            "--plan-json",
            str(REAL_PLAN),
            "--suppressions",
            str(path),
        ]
    )
    output = capsys.readouterr()
    assert result == 1
    assert 'ERROR  AwsSolutions-S2   module.web_many["blue"].aws_s3_bucket.site' not in output.out
    assert "3 findings suppressed by 1 suppression entries" in output.out
    assert "WARNING: suppression entry 1 matched no findings" in output.out


def test_cli_returns_distinct_config_error_exit(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{")
    result = main(["scan", "--plan-json", str(REAL_PLAN), "--suppressions", str(path)])
    output = capsys.readouterr()
    assert result == 3
    assert "suppression configuration error" in output.err
    assert "broken.json" in output.err
