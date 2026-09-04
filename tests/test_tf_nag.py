import json
from pathlib import Path
from xml.etree.ElementTree import fromstring

from tfnag.engine import scan
from tfnag.graph import ResourceGraph
from tfnag.loader import load_plan
from tfnag.model import UNKNOWN, Compliance, Level, Resource
from tfnag.registry import INVENTORY, RULES, discover, status
from tfnag.reporters import exit_code, render
from tfnag.rules.lambda_rules import LATEST_RUNTIMES, PREVIEW_RUNTIMES
from tfnag.suppressions import load_suppressions, suppression_for

FIXTURES = Path(__file__).parent / "fixtures"


def test_plan_and_state_loader():
    resources, configuration = load_plan(FIXTURES / "minimal-plan.json")
    assert len(resources) == 17
    assert configuration["root_module"]
    state, _ = load_plan(FIXTURES / "state.json")
    assert state[0].address == "aws_s3_bucket.state"


def test_unknown_markers_are_preserved(tmp_path):
    document = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.unknown",
                        "type": "aws_s3_bucket",
                        "name": "unknown",
                        "values": {"bucket": None},
                        "after_unknown": {"bucket": True},
                    }
                ]
            }
        }
    }
    resources, _ = load_plan(write_temp(document, tmp_path))
    assert resources[0].get("bucket") is UNKNOWN


def test_real_plan_unknowns_and_module_companions():
    resources, configuration = load_plan(
        Path(__file__).parent / "real-terraform" / "real-plan.json"
    )
    bucket = next(item for item in resources if item.type == "aws_s3_bucket")
    logging = next(item for item in resources if item.type == "aws_s3_bucket_logging")
    assert bucket.get("logging") is None
    assert bucket.get("website") is None
    queue = next(item for item in resources if item.type == "aws_sqs_queue")
    assert queue.get("sqs_managed_sse_enabled") is None
    graph = ResourceGraph(resources, configuration)
    assert graph.companions(bucket, "aws_s3_bucket_logging", "bucket") == [logging]


def test_real_plan_expanded_instances_preserve_unknown_and_companion_resolution():
    resources, configuration = load_plan(
        Path(__file__).parent / "real-terraform" / "real-plan.json"
    )
    graph = ResourceGraph(resources, configuration)
    expanded_queues = [
        item
        for item in resources
        if item.type == "aws_sqs_queue" and item.name in {"insecure_count", "insecure_for_each"}
    ]
    assert {item.address for item in expanded_queues} == {
        "aws_sqs_queue.insecure_count[0]",
        "aws_sqs_queue.insecure_count[1]",
        'aws_sqs_queue.insecure_for_each["blue"]',
        'aws_sqs_queue.insecure_for_each["green"]',
    }
    assert all(item.get("sqs_managed_sse_enabled") is None for item in expanded_queues)

    expanded_buckets = [
        item
        for item in resources
        if item.type == "aws_s3_bucket" and item.address.startswith("module.web_many[")
    ]
    assert {item.address for item in expanded_buckets} == {
        'module.web_many["blue"].aws_s3_bucket.site',
        'module.web_many["green"].aws_s3_bucket.site',
    }
    blue = next(item for item in expanded_buckets if '"blue"' in item.address)
    green = next(item for item in expanded_buckets if '"green"' in item.address)
    blue_logging = graph.companions(blue, "aws_s3_bucket_logging", "bucket")
    assert len(blue_logging) == 1
    assert blue_logging[0].address.startswith('module.web_many["blue"]')
    assert graph.companions(green, "aws_s3_bucket_logging", "bucket") == []
    findings = scan(resources, configuration)
    assert not any(
        finding.rule_id == "AwsSolutions-S1" and '"blue"' in finding.address for finding in findings
    )
    assert any(
        finding.rule_id == "AwsSolutions-S1"
        and '"green"' in finding.address
        and finding.compliance is Compliance.NON_COMPLIANT
        for finding in findings
    )


def test_computed_unknowns_are_absent_but_configured_unknowns_remain(tmp_path):
    document = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_kms_key.example",
                        "type": "aws_kms_key",
                        "name": "example",
                        "values": {},
                    }
                ]
            }
        },
        "resource_changes": [
            {
                "address": "aws_kms_key.example",
                "change": {"after_unknown": {"policy": True, "enable_key_rotation": True}},
            }
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_kms_key.example",
                        "expressions": {"enable_key_rotation": {"references": ["var.rotation"]}},
                    }
                ]
            }
        },
    }
    resources, _ = load_plan(write_temp(document, tmp_path))
    resource = resources[0]
    assert resource.get("policy") is None
    assert resource.get("enable_key_rotation") is UNKNOWN


def test_real_plan_computed_unknowns_do_not_downgrade_findings():
    resources, configuration = load_plan(
        Path(__file__).parent / "real-terraform" / "real-plan.json"
    )
    findings = scan(resources, configuration)
    queue_findings = {
        finding.rule_id: finding
        for finding in findings
        if finding.address == "aws_sqs_queue.insecure"
    }
    assert {rule_id for rule_id in queue_findings} >= {
        "AwsSolutions-SQS2",
        "AwsSolutions-SQS3",
        "AwsSolutions-SQS4",
    }
    assert all(finding.level == Level.ERROR for finding in queue_findings.values())
    bucket_findings = {
        finding.rule_id: finding
        for finding in findings
        if finding.address == "module.web.aws_s3_bucket.site"
    }
    assert bucket_findings["AwsSolutions-S10"].level == Level.ERROR
    assert "AwsSolutions-S5" not in bucket_findings


def test_reference_normalization_nested_and_data_sources():
    bucket = Resource("module.web.aws_s3_bucket.site", "aws_s3_bucket", "site")
    policy = Resource(
        "module.web.data.aws_iam_policy_document.site",
        "aws_iam_policy_document",
        "site",
        {"json": '{"Statement": []}'},
        mode="data",
    )
    attachment = Resource(
        "module.web.aws_s3_bucket_policy.site",
        "aws_s3_bucket_policy",
        "site",
        {"bucket": bucket.address},
    )
    graph = ResourceGraph(
        [bucket, policy, attachment],
        {
            "root_module": {
                "module_calls": {
                    "web": {
                        "module": {
                            "resources": [
                                {
                                    "address": "aws_s3_bucket_policy.site",
                                    "expressions": {
                                        "bucket": {"references": ["aws_s3_bucket.site.id[0]"]},
                                        "policy": {
                                            "nested": [
                                                {
                                                    "references": [
                                                        "data.aws_iam_policy_document.site.json"
                                                    ]
                                                }
                                            ]
                                        },
                                    },
                                }
                            ]
                        }
                    }
                }
            }
        },
    )
    assert {item.address for item in graph.references(attachment)} == {
        bucket.address,
        policy.address,
    }


def test_data_sources_are_retained_but_not_checked():
    data = Resource(
        "data.aws_security_group.open",
        "aws_security_group",
        "open",
        {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
        mode="data",
    )
    assert scan([data], {}) == []


def test_companion_fallback_requires_exact_identity():
    bucket = Resource("aws_s3_bucket.site", "aws_s3_bucket", "site", {"bucket": "site"})
    wrong = Resource(
        "aws_s3_bucket_logging.site_logs",
        "aws_s3_bucket_logging",
        "site_logs",
        {"bucket": "site_logs"},
    )
    graph = ResourceGraph([bucket, wrong])
    assert graph.companions(bucket, "aws_s3_bucket_logging", "bucket") == []


def test_companion_fallback_is_module_instance_scoped():
    resources = [
        Resource("module.a.aws_s3_bucket.site", "aws_s3_bucket", "site", {"name": "site"}),
        Resource(
            "module.a.aws_s3_bucket_logging.site",
            "aws_s3_bucket_logging",
            "site",
            {"bucket": "site"},
        ),
        Resource("module.b.aws_s3_bucket.site", "aws_s3_bucket", "site", {"name": "site"}),
        Resource(
            "module.b.aws_s3_bucket_logging.site",
            "aws_s3_bucket_logging",
            "site",
            {"bucket": "site"},
        ),
    ]
    graph = ResourceGraph(resources)
    assert [
        item.address for item in graph.companions(resources[0], "aws_s3_bucket_logging", "bucket")
    ] == ["module.a.aws_s3_bucket_logging.site"]
    assert [
        item.address for item in graph.companions(resources[2], "aws_s3_bucket_logging", "bucket")
    ] == ["module.b.aws_s3_bucket_logging.site"]


def test_missing_local_companion_is_not_satisfied_by_sibling_module():
    resources = [
        Resource("module.a.aws_s3_bucket.site", "aws_s3_bucket", "site", {"name": "site"}),
        Resource(
            "module.b.aws_s3_bucket_logging.site",
            "aws_s3_bucket_logging",
            "site",
            {"bucket": "site"},
        ),
    ]
    findings = scan(resources, {})
    assert {
        (finding.rule_id, finding.address, finding.compliance)
        for finding in findings
        if finding.rule_id == "AwsSolutions-S1"
    } == {("AwsSolutions-S1", "module.a.aws_s3_bucket.site", Compliance.NON_COMPLIANT)}


def test_policy_document_identifier_fallback_is_module_scoped():
    resources = [
        Resource("module.a.aws_s3_bucket.site", "aws_s3_bucket", "site", {"name": "site"}),
        Resource(
            "module.a.aws_s3_bucket_policy.site",
            "aws_s3_bucket_policy",
            "site",
            {"bucket": "site", "policy": '{"Statement": []}'},
        ),
        Resource("module.b.aws_s3_bucket.site", "aws_s3_bucket", "site", {"name": "site"}),
        Resource(
            "module.b.aws_s3_bucket_policy.site",
            "aws_s3_bucket_policy",
            "site",
            {"bucket": "site", "policy": '{"Statement": [{"Effect": "Allow"}]}'},
        ),
    ]
    graph = ResourceGraph(resources)
    assert graph.policy_documents_for(resources[0]) == ['{"Statement": []}']
    assert graph.policy_documents_for(resources[2]) == ['{"Statement": [{"Effect": "Allow"}]}']


def test_unknown_policy_changes_finding_level():
    resource = Resource(
        "aws_ebs_volume.unknown",
        "aws_ebs_volume",
        "unknown",
        {},
        unknown_paths={"encrypted"},
    )
    assert not scan([resource], {}, unknown_as="ignore")
    findings = scan([resource], {}, unknown_as="error")
    assert findings[0].level == Level.ERROR


def write_temp(document, directory):
    path = directory / "_temporary.json"
    path.write_text(json.dumps(document))
    return path


def test_graph_edges_and_companion_fallback():
    bucket = Resource("aws_s3_bucket.site", "aws_s3_bucket", "site", {"bucket": "site"})
    logging = Resource(
        "aws_s3_bucket_logging.site",
        "aws_s3_bucket_logging",
        "site",
        {"bucket": "aws_s3_bucket.site"},
    )
    graph = ResourceGraph(
        [bucket, logging],
        {
            "root_module": {
                "resources": [
                    {
                        "address": logging.address,
                        "expressions": {"bucket": {"references": ["aws_s3_bucket.site.id"]}},
                    }
                ]
            }
        },
    )
    assert graph.companions(bucket, "aws_s3_bucket_logging", "bucket") == [logging]


def test_phase_one_registry_and_fixture_findings():
    discover()
    resources, configuration = load_plan(FIXTURES / "minimal-plan.json")
    findings = scan(resources, configuration)
    assert len(INVENTORY) == 131
    assert len(RULES) == 126
    assert status("AwsSolutions-CFR6") == "not-applicable-to-terraform"
    assert all(status(rule_id) != "not-implemented" for rule_id in INVENTORY)
    assert findings


def test_compliant_rule_examples():
    discover()
    compliant = [
        Resource("aws_efs_file_system.good", "aws_efs_file_system", "good", {"encrypted": True}),
        Resource("aws_kms_key.good", "aws_kms_key", "good", {"enable_key_rotation": True}),
        Resource("aws_network_acl.bad", "aws_network_acl", "bad", {}),
    ]
    graph = ResourceGraph(compliant)
    context = type("Context", (), {"graph": graph})()
    assert RULES["AwsSolutions-EFS1"].check(compliant[0], context) == Compliance.COMPLIANT
    assert RULES["AwsSolutions-KMS5"].check(compliant[1], context) == Compliance.COMPLIANT
    assert RULES["AwsSolutions-VPC3"].check(compliant[2], context) == Compliance.NON_COMPLIANT


def test_suppressions_and_expiration(tmp_path):
    path = tmp_path / ".tfnag.yml"
    path.write_text("- rule: AwsSolutions-S1\n  address: aws_s3_bucket.*\n  reason: accepted\n")
    values = load_suppressions(path)
    assert suppression_for(values, "AwsSolutions-S1", "aws_s3_bucket.site") == "accepted"
    expired = [
        {"rule": "AwsSolutions-S1", "address": "*", "reason": "old", "expires": "2000-01-01"}
    ]
    assert suppression_for(expired, "AwsSolutions-S1", "aws_s3_bucket.site") is None


def test_report_formats_and_exit_codes():
    finding = __import__("tfnag.model", fromlist=["Finding"]).Finding(
        "AwsSolutions-S1", Level.ERROR, "aws_s3_bucket.site", "bad", Compliance.NON_COMPLIANT
    )
    assert '"AwsSolutions-S1"' in render([finding], "json")
    sarif = render([finding], "sarif")
    assert '"version": "2.1.0"' in sarif
    assert '"level": "error"' in sarif
    assert '"informationUri"' in sarif
    assert "<testsuite" in render([finding], "junit")
    assert exit_code([finding], "error") == 1
    assert exit_code([finding], "never") == 0


def test_suppressed_sarif_junit_and_json_surfaces():
    finding = __import__("tfnag.model", fromlist=["Finding"]).Finding(
        "AwsSolutions-S1",
        Level.ERROR,
        "aws_s3_bucket.site",
        "bad",
        Compliance.NON_COMPLIANT,
        suppression="accepted centrally",
        suppression_entry=7,
    )
    report = json.loads(render([finding], "json"))[0]
    assert report["suppression"] == "accepted centrally"
    assert report["suppression_entry"] == 7

    sarif = json.loads(render([finding], "sarif"))
    result = sarif["runs"][0]["results"][0]
    assert result["suppressions"] == [{"kind": "external", "justification": "accepted centrally"}]
    assert all("suppressions" in item for item in sarif["runs"][0]["results"])

    junit = fromstring(render([finding], "junit"))
    assert junit.attrib["tests"] == "1"
    assert junit.attrib["failures"] == "0"
    assert junit.find("testcase/skipped").attrib["message"] == "accepted centrally"
    assert junit.find("testcase/failure") is None


def test_expired_suppression_is_warn():
    resources = [
        Resource("aws_efs_file_system.files", "aws_efs_file_system", "files", {"encrypted": False})
    ]
    findings = scan(
        resources,
        {},
        suppressions=[
            {"rule": "AwsSolutions-EFS1", "address": "*", "reason": "old", "expires": "2000-01-01"}
        ],
    )
    assert findings[0].level == Level.WARN


def test_regression_provider_defaults_and_ec26_union():
    discover()
    rds = Resource("aws_db_instance.db", "aws_db_instance", "db", {})
    assert RULES["AwsSolutions-RDS13"].check(rds, type("C", (), {})()) == Compliance.NON_COMPLIANT
    volume = Resource(
        "aws_launch_template.web",
        "aws_launch_template",
        "web",
        {
            "ebs_block_device": [{"encrypted": True}],
            "root_block_device": [{"encrypted": False}],
            "block_device_mappings": [{"ebs": {"encrypted": True}}],
        },
    )
    assert RULES["AwsSolutions-EC26"].check(volume, None) == Compliance.NON_COMPLIANT


def test_l1_accepts_latest_and_preview_runtimes():
    discover()
    rule = RULES["AwsSolutions-L1"]

    def compliance(runtime):
        return rule.check(
            Resource("aws_lambda_function.fn", "aws_lambda_function", "fn", {"runtime": runtime}),
            None,
        )

    for runtime in LATEST_RUNTIMES.values():
        expected = (
            Compliance.NOT_APPLICABLE if runtime.startswith("provided") else Compliance.COMPLIANT
        )
        assert compliance(runtime) == expected
    for runtime in PREVIEW_RUNTIMES:
        assert compliance(runtime) == Compliance.COMPLIANT
    for runtime in ("nodejs22.x", "python3.13", "java21", "dotnet8", "ruby3.3"):
        assert compliance(runtime) == Compliance.NON_COMPLIANT


def test_ec23_reports_standalone_ingress_once():
    group = Resource(
        "aws_security_group.db",
        "aws_security_group",
        "db",
        {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
    )
    ingress = Resource(
        "aws_security_group_rule.db",
        "aws_security_group_rule",
        "db",
        {"cidr_blocks": ["0.0.0.0/0"]},
    )
    findings = scan([group, ingress], {})
    assert [finding.address for finding in findings if finding.rule_id == "AwsSolutions-EC23"] == [
        ingress.address
    ]


def test_secure_transport_unknown_policy_is_unknown():
    discover()
    bucket = Resource("aws_s3_bucket.site", "aws_s3_bucket", "site")
    policy = Resource(
        "aws_s3_bucket_policy.site",
        "aws_s3_bucket_policy",
        "site",
        {},
        unknown_paths={"policy"},
    )
    graph = ResourceGraph(
        [bucket, policy],
        {
            "root_module": {
                "resources": [
                    {
                        "address": policy.address,
                        "expressions": {"bucket": {"references": [bucket.address]}},
                    }
                ]
            }
        },
    )
    context = type("Context", (), {"graph": graph})()
    assert RULES["AwsSolutions-S10"].check(bucket, context) == Compliance.UNKNOWN


def test_secure_transport_matches_case_insensitive_condition_and_arn_pair():
    discover()
    bucket = Resource(
        "aws_s3_bucket.site",
        "aws_s3_bucket",
        "site",
        {"arn": "arn:aws:s3:::site"},
    )
    policy = Resource(
        "aws_s3_bucket_policy.site",
        "aws_s3_bucket_policy",
        "site",
        {
            "policy": {
                "Statement": {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": ["arn:aws:s3:::site", "arn:aws:s3:::site/*"],
                    "Condition": {"Bool": {"AWS:SECURETRANSPORT": "false"}},
                }
            }
        },
    )
    graph = ResourceGraph(
        [bucket, policy],
        {
            "root_module": {
                "resources": [
                    {
                        "address": policy.address,
                        "expressions": {"bucket": {"references": [bucket.address]}},
                    }
                ]
            }
        },
    )
    context = type("Context", (), {"graph": graph})()
    assert RULES["AwsSolutions-S10"].check(bucket, context) == Compliance.COMPLIANT


def test_iam4_and_iam5_attachment_and_policy_sources():
    discover()
    managed = Resource(
        "aws_iam_role_policy_attachment.admin",
        "aws_iam_role_policy_attachment",
        "admin",
        {"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    customer = Resource(
        "aws_iam_role_policy_attachment.custom",
        "aws_iam_role_policy_attachment",
        "custom",
        {"policy_arn": "arn:aws:iam::123456789012:policy/custom"},
    )
    assert RULES["AwsSolutions-IAM4"].check(managed, None) == Compliance.NON_COMPLIANT
    assert RULES["AwsSolutions-IAM4"].check(customer, None) == Compliance.COMPLIANT

    wildcard = Resource(
        "aws_iam_role_policy.open",
        "aws_iam_role_policy",
        "open",
        {"policy": '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'},
    )
    assert RULES["AwsSolutions-IAM5"].check(wildcard, None) == Compliance.NON_COMPLIANT
    unresolved = Resource(
        "aws_iam_role_policy.dynamic",
        "aws_iam_role_policy",
        "dynamic",
        {},
        unknown_paths={"policy"},
    )
    assert RULES["AwsSolutions-IAM5"].check(unresolved, None) == Compliance.UNKNOWN


def test_all_registered_rules_accept_a_minimal_resource():
    discover()
    for rule in RULES.values():
        resource = Resource(
            f"aws_test.{rule.id}",
            rule.resource_types[0],
            rule.id,
            {},
        )
        context = type("Context", (), {"graph": ResourceGraph([resource], {})})()
        result = rule.check(resource, context)
        assert result in (
            Compliance.COMPLIANT,
            Compliance.NON_COMPLIANT,
            Compliance.NOT_APPLICABLE,
            Compliance.UNKNOWN,
        )
