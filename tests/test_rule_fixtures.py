"""Table-driven compliant and non-compliant cases for every rule."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from tfnag.engine import scan
from tfnag.model import Compliance, Resource
from tfnag.registry import RULES, discover


@dataclass(frozen=True)
class Case:
    good: list[Resource]
    bad: list[Resource]
    good_configuration: dict[str, Any] | None = None
    bad_configuration: dict[str, Any] | None = None


def resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    configured_paths: set[str] | None = None,
) -> Resource:
    return Resource(
        address,
        resource_type,
        address.rsplit(".", 1)[-1],
        values,
        configured_paths=configured_paths,
    )


def policy(statement: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [statement]})


def secure_policy(arn: str, service: str) -> str:
    suffix = "/*" if service == "s3" else ""
    return policy(
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": f"{service}:*",
            "Resource": [arn, arn + suffix],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    )


def linked_configuration(source: str, target: str) -> dict[str, Any]:
    return {
        "root_module": {
            "resources": [
                {
                    "address": source,
                    "expressions": {
                        "reference": {"references": [target]},
                    },
                }
            ]
        }
    }


def direct(
    rule_id: str,
    resource_type: str,
    good: dict[str, Any],
    bad: dict[str, Any],
    *,
    good_configured: set[str] | None = None,
    bad_configured: set[str] | None = None,
) -> Case:
    return Case(
        [resource(f"{resource_type}.good", resource_type, good, configured_paths=good_configured)],
        [resource(f"{resource_type}.bad", resource_type, bad, configured_paths=bad_configured)],
    )


ALL_CASES: dict[str, Case] = {
    "AwsSolutions-AEC1": direct(
        "AwsSolutions-AEC1", "aws_elasticache_cluster", {"subnet_group_name": "private"}, {}
    ),
    "AwsSolutions-AEC3": direct(
        "AwsSolutions-AEC3",
        "aws_elasticache_replication_group",
        {"at_rest_encryption_enabled": True, "transit_encryption_enabled": True},
        {"at_rest_encryption_enabled": False, "transit_encryption_enabled": False},
    ),
    "AwsSolutions-AEC4": direct(
        "AwsSolutions-AEC4",
        "aws_elasticache_replication_group",
        {"multi_az_enabled": True},
        {"multi_az_enabled": False},
    ),
    "AwsSolutions-AEC5": direct(
        "AwsSolutions-AEC5",
        "aws_elasticache_cluster",
        {"engine": "redis", "port": 6380},
        {"engine": "redis", "port": 6379},
    ),
    "AwsSolutions-AEC6": direct(
        "AwsSolutions-AEC6", "aws_elasticache_replication_group", {"auth_token": "secret"}, {}
    ),
    "AwsSolutions-APIG1": direct(
        "AwsSolutions-APIG1",
        "aws_api_gateway_stage",
        {"access_log_settings": [{"destination_arn": "arn:aws:logs:x"}]},
        {},
    ),
    "AwsSolutions-APIG2": direct(
        "AwsSolutions-APIG2",
        "aws_api_gateway_request_validator",
        {"validate_request_body": True, "validate_request_parameters": True},
        {"validate_request_body": False, "validate_request_parameters": False},
    ),
    "AwsSolutions-APIG3": direct(
        "AwsSolutions-APIG3",
        "aws_wafv2_web_acl_association",
        {"resource_arn": "arn:aws:apig:x", "web_acl_arn": "arn:aws:wafv2:x"},
        {"resource_arn": "arn:aws:apig:x"},
    ),
    "AwsSolutions-APIG4": direct(
        "AwsSolutions-APIG4",
        "aws_api_gateway_method",
        {"authorization": "COGNITO_USER_POOLS"},
        {"authorization": "NONE"},
    ),
    "AwsSolutions-APIG6": direct(
        "AwsSolutions-APIG6",
        "aws_api_gateway_method_settings",
        {"settings": [{"logging_level": "INFO"}]},
        {"settings": [{"logging_level": "OFF"}]},
    ),
    "AwsSolutions-AS1": direct(
        "AwsSolutions-AS1",
        "aws_autoscaling_group",
        {"default_cooldown": 300},
        {"default_cooldown": 0},
    ),
    "AwsSolutions-AS2": direct(
        "AwsSolutions-AS2",
        "aws_autoscaling_group",
        {"health_check_type": "ELB", "health_check_grace_period": 300},
        {"health_check_type": "EC2", "health_check_grace_period": 0},
    ),
    "AwsSolutions-AS3": direct(
        "AwsSolutions-AS3",
        "aws_autoscaling_notification",
        {
            "notifications": [
                "autoscaling:EC2_INSTANCE_LAUNCH",
                "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
                "autoscaling:EC2_INSTANCE_TERMINATE",
                "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
            ]
        },
        {"notifications": []},
    ),
    "AwsSolutions-ASC3": direct(
        "AwsSolutions-ASC3",
        "aws_appsync_graphql_api",
        {"log_config": [{"cloudwatch_logs_role_arn": "arn:aws:iam::role/log"}]},
        {},
    ),
    "AwsSolutions-C91": direct(
        "AwsSolutions-C91",
        "aws_cloud9_environment_ec2",
        {"connection_type": "CONNECT_SSM"},
        {"connection_type": "CONNECT_SSH"},
    ),
    "AwsSolutions-CB4": direct(
        "AwsSolutions-CB4",
        "aws_codebuild_project",
        {"artifacts": [{"encryption_disabled": False}], "encryption_key": "arn:aws:kms:key"},
        {"artifacts": [{"encryption_disabled": True}], "encryption_key": None},
    ),
    "AwsSolutions-CB5": direct(
        "AwsSolutions-CB5",
        "aws_codebuild_project",
        {"environment": [{"image": "aws/codebuild/standard:7.0"}]},
        {"environment": [{"image": "custom/image"}]},
    ),
    "AwsSolutions-CFR1": direct(
        "AwsSolutions-CFR1",
        "aws_cloudfront_distribution",
        {"restrictions": [{"geo_restriction": [{"restriction_type": "whitelist"}]}]},
        {},
    ),
    "AwsSolutions-CFR2": direct(
        "AwsSolutions-CFR2", "aws_cloudfront_distribution", {"web_acl_id": "arn:aws:wafv2:x"}, {}
    ),
    "AwsSolutions-CFR3": direct(
        "AwsSolutions-CFR3",
        "aws_cloudfront_distribution",
        {"logging_config": [{"bucket": "logs.example"}]},
        {},
    ),
    "AwsSolutions-CFR4": direct(
        "AwsSolutions-CFR4",
        "aws_cloudfront_distribution",
        {"default_cache_behavior": [{"viewer_protocol_policy": "https-only"}]},
        {"default_cache_behavior": [{"viewer_protocol_policy": "allow-all"}]},
    ),
    "AwsSolutions-CFR5": direct(
        "AwsSolutions-CFR5",
        "aws_cloudfront_distribution",
        {
            "origin": [
                {
                    "custom_origin_config": [
                        {
                            "origin_protocol_policy": "https-only",
                            "origin_ssl_protocols": ["TLSv1.2_2021"],
                        }
                    ]
                }
            ]
        },
        {
            "origin": [
                {
                    "custom_origin_config": [
                        {
                            "origin_protocol_policy": "http-only",
                            "origin_ssl_protocols": ["TLSv1"],
                        }
                    ]
                }
            ]
        },
    ),
    "AwsSolutions-CFR7": direct(
        "AwsSolutions-CFR7",
        "aws_cloudfront_distribution",
        {"origin": [{"s3_origin_config": [], "origin_access_control_id": ""}]},
        {"origin": [{"s3_origin_config": [{}], "origin_access_control_id": ""}]},
    ),
    "AwsSolutions-COG1": direct(
        "AwsSolutions-COG1",
        "aws_cognito_user_pool",
        {
            "password_policy": [
                {
                    "minimum_length": 12,
                    "require_lowercase": True,
                    "require_uppercase": True,
                    "require_numbers": True,
                    "require_symbols": True,
                }
            ]
        },
        {"password_policy": [{"minimum_length": 6}]},
    ),
    "AwsSolutions-COG2": direct(
        "AwsSolutions-COG2",
        "aws_cognito_user_pool",
        {"mfa_configuration": "ON"},
        {"mfa_configuration": "OFF"},
    ),
    "AwsSolutions-COG4": direct(
        "AwsSolutions-COG4",
        "aws_api_gateway_method",
        {"http_method": "GET", "authorization": "COGNITO_USER_POOLS"},
        {"http_method": "GET", "authorization": "NONE"},
    ),
    "AwsSolutions-COG7": direct(
        "AwsSolutions-COG7",
        "aws_cognito_identity_pool",
        {"allow_unauthenticated_identities": False},
        {"allow_unauthenticated_identities": True},
    ),
    "AwsSolutions-COG8": direct(
        "AwsSolutions-COG8",
        "aws_cognito_user_pool",
        {"user_pool_add_ons": [{"advanced_security_mode": "ENFORCED"}]},
        {"user_pool_add_ons": [{"advanced_security_mode": "AUDIT"}]},
    ),
    "AwsSolutions-DDB3": direct(
        "AwsSolutions-DDB3",
        "aws_dynamodb_table",
        {"point_in_time_recovery": [{"enabled": True}]},
        {"point_in_time_recovery": [{"enabled": False}]},
    ),
    "AwsSolutions-DDB4": direct(
        "AwsSolutions-DDB4",
        "aws_dax_cluster",
        {"server_side_encryption": [{"enabled": True}]},
        {"server_side_encryption": [{"enabled": False}]},
    ),
    "AwsSolutions-DOC1": direct(
        "AwsSolutions-DOC1",
        "aws_docdb_cluster",
        {"storage_encrypted": True},
        {"storage_encrypted": False},
    ),
    "AwsSolutions-DOC2": direct(
        "AwsSolutions-DOC2", "aws_docdb_cluster", {"port": 27018}, {"port": 27017}
    ),
    "AwsSolutions-DOC3": direct(
        "AwsSolutions-DOC3",
        "aws_docdb_cluster",
        {
            "master_username": "{{resolve:secretsmanager:u:SecretString:u}}",
            "master_password": "{{resolve:secretsmanager:u:SecretString:p}}",
        },
        {"master_username": "admin", "master_password": "password"},
    ),
    "AwsSolutions-DOC4": direct(
        "AwsSolutions-DOC4",
        "aws_docdb_cluster",
        {"backup_retention_period": 7},
        {"backup_retention_period": 1},
    ),
    "AwsSolutions-DOC5": direct(
        "AwsSolutions-DOC5",
        "aws_docdb_cluster",
        {"enabled_cloudwatch_logs_exports": ["audit", "error", "general"]},
        {},
    ),
    "AwsSolutions-EB1": direct(
        "AwsSolutions-EB1",
        "aws_elastic_beanstalk_environment",
        {"setting": [{"namespace": "aws:ec2:vpc", "name": "VPCId", "value": "vpc-1"}]},
        {},
    ),
    "AwsSolutions-EB3": direct(
        "AwsSolutions-EB3",
        "aws_elastic_beanstalk_environment",
        {
            "setting": [
                {
                    "namespace": "aws:elasticbeanstalk:managedactions",
                    "name": "ManagedActionsEnabled",
                    "value": "true",
                }
            ]
        },
        {},
    ),
    "AwsSolutions-EB4": direct(
        "AwsSolutions-EB4",
        "aws_elastic_beanstalk_environment",
        {
            "setting": [
                {
                    "namespace": "aws:elasticbeanstalk:environment:logs",
                    "name": "StreamLogs",
                    "value": "true",
                }
            ]
        },
        {},
    ),
    "AwsSolutions-ECR1": direct(
        "AwsSolutions-ECR1",
        "aws_ecr_repository_policy",
        {"policy": policy({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/x"}})},
        {"policy": policy({"Effect": "Allow", "Principal": "*"})},
    ),
    "AwsSolutions-ECS2": direct(
        "AwsSolutions-ECS2",
        "aws_ecs_task_definition",
        {"container_definitions": json.dumps([{"name": "app"}])},
        {
            "container_definitions": json.dumps(
                [{"name": "app", "environment": [{"name": "X", "value": "1"}]}]
            )
        },
    ),
    "AwsSolutions-ECS4": direct(
        "AwsSolutions-ECS4",
        "aws_ecs_cluster",
        {"setting": [{"name": "containerInsights", "value": "enabled"}]},
        {},
    ),
    "AwsSolutions-ECS7": direct(
        "AwsSolutions-ECS7",
        "aws_ecs_task_definition",
        {"container_definitions": json.dumps([{"logConfiguration": {"logDriver": "awslogs"}}])},
        {"container_definitions": json.dumps([{"name": "app"}])},
    ),
    "AwsSolutions-EFS1": direct(
        "AwsSolutions-EFS1", "aws_efs_file_system", {"encrypted": True}, {"encrypted": False}
    ),
    "AwsSolutions-EKS1": direct(
        "AwsSolutions-EKS1",
        "aws_eks_cluster",
        {"vpc_config": [{"endpoint_public_access": False}]},
        {"vpc_config": [{"endpoint_public_access": True}]},
    ),
    "AwsSolutions-EKS2": direct(
        "AwsSolutions-EKS2",
        "aws_eks_cluster",
        {
            "enabled_cluster_log_types": [
                "api",
                "audit",
                "authenticator",
                "controllerManager",
                "scheduler",
            ]
        },
        {},
    ),
    "AwsSolutions-ELB1": direct(
        "AwsSolutions-ELB1",
        "aws_elb",
        {"listener": [{"lb_protocol": "TCP"}]},
        {"listener": [{"lb_protocol": "HTTP"}]},
    ),
    "AwsSolutions-ELB2": direct(
        "AwsSolutions-ELB2", "aws_elb", {"access_logs": [{"enabled": True}]}, {}
    ),
    "AwsSolutions-ELB3": direct(
        "AwsSolutions-ELB3",
        "aws_elb",
        {"connection_draining": True},
        {"connection_draining": False},
    ),
    "AwsSolutions-ELB4": direct(
        "AwsSolutions-ELB4",
        "aws_elb",
        {"availability_zones": ["a", "b"], "cross_zone_load_balancing": True},
        {"availability_zones": ["a"], "cross_zone_load_balancing": False},
    ),
    "AwsSolutions-ELB5": direct(
        "AwsSolutions-ELB5",
        "aws_elb",
        {"listener": [{"lb_protocol": "HTTPS"}]},
        {"listener": [{"lb_protocol": "HTTP"}]},
    ),
    "AwsSolutions-EMR2": direct(
        "AwsSolutions-EMR2", "aws_emr_cluster", {"log_uri": "s3://logs/"}, {}
    ),
    "AwsSolutions-EMR6": direct(
        "AwsSolutions-EMR6", "aws_emr_cluster", {"ec2_attributes": {"key_name": "key"}}, {}
    ),
    "AwsSolutions-EVB1": direct(
        "AwsSolutions-EVB1",
        "aws_cloudwatch_event_bus_policy",
        {
            "policy": policy(
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "123"},
                    "Action": "events:PutEvents",
                    "Resource": "arn:aws:events:x",
                }
            )
        },
        {
            "policy": policy(
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                }
            )
        },
    ),
    "AwsSolutions-KDA3": direct(
        "AwsSolutions-KDA3",
        "aws_kinesisanalyticsv2_application",
        {
            "application_configuration": {
                "flink_application_configuration": {
                    "checkpoint_configuration": {"configuration_type": "CUSTOM"}
                }
            }
        },
        {},
    ),
    "AwsSolutions-KDF1": direct(
        "AwsSolutions-KDF1",
        "aws_kinesis_firehose_delivery_stream",
        {"server_side_encryption": {"enabled": True}},
        {},
    ),
    "AwsSolutions-KDS1": direct(
        "AwsSolutions-KDS1",
        "aws_kinesis_stream",
        {"encryption_type": "KMS"},
        {"encryption_type": "NONE"},
    ),
    "AwsSolutions-KDS3": direct(
        "AwsSolutions-KDS3",
        "aws_kinesis_stream",
        {"encryption_type": "KMS", "kms_key_id": "arn:aws:kms:key"},
        {"encryption_type": "KMS", "kms_key_id": "alias/aws/kinesis"},
    ),
    "AwsSolutions-KMS5": direct(
        "AwsSolutions-KMS5",
        "aws_kms_key",
        {"enable_key_rotation": True},
        {"enable_key_rotation": False},
    ),
    "AwsSolutions-L1": direct(
        "AwsSolutions-L1",
        "aws_lambda_function",
        {"runtime": "python3.14"},
        {"runtime": "python3.9"},
    ),
    "AwsSolutions-LEX4": direct(
        "AwsSolutions-LEX4",
        "aws_lex_bot_alias",
        {"conversation_logs": [{"kms_key_arn": "arn:aws:kms:key"}]},
        {"conversation_logs": [{"destination": "cloudwatch"}]},
    ),
    "AwsSolutions-MSK2": direct(
        "AwsSolutions-MSK2",
        "aws_msk_cluster",
        {"encryption_info": [{"encryption_in_transit": [{"client_broker": "TLS"}]}]},
        {"encryption_info": [{"encryption_in_transit": [{"client_broker": "PLAINTEXT"}]}]},
    ),
    "AwsSolutions-MSK3": direct(
        "AwsSolutions-MSK3",
        "aws_msk_cluster",
        {"encryption_info": [{"encryption_in_transit": [{"in_cluster": True}]}]},
        {"encryption_info": [{"encryption_in_transit": [{"in_cluster": False}]}]},
    ),
    "AwsSolutions-MSK6": direct(
        "AwsSolutions-MSK6",
        "aws_msk_cluster",
        {"logging_info": [{"broker_logs": {"s3": {"enabled": True}}}]},
        {"logging_info": [{"broker_logs": {"s3": {"enabled": False}}}]},
    ),
    "AwsSolutions-N1": direct(
        "AwsSolutions-N1",
        "aws_neptune_cluster",
        {"neptune_subnet_group_name": "private", "availability_zones": ["a", "b"]},
        {},
    ),
    "AwsSolutions-N2": direct(
        "AwsSolutions-N2",
        "aws_neptune_cluster_instance",
        {"auto_minor_version_upgrade": True},
        {"auto_minor_version_upgrade": False},
    ),
    "AwsSolutions-N3": direct(
        "AwsSolutions-N3",
        "aws_neptune_cluster",
        {"backup_retention_period": 7},
        {"backup_retention_period": 1},
    ),
    "AwsSolutions-N4": direct(
        "AwsSolutions-N4",
        "aws_neptune_cluster",
        {"storage_encrypted": True},
        {"storage_encrypted": False},
    ),
    "AwsSolutions-N5": direct(
        "AwsSolutions-N5",
        "aws_neptune_cluster",
        {"iam_database_authentication_enabled": True},
        {"iam_database_authentication_enabled": False},
    ),
    "AwsSolutions-OS1": direct(
        "AwsSolutions-OS1",
        "aws_opensearch_domain",
        {"vpc_options": {"subnet_ids": ["subnet-1"]}},
        {},
    ),
    "AwsSolutions-OS2": direct(
        "AwsSolutions-OS2",
        "aws_opensearch_domain",
        {"node_to_node_encryption": [{"enabled": True}]},
        {"node_to_node_encryption": [{"enabled": False}]},
    ),
    "AwsSolutions-OS3": direct(
        "AwsSolutions-OS3",
        "aws_opensearch_domain",
        {
            "access_policies": policy(
                {
                    "Effect": "Allow",
                    "Principal": "10.0.0.0/8",
                    "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
                }
            )
        },
        {"access_policies": policy({"Effect": "Allow", "Principal": "*", "Action": "*"})},
    ),
    "AwsSolutions-OS4": direct(
        "AwsSolutions-OS4",
        "aws_opensearch_domain",
        {"cluster_config": [{"dedicated_master_enabled": True}]},
        {},
    ),
    "AwsSolutions-OS5": direct(
        "AwsSolutions-OS5",
        "aws_opensearch_domain",
        {"access_policies": policy({"Effect": "Allow", "Principal": "arn:aws:iam::123:role/x"})},
        {"access_policies": policy({"Effect": "Allow", "Principal": "*"})},
    ),
    "AwsSolutions-OS7": direct(
        "AwsSolutions-OS7",
        "aws_opensearch_domain",
        {"cluster_config": [{"zone_awareness_enabled": True}]},
        {},
    ),
    "AwsSolutions-OS8": direct(
        "AwsSolutions-OS8", "aws_opensearch_domain", {"encrypt_at_rest": [{"enabled": True}]}, {}
    ),
    "AwsSolutions-OS9": direct(
        "AwsSolutions-OS9",
        "aws_opensearch_domain",
        {
            "log_publishing_options": [
                {"log_type": "INDEX_SLOW_LOGS", "cloudwatch_log_group_arn": "arn:logs:i"},
                {"log_type": "SEARCH_SLOW_LOGS", "cloudwatch_log_group_arn": "arn:logs:s"},
            ]
        },
        {},
    ),
    "AwsSolutions-QS1": direct(
        "AwsSolutions-QS1",
        "aws_quicksight_data_source",
        {"ssl_properties": [{"disable_ssl": False}]},
        {"ssl_properties": [{"disable_ssl": True}]},
    ),
    "AwsSolutions-RDS2": direct(
        "AwsSolutions-RDS2",
        "aws_db_instance",
        {"engine": "postgres", "storage_encrypted": True},
        {"engine": "postgres", "storage_encrypted": False},
    ),
    "AwsSolutions-RDS3": direct(
        "AwsSolutions-RDS3",
        "aws_db_instance",
        {"engine": "postgres", "multi_az": True},
        {"engine": "postgres", "multi_az": False},
    ),
    "AwsSolutions-RDS6": direct(
        "AwsSolutions-RDS6",
        "aws_rds_cluster",
        {"engine": "aurora-postgresql", "iam_database_authentication_enabled": True},
        {"engine": "aurora-postgresql", "iam_database_authentication_enabled": False},
    ),
    "AwsSolutions-RDS10": direct(
        "AwsSolutions-RDS10",
        "aws_db_instance",
        {"engine": "postgres", "deletion_protection": True},
        {"engine": "postgres", "deletion_protection": False},
    ),
    "AwsSolutions-RDS11": direct(
        "AwsSolutions-RDS11",
        "aws_db_instance",
        {"engine": "postgres", "port": 5433},
        {"engine": "postgres", "port": 5432},
    ),
    "AwsSolutions-RDS13": direct(
        "AwsSolutions-RDS13",
        "aws_db_instance",
        {"backup_retention_period": 7},
        {"backup_retention_period": 0},
    ),
    "AwsSolutions-RDS14": direct(
        "AwsSolutions-RDS14",
        "aws_rds_cluster",
        {"engine": "aurora-mysql", "backtrack_window": 3600},
        {"engine": "aurora-mysql", "backtrack_window": 0},
    ),
    "AwsSolutions-RDS16": direct(
        "AwsSolutions-RDS16",
        "aws_rds_cluster",
        {
            "engine": "aurora-mysql",
            "engine_mode": "serverless",
            "enabled_cloudwatch_logs_exports": ["audit", "error", "general", "slowquery"],
        },
        {
            "engine": "aurora-mysql",
            "engine_mode": "serverless",
            "enabled_cloudwatch_logs_exports": [],
        },
    ),
    "AwsSolutions-RS2": direct(
        "AwsSolutions-RS2", "aws_redshift_cluster", {"cluster_subnet_group_name": "private"}, {}
    ),
    "AwsSolutions-RS3": direct(
        "AwsSolutions-RS3",
        "aws_redshift_cluster",
        {"master_username": "secure-user"},
        {"master_username": "admin"},
    ),
    "AwsSolutions-RS4": direct(
        "AwsSolutions-RS4", "aws_redshift_cluster", {"port": 5440}, {"port": 5439}
    ),
    "AwsSolutions-RS6": direct(
        "AwsSolutions-RS6", "aws_redshift_cluster", {"encrypted": True}, {"encrypted": False}
    ),
    "AwsSolutions-RS8": direct(
        "AwsSolutions-RS8",
        "aws_redshift_cluster",
        {"publicly_accessible": False},
        {"publicly_accessible": True},
    ),
    "AwsSolutions-RS9": direct(
        "AwsSolutions-RS9",
        "aws_redshift_cluster",
        {"allow_version_upgrade": True},
        {"allow_version_upgrade": False},
    ),
    "AwsSolutions-RS10": direct(
        "AwsSolutions-RS10",
        "aws_redshift_cluster",
        {"automated_snapshot_retention_period": 7},
        {"automated_snapshot_retention_period": 0},
    ),
    "AwsSolutions-S1": direct("AwsSolutions-S1", "aws_s3_bucket", {}, {}, good_configured=set()),
    "AwsSolutions-S2": direct(
        "AwsSolutions-S2",
        "aws_s3_bucket",
        {
            "public_access_block": [
                {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                }
            ]
        },
        {},
    ),
    "AwsSolutions-S5": direct(
        "AwsSolutions-S5",
        "aws_s3_bucket",
        {
            "website": [{"index_document": "index.html"}],
            "policy": policy(
                {
                    "Effect": "Allow",
                    "Principal": {"CanonicalUser": "cloudfront origin access identity E"},
                    "Action": ["s3:GetObject"],
                }
            ),
        },
        {
            "website": [{"index_document": "index.html"}],
            "policy": policy({"Effect": "Allow", "Principal": "*", "Action": "*"}),
        },
        good_configured={"website"},
        bad_configured={"website"},
    ),
    "AwsSolutions-S10": direct(
        "AwsSolutions-S10",
        "aws_s3_bucket",
        {"arn": "arn:aws:s3:::bucket", "policy": secure_policy("arn:aws:s3:::bucket", "s3")},
        {
            "arn": "arn:aws:s3:::bucket",
            "policy": policy({"Effect": "Allow", "Principal": "*", "Action": "*"}),
        },
    ),
    "AwsSolutions-SF1": direct(
        "AwsSolutions-SF1",
        "aws_sfn_state_machine",
        {"logging_configuration": [{"log_destination": "arn:logs"}]},
        {},
    ),
    "AwsSolutions-SF2": direct(
        "AwsSolutions-SF2",
        "aws_sfn_state_machine",
        {"tracing_configuration": [{"enabled": True}]},
        {},
    ),
    "AwsSolutions-SM1": direct(
        "AwsSolutions-SM1",
        "aws_sagemaker_notebook_instance",
        {"subnet_id": "subnet-1", "security_groups": ["sg-1"]},
        {},
    ),
    "AwsSolutions-SM2": direct(
        "AwsSolutions-SM2", "aws_sagemaker_notebook_instance", {"kms_key_id": "arn:kms"}, {}
    ),
    "AwsSolutions-SM3": direct(
        "AwsSolutions-SM3",
        "aws_sagemaker_notebook_instance",
        {"direct_internet_access": "Disabled"},
        {},
    ),
    "AwsSolutions-SNS3": direct(
        "AwsSolutions-SNS3", "aws_sns_topic", {"kms_master_key_id": "arn:kms"}, {}
    ),
    "AwsSolutions-SQS2": direct(
        "AwsSolutions-SQS2", "aws_sqs_queue", {"kms_master_key_id": "arn:kms"}, {}
    ),
    "AwsSolutions-SQS3": direct(
        "AwsSolutions-SQS3",
        "aws_sqs_queue",
        {"redrive_policy": {"dead_letter_target_arn": "arn:aws:sqs:dlq"}},
        {},
    ),
    "AwsSolutions-SQS4": direct(
        "AwsSolutions-SQS4",
        "aws_sqs_queue",
        {"arn": "arn:aws:sqs:queue", "policy": secure_policy("arn:aws:sqs:queue", "sqs")},
        {
            "arn": "arn:aws:sqs:queue",
            "policy": policy({"Effect": "Allow", "Principal": "*", "Action": "*"}),
        },
    ),
    "AwsSolutions-TS3": direct(
        "AwsSolutions-TS3", "aws_timestreamwrite_database", {"kms_key_id": "arn:kms"}, {}
    ),
    "AwsSolutions-VPC3": direct("AwsSolutions-VPC3", "aws_network_acl", {}, {}),
}

ALL_CASES.update(
    {
        "AwsSolutions-S1": direct(
            "AwsSolutions-S1",
            "aws_s3_bucket",
            {"logging": [{"target_bucket": "logs"}]},
            {},
        ),
        "AwsSolutions-EC23": direct(
            "AwsSolutions-EC23",
            "aws_security_group",
            {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
            {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
        ),
        "AwsSolutions-EC26": direct(
            "AwsSolutions-EC26",
            "aws_ebs_volume",
            {"encrypted": True},
            {"encrypted": False},
        ),
        "AwsSolutions-EC27": direct(
            "AwsSolutions-EC27",
            "aws_security_group",
            {"description": "database security group"},
            {},
        ),
        "AwsSolutions-EC28": direct(
            "AwsSolutions-EC28",
            "aws_instance",
            {"monitoring": True},
            {"monitoring": False},
        ),
        "AwsSolutions-EC29": direct(
            "AwsSolutions-EC29",
            "aws_instance",
            {"disable_api_termination": True},
            {"disable_api_termination": False},
        ),
        "AwsSolutions-EMR4": Case(
            [
                resource(
                    "aws_emr_cluster.good",
                    "aws_emr_cluster",
                    {"security_configuration": "secure"},
                ),
                resource(
                    "aws_emr_security_configuration.secure",
                    "aws_emr_security_configuration",
                    {
                        "configuration": json.dumps(
                            {
                                "EnableAtRestEncryption": True,
                                "AtRestEncryptionConfiguration": {
                                    "LocalDiskEncryptionConfiguration": {
                                        "EncryptionKeyProviderType": "AwsKmsKey"
                                    }
                                },
                            }
                        )
                    },
                ),
            ],
            [
                resource(
                    "aws_emr_cluster.bad",
                    "aws_emr_cluster",
                    {"security_configuration": "missing"},
                )
            ],
            linked_configuration("aws_emr_cluster.good", "aws_emr_security_configuration.secure"),
        ),
        "AwsSolutions-EMR5": Case(
            [
                resource(
                    "aws_emr_cluster.good",
                    "aws_emr_cluster",
                    {"security_configuration": "secure"},
                ),
                resource(
                    "aws_emr_security_configuration.secure",
                    "aws_emr_security_configuration",
                    {
                        "configuration": json.dumps(
                            {
                                "EnableInTransitEncryption": True,
                                "InTransitEncryptionConfiguration": {
                                    "TLSCertificateConfiguration": {
                                        "CertificateProviderType": "PEM"
                                    }
                                },
                            }
                        )
                    },
                ),
            ],
            [
                resource(
                    "aws_emr_cluster.bad",
                    "aws_emr_cluster",
                    {"security_configuration": "missing"},
                )
            ],
            linked_configuration("aws_emr_cluster.good", "aws_emr_security_configuration.secure"),
        ),
        "AwsSolutions-GL1": direct(
            "AwsSolutions-GL1",
            "aws_glue_security_configuration",
            {
                "encryption_configuration": json.dumps(
                    {"cloudwatch_encryption": {"kms_key_arn": "arn:kms"}}
                )
            },
            {"encryption_configuration": "{}"},
        ),
        "AwsSolutions-GL3": direct(
            "AwsSolutions-GL3",
            "aws_glue_security_configuration",
            {
                "encryption_configuration": json.dumps(
                    {"job_bookmarks_encryption": {"job_bookmarks_encryption_mode": "CSE-KMS"}}
                )
            },
            {"encryption_configuration": "{}"},
        ),
        "AwsSolutions-IAM4": direct(
            "AwsSolutions-IAM4",
            "aws_iam_role_policy_attachment",
            {"policy_arn": "arn:aws:iam::123:policy/custom"},
            {"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        ),
        "AwsSolutions-IAM5": direct(
            "AwsSolutions-IAM5",
            "aws_iam_role_policy",
            {
                "policy": policy(
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket/object",
                    }
                )
            },
            {"policy": policy({"Effect": "Allow", "Action": "*", "Resource": "*"})},
        ),
        "AwsSolutions-MS3": direct(
            "AwsSolutions-MS3",
            "aws_media_store_container_policy",
            {
                "arn": "arn:aws:mediastore:eu-west-1:123:container/c",
                "policy": secure_policy(
                    "arn:aws:mediastore:eu-west-1:123:container/c", "mediastore"
                ),
            },
            {
                "arn": "arn:aws:mediastore:eu-west-1:123:container/c",
                "policy": policy({"Effect": "Allow", "Principal": "*", "Action": "*"}),
            },
        ),
        "AwsSolutions-MS7": direct(
            "AwsSolutions-MS7",
            "aws_media_store_container_policy",
            {"container_name": "container"},
            {},
        ),
        "AwsSolutions-RDS8": Case(
            [
                resource(
                    "aws_db_instance.good",
                    "aws_db_instance",
                    {"vpc_security_group_ids": ["aws_security_group.good"]},
                ),
                resource(
                    "aws_security_group.good",
                    "aws_security_group",
                    {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
                ),
            ],
            [
                resource(
                    "aws_db_instance.bad",
                    "aws_db_instance",
                    {"vpc_security_group_ids": ["aws_security_group.bad"]},
                ),
                resource(
                    "aws_security_group.bad",
                    "aws_security_group",
                    {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
                ),
            ],
        ),
        "AwsSolutions-RS1": Case(
            [
                resource(
                    "aws_redshift_cluster.good",
                    "aws_redshift_cluster",
                    {"cluster_parameter_group_name": "pg"},
                ),
                resource(
                    "aws_redshift_parameter_group.pg",
                    "aws_redshift_parameter_group",
                    {"parameter": [{"name": "require_ssl", "value": "true"}]},
                ),
            ],
            [
                resource(
                    "aws_redshift_cluster.bad",
                    "aws_redshift_cluster",
                    {"cluster_parameter_group_name": "pg"},
                ),
                resource(
                    "aws_redshift_parameter_group.pg",
                    "aws_redshift_parameter_group",
                    {"parameter": [{"name": "require_ssl", "value": "false"}]},
                ),
            ],
            linked_configuration("aws_redshift_cluster.good", "aws_redshift_parameter_group.pg"),
            linked_configuration("aws_redshift_cluster.bad", "aws_redshift_parameter_group.pg"),
        ),
        "AwsSolutions-RS5": direct(
            "AwsSolutions-RS5",
            "aws_redshift_cluster",
            {"logging": [{"enable": True}]},
            {"logging": [{"enable": False}]},
        ),
        "AwsSolutions-RS11": Case(
            [
                resource(
                    "aws_redshift_cluster.good",
                    "aws_redshift_cluster",
                    {"cluster_parameter_group_name": "pg"},
                ),
                resource(
                    "aws_redshift_parameter_group.pg",
                    "aws_redshift_parameter_group",
                    {"parameter": [{"name": "enable_user_activity_logging", "value": "true"}]},
                ),
            ],
            [
                resource(
                    "aws_redshift_cluster.bad",
                    "aws_redshift_cluster",
                    {"cluster_parameter_group_name": "pg"},
                ),
                resource(
                    "aws_redshift_parameter_group.pg",
                    "aws_redshift_parameter_group",
                    {"parameter": [{"name": "enable_user_activity_logging", "value": "false"}]},
                ),
            ],
            linked_configuration("aws_redshift_cluster.good", "aws_redshift_parameter_group.pg"),
            linked_configuration("aws_redshift_cluster.bad", "aws_redshift_parameter_group.pg"),
        ),
        "AwsSolutions-SMG4": direct(
            "AwsSolutions-SMG4",
            "aws_secretsmanager_secret_rotation",
            {"rotation_lambda_arn": "arn:lambda:rotation"},
            {},
        ),
        "AwsSolutions-VPC3": Case([], [resource("aws_network_acl.bad", "aws_network_acl", {})]),
        "AwsSolutions-VPC7": Case(
            [
                resource("aws_vpc.good", "aws_vpc", {"id": "vpc-good"}),
                resource("aws_flow_log.good", "aws_flow_log", {"vpc_id": "vpc-good"}),
            ],
            [resource("aws_vpc.bad", "aws_vpc", {"id": "vpc-bad"})],
        ),
    }
)


def test_every_implemented_rule_has_compliant_and_non_compliant_cases():
    discover()
    assert set(ALL_CASES) == set(RULES)
    for rule_id, case in ALL_CASES.items():
        good = [
            finding
            for finding in scan(case.good, case.good_configuration or {})
            if finding.rule_id == rule_id
        ]
        bad = [
            finding
            for finding in scan(case.bad, case.bad_configuration or {})
            if finding.rule_id == rule_id
        ]
        assert not good, rule_id
        assert len(bad) == 1, rule_id
        assert bad[0].compliance is Compliance.NON_COMPLIANT, rule_id
