"""Per-service offline acceptance test.

For every ``(service, resource_type)`` pair that has a Terraform spec,
synthesize a realistic IR resource, run it through the real-AWS
pipeline, and invoke ``terraform validate`` on the output. Any spec
that cannot produce a valid Terraform block is a failing acceptance.

This is the gate for "service X is supported end-to-end" — if the
spec validates offline, the only remaining variable between local
validation and real-AWS deployment is AWS-side semantic validation
(IAM permissions, quotas, name collisions), which is covered by the
opt-in ``LOCALEMU_EXPORT_E2E_AWS=1`` suite under
``tests/integration/export_realaws/``.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from localemu.export.formats.tf_specs import TF_SPECS
from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.exporter import RealAwsExporter
from localemu.export.realaws.lambda_code import prepare_lambda_code
from localemu.export.realaws.preflight import AwsCredentials
from localemu.export.realaws.rewrite import rewrite_snapshot
from localemu.export.realaws.secrets import extract_secrets
from localemu.export.references import resolve_references


pytestmark = pytest.mark.skipif(
    shutil.which("terraform") is None, reason="terraform not installed"
)


# Synthetic, minimally-complete attributes for each supported service.
# Each entry must produce a valid aws_* Terraform block after translation.
_FIXTURES: dict[tuple[str, str], dict[str, Any]] = {
    ("s3", "bucket"): {
        "bucket_name": "localemu-coverage-bucket",
        "arn": "arn:aws:s3:::localemu-coverage-bucket",
    },
    ("dynamodb", "table"): {
        "table_name": "localemu_coverage_table",
        "arn": "arn:aws:dynamodb:us-east-1:000000000000:table/localemu_coverage_table",
        "billing_mode": "PAY_PER_REQUEST",
        "key_schema": [{"attribute_name": "id", "key_type": "HASH"}],
        "attribute_definitions": [{"attribute_name": "id", "attribute_type": "S"}],
    },
    ("iam", "role"): {
        "role_name": "localemu-coverage-role",
        "arn": "arn:aws:iam::000000000000:role/localemu-coverage-role",
        "assume_role_policy_document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        },
    },
    ("iam", "policy"): {
        "policy_name": "localemu-coverage-policy",
        "arn": "arn:aws:iam::000000000000:policy/localemu-coverage-policy",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        },
    },
    ("iam", "user"): {
        "user_name": "localemu-coverage-user",
        "arn": "arn:aws:iam::000000000000:user/localemu-coverage-user",
        "path": "/",
    },
    ("iam", "group"): {
        "group_name": "localemu-coverage-group",
        "arn": "arn:aws:iam::000000000000:group/localemu-coverage-group",
        "path": "/",
    },
    ("iam", "instance_profile"): {
        "instance_profile_name": "localemu-coverage-instance-profile",
        "arn": (
            "arn:aws:iam::000000000000:instance-profile/"
            "localemu-coverage-instance-profile"
        ),
        "path": "/",
        # No `role` Ref here; companions hook adds one if needed.
        "roles": ["localemu-coverage-role"],
    },
    ("iam", "oidc_provider"): {
        # Resource id (URL host+path); CFN AWS::IAM::OIDCProvider expects
        # the full URL; aws_iam_openid_connect_provider expects the same.
        "url": "https://token.actions.githubusercontent.com",
        "client_id_list": ["sts.amazonaws.com"],
        "thumbprint_list": [
            "6938fd4d98bab03faadb97b34396831e3780aea1"
        ],
        "arn": (
            "arn:aws:iam::000000000000:oidc-provider/"
            "token.actions.githubusercontent.com"
        ),
    },
    # --- Events extensions ---
    ("events", "archive"): {
        "name": "localemu-coverage-archive",
        "event_source_arn": "arn:aws:events:us-east-1:000000000000:event-bus/default",
    },
    ("events", "connection"): {
        "name": "localemu-coverage-conn",
        "authorization_type": "API_KEY",
    },
    ("events", "api_destination"): {
        "name": "localemu-coverage-apidest",
        "invocation_endpoint": "https://example.com/api",
        "http_method": "POST",
        "connection_arn": "arn:aws:events:us-east-1:000000000000:connection/localemu-coverage-conn/abc",
    },
    # --- Redshift extensions ---
    ("redshift", "parameter_group"): {
        "name": "localemu-coverage-pg",
        "family": "redshift-1.0",
        "description": "coverage",
    },
    # --- EC2 more ---
    ("ec2", "placement_group"): {
        "name": "localemu-coverage-pg",
        "strategy": "cluster",
        "id": "pg-coverage",
    },
    ("ec2", "ebs_snapshot"): {
        "volume_id": "vol-abc",
        "description": "coverage snapshot",
        "id": "snap-coverage",
    },
    # --- KMS alias ---
    ("kms", "alias"): {
        "alias_name": "alias/localemu-coverage",
        "target_key_id": "abc-key-id",
    },
    # --- Events event_bus ---
    ("events", "event_bus"): {
        "name": "localemu-coverage-bus",
    },
    # --- Step Functions activity ---
    ("stepfunctions", "activity"): {
        "name": "localemu-coverage-activity",
    },
    # --- EC2 extensions ---
    ("ec2", "launch_template"): {
        "name": "localemu-coverage-lt",
        "instance_type": "t3.micro",
        "image_id": "ami-12345678",
    },
    ("ec2", "ebs_volume"): {
        "availability_zone": "us-east-1a",
        "size": 20,
        "type": "gp3",
    },
    ("ec2", "flow_log"): {
        "log_destination": "arn:aws:logs:us-east-1:000000000000:log-group:/vpc/flow",
        "log_destination_type": "cloud-watch-logs",
        "traffic_type": "ALL",
        "vpc_id": "vpc-abc",
    },
    # --- EC2 more networking ---
    ("ec2", "transit_gateway"): {
        "description": "coverage tgw",
        "id": "tgw-coverage",
    },
    ("ec2", "transit_gateway_vpc_attachment"): {
        "transit_gateway_id": "tgw-coverage",
        "vpc_id": "vpc-coverage",
        "subnet_ids": ["subnet-coverage"],
        "id": "tgw-attach-coverage",
    },
    ("ec2", "dhcp_options"): {
        "domain_name": "coverage.internal",
        "domain_name_servers": ["AmazonProvidedDNS"],
        "id": "dopt-coverage",
    },
    ("ec2", "network_interface"): {
        "subnet_id": "subnet-coverage",
        "description": "coverage eni",
        "id": "eni-coverage",
    },
    # --- Resource Groups ---
    ("resource_groups", "group"): {
        "name": "localemu-coverage-rg",
    },
    # --- API Gateway v1 extensions ---
    ("apigateway", "resource"): {
        "rest_api_id": "abc123",
        "parent_id": "rootresid",
        "path_part": "items",
    },
    ("apigateway", "method"): {
        "rest_api_id": "abc123",
        "resource_id": "res456",
        "http_method": "GET",
        "authorization": "NONE",
    },
    ("apigateway", "stage"): {
        "rest_api_id": "abc123",
        "stage_name": "prod",
        "deployment_id": "dep789",
    },
    ("apigateway", "authorizer"): {
        "rest_api_id": "abc123",
        "name": "my-auth",
        "type": "TOKEN",
    },
    ("apigateway", "api_key"): {
        "name": "localemu-coverage-key",
        "enabled": True,
    },
    ("apigateway", "usage_plan"): {
        "name": "localemu-coverage-plan",
    },
    ("apigateway", "integration"): {
        "rest_api_id": "abc123",
        "resource_id": "res456",
        "http_method": "POST",
        "type": "AWS_PROXY",
        "integration_http_method": "POST",
        "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:myfn/invocations",
    },
    ("apigateway", "deployment"): {
        "rest_api_id": "abc123",
    },
    ("apigateway", "gateway_response"): {
        "rest_api_id": "abc123",
        "response_type": "DEFAULT_4XX",
    },
    ("apigateway", "model"): {
        "rest_api_id": "abc123",
        "name": "Empty",
        "content_type": "application/json",
        "schema": "{}",
    },
    ("apigateway", "request_validator"): {
        "rest_api_id": "abc123",
        "name": "validate-body",
        "validate_request_body": True,
        "validate_request_parameters": False,
    },
    # --- RDS extensions ---
    ("rds", "db_event_subscription"): {
        "name": "localemu-coverage-dbevt",
        "sns_topic": "arn:aws:sns:us-east-1:000000000000:rds-events",
        "source_type": "db-instance",
    },
    # --- EC2 VPN family ---
    ("ec2", "customer_gateway"): {
        "bgp_asn": "65000",
        "ip_address": "203.0.113.1",
        "type": "ipsec.1",
        "id": "cgw-coverage",
    },
    ("ec2", "vpn_gateway"): {
        "id": "vgw-coverage",
    },
    ("ec2", "vpn_connection"): {
        "customer_gateway_id": "cgw-coverage",
        "vpn_gateway_id": "vgw-coverage",
        "type": "ipsec.1",
        "id": "vpn-coverage",
    },
    ("apigateway", "method_response"): {"rest_api_id": "abc", "resource_id": "res", "http_method": "GET", "status_code": "200"},
    ("apigateway", "integration_response"): {"rest_api_id": "abc", "resource_id": "res", "http_method": "GET", "status_code": "200"},
    ("apigateway", "usage_plan_key"): {"key_id": "key123", "key_type": "API_KEY", "usage_plan_id": "plan123"},
    ("apigateway", "base_path_mapping"): {"api_id": "abc", "domain_name": "api.test", "stage_name": "prod"},
    ("apigateway", "account"): {},
    ("apigatewayv2", "integration_response"): {"api_id": "apigw2-cov", "integration_id": "integ1", "integration_response_key": "/200/"},
    ("apigatewayv2", "route_response"): {"api_id": "apigw2-cov", "route_id": "rt1", "route_response_key": "$default"},
    ("apigatewayv2", "api_mapping"): {"api_id": "apigw2-cov", "domain_name": "api.test", "stage": "$default"},
    ("apigatewayv2", "vpc_link"): {"name": "cov-vpclink", "subnet_ids": ["subnet-a"], "security_group_ids": ["sg-a"]},
    ("apigatewayv2", "model"): {"api_id": "apigw2-cov", "name": "Empty", "content_type": "application/json", "schema": "{}"},
    ("cloudformation", "stack"): {"name": "cov-stack", "template_body": "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Resources\":{}}"},
    ("cloudfront", "origin_access_identity"): {"comment": "coverage OAI"},
    ("cloudfront", "origin_access_control"): {"name": "cov-oac", "origin_access_control_origin_type": "s3", "signing_behavior": "always", "signing_protocol": "sigv4"},
    ("cloudfront", "cache_policy"): {"name": "cov-cache-policy", "default_ttl": 86400, "max_ttl": 31536000, "min_ttl": 0},
    ("cloudfront", "function"): {"name": "cov-fn", "runtime": "cloudfront-js-2.0", "code": "function handler(event){return event.request;}"},
    ("cloudtrail", "event_data_store"): {"name": "cov-eds"},
    ("cloudwatch", "composite_alarm"): {"alarm_name": "cov-composite", "alarm_rule": "ALARM(cov-alarm)"},
    ("logs", "log_stream"): {"name": "cov-stream", "log_group_name": "/cov/logs"},
    ("logs", "resource_policy"): {"policy_name": "cov-policy", "policy_document": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"es.amazonaws.com\"},\"Action\":[\"logs:PutLogEvents\"],\"Resource\":\"*\"}]}"},
    ("logs", "query_definition"): {"name": "cov-query", "query_string": "fields @timestamp | limit 20", "log_group_names": ["/cov/logs"]},
    ("cognito", "resource_server"): {"identifier": "https://api.cov.test", "name": "cov-rs", "user_pool_id": "us-east-1_abc"},
    ("cognito", "identity_pool_roles_attachment"): {"identity_pool_id": "us-east-1:abc", "roles": {"authenticated": "arn:aws:iam::000000000000:role/auth-role"}},
    ("configservice", "delivery_channel"): {"name": "default", "s3_bucket_name": "cov-config-bucket"},
    ("dynamodb", "kinesis_streaming_destination"): {"table_name": "cov-table", "stream_arn": "arn:aws:kinesis:us-east-1:000000000000:stream/cov"},
    ("dynamodb", "contributor_insights"): {"table_name": "cov-table"},
    ("dynamodb", "table_replica"): {"global_table_arn": "arn:aws:dynamodb::000000000000:global-table/cov"},
    ("ec2", "volume_attachment"): {"device_name": "/dev/sdf", "instance_id": "i-abc", "volume_id": "vol-abc", "id": "vol-attach-cov"},
    ("ec2", "vpn_gateway_attachment"): {"vpn_gateway_id": "vgw-cov", "vpc_id": "vpc-cov", "id": "vpn-attach-cov"},
    ("ec2", "vpn_connection_route"): {"destination_cidr_block": "10.0.0.0/8", "vpn_connection_id": "vpn-cov", "id": "vpn-route-cov"},
    ("ec2", "egress_only_internet_gateway"): {"vpc_id": "vpc-cov", "id": "eigw-cov"},
    ("ec2", "dhcp_options_association"): {"dhcp_options_id": "dopt-cov", "vpc_id": "vpc-cov", "id": "dhcp-assoc-cov"},
    ("ec2", "eip_association"): {"allocation_id": "eipalloc-cov", "instance_id": "i-cov", "id": "eip-assoc-cov"},
    ("ec2", "vpc_endpoint_service"): {"acceptance_required": False, "id": "vpce-svc-cov"},
    ("ec2", "ec2_managed_prefix_list"): {"name": "cov-pl", "address_family": "IPv4", "max_entries": 10, "id": "pl-cov"},
    ("ec2", "transit_gateway_route_table"): {"transit_gateway_id": "tgw-cov", "id": "tgw-rtb-cov"},
    ("ec2", "transit_gateway_route"): {"destination_cidr_block": "10.0.0.0/8", "transit_gateway_route_table_id": "tgw-rtb-cov", "transit_gateway_attachment_id": "tgw-attach-cov", "id": "tgw-route-cov"},
    ("ecr", "lifecycle_policy"): {"repository": "cov-repo", "policy": "{\"rules\":[]}"},
    ("ecr", "repository_policy"): {"repository": "cov-repo", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"},
    ("ecs", "capacity_provider"): {"name": "cov-cp"},
    ("eks", "fargate_profile"): {"cluster_name": "cov-eks", "fargate_profile_name": "cov-fp", "pod_execution_role_arn": "arn:aws:iam::000000000000:role/fp-role", "subnet_ids": ["subnet-a"], "selector": [{"namespace": "default"}]},
    ("eks", "addon"): {"cluster_name": "cov-eks", "addon_name": "vpc-cni"},
    ("events", "event_bus_policy"): {"event_bus_name": "cov-bus", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"},
    ("iam", "server_certificate"): {"name": "cov-cert", "certificate_body": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"},
    ("iam", "service_linked_role"): {"aws_service_name": "elasticloadbalancing.amazonaws.com"},
    ("lambda", "alias"): {"name": "live", "function_name": "cov-fn", "function_version": "1"},
    ("lambda", "code_signing_config"): {"description": "cov csc"},
    ("lambda", "layer_version_permission"): {"layer_name": "cov-layer", "version_number": 1, "statement_id": "allow-all", "action": "lambda:GetLayerVersion", "principal": "*"},
    ("rds", "db_proxy"): {"name": "cov-proxy", "engine_family": "MYSQL", "role_arn": "arn:aws:iam::000000000000:role/proxy-role", "vpc_subnet_ids": ["subnet-a"], "auth": [{"auth_scheme": "SECRETS", "secret_arn": "arn:aws:secretsmanager:us-east-1:000000000000:secret:cov"}]},
    ("rds", "global_cluster"): {"global_cluster_identifier": "cov-global", "engine": "aurora-mysql"},
    ("redshift", "event_subscription"): {"name": "cov-evt", "sns_topic_arn": "arn:aws:sns:us-east-1:000000000000:cov-topic"},
    ("s3", "bucket_lifecycle_configuration"): {"bucket": "cov-bucket", "rule": [{"id": "expire", "status": "Enabled", "expiration": [{"days": 90}]}]},
    ("s3", "bucket_cors_configuration"): {"bucket": "cov-bucket", "cors_rule": [{"allowed_methods": ["GET"], "allowed_origins": ["*"]}]},
    ("s3", "bucket_acl"): {"bucket": "cov-bucket", "acl": "private"},
    ("s3", "bucket_ownership_controls"): {"bucket": "cov-bucket", "rule": [{"object_ownership": "BucketOwnerPreferred"}]},
    ("s3", "bucket_public_access_block"): {"bucket": "cov-bucket", "block_public_acls": True, "block_public_policy": True, "ignore_public_acls": True, "restrict_public_buckets": True},
    ("s3", "bucket_server_side_encryption_configuration"): {"bucket": "cov-bucket", "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
    ("s3", "bucket_logging"): {"bucket": "cov-bucket", "target_bucket": "cov-log-bucket", "target_prefix": "logs/"},
    ("s3", "bucket_notification"): {"bucket": "cov-bucket"},
    ("s3", "bucket_website_configuration"): {"bucket": "cov-bucket", "index_document": [{"suffix": "index.html"}]},
    ("ses", "domain_identity"): {"domain": "cov.localemu.test"},
    ("ses", "receipt_filter"): {"name": "cov-filter", "cidr": "10.0.0.0/8", "policy": "Block"},
    ("ses", "receipt_rule"): {"name": "cov-rule", "rule_set_name": "cov-ruleset", "recipients": ["test@cov.test"], "enabled": True, "scan_enabled": True},
    ("sns", "topic_policy"): {"arn": "arn:aws:sns:us-east-1:000000000000:cov-topic", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"},
    ("sns", "platform_application"): {"name": "cov-app", "platform": "GCM", "platform_credential": "REPLACE_ME"},
    ("sqs", "queue_redrive_policy"): {"queue_url": "https://sqs.us-east-1.amazonaws.com/000000000000/cov-queue", "redrive_policy": "{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:cov-dlq\",\"maxReceiveCount\":5}"},
    ("sqs", "queue_redrive_allow_policy"): {"queue_url": "https://sqs.us-east-1.amazonaws.com/000000000000/cov-dlq", "redrive_allow_policy": "{\"redrivePermission\":\"allowAll\"}"},
    ("ssm", "association"): {"name": "AWS-RunShellScript"},
    ("ssm", "maintenance_window"): {"name": "cov-mw", "schedule": "cron(0 2 ? * SUN *)", "duration": 3, "cutoff": 1, "allow_unassociated_targets": False},
    ("ssm", "patch_baseline"): {"name": "cov-pb", "operating_system": "AMAZON_LINUX_2"},
    ("stepfunctions", "alias"): {"name": "live"},
    ("secretsmanager", "secret_rotation"): {"secret_id": "arn:aws:secretsmanager:us-east-1:000000000000:secret:cov", "rotation_lambda_arn": "arn:aws:lambda:us-east-1:000000000000:function:cov-rotator"},
    ("transcribe", "vocabulary"): {"vocabulary_name": "cov-vocab", "language_code": "en-US", "vocabulary_file_uri": "s3://cov-bucket/vocab.txt"},
    ("transcribe", "vocabulary_filter"): {"vocabulary_filter_name": "cov-filter", "language_code": "en-US", "words": ["badword"]},
    ("apigateway", "vpc_link"): {
        "name": "localemu-coverage-vpclink",
        "target_arns": ["arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/net/my-nlb/abc"],
    },
    ("apigateway", "domain_name"): {
        "domain_name": "api.coverage.localemu.test",
        "regional_certificate_arn": "arn:aws:acm:us-east-1:000000000000:certificate/abc",
        "security_policy": "TLS_1_2",
    },
    # --- Cognito identity_pool ---
    ("cognito", "identity_pool"): {
        "identity_pool_name": "localemu_coverage_idpool",
        "allow_unauthenticated_identities": False,
    },
    # --- IAM access_key ---
    ("iam", "access_key"): {
        "user": "localemu-coverage-user",
        "status": "Active",
    },
    # --- CloudWatch extensions ---
    ("cloudwatch", "dashboard"): {
        "dashboard_name": "localemu-coverage-dash",
        "dashboard_body": "{\"widgets\":[]}",
    },
    # --- Logs extensions ---
    ("logs", "metric_filter"): {
        "name": "localemu-coverage-mf",
        "log_group_name": "/coverage/logs",
        "pattern": "[ip, id, user, timestamp, request, status_code, size]",
        "metric_transformation": [{"name": "ErrorCount", "namespace": "Coverage", "value": "1"}],
    },
    ("logs", "subscription_filter"): {
        "name": "localemu-coverage-sf",
        "log_group_name": "/coverage/logs",
        "filter_pattern": "ERROR",
        "destination_arn": "arn:aws:lambda:us-east-1:000000000000:function:log-processor",
    },
    # --- ConfigService ---
    ("configservice", "configuration_recorder"): {
        "name": "default",
        "role_arn": "arn:aws:iam::000000000000:role/config-role",
    },
    ("configservice", "config_rule"): {
        "name": "localemu-coverage-rule",
        "source": [{"owner": "AWS", "source_identifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}],
    },
    # --- SSM document ---
    ("ssm", "document"): {
        "name": "localemu-coverage-doc",
        "document_type": "Command",
        "content": "{\"schemaVersion\":\"2.2\",\"mainSteps\":[{\"action\":\"aws:runShellScript\",\"name\":\"run\",\"inputs\":{\"runCommand\":[\"echo hello\"]}}]}",
        "document_format": "JSON",
    },
    # --- SecretsManager extensions ---
    ("secretsmanager", "secret_policy"): {
        "secret_arn": "arn:aws:secretsmanager:us-east-1:000000000000:secret:mysecret-abc",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}]}",
    },
    # --- DynamoDB global_table ---
    ("dynamodb", "global_table"): {
        "name": "localemu-coverage-global",
        "replica": [{"region_name": "us-east-1"}, {"region_name": "eu-west-1"}],
    },
    # --- SWF ---
    ("swf", "domain"): {
        "name": "localemu-coverage-swf",
        "workflow_execution_retention_period_in_days": "30",
    },
    # --- Kinesis stream_consumer ---
    ("kinesis", "stream_consumer"): {
        "name": "localemu-coverage-consumer",
        "stream_arn": "arn:aws:kinesis:us-east-1:000000000000:stream/mystream",
    },
    # --- API Gateway v2 extensions ---
    ("apigatewayv2", "authorizer"): {
        "api_id": "apigw2-cov",
        "name": "my-auth",
        "authorizer_type": "JWT",
    },
    ("apigatewayv2", "deployment"): {
        "api_id": "apigw2-cov",
        "description": "coverage deploy",
    },
    ("apigatewayv2", "domain_name"): {
        "domain_name": "api.coverage.localemu.test",
    },
    # --- Cognito extensions ---
    ("cognito", "user_pool_domain"): {
        "domain": "localemu-coverage-domain",
        "user_pool_id": "us-east-1_abc",
    },
    ("cognito", "identity_provider"): {
        "user_pool_id": "us-east-1_abc",
        "provider_name": "Google",
        "provider_type": "Google",
        "provider_details": {"client_id": "xxx", "client_secret": "xxx", "authorize_scopes": "openid"},
        "attribute_mapping": {"email": "email"},
    },
    ("cognito", "user_group"): {
        "name": "admins",
        "user_pool_id": "us-east-1_abc",
        "description": "Admin group",
    },
    # --- SES receipt_rule_set ---
    ("ses", "receipt_rule_set"): {
        "rule_set_name": "localemu-coverage-ruleset",
    },
    # --- Route53Resolver ---
    ("route53resolver", "endpoint"): {
        "name": "localemu-coverage-ep",
        "direction": "INBOUND",
        "security_group_ids": ["sg-abc"],
        "ip_address": [{"subnet_id": "subnet-aaa"}, {"subnet_id": "subnet-bbb"}],
        "id": "rslvr-in-coverage",
    },
    ("route53resolver", "rule"): {
        "name": "localemu-coverage-rule",
        "domain_name": "coverage.internal.",
        "rule_type": "FORWARD",
        "target_ip": [{"ip": "10.0.0.1", "port": 53}],
        "id": "rslvr-rr-coverage",
    },
    ("route53resolver", "rule_association"): {
        "name": "localemu-coverage-assoc",
        "resolver_rule_id": "rslvr-rr-coverage",
        "vpc_id": "vpc-coverage",
        "id": "rslvr-rrassoc-coverage",
    },
    # --- Redshift security_group: REMOVED — aws_redshift_security_group is
    # deprecated in the modern AWS TF provider (use VPC security groups).
    # --- CloudFront ---
    ("cloudfront", "distribution"): {
        "distribution_id": "EDFDVBD6EXAMPLE",
        "enabled": True,
        "comment": "coverage",
        "origin": [{"domain_name": "mybucket.s3.amazonaws.com", "origin_id": "myS3Origin"}],
        "default_cache_behavior": [{"target_origin_id": "myS3Origin", "viewer_protocol_policy": "allow-all", "allowed_methods": ["GET", "HEAD"], "cached_methods": ["GET", "HEAD"]}],
        "restrictions": [{"geo_restriction": [{"restriction_type": "none"}]}],
        "viewer_certificate": [{"cloudfront_default_certificate": True}],
    },
    # --- Redshift ---
    ("redshift", "cluster"): {
        "cluster_identifier": "localemu-coverage-rs",
        "node_type": "dc2.large",
        "number_of_nodes": 1,
        "master_username": "admin",
        "master_password": "Passw0rd!",
        "database_name": "dev",
        "cluster_type": "single-node",
        "skip_final_snapshot": True,
    },
    ("redshift", "subnet_group"): {
        "name": "localemu-coverage-rs-sng",
        "subnet_ids": ["subnet-aaa", "subnet-bbb"],
        "description": "coverage",
    },
    # --- S3 extensions ---
    ("s3", "bucket_policy"): {
        "bucket": "localemu-coverage-bucket",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::localemu-coverage-bucket/*\"}]}",
    },
    # --- SQS extensions ---
    ("sqs", "queue_policy"): {
        "queue_url": "https://sqs.us-east-1.amazonaws.com/000000000000/localemu-coverage-queue",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"*\"}]}",
    },
    # --- Lambda extensions ---
    ("lambda", "permission"): {
        "statement_id": "AllowS3Invoke",
        "action": "lambda:InvokeFunction",
        "function_name": "arn:aws:lambda:us-east-1:000000000000:function:myfn",
        "principal": "s3.amazonaws.com",
        "source_arn": "arn:aws:s3:::mybucket",
    },
    ("lambda", "event_source_mapping"): {
        "event_source_arn": "arn:aws:sqs:us-east-1:000000000000:myqueue",
        "function_name": "arn:aws:lambda:us-east-1:000000000000:function:myfn",
        "batch_size": 10,
        "enabled": True,
    },
    ("lambda", "layer_version"): {
        "layer_name": "localemu-coverage-layer",
        "compatible_runtimes": ["python3.11"],
        "description": "coverage layer",
    },
    # --- Lambda function_url ---
    ("lambda", "function_url"): {
        "function_name": "arn:aws:lambda:us-east-1:000000000000:function:myfn",
        "authorization_type": "NONE",
    },
    # --- SNS subscription ---
    ("sns", "subscription"): {
        "topic_arn": "arn:aws:sns:us-east-1:000000000000:mytopic",
        "protocol": "sqs",
        "endpoint": "arn:aws:sqs:us-east-1:000000000000:myqueue",
    },
    # --- OpenSearch ---
    ("opensearch", "domain"): {
        "domain_name": "localemu-coverage-os",
        "engine_version": "OpenSearch_2.11",
        "cluster_config": [{"instance_type": "t3.small.search", "instance_count": 1}],
        "ebs_options": [{"ebs_enabled": True, "volume_size": 10, "volume_type": "gp3"}],
    },
    # --- API Gateway v2 ---
    ("apigatewayv2", "api"): {
        "name": "localemu-coverage-httpapi",
        "protocol_type": "HTTP",
    },
    ("apigatewayv2", "stage"): {
        "name": "$default",
        "api_id": "apigw2-coverage",
        "auto_deploy": True,
    },
    ("apigatewayv2", "route"): {
        "route_key": "GET /hello",
        "api_id": "apigw2-coverage",
    },
    ("apigatewayv2", "integration"): {
        "integration_type": "AWS_PROXY",
        "integration_uri": "arn:aws:lambda:us-east-1:000000000000:function:hello",
        "api_id": "apigw2-coverage",
        "payload_format_version": "2.0",
    },
    # --- Cognito ---
    ("cognito", "user_pool"): {
        "name": "localemu-coverage-pool",
        "arn": "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_abc",
    },
    ("cognito", "user_pool_client"): {
        "name": "localemu-coverage-client",
        "user_pool_id": "us-east-1_abc",
        "explicit_auth_flows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    },
    # --- SES ---
    ("ses", "email_identity"): {
        "email_identity": "test@localemu-coverage.test",
    },
    ("ses", "template"): {
        "name": "localemu-coverage-template",
        "subject": "Hello {{name}}",
        "html": "<h1>Hello {{name}}</h1>",
        "text": "Hello {{name}}",
    },
    ("ses", "configuration_set"): {
        "name": "localemu-coverage-configset",
    },
    # --- CloudTrail ---
    ("cloudtrail", "trail"): {
        "name": "localemu-coverage-trail",
        "s3_bucket_name": "localemu-coverage-trail-bucket",
        "is_multi_region_trail": True,
        "include_global_service_events": True,
        "enable_logging": True,
    },
    # --- Firehose ---
    ("firehose", "delivery_stream"): {
        "name": "localemu-coverage-firehose",
        "arn": "arn:aws:firehose:us-east-1:000000000000:deliverystream/localemu-coverage-firehose",
    },
    # --- Scheduler ---
    ("scheduler", "schedule_group"): {
        "name": "localemu-coverage-group",
    },
    ("scheduler", "schedule"): {
        "name": "localemu-coverage-schedule",
        "schedule_expression": "rate(1 hour)",
        "flexible_time_window": {"mode": "OFF"},
        "target": {"arn": "arn:aws:sqs:us-east-1:000000000000:target-queue", "role_arn": "arn:aws:iam::000000000000:role/sched-role"},
    },
    # --- ECR ---
    ("ecr", "repository"): {
        "name": "localemu-coverage-repo",
        "arn": "arn:aws:ecr:us-east-1:000000000000:repository/localemu-coverage-repo",
        "image_tag_mutability": "MUTABLE",
    },
    # --- ECS ---
    ("ecs", "cluster"): {
        "name": "localemu-coverage-cluster",
        "arn": "arn:aws:ecs:us-east-1:000000000000:cluster/localemu-coverage-cluster",
    },
    ("ecs", "task_definition"): {
        "family": "localemu-coverage-td",
        "arn": "arn:aws:ecs:us-east-1:000000000000:task-definition/localemu-coverage-td:1",
        "network_mode": "awsvpc",
        "requires_compatibilities": ["FARGATE"],
        "cpu": "256",
        "memory": "512",
        "container_definitions": [
            {"name": "app", "image": "nginx:latest", "essential": True, "portMappings": [{"containerPort": 80}]},
        ],
    },
    ("ecs", "service"): {
        "name": "localemu-coverage-svc",
        "arn": "arn:aws:ecs:us-east-1:000000000000:service/localemu-coverage-cluster/localemu-coverage-svc",
        "cluster": "arn:aws:ecs:us-east-1:000000000000:cluster/localemu-coverage-cluster",
        "task_definition": "arn:aws:ecs:us-east-1:000000000000:task-definition/localemu-coverage-td:1",
        "desired_count": 1,
        "launch_type": "FARGATE",
    },
    # --- EKS ---
    ("eks", "cluster"): {
        "name": "localemu-coverage-eks",
        "arn": "arn:aws:eks:us-east-1:000000000000:cluster/localemu-coverage-eks",
        "version": "1.29",
        "role_arn": "arn:aws:iam::000000000000:role/eks-role",
        "vpc_config": [{"subnet_ids": ["subnet-aaa", "subnet-bbb"], "security_group_ids": ["sg-ccc"]}],
    },
    ("eks", "node_group"): {
        "cluster_name": "localemu-coverage-eks",
        "node_group_name": "localemu-coverage-ng",
        "arn": "arn:aws:eks:us-east-1:000000000000:nodegroup/localemu-coverage-eks/localemu-coverage-ng/abc",
        "node_role_arn": "arn:aws:iam::000000000000:role/ng-role",
        "subnet_ids": ["subnet-aaa"],
        "instance_types": ["t3.medium"],
        "scaling_config": [{"desired_size": 2, "min_size": 1, "max_size": 4}],
    },
    # --- Route53 ---
    ("route53", "zone"): {
        "name": "coverage.localemu.test.",
        "comment": "Coverage test",
    },
    ("route53", "record"): {
        "name": "www.coverage.localemu.test.",
        "type": "A",
        "ttl": 300,
        "records": ["10.0.0.1"],
        "zone_id": "Z000COVERAGE",
    },
    ("route53", "health_check"): {
        "health_check_id": "hc-coverage",
        "type": "HTTP",
        "fqdn": "example.com",
        "port": 80,
        "resource_path": "/health",
        "request_interval": 30,
        "failure_threshold": 3,
    },
    # --- ACM ---
    ("acm", "certificate"): {
        "domain_name": "coverage.localemu.test",
        "validation_method": "DNS",
        "arn": "arn:aws:acm:us-east-1:000000000000:certificate/abc",
    },
    # --- IAM SAML (existing) ---
    ("iam", "saml_provider"): {
        "name": "localemu-coverage-saml",
        # AWS rejects SAML metadata under 1000 chars; pad with X509Certificate
        # data (a placeholder is fine — the provider's terraform validate
        # checks length, not signature).
        "saml_metadata_document": (
            "<?xml version=\"1.0\"?><EntityDescriptor "
            "xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
            "entityID=\"urn:example:localemu-coverage\">"
            "<IDPSSODescriptor "
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
            "<KeyDescriptor use=\"signing\"><KeyInfo "
            "xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>"
            "<X509Certificate>" + ("MIIB" + "A" * 1100) + "</X509Certificate>"
            "</X509Data></KeyInfo></KeyDescriptor>"
            "<SingleSignOnService "
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "
            "Location=\"https://example.com/idp/sso\"/>"
            "</IDPSSODescriptor></EntityDescriptor>"
        ),
        "arn": "arn:aws:iam::000000000000:saml-provider/localemu-coverage-saml",
    },
    ("sqs", "queue"): {
        "queue_name": "localemu-coverage-queue",
        "arn": "arn:aws:sqs:us-east-1:000000000000:localemu-coverage-queue",
    },
    ("sns", "topic"): {
        "topic_name": "localemu-coverage-topic",
        "arn": "arn:aws:sns:us-east-1:000000000000:localemu-coverage-topic",
    },
    ("events", "rule"): {
        "rule_name": "localemu-coverage-rule",
        "arn": "arn:aws:events:us-east-1:000000000000:rule/localemu-coverage-rule",
        "schedule_expression": "rate(1 hour)",
    },
    ("logs", "log_group"): {
        "log_group_name": "/localemu/coverage",
        "arn": "arn:aws:logs:us-east-1:000000000000:log-group:/localemu/coverage",
        "retention_in_days": 7,
    },
    ("cloudwatch", "alarm"): {
        "alarm_name": "localemu-coverage-alarm",
        "arn": "arn:aws:cloudwatch:us-east-1:000000000000:alarm:localemu-coverage-alarm",
        "comparison_operator": "GreaterThanThreshold",
        "evaluation_periods": 1,
        "metric_name": "CPUUtilization",
        "namespace": "AWS/EC2",
        "period": 60,
        "statistic": "Average",
        "threshold": 80,
    },
    ("secretsmanager", "secret"): {
        "secret_name": "localemu/coverage",
        "arn": "arn:aws:secretsmanager:us-east-1:000000000000:secret:localemu/coverage",
    },
    ("ssm", "parameter"): {
        "parameter_name": "/localemu/coverage",
        "type": "String",
        "value": "hello",
    },
    ("kms", "key"): {
        "description": "localemu coverage key",
        "arn": "arn:aws:kms:us-east-1:000000000000:key/abc",
    },
    ("apigateway", "rest_api"): {
        "api_name": "localemu-coverage-api",
        "arn": "arn:aws:apigateway:us-east-1::/restapis/abc",
    },
    ("stepfunctions", "state_machine"): {
        "state_machine_name": "localemu-coverage-sm",
        "arn": "arn:aws:states:us-east-1:000000000000:stateMachine:localemu-coverage-sm",
        "role_arn": "arn:aws:iam::000000000000:role/sm-role",
        "definition": {"StartAt": "X", "States": {"X": {"Type": "Succeed"}}},
    },
    ("kinesis", "stream"): {
        "stream_name": "localemu-coverage-stream",
        "arn": "arn:aws:kinesis:us-east-1:000000000000:stream/localemu-coverage-stream",
        "shard_count": 1,
    },
    ("lambda", "function"): {
        "function_name": "localemu-coverage-fn",
        "arn": "arn:aws:lambda:us-east-1:000000000000:function:localemu-coverage-fn",
        "handler": "index.handler",
        "runtime": "python3.11",
        "role": "arn:aws:iam::000000000000:role/fn-role",
        "code_zip": b"PK\x03\x04coverage",
    },
    ("s3", "object"): {
        "bucket": "localemu-coverage-bucket",
        "key": "k",
        "source": "lambda/placeholder.zip",
    },
    # --- EC2 / VPC -----------------------------------------------------
    ("ec2", "vpc"): {
        "id": "vpc-coverage",
        "cidr_block": "10.0.0.0/16",
        "instance_tenancy": "default",
        "enable_dns_support": True,
        "enable_dns_hostnames": False,
    },
    ("ec2", "subnet"): {
        "id": "subnet-coverage",
        "cidr_block": "10.0.1.0/24",
        "availability_zone": "us-east-1a",
        "map_public_ip_on_launch": False,
    },
    ("ec2", "security_group"): {
        "id": "sg-coverage",
        "name": "localemu-coverage-sg",
        "description": "coverage",
    },
    ("ec2", "security_group_rule"): {
        "id": "sgr-coverage",
        "type": "ingress",
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"],
        "security_group_id": "sg-coverage",
    },
    ("ec2", "internet_gateway"): {
        "id": "igw-coverage",
    },
    ("ec2", "nat_gateway"): {
        "id": "nat-coverage",
        "connectivity_type": "public",
    },
    ("ec2", "elastic_ip"): {
        "id": "eipalloc-coverage",
        "allocation_id": "eipalloc-coverage",
        "domain": "vpc",
    },
    ("ec2", "route_table"): {
        "id": "rtb-coverage",
    },
    ("ec2", "route"): {
        "id": "route-coverage",
        "destination_cidr_block": "0.0.0.0/0",
    },
    ("ec2", "route_table_association"): {
        "id": "rtbassoc-coverage",
    },
    ("ec2", "vpc_endpoint"): {
        "id": "vpce-coverage",
        "service_name": "com.amazonaws.us-east-1.s3",
        "vpc_endpoint_type": "Gateway",
    },
    ("ec2", "network_acl"): {
        "id": "acl-coverage",
    },
    ("ec2", "network_acl_rule"): {
        "id": "aclrule-coverage",
        "rule_number": 100,
        "egress": False,
        "protocol": "-1",
        "rule_action": "allow",
        "cidr_block": "0.0.0.0/0",
    },
    ("ec2", "vpc_peering_connection"): {
        "id": "pcx-coverage",
        "auto_accept": True,
    },
    ("ec2", "key_pair"): {
        "key_name": "localemu-coverage-key",
        "public_key": "ssh-rsa AAAAB3NzaC1yc2ELOCALEMU coverage@example",
    },
    # --- RDS -----------------------------------------------------------
    ("rds", "db_instance"): {
        "identifier": "localemu-coverage-db",
        "engine": "mysql",
        "engine_version": "8.0.35",
        "instance_class": "db.t3.micro",
        "allocated_storage": 20,
        "db_name": "mydb",
        "username": "admin",
        "password": "changeme123",
        "port": 3306,
        "publicly_accessible": False,
        "skip_final_snapshot": True,
    },
    ("rds", "db_cluster"): {
        "cluster_identifier": "localemu-coverage-cluster",
        "engine": "aurora-mysql",
        "engine_version": "8.0.mysql_aurora.3.04.0",
        "master_username": "admin",
        "master_password": "changeme123",
        "database_name": "mydb",
        "skip_final_snapshot": True,
    },
    ("rds", "db_subnet_group"): {
        "name": "localemu-coverage-sng",
        "description": "coverage",
    },
    ("rds", "db_parameter_group"): {
        "name": "localemu-coverage-pg",
        "family": "mysql8.0",
        "description": "coverage",
        "parameters": [{"name": "character_set_server", "value": "utf8"}],
    },
    ("rds", "db_cluster_parameter_group"): {
        "name": "localemu-coverage-cpg",
        "family": "aurora-mysql8.0",
        "description": "coverage",
        "parameters": [{"name": "character_set_server", "value": "utf8"}],
    },
    ("rds", "db_option_group"): {
        "name": "localemu-coverage-og",
        "engine_name": "mysql",
        "major_engine_version": "8.0",
        "description": "coverage",
    },
    # --- ELBv2 ---------------------------------------------------------
    ("elbv2", "load_balancer"): {
        "name": "localemu-coverage-lb",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/localemu-coverage-lb/abc",
        "load_balancer_type": "application",
        "internal": False,
    },
    ("elbv2", "target_group"): {
        "name": "localemu-coverage-tg",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/localemu-coverage-tg/abc",
        "port": 80,
        "protocol": "HTTP",
        "target_type": "instance",
        "health_check": {
            "protocol": "HTTP",
            "path": "/health",
            "interval": 30,
            "timeout": 5,
            "healthy_threshold": 3,
            "unhealthy_threshold": 3,
        },
    },
    ("elbv2", "listener"): {
        "arn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/localemu-coverage-lb/abc/def",
        "port": 80,
        "protocol": "HTTP",
    },
    ("elbv2", "listener_rule"): {
        "arn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener-rule/app/localemu-coverage-lb/abc/def/ghi",
        "priority": 10,
    },
    # --- CloudFormation extensions ---
    ("cloudformation", "stack_set"): {
        "name": "cov-stack-set",
        "template_body": "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Resources\":{}}",
    },
    # --- CloudFront extensions (new) ---
    ("cloudfront", "origin_request_policy"): {
        "name": "cov-orp",
    },
    ("cloudfront", "response_headers_policy"): {
        "name": "cov-rhp",
    },
    ("cloudfront", "key_group"): {
        "name": "cov-kg",
        "items": ["K2PLACEHOLDER"],
    },
    ("cloudfront", "public_key"): {
        "name": "cov-pk",
        "encoded_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0PLACEHOLDER\n-----END PUBLIC KEY-----",
    },
    ("cloudfront", "realtime_log_config"): {
        "name": "cov-rtlc",
        "sampling_rate": 100,
        "fields": ["timestamp", "c-ip"],
        "endpoint": [{"stream_type": "Kinesis", "kinesis_stream_config": [{"role_arn": "arn:aws:iam::000000000000:role/cov-role", "stream_arn": "arn:aws:kinesis:us-east-1:000000000000:stream/cov"}]}],
    },
    ("cloudfront", "field_level_encryption_config"): {
        "comment": "cov fle config",
    },
    ("cloudfront", "field_level_encryption_profile"): {
        "name": "cov-fle-profile",
    },
    # --- CloudWatch extensions (new) ---
    ("cloudwatch", "metric_stream"): {
        "name": "cov-metric-stream",
        "firehose_arn": "arn:aws:firehose:us-east-1:000000000000:deliverystream/cov",
        "role_arn": "arn:aws:iam::000000000000:role/cov-role",
        "output_format": "json",
    },
    ("logs", "log_destination"): {
        "name": "cov-log-dest",
        "target_arn": "arn:aws:kinesis:us-east-1:000000000000:stream/cov",
        "role_arn": "arn:aws:iam::000000000000:role/cov-role",
    },
    # --- Cognito extensions (new) ---
    ("cognito", "risk_configuration"): {
        "user_pool_id": "us-east-1_abc",
    },
    ("cognito", "ui_customization"): {
        "user_pool_id": "us-east-1_abc",
        "css": ".logo { display: none; }",
    },
    # --- ConfigService extensions (new) ---
    ("configservice", "aggregate_authorization"): {
        "account_id": "000000000000",
        "region": "us-east-1",
    },
    ("configservice", "configuration_aggregator"): {
        "name": "cov-aggregator",
    },
    ("configservice", "conformance_pack"): {
        "name": "cov-conformance-pack",
        "template_body": "AWSTemplateFormatVersion: '2010-09-09'\nResources: []",
    },
    ("configservice", "organization_conformance_pack"): {
        "name": "cov-org-conformance-pack",
        "template_body": "AWSTemplateFormatVersion: '2010-09-09'\nResources: []",
    },
    ("configservice", "organization_managed_rule"): {
        "name": "cov-org-managed-rule",
        "rule_identifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    },
    ("configservice", "organization_custom_rule"): {
        "name": "cov-org-custom-rule",
        "lambda_function_arn": "arn:aws:lambda:us-east-1:000000000000:function:cov-config",
        "trigger_types": ["ConfigurationItemChangeNotification"],
    },
    ("configservice", "remediation_configuration"): {
        "config_rule_name": "cov-rule",
        "target_type": "SSM_DOCUMENT",
        "target_id": "AWS-PublishSNSNotification",
    },
    ("configservice", "retention_configuration"): {
        "retention_period_in_days": 365,
    },
    # --- EC2 extensions (new) ---
    ("ec2", "ami"): {
        "name": "cov-ami",
        "root_device_name": "/dev/xvda",
        "virtualization_type": "hvm",
        "id": "ami-cov",
    },
    ("ec2", "launch_configuration"): {
        "name": "cov-lc",
        "image_id": "ami-12345678",
        "instance_type": "t3.micro",
        "id": "cov-lc",
    },
    ("ec2", "spot_fleet_request"): {
        "iam_fleet_role": "arn:aws:iam::000000000000:role/fleet-role",
        "target_capacity": 1,
        "id": "sfr-cov",
    },
    ("ec2", "fleet"): {
        "type": "maintain",
        "id": "fleet-cov",
    },
    ("ec2", "capacity_reservation"): {
        "instance_type": "t3.micro",
        "instance_platform": "Linux/UNIX",
        "availability_zone": "us-east-1a",
        "instance_count": 1,
        "id": "cr-cov",
    },
    ("ec2", "dedicated_host"): {
        "instance_type": "m5.large",
        "availability_zone": "us-east-1a",
        "id": "h-cov",
    },
    ("ec2", "transit_gateway_route_table_association"): {
        "transit_gateway_attachment_id": "tgw-attach-cov",
        "transit_gateway_route_table_id": "tgw-rtb-cov",
        "id": "tgw-rtba-cov",
    },
    ("ec2", "transit_gateway_route_table_propagation"): {
        "transit_gateway_attachment_id": "tgw-attach-cov",
        "transit_gateway_route_table_id": "tgw-rtb-cov",
        "id": "tgw-rtbp-cov",
    },
    ("ec2", "transit_gateway_peering_attachment"): {
        "transit_gateway_id": "tgw-cov",
        "peer_transit_gateway_id": "tgw-peer-cov",
        "peer_account_id": "000000000001",
        "peer_region": "eu-west-1",
        "id": "tgw-pcx-cov",
    },
    ("ec2", "network_interface_attachment"): {
        "instance_id": "i-cov",
        "network_interface_id": "eni-cov",
        "device_index": 1,
        "id": "eni-attach-cov",
    },
    ("ec2", "network_acl_association"): {
        "network_acl_id": "acl-cov",
        "subnet_id": "subnet-cov",
        "id": "aclassoc-cov",
    },
    ("ec2", "vpc_endpoint_service_allowed_principal"): {
        "vpc_endpoint_service_id": "vpce-svc-cov",
        "principal_arn": "arn:aws:iam::000000000000:root",
        "id": "vpce-svc-ap-cov",
    },
    ("ec2", "vpc_endpoint_connection_notification"): {
        "vpc_endpoint_service_id": "vpce-svc-cov",
        "connection_notification_arn": "arn:aws:sns:us-east-1:000000000000:cov-topic",
        "connection_events": ["Accept", "Reject"],
        "id": "vpce-nfn-cov",
    },
    ("ec2", "vpc_peering_connection_accepter"): {
        "vpc_peering_connection_id": "pcx-cov",
        "auto_accept": True,
        "id": "pcx-accept-cov",
    },
    ("ec2", "vpc_ipv4_cidr_block_association"): {
        "vpc_id": "vpc-cov",
        "cidr_block": "10.1.0.0/16",
        "id": "vpc-cidr-assoc-cov",
    },
    ("ec2", "vpc_ipv6_cidr_block_association"): {
        "vpc_id": "vpc-cov",
        "ipv6_ipam_pool_id": "ipam-pool-cov",
        "ipv6_netmask_length": 56,
        "id": "vpc-cidr6-assoc-cov",
    },
    ("ec2", "vpc_ipam"): {
        "description": "cov ipam",
        "id": "ipam-cov",
    },
    ("ec2", "vpc_ipam_pool"): {
        "address_family": "ipv4",
        "ipam_scope_id": "ipam-scope-cov",
        "id": "ipam-pool-cov",
    },
    ("ec2", "vpc_ipam_scope"): {
        "ipam_id": "ipam-cov",
        "id": "ipam-scope-cov",
    },
    ("ec2", "ec2_traffic_mirror_filter"): {
        "description": "cov filter",
        "id": "tmf-cov",
    },
    ("ec2", "ec2_traffic_mirror_filter_rule"): {
        "traffic_mirror_filter_id": "tmf-cov",
        "traffic_direction": "ingress",
        "rule_number": 100,
        "rule_action": "accept",
        "destination_cidr_block": "0.0.0.0/0",
        "source_cidr_block": "0.0.0.0/0",
        "id": "tmfr-cov",
    },
    ("ec2", "ec2_traffic_mirror_session"): {
        "traffic_mirror_target_id": "tmt-cov",
        "traffic_mirror_filter_id": "tmf-cov",
        "network_interface_id": "eni-cov",
        "session_number": 1,
        "id": "tms-cov",
    },
    ("ec2", "ec2_traffic_mirror_target"): {
        "network_interface_id": "eni-cov",
        "description": "cov target",
        "id": "tmt-cov",
    },
    # --- ECR extensions (new) ---
    ("ecr", "pull_through_cache_rule"): {
        "ecr_repository_prefix": "ecr-public",
        "upstream_registry_url": "public.ecr.aws",
    },
    ("ecr", "registry_policy"): {
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::000000000000:root\"},\"Action\":[\"ecr:ReplicateImage\"],\"Resource\":[\"arn:aws:ecr:us-east-1:000000000000:repository/*\"]}]}",
    },
    ("ecr", "registry_scanning_configuration"): {
        "scan_type": "ENHANCED",
    },
    ("ecr", "replication_configuration"): {},
    # --- ECS extensions (new) ---
    ("ecs", "cluster_capacity_providers"): {
        "cluster_name": "cov-cluster",
        "capacity_providers": ["FARGATE"],
    },
    ("ecs", "task_set"): {
        "service": "cov-svc",
        "cluster": "cov-cluster",
        "task_definition": "arn:aws:ecs:us-east-1:000000000000:task-definition/cov:1",
    },
    # --- EKS extensions (new) ---
    ("eks", "identity_provider_config"): {
        "cluster_name": "cov-eks",
    },
    ("eks", "access_entry"): {
        "cluster_name": "cov-eks",
        "principal_arn": "arn:aws:iam::000000000000:role/cov-role",
    },
    ("eks", "pod_identity_association"): {
        "cluster_name": "cov-eks",
        "namespace": "default",
        "service_account": "cov-sa",
        "role_arn": "arn:aws:iam::000000000000:role/cov-role",
    },
    # --- OpenSearch extensions (new) ---
    ("opensearch", "package"): {
        "package_name": "cov-pkg",
        "package_type": "TXT-DICTIONARY",
    },
    ("opensearch", "serverless_collection"): {
        "name": "cov-collection",
        "type": "SEARCH",
    },
    ("opensearch", "serverless_security_policy"): {
        "name": "cov-sec-policy",
        "type": "encryption",
        "policy": "{\"Rules\":[{\"ResourceType\":\"collection\",\"Resource\":[\"collection/cov-collection\"]}],\"AWSOwnedKey\":true}",
    },
    ("opensearch", "serverless_access_policy"): {
        "name": "cov-access-policy",
        "type": "data",
        "policy": "[{\"Rules\":[{\"ResourceType\":\"index\",\"Resource\":[\"index/cov-collection/*\"],\"Permission\":[\"aoss:ReadDocument\"]}],\"Principal\":[\"arn:aws:iam::000000000000:root\"]}]",
    },
    ("opensearch", "serverless_vpc_endpoint"): {
        "name": "cov-vpce",
        "vpc_id": "vpc-cov",
        "subnet_ids": ["subnet-cov"],
    },
    ("opensearch", "serverless_lifecycle_policy"): {
        "name": "cov-lifecycle",
        "type": "retention",
        "policy": "{\"Rules\":[{\"ResourceType\":\"index\",\"Resource\":[\"index/cov-collection/*\"],\"MinIndexRetention\":\"81d\"}]}",
    },
    # --- Kinesis extensions (new) ---
    ("kinesis", "analytics_application"): {
        "name": "cov-kda",
    },
    ("kinesis", "analyticsv2_application"): {
        "name": "cov-kdav2",
        "runtime_environment": "FLINK-1_18",
        "service_execution_role": "arn:aws:iam::000000000000:role/cov-role",
    },
    ("kinesis", "video_stream"): {
        "name": "cov-kvs",
        "data_retention_in_hours": 24,
    },
    # --- Lambda extensions (new) ---
    ("lambda", "function_event_invoke_config"): {
        "function_name": "cov-fn",
        "maximum_retry_attempts": 1,
    },
    # --- RDS extensions (new) ---
    ("rds", "db_proxy_target"): {
        "db_proxy_name": "cov-proxy",
        "target_group_name": "default",
        "db_instance_identifier": "cov-db",
    },
    ("rds", "db_proxy_endpoint"): {
        "db_proxy_name": "cov-proxy",
        "db_proxy_endpoint_name": "cov-proxy-ep",
        "vpc_subnet_ids": ["subnet-a"],
    },
    ("rds", "cluster_endpoint"): {
        "cluster_identifier": "cov-cluster",
        "cluster_endpoint_identifier": "cov-ep",
        "custom_endpoint_type": "READER",
    },
    # --- Redshift extensions (new) ---
    ("redshift", "snapshot_schedule"): {
        "identifier": "cov-snap-sched",
        "definitions": ["rate(12 hours)"],
    },
    ("redshift", "authentication_profile"): {
        "authentication_profile_name": "cov-auth-profile",
        "authentication_profile_content": "{\"AllowDBUserOverride\":\"1\"}",
    },
    ("redshift", "endpoint_access"): {
        "endpoint_name": "cov-ep",
        "subnet_group_name": "cov-sg",
        "cluster_identifier": "cov-cluster",
    },
    ("redshift", "scheduled_action"): {
        "name": "cov-sched-action",
        "schedule": "cron(0 0 * * ? *)",
        "iam_role": "arn:aws:iam::000000000000:role/cov-role",
    },
    ("redshift", "serverless_namespace"): {
        "namespace_name": "cov-ns",
    },
    ("redshift", "serverless_workgroup"): {
        "workgroup_name": "cov-wg",
        "namespace_name": "cov-ns",
    },
    # --- Route53 extensions (new) ---
    ("route53", "zone_association"): {
        "zone_id": "Z000COV",
        "vpc_id": "vpc-cov",
    },
    ("route53", "query_log"): {
        "zone_id": "Z000COV",
        "cloudwatch_log_group_arn": "arn:aws:logs:us-east-1:000000000000:log-group:/cov/query-log",
    },
    ("route53", "key_signing_key"): {
        "hosted_zone_id": "Z000COV",
        "key_management_service_arn": "arn:aws:kms:us-east-1:000000000000:key/cov-key",
        "name": "cov-ksk",
    },
    ("route53", "cidr_collection"): {
        "name": "cov-cidr-col",
    },
    # --- Route53 Resolver extensions (new) ---
    ("route53resolver", "query_log_config"): {
        "name": "cov-qlc",
        "destination_arn": "arn:aws:logs:us-east-1:000000000000:log-group:/cov/resolver",
    },
    ("route53resolver", "query_log_config_association"): {
        "resolver_query_log_config_id": "rqlc-cov",
        "resource_id": "vpc-cov",
    },
    ("route53resolver", "dnssec_config"): {
        "resource_id": "vpc-cov",
    },
    ("route53resolver", "firewall_config"): {
        "resource_id": "vpc-cov",
        "firewall_fail_open": "ENABLED",
    },
    ("route53resolver", "firewall_domain_list"): {
        "name": "cov-fdl",
        "domains": ["example.com"],
    },
    ("route53resolver", "firewall_rule_group"): {
        "name": "cov-frg",
    },
    ("route53resolver", "firewall_rule_group_association"): {
        "name": "cov-frga",
        "firewall_rule_group_id": "rslvr-frg-cov",
        "vpc_id": "vpc-cov",
        "priority": 101,
    },
    # --- S3 extensions (new) ---
    ("s3", "directory_bucket"): {
        "bucket": "cov-bucket--use1-az4--x-s3",
    },
    ("s3", "access_point"): {
        "name": "cov-ap",
        "bucket": "cov-bucket",
    },
    # --- S3 Control extensions (new) ---
    ("s3control", "storage_lens_configuration"): {
        "config_id": "cov-storage-lens",
    },
    ("s3control", "multi_region_access_point"): {},
    ("s3control", "multi_region_access_point_policy"): {},
    ("s3control", "object_lambda_access_point"): {
        "name": "cov-olap",
    },
    ("s3control", "object_lambda_access_point_policy"): {
        "name": "cov-olap",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3-object-lambda:GetObject\",\"Resource\":\"*\"}]}",
    },
    ("s3control", "bucket"): {
        "bucket": "cov-outpost-bucket",
        "outpost_id": "op-cov",
    },
    # --- SES extensions (new) ---
    ("ses", "event_destination"): {
        "name": "cov-evt-dest",
        "configuration_set_name": "cov-configset",
        "matching_types": ["send", "bounce"],
    },
    ("ses", "contact_list"): {
        "contact_list_name": "cov-contacts",
    },
    ("ses", "dedicated_ip_pool"): {
        "pool_name": "cov-ip-pool",
    },
    ("ses", "account_vdm_attributes"): {
        "vdm_enabled": "ENABLED",
    },
    # --- SSM extensions (new) ---
    ("ssm", "maintenance_window_target"): {
        "window_id": "mw-cov",
        "resource_type": "INSTANCE",
        "name": "cov-mwt",
    },
    ("ssm", "maintenance_window_task"): {
        "window_id": "mw-cov",
        "task_type": "RUN_COMMAND",
        "task_arn": "AWS-RunShellScript",
        "max_concurrency": "1",
        "max_errors": "1",
        "name": "cov-mwtask",
    },
    ("ssm", "resource_data_sync"): {
        "name": "cov-rds",
    },
    # NOTE: ``stepfunctions.state_machine_version`` is NOT a standalone
    # Terraform resource — the AWS provider exposes versioning via the
    # ``publish`` argument on ``aws_sfn_state_machine`` instead, so there
    # is nothing to validate here. Keep this comment so the absence is
    # deliberate, not a forgotten TODO.
    # --- Events / EventBridge extensions (new) ---
    ("events", "endpoint"): {
        "name": "cov-endpoint",
    },
    # --- Pipes (new) ---
    ("pipes", "pipe"): {
        "name": "cov-pipe",
        "source": "arn:aws:sqs:us-east-1:000000000000:cov-source",
        "target": "arn:aws:sqs:us-east-1:000000000000:cov-target",
        "role_arn": "arn:aws:iam::000000000000:role/cov-pipe-role",
    },
    # --- KMS extensions (new) ---
    ("kms", "replica_key"): {
        "primary_key_arn": "arn:aws:kms:eu-west-1:000000000000:key/mrk-placeholder",
        "description": "cov replica",
    },
    # --- IAM extensions (2026-04-18) ---
    ("iam", "account_alias"): {
        "account_alias": "cov-alias",
    },
    ("iam", "account_password_policy"): {
        "minimum_password_length": 14,
        "require_lowercase_characters": True,
        "require_uppercase_characters": True,
        "require_numbers": True,
        "require_symbols": True,
        "allow_users_to_change_password": True,
        "max_password_age": 90,
        "password_reuse_prevention": 5,
        "hard_expiry": False,
    },
    ("iam", "group_membership"): {
        "name": "cov-membership",
        "users": ["cov-user"],
        "group": "cov-group",
    },
    ("iam", "user_login_profile"): {
        "user": "cov-user",
        "password_length": 20,
        "password_reset_required": True,
    },
    ("iam", "user_ssh_key"): {
        "username": "cov-user",
        "encoding": "SSH",
        "public_key": "ssh-rsa AAAAB3NzaC1yc2ELOCALEMU cov@example",
    },
    ("iam", "virtual_mfa_device"): {
        "virtual_mfa_device_name": "cov-mfa",
        "path": "/",
    },
    ("iam", "signing_certificate"): {
        "user_name": "cov-user",
        "certificate_body": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBLOCALEMUcovplaceholder\n"
            "-----END CERTIFICATE-----"
        ),
        "status": "Active",
    },
    # --- S3 bucket configuration extensions (2026-04-18) ---
    ("s3", "bucket_replication_configuration"): {
        "bucket": "cov-bucket",
    },
    ("s3", "bucket_request_payment_configuration"): {
        "bucket": "cov-bucket",
        "payer": "BucketOwner",
    },
    ("s3", "bucket_object_lock_configuration"): {
        "bucket": "cov-bucket",
    },
    ("s3", "bucket_intelligent_tiering_configuration"): {
        "bucket": "cov-bucket",
        "name": "cov-tiering",
    },
    ("s3", "bucket_inventory"): {
        "bucket": "cov-bucket",
        "name": "cov-inventory",
    },
    ("s3", "bucket_metric"): {
        "bucket": "cov-bucket",
        "name": "cov-metric",
    },
    ("s3", "bucket_analytics_configuration"): {
        "bucket": "cov-bucket",
        "name": "cov-analytics",
    },
    ("s3", "bucket_accelerate_configuration"): {
        "bucket": "cov-bucket",
        "status": "Enabled",
    },
    # --- Route53 extensions (2026-04-18) ---
    ("route53", "vpc_association_authorization"): {
        "zone_id": "Z000COV",
        "vpc_id": "vpc-cov",
    },
    ("route53", "delegation_set"): {
        "reference_name": "cov-delegation-set",
    },
    ("route53", "traffic_policy"): {
        "name": "cov-traffic-policy",
        "comment": "coverage",
        "document": (
            "{\"AWSPolicyFormatVersion\":\"2015-10-01\","
            "\"RecordType\":\"A\","
            "\"Endpoints\":{\"endpoint-start\":{\"Type\":\"value\",\"Value\":\"10.0.0.1\"}},"
            "\"StartEndpoint\":\"endpoint-start\"}"
        ),
    },
    ("route53", "traffic_policy_instance"): {
        "name": "cov.example.com",
        "hosted_zone_id": "Z000COV",
        "traffic_policy_id": "tp-cov-placeholder",
        "traffic_policy_version": 1,
        "ttl": 300,
    },
    ("route53", "hosted_zone_dnssec"): {
        "hosted_zone_id": "Z000COV",
    },
    # --- RDS extensions (2026-04-18) ---
    ("rds", "db_snapshot"): {
        "db_instance_identifier": "cov-db",
        "db_snapshot_identifier": "cov-db-snapshot",
    },
    ("rds", "db_cluster_snapshot"): {
        "db_cluster_identifier": "cov-cluster",
        "db_cluster_snapshot_identifier": "cov-cluster-snapshot",
    },
    ("rds", "db_instance_role_association"): {
        "db_instance_identifier": "cov-db",
        "role_arn": "arn:aws:iam::000000000000:role/cov-db-role",
        "feature_name": "S3_INTEGRATION",
    },
    ("rds", "db_cluster_role_association"): {
        "db_cluster_identifier": "cov-cluster",
        "role_arn": "arn:aws:iam::000000000000:role/cov-cluster-role",
        "feature_name": "S3Export",
    },
    ("rds", "db_cluster_activity_stream"): {
        "resource_arn": "arn:aws:rds:us-east-1:000000000000:cluster:cov-cluster",
        "mode": "async",
        "kms_key_id": "arn:aws:kms:us-east-1:000000000000:key/cov-key",
    },
    # --- KMS extensions (2026-04-18) ---
    ("kms", "grant"): {
        "name": "cov-grant",
        "key_id": "arn:aws:kms:us-east-1:000000000000:key/cov-key",
        "grantee_principal": "arn:aws:iam::000000000000:role/cov-grant-role",
        "operations": ["Encrypt", "Decrypt"],
    },
    ("kms", "key_policy"): {
        "key_id": "arn:aws:kms:us-east-1:000000000000:key/cov-key",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}",
    },
    ("kms", "custom_key_store"): {
        "custom_key_store_name": "cov-cks",
        "cloud_hsm_cluster_id": "cluster-cov",
        "key_store_password": "CovPassword1!",
        "trust_anchor_certificate": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBLOCALEMUcovhsmplaceholder\n"
            "-----END CERTIFICATE-----"
        ),
    },
    ("kms", "external_key"): {
        "description": "cov external key",
        "enabled": True,
    },
    # --- Misc singletons across services (2026-04-18) ---
    ("acm", "certificate_validation"): {
        "certificate_arn": "arn:aws:acm:us-east-1:000000000000:certificate/cov",
        "validation_record_fqdns": ["_abc123.cov.localemu.test"],
    },
    ("secretsmanager", "secret_version"): {
        "secret_id": "arn:aws:secretsmanager:us-east-1:000000000000:secret:cov",
        "secret_string": "REPLACE_ME",
    },
    ("lambda", "provisioned_concurrency_config"): {
        "function_name": "cov-fn",
        "provisioned_concurrent_executions": 1,
        "qualifier": "cov-alias",
    },
    ("dynamodb", "resource_policy"): {
        "resource_arn": "arn:aws:dynamodb:us-east-1:000000000000:table/cov-table",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"dynamodb:GetItem\",\"Resource\":\"*\"}]}",
    },
    ("dynamodb", "tag"): {
        "resource_arn": "arn:aws:dynamodb:us-east-1:000000000000:table/cov-table",
        "key": "Environment",
        "value": "coverage",
    },
    ("ecs", "account_setting_default"): {
        "name": "containerInsights",
        "value": "enabled",
    },
    ("redshift", "logging"): {
        "cluster_identifier": "cov-cluster",
        "log_destination_type": "s3",
        "bucket_name": "cov-redshift-logs",
        "s3_key_prefix": "logs/",
    },
    ("redshift", "snapshot_copy_grant"): {
        "snapshot_copy_grant_name": "cov-copy-grant",
    },
    ("sns", "data_protection_policy"): {
        "arn": "arn:aws:sns:us-east-1:000000000000:cov-topic",
        "policy": "{\"Name\":\"cov-policy\",\"Version\":\"2021-06-01\",\"Statement\":[{\"DataDirection\":\"Inbound\",\"Principal\":[\"*\"],\"DataIdentifier\":[\"arn:aws:dataprotection::aws:data-identifier/EmailAddress\"],\"Operation\":{\"Deny\":{}}}]}",
    },
    ("transcribe", "medical_vocabulary"): {
        "vocabulary_name": "cov-med-vocab",
        "language_code": "en-US",
        "vocabulary_file_uri": "s3://cov-bucket/medical-vocab.txt",
    },
    ("transcribe", "language_model"): {
        "model_name": "cov-lang-model",
        "language_code": "en-US",
        "base_model_name": "NarrowBand",
    },
    ("logs", "destination_policy"): {
        "destination_name": "cov-dest",
        "access_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"logs:PutSubscriptionFilter\",\"Resource\":\"*\"}]}",
    },
    # --- EC2 association extensions (2026-04-18) ---
    ("ec2", "main_route_table_association"): {
        "vpc_id": "vpc-cov",
        "route_table_id": "rtb-cov",
        "id": "rtb-main-assoc-cov",
    },
    # ``ec2.nat_gateway_eip_association`` intentionally absent — see the
    # comment on the same key in ``tf_specs.py``.
    ("ec2", "vpc_endpoint_route_table_association"): {
        "vpc_endpoint_id": "vpce-cov",
        "route_table_id": "rtb-cov",
        "id": "vpce-rtb-assoc-cov",
    },
    ("ec2", "vpc_endpoint_subnet_association"): {
        "vpc_endpoint_id": "vpce-cov",
        "subnet_id": "subnet-cov",
        "id": "vpce-subnet-assoc-cov",
    },
    ("ec2", "vpc_endpoint_security_group_association"): {
        "vpc_endpoint_id": "vpce-cov",
        "security_group_id": "sg-cov",
        "id": "vpce-sg-assoc-cov",
    },
    ("ec2", "vpc_endpoint_connection_accepter"): {
        "vpc_endpoint_service_id": "vpce-svc-cov",
        "vpc_endpoint_id": "vpce-cov",
        "id": "vpce-accept-cov",
    },
    ("ec2", "vpc_peering_connection_options"): {
        "vpc_peering_connection_id": "pcx-cov",
        "id": "pcx-opts-cov",
    },
    ("ec2", "network_interface_sg_attachment"): {
        "security_group_id": "sg-cov",
        "network_interface_id": "eni-cov",
        "id": "eni-sg-attach-cov",
    },
    ("ec2", "ec2_managed_prefix_list_entry"): {
        "prefix_list_id": "pl-cov",
        "cidr": "10.0.0.0/16",
        "description": "cov entry",
        "id": "pl-entry-cov",
    },
    ("ec2", "ebs_snapshot_copy"): {
        "source_snapshot_id": "snap-source-cov",
        "source_region": "us-west-2",
        "description": "cov snapshot copy",
        "id": "snap-copy-cov",
    },
    ("ec2", "ebs_default_kms_key"): {
        "key_arn": "arn:aws:kms:us-east-1:000000000000:key/cov-key",
        "id": "ebs-default-kms-cov",
    },
    ("ec2", "ebs_encryption_by_default"): {
        "enabled": True,
        "id": "ebs-enc-default-cov",
    },
    # --- SES extensions (2026-04-18) ---
    ("ses", "domain_dkim"): {
        "domain": "cov.localemu.test",
    },
    ("ses", "domain_mail_from"): {
        "domain": "cov.localemu.test",
        "mail_from_domain": "bounce.cov.localemu.test",
        "behavior_on_mx_failure": "UseDefaultValue",
    },
    ("ses", "identity_notification_topic"): {
        "identity": "cov.localemu.test",
        "notification_type": "Bounce",
        "topic_arn": "arn:aws:sns:us-east-1:000000000000:cov-ses-topic",
    },
    ("ses", "identity_policy"): {
        "identity": "arn:aws:ses:us-east-1:000000000000:identity/cov.localemu.test",
        "name": "cov-identity-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"ses:SendEmail\",\"Resource\":\"*\"}]}",
    },
    ("ses", "active_receipt_rule_set"): {
        "rule_set_name": "cov-ruleset",
    },
    ("ses", "domain_identity_verification"): {
        "domain": "cov.localemu.test",
    },
    # --- Redshift extensions (2026-04-18) ---
    ("redshift", "snapshot_schedule_association"): {
        "cluster_identifier": "cov-cluster",
        "schedule_identifier": "cov-snap-sched",
    },
    ("redshift", "usage_limit"): {
        "cluster_identifier": "cov-cluster",
        "feature_type": "concurrency-scaling",
        "limit_type": "time",
        "amount": 60,
        "breach_action": "log",
        "period": "monthly",
    },
    ("redshift", "resource_policy"): {
        "resource_arn": "arn:aws:redshift:us-east-1:000000000000:cluster:cov-cluster",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"redshift:DescribeClusters\",\"Resource\":\"*\"}]}",
    },
    ("redshift", "cluster_iam_roles"): {
        "cluster_identifier": "cov-cluster",
        "iam_role_arns": ["arn:aws:iam::000000000000:role/cov-redshift-role"],
    },
    # --- Elasticache (2026-04-19) ---
    ("elasticache", "cluster"): {
        "cluster_id": "cov-cache",
        "engine": "redis",
        "engine_version": "7.1",
        "node_type": "cache.t3.micro",
        "num_cache_nodes": 1,
        "parameter_group_name": "default.redis7",
        "port": 6379,
    },
    ("elasticache", "replication_group"): {
        "replication_group_id": "cov-rg",
        "description": "coverage replication group",
        "engine": "redis",
        "node_type": "cache.t3.micro",
        "num_cache_clusters": 2,
        "automatic_failover_enabled": True,
        "multi_az_enabled": True,
        "port": 6379,
    },
    ("elasticache", "subnet_group"): {
        "name": "cov-subnet-group",
        "description": "coverage subnet group",
        "subnet_ids": ["subnet-a", "subnet-b"],
    },
    ("elasticache", "parameter_group"): {
        "name": "cov-pg",
        "family": "redis7",
        "description": "coverage parameter group",
    },
    ("elasticache", "user"): {
        "user_id": "cov-user",
        "user_name": "covuser",
        "access_string": "on ~* +@all",
        "engine": "REDIS",
        "passwords": ["covpasscovpasscovpasscovpass1234"],
    },
    ("elasticache", "user_group"): {
        "user_group_id": "cov-ug",
        "engine": "REDIS",
        "user_ids": ["default"],
    },
    # --- Backup (2026-04-19) ---
    ("backup", "vault"): {
        "name": "cov-vault",
    },
    ("backup", "plan"): {
        "name": "cov-plan",
    },
    ("backup", "selection"): {
        "name": "cov-selection",
        "plan_id": "cov-plan-id",
        "iam_role_arn": "arn:aws:iam::000000000000:role/cov-backup-role",
        "resources": ["arn:aws:dynamodb:us-east-1:000000000000:table/cov-table"],
    },
    ("backup", "vault_policy"): {
        "backup_vault_name": "cov-vault",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"backup:*\",\"Resource\":\"*\"}]}",
    },
    ("backup", "vault_lock_configuration"): {
        "backup_vault_name": "cov-vault",
        "max_retention_days": 365,
        "min_retention_days": 7,
        "changeable_for_days": 3,
    },
    # --- WAF v2 (2026-04-19) ---
    ("wafv2", "web_acl"): {
        "name": "cov-web-acl",
        "scope": "REGIONAL",
        "description": "coverage web acl",
    },
    ("wafv2", "rule_group"): {
        "name": "cov-rule-group",
        "scope": "REGIONAL",
        "capacity": 10,
    },
    ("wafv2", "ip_set"): {
        "name": "cov-ip-set",
        "scope": "REGIONAL",
        "ip_address_version": "IPV4",
        "addresses": ["10.0.0.0/16"],
    },
    ("wafv2", "regex_pattern_set"): {
        "name": "cov-regex-set",
        "scope": "REGIONAL",
    },
    ("wafv2", "web_acl_association"): {
        "web_acl_arn": "arn:aws:wafv2:us-east-1:000000000000:regional/webacl/cov-web-acl/abcd",
        "resource_arn": "arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/cov-alb/xyz",
    },
    ("wafv2", "web_acl_logging_configuration"): {
        "resource_arn": "arn:aws:wafv2:us-east-1:000000000000:regional/webacl/cov-web-acl/abcd",
    },
    # --- Glue (2026-04-19) ---
    ("glue", "catalog_database"): {
        "name": "cov_db",
        "description": "coverage catalog db",
    },
    ("glue", "catalog_table"): {
        "name": "cov_table",
        "database_name": "cov_db",
        "table_type": "EXTERNAL_TABLE",
    },
    ("glue", "job"): {
        "name": "cov-job",
        "role_arn": "arn:aws:iam::000000000000:role/cov-glue-role",
        "glue_version": "4.0",
        "number_of_workers": 2,
        "worker_type": "G.1X",
    },
    ("glue", "crawler"): {
        "name": "cov-crawler",
        "role": "arn:aws:iam::000000000000:role/cov-glue-role",
        "database_name": "cov_db",
    },
    ("glue", "trigger"): {
        "name": "cov-trigger",
        "type": "SCHEDULED",
        "schedule": "cron(0 12 * * ? *)",
    },
    ("glue", "workflow"): {
        "name": "cov-workflow",
        "description": "coverage workflow",
    },
    # --- AppConfig (2026-04-19) ---
    ("appconfig", "application"): {
        "name": "cov-app",
        "description": "coverage app",
    },
    ("appconfig", "environment"): {
        "name": "cov-env",
        "application_id": "covapp1",
    },
    ("appconfig", "configuration_profile"): {
        "name": "cov-config-profile",
        "application_id": "covapp1",
        "location_uri": "hosted",
    },
    ("appconfig", "deployment_strategy"): {
        "name": "cov-deployment-strategy",
        "deployment_duration_in_minutes": 3,
        "growth_factor": 10,
        "replicate_to": "NONE",
    },
    ("appconfig", "hosted_configuration_version"): {
        "application_id": "covapp1",
        "configuration_profile_id": "covprof",
        "content": "{\"enabled\":true}",
        "content_type": "application/json",
    },
    # --- CodeCommit (2026-04-19) ---
    ("codecommit", "repository"): {
        "repository_name": "cov-repo",
        "description": "coverage repo",
        "default_branch": "main",
    },
    ("codecommit", "approval_rule_template"): {
        "name": "cov-approval-template",
        "content": "{\"Version\":\"2018-11-08\",\"DestinationReferences\":[\"refs/heads/main\"],\"Statements\":[{\"Type\":\"Approvers\",\"NumberOfApprovalsNeeded\":1}]}",
        "description": "coverage approval template",
    },
    # --- CodeBuild (2026-04-19) ---
    ("codebuild", "project"): {
        "name": "cov-cb-project",
        "service_role": "arn:aws:iam::000000000000:role/cov-codebuild-role",
        "description": "coverage codebuild project",
    },
    ("codebuild", "webhook"): {
        "project_name": "cov-cb-project",
        "branch_filter": "main",
    },
    ("codebuild", "report_group"): {
        "name": "cov-cb-report-group",
        "type": "TEST",
    },
    ("codebuild", "source_credential"): {
        "auth_type": "PERSONAL_ACCESS_TOKEN",
        "server_type": "GITHUB",
        "token": "cov-replace-me-token",
    },
    # --- CodePipeline (2026-04-19) ---
    ("codepipeline", "codepipeline"): {
        "name": "cov-pipeline",
        "role_arn": "arn:aws:iam::000000000000:role/cov-pipeline-role",
    },
    ("codepipeline", "webhook"): {
        "name": "cov-webhook",
        "authentication": "GITHUB_HMAC",
        "target_action": "Source",
        "target_pipeline": "cov-pipeline",
        "filter": [{"json_path": "$.ref", "match_equals": "refs/heads/{Branch}"}],
        "authentication_configuration": [{"secret_token": "cov-webhook-secret-token"}],
    },
    ("codepipeline", "custom_action_type"): {
        "category": "Build",
        "provider_name": "CovProvider",
        "version": "1",
        "input_artifact_details": [{"maximum_count": 1, "minimum_count": 0}],
        "output_artifact_details": [{"maximum_count": 1, "minimum_count": 0}],
    },
    # --- CodeDeploy (2026-04-19) ---
    ("codedeploy", "app"): {
        "name": "cov-cd-app",
        "compute_platform": "Server",
    },
    ("codedeploy", "deployment_group"): {
        "app_name": "cov-cd-app",
        "deployment_group_name": "cov-cd-group",
        "service_role_arn": "arn:aws:iam::000000000000:role/cov-codedeploy-role",
        "deployment_config_name": "CodeDeployDefault.AllAtOnce",
    },
    ("codedeploy", "deployment_config"): {
        "deployment_config_name": "cov-cd-config",
        "compute_platform": "Server",
    },
    # --- IoT Core (2026-04-19) ---
    ("iot", "thing"): {
        "name": "cov-thing",
        "attributes": {"env": "coverage"},
    },
    ("iot", "thing_type"): {
        "name": "cov-thing-type",
    },
    ("iot", "thing_group"): {
        "name": "cov-thing-group",
    },
    ("iot", "policy"): {
        "name": "cov-iot-policy",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iot:Connect\",\"Resource\":\"*\"}]}",
    },
    ("iot", "topic_rule"): {
        "name": "cov_iot_rule",
    },
    ("iot", "role_alias"): {
        "alias": "cov-iot-alias",
        "role_arn": "arn:aws:iam::000000000000:role/cov-iot-role",
        "credential_duration": 3600,
    },
    # --- Organizations (2026-04-19) ---
    ("organizations", "organization"): {
        "feature_set": "ALL",
        "aws_service_access_principals": ["cloudtrail.amazonaws.com"],
    },
    ("organizations", "account"): {
        "name": "cov-account",
        "email": "cov+sub@example.test",
    },
    ("organizations", "organizational_unit"): {
        "name": "cov-ou",
        "parent_id": "r-cov1",
    },
    ("organizations", "policy"): {
        "name": "cov-org-policy",
        "content": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowAll\",\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
        "type": "SERVICE_CONTROL_POLICY",
    },
    ("organizations", "policy_attachment"): {
        "policy_id": "p-cov",
        "target_id": "ou-cov",
    },
    # --- MSK / Kafka (2026-04-19) ---
    ("kafka", "cluster"): {
        "cluster_name": "cov-msk",
        "kafka_version": "3.5.1",
        "number_of_broker_nodes": 2,
    },
    ("kafka", "configuration"): {
        "name": "cov-msk-config",
        "kafka_versions": ["3.5.1"],
        "server_properties": "auto.create.topics.enable=true\ndelete.topic.enable=true",
    },
    ("kafka", "scram_secret_association"): {
        "cluster_arn": "arn:aws:kafka:us-east-1:000000000000:cluster/cov-msk/abc",
        "secret_arn_list": ["arn:aws:secretsmanager:us-east-1:000000000000:secret:AmazonMSK_cov"],
    },
    ("kafka", "serverless_cluster"): {
        "cluster_name": "cov-msk-serverless",
    },
    # --- Neptune (2026-04-19) ---
    ("neptune", "cluster"): {
        "cluster_identifier": "cov-neptune",
        "engine": "neptune",
        "skip_final_snapshot": True,
    },
    ("neptune", "cluster_instance"): {
        "cluster_identifier": "cov-neptune",
        "instance_class": "db.t3.medium",
    },
    ("neptune", "cluster_parameter_group"): {
        "name": "cov-neptune-cpg",
        "family": "neptune1.3",
        "description": "coverage cluster param group",
    },
    ("neptune", "parameter_group"): {
        "name": "cov-neptune-pg",
        "family": "neptune1.3",
        "description": "coverage instance param group",
    },
    ("neptune", "subnet_group"): {
        "name": "cov-neptune-sng",
        "description": "coverage neptune subnet group",
        "subnet_ids": ["subnet-a", "subnet-b"],
    },
    # --- MQ (2026-04-19) ---
    ("mq", "broker"): {
        "broker_name": "cov-mq-broker",
        "engine_type": "ActiveMQ",
        "engine_version": "5.17.6",
        "host_instance_type": "mq.t3.micro",
        "deployment_mode": "SINGLE_INSTANCE",
        "publicly_accessible": False,
    },
    ("mq", "configuration"): {
        "name": "cov-mq-config",
        "engine_type": "ActiveMQ",
        "engine_version": "5.17.6",
        "data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<broker/>",
    },
    # --- Batch (2026-04-19) ---
    ("batch", "compute_environment"): {
        "name": "cov-batch-ce",
        "service_role": "arn:aws:iam::000000000000:role/cov-batch-service-role",
        "type": "MANAGED",
        "state": "ENABLED",
    },
    ("batch", "job_queue"): {
        "name": "cov-batch-queue",
        "state": "ENABLED",
        "priority": 1,
    },
    ("batch", "job_definition"): {
        "name": "cov-batch-jobdef",
        "type": "container",
        "container_properties": "{\"image\":\"busybox\",\"resourceRequirements\":[{\"type\":\"VCPU\",\"value\":\"0.25\"},{\"type\":\"MEMORY\",\"value\":\"512\"}]}",
    },
    ("batch", "scheduling_policy"): {
        "name": "cov-batch-scheduling-policy",
    },
    # --- EMR (2026-04-19) ---
    ("emr", "cluster"): {
        "name": "cov-emr-cluster",
        "release_label": "emr-6.15.0",
        "service_role": "arn:aws:iam::000000000000:role/cov-emr-service-role",
        "applications": ["Spark"],
        "ec2_attributes": [{
            "subnet_id": "subnet-a",
            "instance_profile": "arn:aws:iam::000000000000:instance-profile/cov-emr-ec2-profile",
            "emr_managed_master_security_group": "sg-master",
            "emr_managed_slave_security_group": "sg-slave",
        }],
        "master_instance_group": [{"instance_type": "m5.xlarge"}],
        "core_instance_group": [{"instance_type": "m5.xlarge", "instance_count": 1}],
    },
    ("emr", "security_configuration"): {
        "name": "cov-emr-sec-config",
        "configuration": "{\"EncryptionConfiguration\":{\"EnableInTransitEncryption\":false,\"EnableAtRestEncryption\":false}}",
    },
    ("emr", "managed_scaling_policy"): {
        "cluster_id": "j-COVCLUSTER",
        "compute_limits": [{
            "unit_type": "Instances",
            "minimum_capacity_units": 1,
            "maximum_capacity_units": 5,
        }],
    },
    # --- Timestream Write (2026-04-19) ---
    ("timestream-write", "database"): {
        "database_name": "cov_timestream_db",
    },
    ("timestream-write", "table"): {
        "database_name": "cov_timestream_db",
        "table_name": "cov_timestream_table",
    },
    # --- GuardDuty (2026-04-19) ---
    ("guardduty", "detector"): {
        "enable": True,
        "finding_publishing_frequency": "SIX_HOURS",
    },
    ("guardduty", "filter"): {
        "name": "cov-gd-filter",
        "detector_id": "abcd1234abcd1234abcd1234abcd1234",
        "action": "ARCHIVE",
        "rank": 1,
        "finding_criteria": [{"criterion": [{"field": "severity", "greater_than_or_equal": "5"}]}],
    },
    ("guardduty", "ipset"): {
        "name": "cov-gd-ipset",
        "detector_id": "abcd1234abcd1234abcd1234abcd1234",
        "format": "TXT",
        "location": "https://s3.amazonaws.com/cov-bucket/ipset.txt",
        "activate": True,
    },
    ("guardduty", "threatintelset"): {
        "name": "cov-gd-threat",
        "detector_id": "abcd1234abcd1234abcd1234abcd1234",
        "format": "TXT",
        "location": "https://s3.amazonaws.com/cov-bucket/threats.txt",
        "activate": True,
    },
    ("guardduty", "member"): {
        "account_id": "111111111111",
        "detector_id": "abcd1234abcd1234abcd1234abcd1234",
        "email": "cov-member@example.test",
    },
    ("guardduty", "organization_admin_account"): {
        "admin_account_id": "111111111111",
    },
    # --- Lake Formation (2026-04-19) ---
    ("lakeformation", "data_lake_settings"): {
        "admins": ["arn:aws:iam::000000000000:user/admin"],
    },
    ("lakeformation", "permissions"): {
        "principal": "arn:aws:iam::000000000000:role/cov-lf-role",
        "permissions": ["SELECT"],
        "table": [{"database_name": "cov_db", "name": "cov_table"}],
    },
    ("lakeformation", "resource"): {
        "arn": "arn:aws:s3:::cov-lake-bucket",
        "use_service_linked_role": True,
    },
    ("lakeformation", "lf_tag"): {
        "key": "CoverageTag",
        "values": ["public", "private"],
    },
    # --- DMS (2026-04-19) ---
    ("dms", "replication_instance"): {
        "replication_instance_id": "cov-dms-ri",
        "replication_instance_class": "dms.t3.micro",
        "allocated_storage": 20,
    },
    ("dms", "replication_subnet_group"): {
        "replication_subnet_group_id": "cov-dms-sng",
        "replication_subnet_group_description": "coverage dms subnet group",
        "subnet_ids": ["subnet-a", "subnet-b"],
    },
    ("dms", "endpoint"): {
        "endpoint_id": "cov-dms-endpoint",
        "endpoint_type": "source",
        "engine_name": "mysql",
        "database_name": "covdb",
        "server_name": "cov-db.internal",
        "port": 3306,
        "username": "covuser",
        "password": "CovPassword1!",
    },
    ("dms", "replication_task"): {
        "replication_task_id": "cov-dms-task",
        "migration_type": "full-load",
        "replication_instance_arn": "arn:aws:dms:us-east-1:000000000000:rep:cov-ri",
        "source_endpoint_arn": "arn:aws:dms:us-east-1:000000000000:endpoint:cov-src",
        "target_endpoint_arn": "arn:aws:dms:us-east-1:000000000000:endpoint:cov-tgt",
        "table_mappings": "{\"rules\":[{\"rule-type\":\"selection\",\"rule-id\":\"1\",\"rule-name\":\"1\",\"object-locator\":{\"schema-name\":\"%\",\"table-name\":\"%\"},\"rule-action\":\"include\"}]}",
    },
    ("dms", "event_subscription"): {
        "name": "cov-dms-events",
        "sns_topic_arn": "arn:aws:sns:us-east-1:000000000000:cov-dms-topic",
        "source_type": "replication-instance",
        "event_categories": ["creation"],
        "enabled": True,
    },
    # --- SageMaker (2026-04-19) ---
    ("sagemaker", "endpoint"): {
        "name": "cov-sm-endpoint",
        "endpoint_config_name": "cov-sm-endpoint-config",
    },
    ("sagemaker", "endpoint_configuration"): {
        "name": "cov-sm-endpoint-config",
    },
    ("sagemaker", "model"): {
        "name": "cov-sm-model",
        "execution_role_arn": "arn:aws:iam::000000000000:role/cov-sagemaker-role",
    },
    ("sagemaker", "notebook_instance"): {
        "name": "cov-sm-notebook",
        "role_arn": "arn:aws:iam::000000000000:role/cov-sagemaker-role",
        "instance_type": "ml.t3.medium",
    },
    ("sagemaker", "feature_group"): {
        "feature_group_name": "cov-sm-feature-group",
        "record_identifier_feature_name": "cov_id",
        "event_time_feature_name": "cov_event_time",
        "role_arn": "arn:aws:iam::000000000000:role/cov-sagemaker-role",
    },
    ("sagemaker", "domain"): {
        "domain_name": "cov-sm-domain",
        "auth_mode": "IAM",
        "vpc_id": "vpc-cov",
        "subnet_ids": ["subnet-a"],
    },
    # --- Inspector v2 (2026-04-19) ---
    ("inspector2", "enabler"): {
        "account_ids": ["000000000000"],
        "resource_types": ["EC2"],
    },
    ("inspector2", "delegated_admin_account"): {
        "account_id": "111111111111",
    },
    ("inspector2", "organization_configuration"): {
        "auto_enable": [{"ec2": True, "ecr": False, "lambda": False}],
    },
    ("inspector2", "member_association"): {
        "account_id": "111111111111",
    },
    # --- Shield (2026-04-19) ---
    ("shield", "protection"): {
        "name": "cov-shield-protection",
        "resource_arn": "arn:aws:cloudfront::000000000000:distribution/EDFDVBD6EXAMPLE",
    },
    ("shield", "protection_group"): {
        "protection_group_id": "cov-shield-pg",
        "aggregation": "SUM",
        "pattern": "ALL",
    },
    # --- Macie2 (2026-04-19) ---
    ("macie2", "account"): {
        "finding_publishing_frequency": "FIFTEEN_MINUTES",
        "status": "ENABLED",
    },
    ("macie2", "classification_job"): {
        "name": "cov-macie-job",
        "job_type": "ONE_TIME",
        "s3_job_definition": [{"bucket_definitions": [{"account_id": "000000000000", "buckets": ["cov-bucket"]}]}],
    },
    ("macie2", "member"): {
        "account_id": "111111111111",
        "email": "cov-macie@example.test",
    },
    ("macie2", "custom_data_identifier"): {
        "name": "cov-macie-cdi",
        "regex": "[A-Z]{3}-[0-9]{3}",
        "keywords": ["CODE"],
    },
    # --- Detective (2026-04-19) ---
    ("detective", "graph"): {},
    ("detective", "member"): {
        "graph_arn": "arn:aws:detective:us-east-1:000000000000:graph:cov",
        "account_id": "111111111111",
        "email_address": "cov-detective@example.test",
    },
    ("detective", "invitation_accepter"): {
        "graph_arn": "arn:aws:detective:us-east-1:000000000000:graph:cov",
    },
    # --- Service Catalog (2026-04-19) ---
    ("servicecatalog", "portfolio"): {
        "name": "cov-sc-portfolio",
        "description": "coverage portfolio",
        "provider_name": "Coverage",
    },
    ("servicecatalog", "product"): {
        "name": "cov-sc-product",
        "owner": "Coverage",
        "type": "CLOUD_FORMATION_TEMPLATE",
        "provisioning_artifact_parameters": [{
            "name": "v1",
            "template_url": "https://s3.amazonaws.com/cov-bucket/template.json",
            "type": "CLOUD_FORMATION_TEMPLATE",
            "description": "coverage provisioning artifact",
        }],
    },
    ("servicecatalog", "constraint"): {
        "portfolio_id": "port-cov",
        "product_id": "prod-cov",
        "type": "LAUNCH",
        "parameters": "{\"RoleArn\":\"arn:aws:iam::000000000000:role/cov-launch-role\"}",
    },
    ("servicecatalog", "principal_portfolio_association"): {
        "portfolio_id": "port-cov",
        "principal_arn": "arn:aws:iam::000000000000:role/cov-principal",
        "principal_type": "IAM",
    },
    # --- App Runner (2026-04-19) ---
    ("apprunner", "service"): {
        "service_name": "cov-apprunner-service",
    },
    ("apprunner", "auto_scaling_configuration_version"): {
        "auto_scaling_configuration_name": "cov-apprunner-asc",
        "max_concurrency": 100,
    },
    ("apprunner", "connection"): {
        "connection_name": "cov-apprunner-conn",
        "provider_type": "GITHUB",
    },
    ("apprunner", "observability_configuration"): {
        "observability_configuration_name": "cov-apprunner-obs",
        "trace_configuration": [{"vendor": "AWSXRAY"}],
    },
    ("apprunner", "vpc_connector"): {
        "vpc_connector_name": "cov-apprunner-vpc-conn",
        "security_groups": ["sg-cov"],
    },
    # --- AppMesh (2026-04-19) ---
    ("appmesh", "mesh"): {
        "name": "cov-mesh",
    },
    ("appmesh", "virtual_node"): {
        "name": "cov-virtual-node",
        "mesh_name": "cov-mesh",
    },
    ("appmesh", "virtual_service"): {
        "name": "cov.example.local",
        "mesh_name": "cov-mesh",
    },
    # --- DataSync (2026-04-19) ---
    ("datasync", "agent"): {
        "activation_key": "COVER-AGEKY-ABCDE-12345-67890",
        "name": "cov-datasync-agent",
    },
    ("datasync", "location_s3"): {
        "s3_bucket_arn": "arn:aws:s3:::cov-datasync-bucket",
        "subdirectory": "/cov-data/",
    },
    ("datasync", "location_efs"): {
        "efs_file_system_arn": "arn:aws:elasticfilesystem:us-east-1:000000000000:file-system/fs-cov",
        "subdirectory": "/cov-efs/",
    },
    ("datasync", "location_nfs"): {
        "server_hostname": "cov-nfs.internal",
        "subdirectory": "/exports/cov",
    },
    ("datasync", "task"): {
        "name": "cov-datasync-task",
        "source_location_arn": "arn:aws:datasync:us-east-1:000000000000:location/loc-src-cov",
        "destination_location_arn": "arn:aws:datasync:us-east-1:000000000000:location/loc-dst-cov",
    },
    # --- FSx (2026-04-19) ---
    ("fsx", "lustre_file_system"): {
        "storage_capacity": 1200,
        "subnet_ids": ["subnet-cov-a"],
        "deployment_type": "SCRATCH_2",
    },
    ("fsx", "windows_file_system"): {
        "storage_capacity": 32,
        "subnet_ids": ["subnet-cov-a"],
        "throughput_capacity": 8,
        "deployment_type": "SINGLE_AZ_1",
        "active_directory_id": "d-1234567890",
        "skip_final_backup": True,
    },
    ("fsx", "openzfs_file_system"): {
        "storage_capacity": 64,
        "subnet_ids": ["subnet-cov-a"],
        "deployment_type": "SINGLE_AZ_1",
        "throughput_capacity": 64,
    },
    # --- Amplify (2026-04-19) ---
    ("amplify", "app"): {
        "name": "cov-amplify-app",
    },
    ("amplify", "branch"): {
        "app_id": "d3cov1234abcde",
        "branch_name": "main",
        "stage": "PRODUCTION",
    },
    ("amplify", "webhook"): {
        "app_id": "d3cov1234abcde",
        "branch_name": "main",
        "description": "coverage webhook",
    },
    ("amplify", "backend_environment"): {
        "app_id": "d3cov1234abcde",
        "environment_name": "prod",
    },
    ("amplify", "domain_association"): {
        "app_id": "d3cov1234abcde",
        "domain_name": "cov.localemu.test",
    },
    # --- AppSync (2026-04-19) ---
    ("appsync", "graphql_api"): {
        "name": "cov-appsync-api",
        "authentication_type": "API_KEY",
    },
    ("appsync", "api_key"): {
        "api_id": "covapi1234abcde",
        "description": "coverage api key",
    },
    ("appsync", "datasource"): {
        "api_id": "covapi1234abcde",
        "name": "cov_datasource",
        "type": "NONE",
    },
    ("appsync", "resolver"): {
        "api_id": "covapi1234abcde",
        "type": "Query",
        "field": "getItem",
        "data_source": "cov_datasource",
    },
    ("appsync", "function"): {
        "api_id": "covapi1234abcde",
        "data_source": "cov_datasource",
        "name": "cov_function",
        "request_mapping_template": "$util.toJson({})",
        "response_mapping_template": "$util.toJson($ctx.result)",
    },
    # --- Global Accelerator (2026-04-19) ---
    ("globalaccelerator", "accelerator"): {
        "name": "cov-ga",
        "ip_address_type": "IPV4",
        "enabled": True,
    },
    ("globalaccelerator", "listener"): {
        "accelerator_arn": "arn:aws:globalaccelerator::000000000000:accelerator/cov",
        "protocol": "TCP",
    },
    ("globalaccelerator", "endpoint_group"): {
        "listener_arn": "arn:aws:globalaccelerator::000000000000:accelerator/cov/listener/lstnr-cov",
        "health_check_protocol": "TCP",
        "health_check_port": 80,
    },
    # --- CodeArtifact (2026-04-19) ---
    ("codeartifact", "domain"): {
        "domain": "cov-ca-domain",
    },
    ("codeartifact", "repository"): {
        "repository": "cov-ca-repo",
        "domain": "cov-ca-domain",
        "description": "coverage code artifact repository",
    },
}


_EC2_VPC_ID = "vpc-coverage"
_EC2_SUBNET_ID = "subnet-coverage"
_EC2_SG_ID = "sg-coverage"
_EC2_RT_ID = "rtb-coverage"
_EC2_IGW_ID = "igw-coverage"
_EC2_NAT_ID = "nat-coverage"
_EC2_EIP_ID = "eipalloc-coverage"
_EC2_NACL_ID = "acl-coverage"
_EC2_PEER_VPC_ID = "vpc-peer-coverage"

_RDS_SNG_ID = "localemu-coverage-sng-companion"
_RDS_PG_ID = "localemu-coverage-pg-companion"
_RDS_CPG_ID = "localemu-coverage-cpg-companion"

_ELB_LB_ARN = (
    "arn:aws:elasticloadbalancing:us-east-1:000000000000:"
    "loadbalancer/app/localemu-coverage-lb/abc"
)
_ELB_TG_ARN = (
    "arn:aws:elasticloadbalancing:us-east-1:000000000000:"
    "targetgroup/localemu-coverage-tg/abc"
)
_ELB_LISTENER_ARN = (
    "arn:aws:elasticloadbalancing:us-east-1:000000000000:"
    "listener/app/localemu-coverage-lb/abc/def"
)


def _ec2_resource(
    resource_type: str, resource_id: str, attributes: dict[str, Any]
) -> Resource:
    """Build a minimal EC2 companion resource for the coverage fixtures."""
    return Resource(
        service="ec2",
        resource_type=resource_type,
        resource_id=resource_id,
        account_id="000000000000",
        region="us-east-1",
        attributes={"id": resource_id, **attributes},
    )


def _add_ec2_companions(
    spec_key: tuple[str, str],
    attrs: dict[str, Any],
    resources: list[Resource],
) -> None:
    """Inject cross-resource refs + companion resources for EC2 fixtures.

    Keeps the ``_FIXTURES`` table readable (just the attributes unique
    to the resource under test) by wiring up the surrounding VPC / subnet
    / route table / etc. here. Every companion carries its AWS-style id
    as ``resource_id`` so the reference resolver swaps raw id strings
    inside ``attrs`` for :class:`Ref` values pointing at the right
    logical name.
    """
    _, resource_type = spec_key

    # ``aws_vpc`` standalone: nothing extra.
    if resource_type == "vpc":
        return

    # Every other EC2 resource wants a VPC in scope.
    resources.append(
        _ec2_resource(
            "vpc",
            _EC2_VPC_ID,
            {
                "cidr_block": "10.0.0.0/16",
                "enable_dns_support": True,
                "enable_dns_hostnames": False,
            },
        )
    )

    if resource_type == "subnet":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "security_group":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "security_group_rule":
        # Needs the owning SG (for security_group_id) + SG needs its VPC.
        resources.append(
            _ec2_resource(
                "security_group",
                _EC2_SG_ID,
                {
                    "name": "coverage-sg",
                    "description": "coverage",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        return
    if resource_type == "internet_gateway":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "elastic_ip":
        return
    if resource_type == "nat_gateway":
        # Needs a subnet + an allocation.
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID,
                {
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "us-east-1a",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _ec2_resource(
                "elastic_ip",
                _EC2_EIP_ID,
                {"allocation_id": _EC2_EIP_ID, "domain": "vpc"},
            )
        )
        attrs["subnet_id"] = _EC2_SUBNET_ID
        attrs["allocation_id"] = _EC2_EIP_ID
        return
    if resource_type == "route_table":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type in ("route", "route_table_association"):
        resources.append(
            _ec2_resource(
                "route_table",
                _EC2_RT_ID,
                {"vpc_id": _EC2_VPC_ID},
            )
        )
        if resource_type == "route":
            # Target gateway for the route.
            resources.append(
                _ec2_resource(
                    "internet_gateway",
                    _EC2_IGW_ID,
                    {"vpc_id": _EC2_VPC_ID},
                )
            )
            attrs["route_table_id"] = _EC2_RT_ID
            attrs["gateway_id"] = _EC2_IGW_ID
        else:
            resources.append(
                _ec2_resource(
                    "subnet",
                    _EC2_SUBNET_ID,
                    {
                        "cidr_block": "10.0.1.0/24",
                        "availability_zone": "us-east-1a",
                        "vpc_id": _EC2_VPC_ID,
                    },
                )
            )
            attrs["route_table_id"] = _EC2_RT_ID
            attrs["subnet_id"] = _EC2_SUBNET_ID
        return
    if resource_type == "vpc_endpoint":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "network_acl":
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "network_acl_rule":
        resources.append(
            _ec2_resource(
                "network_acl",
                _EC2_NACL_ID,
                {"vpc_id": _EC2_VPC_ID},
            )
        )
        attrs["network_acl_id"] = _EC2_NACL_ID
        return
    if resource_type == "vpc_peering_connection":
        resources.append(
            _ec2_resource(
                "vpc",
                _EC2_PEER_VPC_ID,
                {"cidr_block": "10.1.0.0/16"},
            )
        )
        attrs["vpc_id"] = _EC2_VPC_ID
        attrs["peer_vpc_id"] = _EC2_PEER_VPC_ID
        return
    # key_pair needs nothing.


def _rds_resource(
    resource_type: str, resource_id: str, attributes: dict[str, Any]
) -> Resource:
    """Build a minimal RDS companion resource for the coverage fixtures."""
    return Resource(
        service="rds",
        resource_type=resource_type,
        resource_id=resource_id,
        account_id="000000000000",
        region="us-east-1",
        attributes={"id": resource_id, **attributes},
    )


def _add_rds_companions(
    spec_key: tuple[str, str],
    attrs: dict[str, Any],
    resources: list[Resource],
) -> None:
    """Wire RDS fixtures to their parameter-group / subnet-group companions.

    ``aws_db_instance`` accepts ``vpc_security_group_ids``,
    ``db_subnet_group_name`` and ``parameter_group_name`` as optional
    arguments, but we want the reference-resolution path under test.
    Every RDS fixture that references another resource gets a companion
    inserted here so the :class:`Ref` resolver produces valid Terraform
    addresses.
    """
    _, resource_type = spec_key

    def _add_sng_with_subnets() -> None:
        resources.append(
            _ec2_resource(
                "vpc",
                _EC2_VPC_ID,
                {"cidr_block": "10.0.0.0/16"},
            )
        )
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID,
                {
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "us-east-1a",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID + "-b",
                {
                    "cidr_block": "10.0.2.0/24",
                    "availability_zone": "us-east-1b",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _rds_resource(
                "db_subnet_group",
                _RDS_SNG_ID,
                {
                    "name": _RDS_SNG_ID,
                    "description": "coverage",
                    "subnet_ids": [_EC2_SUBNET_ID, _EC2_SUBNET_ID + "-b"],
                },
            )
        )

    if resource_type == "db_instance":
        _add_sng_with_subnets()
        resources.append(
            _rds_resource(
                "db_parameter_group",
                _RDS_PG_ID,
                {
                    "name": _RDS_PG_ID,
                    "family": "mysql8.0",
                    "description": "coverage",
                },
            )
        )
        attrs["db_subnet_group_name"] = _RDS_SNG_ID
        attrs["parameter_group_name"] = _RDS_PG_ID
    elif resource_type == "db_cluster":
        _add_sng_with_subnets()
        resources.append(
            _rds_resource(
                "db_cluster_parameter_group",
                _RDS_CPG_ID,
                {
                    "name": _RDS_CPG_ID,
                    "family": "aurora-mysql8.0",
                    "description": "coverage",
                },
            )
        )
        attrs["db_subnet_group_name"] = _RDS_SNG_ID
        attrs["db_cluster_parameter_group_name"] = _RDS_CPG_ID
    elif resource_type == "db_subnet_group":
        # ``aws_db_subnet_group`` requires at least one subnet id.
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID,
                {
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "us-east-1a",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _ec2_resource(
                "vpc",
                _EC2_VPC_ID,
                {"cidr_block": "10.0.0.0/16"},
            )
        )
        attrs["subnet_ids"] = [_EC2_SUBNET_ID]


def _elbv2_resource(
    resource_type: str, resource_id: str, attributes: dict[str, Any]
) -> Resource:
    return Resource(
        service="elbv2",
        resource_type=resource_type,
        resource_id=resource_id,
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": resource_id, **attributes},
    )


def _add_elbv2_companions(
    spec_key: tuple[str, str],
    attrs: dict[str, Any],
    resources: list[Resource],
) -> None:
    """Wire ELBv2 fixtures to companion VPC / LB / TG resources."""
    _, resource_type = spec_key

    def _add_vpc_and_subnets() -> None:
        resources.append(
            _ec2_resource(
                "vpc", _EC2_VPC_ID, {"cidr_block": "10.0.0.0/16"}
            )
        )
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID,
                {
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "us-east-1a",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _ec2_resource(
                "subnet",
                _EC2_SUBNET_ID + "-b",
                {
                    "cidr_block": "10.0.2.0/24",
                    "availability_zone": "us-east-1b",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )

    if resource_type == "load_balancer":
        _add_vpc_and_subnets()
        attrs["subnets"] = [_EC2_SUBNET_ID, _EC2_SUBNET_ID + "-b"]
        return
    if resource_type == "target_group":
        _add_vpc_and_subnets()
        attrs["vpc_id"] = _EC2_VPC_ID
        return
    if resource_type == "listener":
        _add_vpc_and_subnets()
        resources.append(
            _elbv2_resource(
                "load_balancer",
                _ELB_LB_ARN,
                {
                    "name": "localemu-coverage-lb",
                    "load_balancer_type": "application",
                    "internal": False,
                    "subnets": [_EC2_SUBNET_ID, _EC2_SUBNET_ID + "-b"],
                },
            )
        )
        resources.append(
            _elbv2_resource(
                "target_group",
                _ELB_TG_ARN,
                {
                    "name": "localemu-coverage-tg",
                    "port": 80,
                    "protocol": "HTTP",
                    "target_type": "instance",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        attrs["load_balancer_arn"] = _ELB_LB_ARN
        attrs["default_action"] = [
            {"type": "forward", "target_group_arn": _ELB_TG_ARN}
        ]
        return
    if resource_type == "listener_rule":
        _add_vpc_and_subnets()
        resources.append(
            _elbv2_resource(
                "load_balancer",
                _ELB_LB_ARN,
                {
                    "name": "localemu-coverage-lb",
                    "load_balancer_type": "application",
                    "internal": False,
                    "subnets": [_EC2_SUBNET_ID, _EC2_SUBNET_ID + "-b"],
                },
            )
        )
        resources.append(
            _elbv2_resource(
                "target_group",
                _ELB_TG_ARN,
                {
                    "name": "localemu-coverage-tg",
                    "port": 80,
                    "protocol": "HTTP",
                    "target_type": "instance",
                    "vpc_id": _EC2_VPC_ID,
                },
            )
        )
        resources.append(
            _elbv2_resource(
                "listener",
                _ELB_LISTENER_ARN,
                {
                    "port": 80,
                    "protocol": "HTTP",
                    "load_balancer_arn": _ELB_LB_ARN,
                    "default_action": [
                        {"type": "forward", "target_group_arn": _ELB_TG_ARN}
                    ],
                },
            )
        )
        attrs["listener_arn"] = _ELB_LISTENER_ARN
        attrs["action"] = [
            {"type": "forward", "target_group_arn": _ELB_TG_ARN}
        ]
        attrs["condition"] = [
            {"path_pattern": {"values": ["/foo"]}}
        ]
        return


@pytest.mark.parametrize(
    "spec_key",
    sorted(TF_SPECS.keys()),
    ids=lambda key: f"{key[0]}-{key[1]}",
)
def test_service_renders_valid_terraform(
    tmp_path: Path, spec_key: tuple[str, str]
) -> None:
    if spec_key not in _FIXTURES:
        pytest.skip(
            f"no coverage fixture yet for {spec_key}; service acceptance "
            "lands in the commit that adds its fixture"
        )
    attrs = dict(_FIXTURES[spec_key])
    service, resource_type = spec_key
    resource_id = attrs.get("identifier") or attrs.get(
        "cluster_identifier"
    ) or attrs.get("role_name") or attrs.get("name") or attrs.get(
        f"{resource_type}_name"
    ) or attrs.get("bucket_name") or attrs.get("table_name") or attrs.get(
        "function_name"
    ) or attrs.get("secret_name") or attrs.get("parameter_name") or attrs.get(
        "policy_name"
    ) or attrs.get("topic_name") or attrs.get("queue_name") or attrs.get(
        "rule_name"
    ) or attrs.get("log_group_name") or attrs.get("alarm_name") or attrs.get(
        "api_name"
    ) or attrs.get("state_machine_name") or attrs.get("stream_name") or attrs.get(
        "key_name"
    ) or attrs.get("id") or attrs.get(
        "key"
    ) or f"{service}-{resource_type}"

    resources = [
        Resource(
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            account_id="000000000000",
            region="us-east-1",
            attributes=attrs,
        )
    ]
    # Lambda coverage additionally needs the referenced IAM role in the
    # snapshot so the resolver can swap the ARN string for a ref. The
    # role_arn is otherwise emitted literally and ``terraform validate``
    # accepts it as a string anyway, but we want the ref path covered.
    # EC2/VPC companions: most aws_* resources require cross-resource
    # references (vpc_id, subnet_id, ...). We wire the fixture's raw id
    # strings to minimal companion resources so the reference resolver
    # produces valid ``aws_X.Y.id`` addresses and ``terraform validate``
    # doesn't error on dangling cross-references.
    if service == "ec2":
        _add_ec2_companions(spec_key, attrs, resources)
    if service == "rds":
        _add_rds_companions(spec_key, attrs, resources)
    if service == "elbv2":
        _add_elbv2_companions(spec_key, attrs, resources)

    if spec_key == ("route53", "record"):
        from localemu.export.ir import Ref as _Ref

        attrs["zone_id"] = _Ref("route53", "zone", "Z000COVERAGE", attribute="zone_id")
        resources.append(
            Resource(
                service="route53",
                resource_type="zone",
                resource_id="Z000COVERAGE",
                account_id="000000000000",
                region="us-east-1",
                attributes={"name": "coverage.localemu.test."},
            )
        )

    if spec_key == ("iam", "instance_profile"):
        # Instance profile must reference a Role that exists in the same
        # snapshot so the resolver can wire the dependency. The collector
        # carries this as ``attributes.role`` (a Ref); the fixture above
        # stores ``roles=[name]`` only — promote to a Ref for the test.
        from localemu.export.ir import Ref as _Ref

        attrs["role"] = _Ref(
            "iam", "role", "localemu-coverage-role", attribute="name"
        )
        resources.append(
            Resource(
                service="iam",
                resource_type="role",
                resource_id="localemu-coverage-role",
                account_id="000000000000",
                region="us-east-1",
                attributes={
                    "role_name": "localemu-coverage-role",
                    "arn": (
                        "arn:aws:iam::000000000000:role/"
                        "localemu-coverage-role"
                    ),
                    "assume_role_policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            )
        )

    if spec_key == ("lambda", "function"):
        resources.append(
            Resource(
                service="iam",
                resource_type="role",
                resource_id="fn-role",
                account_id="000000000000",
                region="us-east-1",
                attributes={
                    "role_name": "fn-role",
                    "arn": "arn:aws:iam::000000000000:role/fn-role",
                    "assume_role_policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            )
        )

    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=resources,
    )
    snap = rewrite_snapshot(snap, "123456789012", "us-east-1")
    lr = prepare_lambda_code(snap, "123456789012", "us-east-1")
    sr = extract_secrets(lr.snapshot)
    final = resolve_references(sr.snapshot)

    ex = RealAwsExporter(
        creds=AwsCredentials(),
        target_account="123456789012",
        target_region="us-east-1",
    )
    unsupported = ex._write_terraform(final, tmp_path, sr.slots)
    assert unsupported == [], f"unsupported resources emitted: {unsupported}"

    # Lambda: provide a placeholder zip so filemd5 resolves.
    (tmp_path / "lambda").mkdir(exist_ok=True)
    for zip_path in (tmp_path / "lambda").glob("*.zip"):
        if zip_path.stat().st_size == 0:
            zip_path.write_bytes(b"PK\x03\x04")
    placeholder = tmp_path / "lambda" / "placeholder.zip"
    if not placeholder.exists():
        placeholder.write_bytes(b"PK\x03\x04")

    init = subprocess.run(
        ["terraform", "init", "-backend=false", "-input=false"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert init.returncode == 0, init.stderr
    val = subprocess.run(
        ["terraform", "validate"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert val.returncode == 0, (
        f"terraform validate failed for {spec_key}:\n"
        f"stdout: {val.stdout}\nstderr: {val.stderr}"
    )
