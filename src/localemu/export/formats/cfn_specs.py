"""CloudFormation-only translation specs for LocalEmu IR resources.

Why a dedicated module?
-----------------------
Version 1 of the export feature re-used the Terraform ``field_map`` tables
when emitting CloudFormation. Terraform property names (snake_case, mostly
aligned with the HashiCorp ``aws`` provider) are **not** the same as
CloudFormation property names (PascalCase, aligned with the AWS CFN resource
schema). Re-using the Terraform map produced invalid templates across every
resource — ``Bucket`` instead of ``BucketName``, ``AssumeRolePolicy`` instead
of ``AssumeRolePolicyDocument``, ``Handler`` lowercased, and so on.

This module therefore defines *CloudFormation-only* specs. Every key in
every :attr:`CfnSpec.attribute_map` is the **exact** property name taken
from the upstream CloudFormation resource specification. Where a single IR
attribute expands into a nested CFN property block (e.g.
``versioning_enabled`` → ``VersioningConfiguration.Status``), the value is a
callable that returns the nested dict; straight renames use a plain string.

Any attribute not in the map is dropped — CloudFormation rejects unknown
properties, so silent filtering is safer than passthrough. Builders
(:attr:`CfnSpec.builder`) take over when a resource needs structural
assembly beyond per-field renaming (Lambda ``Code``, DynamoDB key schema,
IAM inline policies, …).
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

# Maximum size (in bytes) of a Lambda deployment zip that CloudFormation
# will accept as an inline ``Code.ZipFile`` property. AWS documents the
# limit as 4096 characters of text; we use the same bound for binary zips
# since we base64-decode before measuring.
LAMBDA_INLINE_CODE_MAX_BYTES = 4096


# ---------------------------------------------------------------------------
# Spec dataclass
# ---------------------------------------------------------------------------


AttributeMapValue = str | Callable[[Any], dict[str, Any] | Any]


@dataclass(frozen=True)
class CfnSpec:
    """Mapping rule for a single (service, resource_type) pair.

    Attributes:
        cfn_type: CloudFormation resource type string
            (``"AWS::S3::Bucket"`` etc.).
        attribute_map: Mapping from IR attribute name to either a CFN
            property name (string) or a callable ``(value) -> dict`` that
            returns one-or-more CFN properties to merge into the resource's
            ``Properties`` dict. Callables let us expand a single IR field
            into the nested configuration blocks CFN requires.
        builder: Optional name of a builder function in
            :mod:`localemu.export.formats.cloudformation` that takes over
            Properties construction entirely. When set, ``attribute_map``
            is ignored (the builder is free to consult it, but does not
            have to).
        emit_tags: Whether to emit a top-level ``Tags`` property built from
            the IR resource's ``tags`` dict. Some CFN resource types don't
            support tagging (notably ``AWS::Lambda::Permission``).
    """

    cfn_type: str
    attribute_map: dict[str, AttributeMapValue] = field(default_factory=dict)
    builder: str | None = None
    emit_tags: bool = True


# ---------------------------------------------------------------------------
# Small value-transformation helpers
# ---------------------------------------------------------------------------


def _versioning(value: Any) -> dict[str, Any]:
    """Expand ``versioning_enabled: bool`` → ``VersioningConfiguration``."""
    enabled = bool(value)
    return {"VersioningConfiguration": {"Status": "Enabled" if enabled else "Suspended"}}


def _sse_algorithm(value: Any) -> dict[str, Any]:
    """Expand an S3 SSE algorithm string into ``BucketEncryption``."""
    if not value:
        return {}
    return {
        "BucketEncryption": {
            "ServerSideEncryptionConfiguration": [
                {"ServerSideEncryptionByDefault": {"SSEAlgorithm": str(value)}}
            ]
        }
    }


def _public_access_block(value: Any) -> dict[str, Any]:
    """Expand an IR public-access-block dict to the CFN property block."""
    if not isinstance(value, dict) or not value:
        return {}
    return {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": bool(value.get("BlockPublicAcls", True)),
            "BlockPublicPolicy": bool(value.get("BlockPublicPolicy", True)),
            "IgnorePublicAcls": bool(value.get("IgnorePublicAcls", True)),
            "RestrictPublicBuckets": bool(value.get("RestrictPublicBuckets", True)),
        }
    }


def _sqs_visibility_timeout(value: Any) -> dict[str, Any]:
    """Coerce SQS visibility-timeout to an int (CFN rejects strings)."""
    try:
        return {"VisibilityTimeout": int(value)}
    except (TypeError, ValueError):
        return {}


def _sqs_max_message_size(value: Any) -> dict[str, Any]:
    try:
        return {"MaximumMessageSize": int(value)}
    except (TypeError, ValueError):
        return {}


def _sqs_message_retention(value: Any) -> dict[str, Any]:
    try:
        return {"MessageRetentionPeriod": int(value)}
    except (TypeError, ValueError):
        return {}


def _sqs_delay(value: Any) -> dict[str, Any]:
    try:
        return {"DelaySeconds": int(value)}
    except (TypeError, ValueError):
        return {}


def _sqs_receive_wait(value: Any) -> dict[str, Any]:
    try:
        return {"ReceiveMessageWaitTimeSeconds": int(value)}
    except (TypeError, ValueError):
        return {}


# Map IR target dict keys (snake_case, set by the events collector) to the
# CloudFormation Targets property keys (PascalCase). Anything not in this map
# is passed through verbatim so future fields don't get silently dropped.
_EVENTS_TARGET_KEY_MAP = {
    "id": "Id",
    "arn": "Arn",
    "input": "Input",
    "input_path": "InputPath",
    "input_transformer": "InputTransformer",
    "role_arn": "RoleArn",
    "retry_policy": "RetryPolicy",
    "dead_letter_config": "DeadLetterConfig",
    "ecs_parameters": "EcsParameters",
    "batch_parameters": "BatchParameters",
    "kinesis_parameters": "KinesisParameters",
    "sqs_parameters": "SqsParameters",
    "http_parameters": "HttpParameters",
    "redshift_data_parameters": "RedshiftDataParameters",
    "sage_maker_pipeline_parameters": "SageMakerPipelineParameters",
    "run_command_parameters": "RunCommandParameters",
}


def _events_targets_pascal(value: Any) -> dict[str, Any]:
    """Translate the IR ``targets`` list into CFN-PascalCase ``Targets``.

    Each target in the IR is an object collected with snake_case keys (``arn``,
    ``id``, ``input_path``, ...). CloudFormation rejects those — its
    ``AWS::Events::Rule.Properties.Targets`` schema requires PascalCase
    (``Arn``, ``Id``, ``InputPath``, ...). Without this, the stack create
    fails at the ``Properties`` validation step with a confusing
    "encountered unsupported properties" error.
    """
    if not isinstance(value, list):
        return {}
    out: list[dict[str, Any]] = []
    for tgt in value:
        if not isinstance(tgt, dict):
            continue
        out.append(
            {
                _EVENTS_TARGET_KEY_MAP.get(k, k[:1].upper() + k[1:]): v
                for k, v in tgt.items()
            }
        )
    return {"Targets": out}


def _as_json_string(value: Any) -> str:
    """Serialise ``value`` as a compact JSON string for CFN ``DefinitionString``."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Spec registry
# ---------------------------------------------------------------------------
#
# NOTE on property names: every string value below was cross-checked
# against the upstream AWS CloudFormation resource specification. Do not
# "normalise" them to match Terraform's snake_case equivalents — that is
# the exact bug that plagued the v1 exporter.


CFN_SPECS: dict[tuple[str, str], CfnSpec] = {
    # --- S3 ----------------------------------------------------------------
    ("s3", "bucket"): CfnSpec(
        cfn_type="AWS::S3::Bucket",
        attribute_map={
            "name": "BucketName",
            "bucket_name": "BucketName",
            "versioning_enabled": _versioning,
            "sse_algorithm": _sse_algorithm,
            "public_access_block": _public_access_block,
        },
        builder="_build_s3_bucket",
    ),
    # --- SNS ---------------------------------------------------------------
    ("sns", "topic"): CfnSpec(
        cfn_type="AWS::SNS::Topic",
        attribute_map={
            "name": "TopicName",
            "display_name": "DisplayName",
            "fifo_topic": "FifoTopic",
            "content_based_deduplication": "ContentBasedDeduplication",
            "kms_master_key_id": "KmsMasterKeyId",
            "signature_version": "SignatureVersion",
            "tracing_config": "TracingConfig",
            "data_protection_policy": "DataProtectionPolicy",
        },
    ),
    ("sns", "topic_policy"): CfnSpec(
        cfn_type="AWS::SNS::TopicPolicy",
        attribute_map={
            "policy": "PolicyDocument",
            # ``arn`` IR field is rewritten as a Ref to the topic; the CFN
            # type expects ``Topics`` as a list of topic ARNs.
        },
        builder="_build_sns_topic_policy",
    ),
    ("sns", "subscription"): CfnSpec(
        cfn_type="AWS::SNS::Subscription",
        attribute_map={
            "protocol": "Protocol",
            "endpoint": "Endpoint",
            "topic_arn": "TopicArn",
            "filter_policy": "FilterPolicy",
            "filter_policy_scope": "FilterPolicyScope",
            "raw_message_delivery": "RawMessageDelivery",
            "redrive_policy": "RedrivePolicy",
            "delivery_policy": "DeliveryPolicy",
            "subscription_role_arn": "SubscriptionRoleArn",
        },
        emit_tags=False,  # AWS::SNS::Subscription does not support tags.
    ),
    # --- SQS ---------------------------------------------------------------
    ("sqs", "queue"): CfnSpec(
        cfn_type="AWS::SQS::Queue",
        attribute_map={
            "name": "QueueName",
            "queue_name": "QueueName",
            "fifo_queue": "FifoQueue",
            "content_based_deduplication": "ContentBasedDeduplication",
            "visibility_timeout": _sqs_visibility_timeout,
            "maximum_message_size": _sqs_max_message_size,
            "message_retention_period": _sqs_message_retention,
            "delay_seconds": _sqs_delay,
            "receive_message_wait_time_seconds": _sqs_receive_wait,
            "kms_master_key_id": "KmsMasterKeyId",
            "kms_data_key_reuse_period_seconds": "KmsDataKeyReusePeriodSeconds",
            "redrive_policy": "RedrivePolicy",
        },
    ),
    # --- IAM ---------------------------------------------------------------
    ("iam", "role"): CfnSpec(
        cfn_type="AWS::IAM::Role",
        attribute_map={
            "name": "RoleName",
            "role_name": "RoleName",
            "path": "Path",
            "description": "Description",
            "max_session_duration": "MaxSessionDuration",
            "permissions_boundary": "PermissionsBoundary",
            "assume_role_policy_document": "AssumeRolePolicyDocument",
        },
        builder="_build_iam_role",
    ),
    ("iam", "policy"): CfnSpec(
        cfn_type="AWS::IAM::ManagedPolicy",
        attribute_map={
            "name": "ManagedPolicyName",
            "policy_name": "ManagedPolicyName",
            "path": "Path",
            "description": "Description",
            "policy_document": "PolicyDocument",
        },
    ),
    ("iam", "user"): CfnSpec(
        cfn_type="AWS::IAM::User",
        attribute_map={
            "name": "UserName",
            "user_name": "UserName",
            "path": "Path",
            "permissions_boundary": "PermissionsBoundary",
        },
        builder="_build_iam_user",
    ),
    ("iam", "group"): CfnSpec(
        cfn_type="AWS::IAM::Group",
        attribute_map={
            "name": "GroupName",
            "group_name": "GroupName",
            "path": "Path",
        },
        builder="_build_iam_group",
    ),
    ("iam", "instance_profile"): CfnSpec(
        cfn_type="AWS::IAM::InstanceProfile",
        attribute_map={
            "name": "InstanceProfileName",
            "instance_profile_name": "InstanceProfileName",
            "path": "Path",
        },
        builder="_build_iam_instance_profile",
        emit_tags=False,  # AWS::IAM::InstanceProfile does not accept Tags.
    ),
    ("iam", "oidc_provider"): CfnSpec(
        cfn_type="AWS::IAM::OIDCProvider",
        attribute_map={
            "url": "Url",
            "client_id_list": "ClientIdList",
            "thumbprint_list": "ThumbprintList",
        },
    ),
    ("iam", "saml_provider"): CfnSpec(
        cfn_type="AWS::IAM::SAMLProvider",
        attribute_map={
            "name": "Name",
            "saml_metadata_document": "SamlMetadataDocument",
        },
    ),
    # --- Lambda ------------------------------------------------------------
    ("lambda", "function"): CfnSpec(
        cfn_type="AWS::Lambda::Function",
        attribute_map={
            "function_name": "FunctionName",
            "name": "FunctionName",
            "runtime": "Runtime",
            "handler": "Handler",
            "role": "Role",
            "description": "Description",
            "timeout": "Timeout",
            "memory_size": "MemorySize",
            "architectures": "Architectures",
            "package_type": "PackageType",
            "environment": "Environment",
            "kms_key_arn": "KmsKeyArn",
            "tracing_config": "TracingConfig",
            "layers": "Layers",
        },
        builder="_build_lambda_function",
    ),
    # --- DynamoDB ----------------------------------------------------------
    ("dynamodb", "table"): CfnSpec(
        cfn_type="AWS::DynamoDB::Table",
        attribute_map={
            "name": "TableName",
            "table_name": "TableName",
            "billing_mode": "BillingMode",
            "stream_specification": "StreamSpecification",
            "sse_specification": "SSESpecification",
            "time_to_live_specification": "TimeToLiveSpecification",
            "point_in_time_recovery": "PointInTimeRecoverySpecification",
        },
        builder="_build_dynamodb_table",
    ),
    # --- KMS ---------------------------------------------------------------
    ("kms", "key"): CfnSpec(
        cfn_type="AWS::KMS::Key",
        attribute_map={
            "description": "Description",
            "key_usage": "KeyUsage",
            "key_spec": "KeySpec",
            "enabled": "Enabled",
            "enable_key_rotation": "EnableKeyRotation",
            "pending_window_in_days": "PendingWindowInDays",
            "policy": "KeyPolicy",
            "multi_region": "MultiRegion",
        },
    ),
    ("kms", "alias"): CfnSpec(
        cfn_type="AWS::KMS::Alias",
        attribute_map={
            "alias_name": "AliasName",
            "name": "AliasName",
            "target_key_id": "TargetKeyId",
        },
        emit_tags=False,  # AWS::KMS::Alias is untagged.
    ),
    # --- SecretsManager ----------------------------------------------------
    ("secretsmanager", "secret"): CfnSpec(
        cfn_type="AWS::SecretsManager::Secret",
        attribute_map={
            "name": "Name",
            "secret_name": "Name",
            "description": "Description",
            "kms_key_id": "KmsKeyId",
            "secret_string": "SecretString",
        },
    ),
    # --- SSM ---------------------------------------------------------------
    ("ssm", "parameter"): CfnSpec(
        cfn_type="AWS::SSM::Parameter",
        attribute_map={
            "name": "Name",
            "parameter_name": "Name",
            "type": "Type",
            "value": "Value",
            "description": "Description",
            "tier": "Tier",
            "data_type": "DataType",
            "allowed_pattern": "AllowedPattern",
        },
        builder="_build_ssm_parameter",
    ),
    # --- CloudWatch Logs ---------------------------------------------------
    ("logs", "log_group"): CfnSpec(
        cfn_type="AWS::Logs::LogGroup",
        attribute_map={
            "name": "LogGroupName",
            "log_group_name": "LogGroupName",
            "retention_in_days": "RetentionInDays",
            "kms_key_id": "KmsKeyId",
        },
    ),
    # --- EventBridge -------------------------------------------------------
    ("events", "rule"): CfnSpec(
        cfn_type="AWS::Events::Rule",
        attribute_map={
            "name": "Name",
            "rule_name": "Name",
            "description": "Description",
            "event_bus_name": "EventBusName",
            "schedule_expression": "ScheduleExpression",
            "event_pattern": "EventPattern",
            "state": "State",
            "role_arn": "RoleArn",
            "targets": _events_targets_pascal,
        },
    ),
    ("events", "event_bus"): CfnSpec(
        cfn_type="AWS::Events::EventBus",
        attribute_map={
            "name": "Name",
            "event_source_name": "EventSourceName",
        },
    ),
    # --- Step Functions ----------------------------------------------------
    ("stepfunctions", "state_machine"): CfnSpec(
        cfn_type="AWS::StepFunctions::StateMachine",
        attribute_map={
            "name": "StateMachineName",
            "state_machine_name": "StateMachineName",
            "type": "StateMachineType",
            "role_arn": "RoleArn",
            "definition": lambda v: {"DefinitionString": _as_json_string(v)},
            "logging_configuration": "LoggingConfiguration",
            "tracing_configuration": "TracingConfiguration",
        },
    ),
    # --- API Gateway (REST) -----------------------------------------------
    ("apigateway", "rest_api"): CfnSpec(
        cfn_type="AWS::ApiGateway::RestApi",
        attribute_map={
            "name": "Name",
            "api_name": "Name",
            "description": "Description",
            # CFN uses ``ApiKeySourceType``; ``ApiKeySource`` (no suffix)
            # is the AWS-API name but CFN rejects it.
            "api_key_source": "ApiKeySourceType",
            "binary_media_types": "BinaryMediaTypes",
            "endpoint_configuration": "EndpointConfiguration",
            "minimum_compression_size": "MinimumCompressionSize",
            "policy": "Policy",
        },
    ),
    ("apigateway", "resource"): CfnSpec(
        cfn_type="AWS::ApiGateway::Resource",
        attribute_map={
            "rest_api_id": "RestApiId",
            "parent_id": "ParentId",
            "path_part": "PathPart",
        },
        emit_tags=False,
    ),
    ("apigateway", "method"): CfnSpec(
        cfn_type="AWS::ApiGateway::Method",
        attribute_map={
            "rest_api_id": "RestApiId",
            "resource_id": "ResourceId",
            "http_method": "HttpMethod",
            "authorization": "AuthorizationType",
            "authorization_type": "AuthorizationType",
            "authorizer_id": "AuthorizerId",
            "api_key_required": "ApiKeyRequired",
            "request_parameters": "RequestParameters",
            "request_models": "RequestModels",
            "method_responses": "MethodResponses",
            # ``integration`` is rewritten in the builder below to use the
            # CFN PascalCase ``Integration`` sub-properties.
        },
        emit_tags=False,
        builder="_build_apigateway_method",
    ),
    # --- OpenSearch --------------------------------------------------------
    ("opensearch", "domain"): CfnSpec(
        cfn_type="AWS::OpenSearchService::Domain",
        attribute_map={
            "domain_name": "DomainName",
            "name": "DomainName",
            "engine_version": "EngineVersion",
            "cluster_config": "ClusterConfig",
            "ebs_options": "EBSOptions",
            "access_policies": "AccessPolicies",
            "advanced_options": "AdvancedOptions",
            "encryption_at_rest_options": "EncryptionAtRestOptions",
            "node_to_node_encryption_options": "NodeToNodeEncryptionOptions",
            "domain_endpoint_options": "DomainEndpointOptions",
        },
    ),
    # --- EC2 / VPC ---------------------------------------------------------
    ("ec2", "vpc"): CfnSpec(
        cfn_type="AWS::EC2::VPC",
        attribute_map={
            "cidr_block": "CidrBlock",
            "enable_dns_hostnames": "EnableDnsHostnames",
            "enable_dns_support": "EnableDnsSupport",
            "instance_tenancy": "InstanceTenancy",
        },
    ),
    ("ec2", "subnet"): CfnSpec(
        cfn_type="AWS::EC2::Subnet",
        attribute_map={
            "vpc_id": "VpcId",
            "cidr_block": "CidrBlock",
            "availability_zone": "AvailabilityZone",
            "map_public_ip_on_launch": "MapPublicIpOnLaunch",
        },
    ),
    ("ec2", "security_group"): CfnSpec(
        cfn_type="AWS::EC2::SecurityGroup",
        attribute_map={
            "name": "GroupName",
            "group_name": "GroupName",
            "description": "GroupDescription",
            "vpc_id": "VpcId",
            "ingress": "SecurityGroupIngress",
            "egress": "SecurityGroupEgress",
        },
    ),
    ("ec2", "internet_gateway"): CfnSpec(
        cfn_type="AWS::EC2::InternetGateway",
        attribute_map={},
    ),
    ("ec2", "internet_gateway_attachment"): CfnSpec(
        cfn_type="AWS::EC2::VPCGatewayAttachment",
        attribute_map={
            "internet_gateway_id": "InternetGatewayId",
            "vpc_id": "VpcId",
        },
    ),
    ("ec2", "nat_gateway"): CfnSpec(
        cfn_type="AWS::EC2::NatGateway",
        attribute_map={
            "subnet_id": "SubnetId",
            "allocation_id": "AllocationId",
            "connectivity_type": "ConnectivityType",
        },
    ),
    ("ec2", "route_table"): CfnSpec(
        cfn_type="AWS::EC2::RouteTable",
        attribute_map={
            "vpc_id": "VpcId",
        },
    ),
    ("ec2", "security_group_rule"): CfnSpec(
        cfn_type="AWS::EC2::SecurityGroupIngress",
        attribute_map={
            "security_group_id": "GroupId",
            "protocol": "IpProtocol",
            "from_port": "FromPort",
            "to_port": "ToPort",
            "cidr_blocks": lambda v: (
                {"CidrIp": v[0]} if isinstance(v, list) and v else {}
            ),
            "source_security_group_id": "SourceSecurityGroupId",
            "description": "Description",
        },
        emit_tags=False,
    ),
    ("ec2", "elastic_ip"): CfnSpec(
        cfn_type="AWS::EC2::EIP",
        attribute_map={
            "domain": "Domain",
        },
    ),
    ("ec2", "route"): CfnSpec(
        cfn_type="AWS::EC2::Route",
        attribute_map={
            "route_table_id": "RouteTableId",
            "destination_cidr_block": "DestinationCidrBlock",
            "destination_ipv6_cidr_block": "DestinationIpv6CidrBlock",
            "gateway_id": "GatewayId",
            "nat_gateway_id": "NatGatewayId",
            "vpc_peering_connection_id": "VpcPeeringConnectionId",
            "vpc_endpoint_id": "VpcEndpointId",
            "transit_gateway_id": "TransitGatewayId",
        },
        emit_tags=False,
    ),
    ("ec2", "route_table_association"): CfnSpec(
        cfn_type="AWS::EC2::SubnetRouteTableAssociation",
        attribute_map={
            "route_table_id": "RouteTableId",
            "subnet_id": "SubnetId",
        },
        emit_tags=False,
    ),
    ("ec2", "vpc_endpoint"): CfnSpec(
        cfn_type="AWS::EC2::VPCEndpoint",
        attribute_map={
            "vpc_id": "VpcId",
            "service_name": "ServiceName",
            "vpc_endpoint_type": "VpcEndpointType",
            "route_table_ids": "RouteTableIds",
            "subnet_ids": "SubnetIds",
            "security_group_ids": "SecurityGroupIds",
            "private_dns_enabled": "PrivateDnsEnabled",
            "policy": "PolicyDocument",
        },
        emit_tags=False,
    ),
    ("ec2", "network_acl"): CfnSpec(
        cfn_type="AWS::EC2::NetworkAcl",
        attribute_map={
            "vpc_id": "VpcId",
        },
    ),
    ("ec2", "network_acl_rule"): CfnSpec(
        cfn_type="AWS::EC2::NetworkAclEntry",
        attribute_map={
            "network_acl_id": "NetworkAclId",
            "rule_number": "RuleNumber",
            "egress": "Egress",
            "protocol": "Protocol",
            "rule_action": "RuleAction",
            "cidr_block": "CidrBlock",
            "ipv6_cidr_block": "Ipv6CidrBlock",
            "from_port": lambda v: (
                {"PortRange": {"From": int(v)}} if v is not None else {}
            ),
            "to_port": lambda v: (
                {"PortRange": {"To": int(v)}} if v is not None else {}
            ),
        },
        emit_tags=False,
    ),
    ("ec2", "vpc_peering_connection"): CfnSpec(
        cfn_type="AWS::EC2::VPCPeeringConnection",
        attribute_map={
            "vpc_id": "VpcId",
            "peer_vpc_id": "PeerVpcId",
            "peer_owner_id": "PeerOwnerId",
            "peer_region": "PeerRegion",
        },
    ),
    ("ec2", "key_pair"): CfnSpec(
        cfn_type="AWS::EC2::KeyPair",
        attribute_map={
            "key_name": "KeyName",
            "public_key": "PublicKeyMaterial",
        },
    ),
    # --- RDS ---------------------------------------------------------------
    ("rds", "db_instance"): CfnSpec(
        cfn_type="AWS::RDS::DBInstance",
        attribute_map={
            "identifier": "DBInstanceIdentifier",
            "engine": "Engine",
            "engine_version": "EngineVersion",
            "instance_class": "DBInstanceClass",
            "allocated_storage": lambda v: (
                {"AllocatedStorage": str(v)} if v is not None else {}
            ),
            "db_name": "DBName",
            "username": "MasterUsername",
            "password": "MasterUserPassword",
            "port": "Port",
            "vpc_security_group_ids": "VPCSecurityGroups",
            "db_subnet_group_name": "DBSubnetGroupName",
            "parameter_group_name": "DBParameterGroupName",
            "publicly_accessible": "PubliclyAccessible",
            "skip_final_snapshot": lambda v: (
                # CFN does not accept SkipFinalSnapshot — it uses
                # ``DeletionPolicy`` instead, which is a template-level
                # attribute. Emit as a tag-ish note via the description
                # path so the property is never sent to CFN.
                {}
            ),
        },
    ),
    ("rds", "db_cluster"): CfnSpec(
        cfn_type="AWS::RDS::DBCluster",
        attribute_map={
            "cluster_identifier": "DBClusterIdentifier",
            "engine": "Engine",
            "engine_version": "EngineVersion",
            "master_username": "MasterUsername",
            "master_password": "MasterUserPassword",
            "database_name": "DatabaseName",
            "vpc_security_group_ids": "VpcSecurityGroupIds",
            "db_subnet_group_name": "DBSubnetGroupName",
            "db_cluster_parameter_group_name": "DBClusterParameterGroupName",
            "skip_final_snapshot": lambda v: {},
        },
    ),
    ("rds", "db_subnet_group"): CfnSpec(
        cfn_type="AWS::RDS::DBSubnetGroup",
        attribute_map={
            "name": "DBSubnetGroupName",
            "description": "DBSubnetGroupDescription",
            "subnet_ids": "SubnetIds",
        },
    ),
    ("rds", "db_parameter_group"): CfnSpec(
        cfn_type="AWS::RDS::DBParameterGroup",
        attribute_map={
            "name": "DBParameterGroupName",
            "family": "Family",
            "description": "Description",
            "parameters": lambda v: (
                {"Parameters": {p["name"]: p["value"] for p in v if "name" in p}}
                if isinstance(v, list) else {}
            ),
        },
    ),
    ("rds", "db_cluster_parameter_group"): CfnSpec(
        cfn_type="AWS::RDS::DBClusterParameterGroup",
        attribute_map={
            "name": "DBClusterParameterGroupName",
            "family": "Family",
            "description": "Description",
            "parameters": lambda v: (
                {"Parameters": {p["name"]: p["value"] for p in v if "name" in p}}
                if isinstance(v, list) else {}
            ),
        },
    ),
    ("rds", "db_option_group"): CfnSpec(
        cfn_type="AWS::RDS::OptionGroup",
        attribute_map={
            "name": "OptionGroupName",
            "engine_name": "EngineName",
            "major_engine_version": "MajorEngineVersion",
            "description": "OptionGroupDescription",
        },
    ),
    # --- ELBv2 -------------------------------------------------------------
    ("elbv2", "load_balancer"): CfnSpec(
        cfn_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
        attribute_map={
            "name": "Name",
            "load_balancer_type": "Type",
            "subnets": "Subnets",
            "security_groups": "SecurityGroups",
            "internal": lambda v: (
                {"Scheme": "internal" if v else "internet-facing"}
                if v is not None else {}
            ),
        },
    ),
    ("elbv2", "target_group"): CfnSpec(
        cfn_type="AWS::ElasticLoadBalancingV2::TargetGroup",
        attribute_map={
            "name": "Name",
            "port": "Port",
            "protocol": "Protocol",
            "vpc_id": "VpcId",
            "target_type": "TargetType",
            "health_check": lambda v: (
                _cfn_health_check(v) if isinstance(v, dict) else {}
            ),
        },
    ),
    ("elbv2", "listener"): CfnSpec(
        cfn_type="AWS::ElasticLoadBalancingV2::Listener",
        attribute_map={
            "load_balancer_arn": "LoadBalancerArn",
            "port": "Port",
            "protocol": "Protocol",
            "ssl_policy": "SslPolicy",
            "certificate_arn": lambda v: (
                {"Certificates": [{"CertificateArn": v}]} if v else {}
            ),
            "default_action": lambda v: (
                {"DefaultActions": _cfn_actions(v)} if isinstance(v, list) else {}
            ),
        },
    ),
    ("elbv2", "listener_rule"): CfnSpec(
        cfn_type="AWS::ElasticLoadBalancingV2::ListenerRule",
        attribute_map={
            "listener_arn": "ListenerArn",
            "priority": "Priority",
            "action": lambda v: (
                {"Actions": _cfn_actions(v)} if isinstance(v, list) else {}
            ),
            "condition": lambda v: (
                {"Conditions": _cfn_conditions(v)} if isinstance(v, list) else {}
            ),
        },
    ),
    # --- ECR ---------------------------------------------------------------
    ("ecr", "repository"): CfnSpec(
        cfn_type="AWS::ECR::Repository",
        attribute_map={
            "name": "RepositoryName",
            "image_tag_mutability": "ImageTagMutability",
        },
    ),
    # --- ECS ---------------------------------------------------------------
    ("ecs", "cluster"): CfnSpec(
        cfn_type="AWS::ECS::Cluster",
        attribute_map={
            "name": "ClusterName",
        },
    ),
    ("ecs", "task_definition"): CfnSpec(
        cfn_type="AWS::ECS::TaskDefinition",
        attribute_map={
            "family": "Family",
            "network_mode": "NetworkMode",
            "requires_compatibilities": "RequiresCompatibilities",
            "cpu": "Cpu",
            "memory": "Memory",
            "task_role_arn": "TaskRoleArn",
            "execution_role_arn": "ExecutionRoleArn",
            "container_definitions": "ContainerDefinitions",
            "volume": "Volumes",
        },
    ),
    ("ecs", "service"): CfnSpec(
        cfn_type="AWS::ECS::Service",
        attribute_map={
            "name": "ServiceName",
            "cluster": "Cluster",
            "task_definition": "TaskDefinition",
            "desired_count": "DesiredCount",
            "launch_type": "LaunchType",
            "network_configuration": "NetworkConfiguration",
            "load_balancer": "LoadBalancers",
        },
    ),
    # --- EKS ---------------------------------------------------------------
    ("eks", "cluster"): CfnSpec(
        cfn_type="AWS::EKS::Cluster",
        attribute_map={
            "name": "Name",
            "version": "Version",
            "role_arn": "RoleArn",
        },
        builder="_build_eks_cluster",
    ),
    ("eks", "node_group"): CfnSpec(
        cfn_type="AWS::EKS::Nodegroup",
        attribute_map={
            "cluster_name": "ClusterName",
            "node_group_name": "NodegroupName",
            "node_role_arn": "NodeRole",
            "subnet_ids": "Subnets",
            "instance_types": "InstanceTypes",
            "scaling_config": "ScalingConfig",
        },
    ),
    # --- CloudTrail --------------------------------------------------------
    ("cloudtrail", "trail"): CfnSpec(
        cfn_type="AWS::CloudTrail::Trail",
        attribute_map={
            "name": "TrailName",
            "s3_bucket_name": "S3BucketName",
            "s3_key_prefix": "S3KeyPrefix",
            "include_global_service_events": "IncludeGlobalServiceEvents",
            "is_multi_region_trail": "IsMultiRegionTrail",
            "enable_logging": "IsLogging",
            "enable_log_file_validation": "EnableLogFileValidation",
            "sns_topic_name": "SnsTopicName",
            "cloud_watch_logs_group_arn": "CloudWatchLogsLogGroupArn",
            "cloud_watch_logs_role_arn": "CloudWatchLogsRoleArn",
            "kms_key_id": "KMSKeyId",
        },
        # CloudTrail validates the destination bucket's policy at
        # ``CreateTrail`` — if the bucket policy hasn't been attached
        # yet, AWS returns ``InsufficientS3BucketPolicyException``.
        # Add explicit DependsOn on every BucketPolicy in the template.
        builder="_build_cloudtrail_trail",
    ),
    # --- Firehose ----------------------------------------------------------
    ("firehose", "delivery_stream"): CfnSpec(
        cfn_type="AWS::KinesisFirehose::DeliveryStream",
        attribute_map={
            "name": "DeliveryStreamName",
            "delivery_stream_type": "DeliveryStreamType",
        },
    ),
    # --- Scheduler ---------------------------------------------------------
    ("scheduler", "schedule_group"): CfnSpec(
        cfn_type="AWS::Scheduler::ScheduleGroup",
        attribute_map={"name": "Name"},
    ),
    ("scheduler", "schedule"): CfnSpec(
        cfn_type="AWS::Scheduler::Schedule",
        attribute_map={
            "name": "Name",
            "schedule_expression": "ScheduleExpression",
            "schedule_expression_timezone": "ScheduleExpressionTimezone",
            "state": "State",
            "group_name": "GroupName",
            "description": "Description",
            "flexible_time_window": "FlexibleTimeWindow",
            "target": "Target",
        },
    ),
    # --- Step Functions activity ---------------------------------------------
    ("stepfunctions", "activity"): CfnSpec(
        cfn_type="AWS::StepFunctions::Activity",
        attribute_map={"name": "Name"},
    ),
    # --- EC2 extensions -----------------------------------------------------
    ("ec2", "launch_template"): CfnSpec(
        cfn_type="AWS::EC2::LaunchTemplate",
        attribute_map={},
        builder="_build_ec2_launch_template",
    ),
    ("ec2", "ebs_volume"): CfnSpec(
        cfn_type="AWS::EC2::Volume",
        attribute_map={
            "availability_zone": "AvailabilityZone",
            "size": "Size",
            "type": "VolumeType",
            "iops": "Iops",
            "throughput": "Throughput",
            "encrypted": "Encrypted",
            "kms_key_id": "KmsKeyId",
        },
    ),
    ("ec2", "flow_log"): CfnSpec(
        cfn_type="AWS::EC2::FlowLog",
        attribute_map={
            "log_destination": "LogDestination",
            "log_destination_type": "LogDestinationType",
            "traffic_type": "TrafficType",
            "vpc_id": "ResourceId",
        },
    ),
    # --- Events extensions --------------------------------------------------
    ("events", "archive"): CfnSpec(
        cfn_type="AWS::Events::Archive",
        attribute_map={
            "name": "ArchiveName",
            "event_source_arn": "SourceArn",
            "description": "Description",
            "event_pattern": "EventPattern",
            "retention_days": "RetentionDays",
        },
    ),
    ("events", "connection"): CfnSpec(
        cfn_type="AWS::Events::Connection",
        attribute_map={
            "name": "Name",
            "description": "Description",
            "authorization_type": "AuthorizationType",
        },
        # AuthParameters is required by AWS::Events::Connection and uses a
        # different field shape than the snake_case TF representation the
        # collector produces; convert in the CFN builder.
        builder="_build_events_connection",
    ),
    ("events", "api_destination"): CfnSpec(
        cfn_type="AWS::Events::ApiDestination",
        attribute_map={
            "name": "Name",
            "description": "Description",
            "invocation_endpoint": "InvocationEndpoint",
            "http_method": "HttpMethod",
            "connection_arn": "ConnectionArn",
            "invocation_rate_limit_per_second": "InvocationRateLimitPerSecond",
        },
    ),
    # --- Redshift extensions ------------------------------------------------
    ("redshift", "parameter_group"): CfnSpec(
        cfn_type="AWS::Redshift::ClusterParameterGroup",
        attribute_map={
            "name": "ParameterGroupName",
            "family": "ParameterGroupFamily",
            "description": "Description",
        },
    ),
    # --- EC2 more -----------------------------------------------------------
    ("ec2", "placement_group"): CfnSpec(
        cfn_type="AWS::EC2::PlacementGroup",
        attribute_map={
            "strategy": "Strategy",
        },
    ),
    # --- EC2 more networking ------------------------------------------------
    ("ec2", "transit_gateway"): CfnSpec(
        cfn_type="AWS::EC2::TransitGateway",
        attribute_map={
            "description": "Description",
            "amazon_side_asn": "AmazonSideAsn",
            "auto_accept_shared_attachments": "AutoAcceptSharedAttachments",
            "default_route_table_association": "DefaultRouteTableAssociation",
            "default_route_table_propagation": "DefaultRouteTablePropagation",
            "dns_support": "DnsSupport",
        },
    ),
    ("ec2", "transit_gateway_vpc_attachment"): CfnSpec(
        cfn_type="AWS::EC2::TransitGatewayVpcAttachment",
        attribute_map={
            "transit_gateway_id": "TransitGatewayId",
            "vpc_id": "VpcId",
            "subnet_ids": "SubnetIds",
        },
    ),
    ("ec2", "dhcp_options"): CfnSpec(
        cfn_type="AWS::EC2::DHCPOptions",
        attribute_map={
            "domain_name": "DomainName",
            "domain_name_servers": "DomainNameServers",
            "ntp_servers": "NtpServers",
            "netbios_name_servers": "NetbiosNameServers",
            "netbios_node_type": "NetbiosNodeType",
        },
    ),
    ("ec2", "network_interface"): CfnSpec(
        cfn_type="AWS::EC2::NetworkInterface",
        attribute_map={
            "subnet_id": "SubnetId",
            "description": "Description",
            "private_ips": "PrivateIpAddresses",
            "security_groups": "GroupSet",
        },
    ),
    # --- Resource Groups ----------------------------------------------------
    ("resource_groups", "group"): CfnSpec(
        cfn_type="AWS::ResourceGroups::Group",
        attribute_map={
            "name": "Name",
            "description": "Description",
        },
    ),
    # --- API Gateway v1 extensions ------------------------------------------
    ("apigateway", "stage"): CfnSpec(
        cfn_type="AWS::ApiGateway::Stage",
        attribute_map={
            "rest_api_id": "RestApiId",
            "stage_name": "StageName",
            "deployment_id": "DeploymentId",
            "description": "Description",
        },
    ),
    ("apigateway", "authorizer"): CfnSpec(
        cfn_type="AWS::ApiGateway::Authorizer",
        attribute_map={
            "rest_api_id": "RestApiId",
            "name": "Name",
            "type": "Type",
            "authorizer_uri": "AuthorizerUri",
            "authorizer_credentials": "AuthorizerCredentials",
            "identity_source": "IdentitySource",
        },
    ),
    ("apigateway", "api_key"): CfnSpec(
        cfn_type="AWS::ApiGateway::ApiKey",
        attribute_map={
            "name": "Name",
            "description": "Description",
            "enabled": "Enabled",
        },
    ),
    ("apigateway", "usage_plan"): CfnSpec(
        cfn_type="AWS::ApiGateway::UsagePlan",
        attribute_map={
            "name": "UsagePlanName",
            "description": "Description",
        },
    ),
    # NOTE: no CFN spec for ``("apigateway", "integration")`` — CFN does
    # not expose ``AWS::ApiGateway::Integration`` as a standalone type
    # (Terraform does, via ``aws_api_gateway_integration``). The CFN
    # writer reads the integration data inline off the parent
    # ``apigateway.method`` IR resource via
    # ``_build_apigateway_method``.
    ("apigateway", "deployment"): CfnSpec(
        cfn_type="AWS::ApiGateway::Deployment",
        attribute_map={
            "rest_api_id": "RestApiId",
            "description": "Description",
        },
        # AWS::ApiGateway::Deployment fails with "The REST API doesn't
        # contain any methods" if it gets created before the methods
        # exist. We add explicit DependsOn for every method on the same
        # API in the builder.
        builder="_build_apigateway_deployment",
    ),
    ("apigateway", "gateway_response"): CfnSpec(
        cfn_type="AWS::ApiGateway::GatewayResponse",
        attribute_map={
            "rest_api_id": "RestApiId",
            "response_type": "ResponseType",
            "status_code": "StatusCode",
            "response_parameters": "ResponseParameters",
            "response_templates": "ResponseTemplates",
        },
    ),
    ("apigateway", "model"): CfnSpec(
        cfn_type="AWS::ApiGateway::Model",
        attribute_map={
            "rest_api_id": "RestApiId",
            "name": "Name",
            "content_type": "ContentType",
            "schema": "Schema",
            "description": "Description",
        },
    ),
    ("apigateway", "request_validator"): CfnSpec(
        cfn_type="AWS::ApiGateway::RequestValidator",
        attribute_map={
            "rest_api_id": "RestApiId",
            "name": "Name",
            "validate_request_body": "ValidateRequestBody",
            "validate_request_parameters": "ValidateRequestParameters",
        },
    ),
    # --- RDS extensions -----------------------------------------------------
    ("rds", "db_event_subscription"): CfnSpec(
        cfn_type="AWS::RDS::EventSubscription",
        attribute_map={
            "sns_topic": "SnsTopicArn",
            "source_type": "SourceType",
            "event_categories": "EventCategories",
            "enabled": "Enabled",
        },
    ),
    # --- EC2 VPN family -----------------------------------------------------
    ("ec2", "customer_gateway"): CfnSpec(
        cfn_type="AWS::EC2::CustomerGateway",
        attribute_map={
            "bgp_asn": "BgpAsn",
            "ip_address": "IpAddress",
            "type": "Type",
        },
    ),
    ("ec2", "vpn_gateway"): CfnSpec(
        cfn_type="AWS::EC2::VPNGateway",
        attribute_map={
            "type": "Type",
            "amazon_side_asn": "AmazonSideAsn",
        },
    ),
    ("ec2", "vpn_connection"): CfnSpec(
        cfn_type="AWS::EC2::VPNConnection",
        attribute_map={
            "customer_gateway_id": "CustomerGatewayId",
            "vpn_gateway_id": "VpnGatewayId",
            "transit_gateway_id": "TransitGatewayId",
            "type": "Type",
            "static_routes_only": "StaticRoutesOnly",
        },
    ),
    ("apigateway", "vpc_link"): CfnSpec(
        cfn_type="AWS::ApiGateway::VpcLink",
        attribute_map={
            "name": "Name",
            "description": "Description",
            "target_arns": "TargetArns",
        },
    ),
    ("apigateway", "domain_name"): CfnSpec(
        cfn_type="AWS::ApiGateway::DomainName",
        attribute_map={
            "domain_name": "DomainName",
            "certificate_arn": "CertificateArn",
            "regional_certificate_arn": "RegionalCertificateArn",
            "security_policy": "SecurityPolicy",
        },
    ),
    # --- Cognito identity_pool -----------------------------------------------
    ("cognito", "identity_pool"): CfnSpec(
        cfn_type="AWS::Cognito::IdentityPool",
        attribute_map={
            "identity_pool_name": "IdentityPoolName",
            "allow_unauthenticated_identities": "AllowUnauthenticatedIdentities",
            "allow_classic_flow": "AllowClassicFlow",
        },
    ),
    # --- IAM access_key -----------------------------------------------------
    ("iam", "access_key"): CfnSpec(
        cfn_type="AWS::IAM::AccessKey",
        attribute_map={
            "user": "UserName",
            "status": "Status",
        },
    ),
    # --- CloudWatch extensions ----------------------------------------------
    ("cloudwatch", "dashboard"): CfnSpec(
        cfn_type="AWS::CloudWatch::Dashboard",
        attribute_map={
            "dashboard_name": "DashboardName",
            "dashboard_body": "DashboardBody",
        },
    ),
    ("cloudwatch", "alarm"): CfnSpec(
        cfn_type="AWS::CloudWatch::Alarm",
        attribute_map={
            "name": "AlarmName",
            "alarm_name": "AlarmName",
            "description": "AlarmDescription",
            "alarm_description": "AlarmDescription",
            "comparison_operator": "ComparisonOperator",
            "evaluation_periods": "EvaluationPeriods",
            "metric_name": "MetricName",
            "namespace": "Namespace",
            "period": "Period",
            "statistic": "Statistic",
            "threshold": "Threshold",
            "actions_enabled": "ActionsEnabled",
            "treat_missing_data": "TreatMissingData",
        },
    ),
    # --- Logs extensions ----------------------------------------------------
    ("logs", "metric_filter"): CfnSpec(
        cfn_type="AWS::Logs::MetricFilter",
        attribute_map={
            "name": "FilterName",
            "log_group_name": "LogGroupName",
            "pattern": "FilterPattern",
            "metric_transformation": "MetricTransformations",
        },
    ),
    ("logs", "subscription_filter"): CfnSpec(
        cfn_type="AWS::Logs::SubscriptionFilter",
        attribute_map={
            "name": "FilterName",
            "log_group_name": "LogGroupName",
            "filter_pattern": "FilterPattern",
            "destination_arn": "DestinationArn",
            "role_arn": "RoleArn",
        },
    ),
    # --- ConfigService ------------------------------------------------------
    ("configservice", "configuration_recorder"): CfnSpec(
        cfn_type="AWS::Config::ConfigurationRecorder",
        attribute_map={
            "name": "Name",
            "role_arn": "RoleARN",
            "recording_group": "RecordingGroup",
        },
    ),
    ("configservice", "config_rule"): CfnSpec(
        cfn_type="AWS::Config::ConfigRule",
        attribute_map={
            "name": "ConfigRuleName",
            "description": "Description",
            "source": "Source",
            "scope": "Scope",
            "input_parameters": "InputParameters",
            "maximum_execution_frequency": "MaximumExecutionFrequency",
        },
    ),
    # --- SSM document -------------------------------------------------------
    ("ssm", "document"): CfnSpec(
        cfn_type="AWS::SSM::Document",
        attribute_map={
            "name": "Name",
            "document_type": "DocumentType",
            "content": "Content",
            "document_format": "DocumentFormat",
        },
    ),
    ("ssm", "maintenance_window"): CfnSpec(
        cfn_type="AWS::SSM::MaintenanceWindow",
        attribute_map={
            "name": "Name",
            "schedule": "Schedule",
            "duration": "Duration",
            "cutoff": "Cutoff",
            "allow_unassociated_targets": "AllowUnassociatedTargets",
            "description": "Description",
            "schedule_timezone": "ScheduleTimezone",
            "schedule_offset": "ScheduleOffset",
            "start_date": "StartDate",
            "end_date": "EndDate",
        },
    ),
    # --- SecretsManager extensions ------------------------------------------
    ("secretsmanager", "secret_policy"): CfnSpec(
        cfn_type="AWS::SecretsManager::ResourcePolicy",
        attribute_map={
            "secret_arn": "SecretId",
            "policy": "ResourcePolicy",
        },
    ),
    # --- Kinesis -----------------------------------------------------------
    ("kinesis", "stream"): CfnSpec(
        cfn_type="AWS::Kinesis::Stream",
        attribute_map={
            "stream_name": "Name",
            "name": "Name",
            "shard_count": "ShardCount",
            "retention_period": "RetentionPeriodHours",
            "stream_encryption": "StreamEncryption",
            "stream_mode_details": "StreamModeDetails",
        },
    ),
    ("kinesis", "stream_consumer"): CfnSpec(
        cfn_type="AWS::Kinesis::StreamConsumer",
        attribute_map={
            "name": "ConsumerName",
            "stream_arn": "StreamARN",
        },
    ),
    # --- Route53Resolver ----------------------------------------------------
    ("route53resolver", "endpoint"): CfnSpec(
        cfn_type="AWS::Route53Resolver::ResolverEndpoint",
        attribute_map={
            "name": "Name",
            "direction": "Direction",
            "security_group_ids": "SecurityGroupIds",
            "ip_address": "IpAddresses",
        },
    ),
    ("route53resolver", "rule"): CfnSpec(
        cfn_type="AWS::Route53Resolver::ResolverRule",
        attribute_map={
            "name": "Name",
            "domain_name": "DomainName",
            "rule_type": "RuleType",
            "resolver_endpoint_id": "ResolverEndpointId",
            "target_ip": "TargetIps",
        },
    ),
    ("route53resolver", "rule_association"): CfnSpec(
        cfn_type="AWS::Route53Resolver::ResolverRuleAssociation",
        attribute_map={
            "name": "Name",
            "resolver_rule_id": "ResolverRuleId",
            "vpc_id": "VPCId",
        },
    ),
    # --- Redshift security_group: removed — deprecated in modern AWS.
    # --- CloudFront --------------------------------------------------------
    ("cloudfront", "distribution"): CfnSpec(
        cfn_type="AWS::CloudFront::Distribution",
        attribute_map={},
        builder="_build_cloudfront_distribution",
    ),
    # --- Redshift ----------------------------------------------------------
    ("redshift", "cluster"): CfnSpec(
        cfn_type="AWS::Redshift::Cluster",
        attribute_map={
            "cluster_identifier": "ClusterIdentifier",
            "node_type": "NodeType",
            "number_of_nodes": "NumberOfNodes",
            "master_username": "MasterUsername",
            "master_password": "MasterUserPassword",
            "database_name": "DBName",
            "cluster_type": "ClusterType",
            "cluster_subnet_group_name": "ClusterSubnetGroupName",
        },
    ),
    ("redshift", "subnet_group"): CfnSpec(
        cfn_type="AWS::Redshift::ClusterSubnetGroup",
        attribute_map={
            "description": "Description",
            "subnet_ids": "SubnetIds",
        },
    ),
    # --- S3 extensions ------------------------------------------------------
    ("s3", "bucket_policy"): CfnSpec(
        cfn_type="AWS::S3::BucketPolicy",
        attribute_map={
            "bucket": "Bucket",
            "policy": "PolicyDocument",
        },
    ),
    # --- SQS extensions -----------------------------------------------------
    ("sqs", "queue_policy"): CfnSpec(
        cfn_type="AWS::SQS::QueuePolicy",
        attribute_map={
            "policy": "PolicyDocument",
        },
        # ``AWS::SQS::QueuePolicy.Queues`` is a LIST of queue URLs, not a
        # scalar — the attribute_map flat mapping cannot express that, so
        # we wrap it in a builder.
        builder="_build_sqs_queue_policy",
    ),
    # --- Lambda extensions --------------------------------------------------
    ("lambda", "alias"): CfnSpec(
        cfn_type="AWS::Lambda::Alias",
        attribute_map={
            "name": "Name",
            "function_name": "FunctionName",
            "function_version": "FunctionVersion",
            "description": "Description",
        },
        builder="_build_lambda_alias",
    ),
    ("lambda", "permission"): CfnSpec(
        cfn_type="AWS::Lambda::Permission",
        attribute_map={
            "function_name": "FunctionName",
            "action": "Action",
            "principal": "Principal",
            "source_arn": "SourceArn",
        },
        emit_tags=False,
    ),
    ("lambda", "event_source_mapping"): CfnSpec(
        cfn_type="AWS::Lambda::EventSourceMapping",
        attribute_map={
            "event_source_arn": "EventSourceArn",
            "function_name": "FunctionName",
            "batch_size": "BatchSize",
            "enabled": "Enabled",
            "starting_position": "StartingPosition",
        },
        emit_tags=False,
    ),
    ("lambda", "layer_version"): CfnSpec(
        cfn_type="AWS::Lambda::LayerVersion",
        attribute_map={
            "layer_name": "LayerName",
            "compatible_runtimes": "CompatibleRuntimes",
            "description": "Description",
        },
    ),
    # --- API Gateway v2 ----------------------------------------------------
    ("apigatewayv2", "api"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Api",
        attribute_map={
            "name": "Name",
            "protocol_type": "ProtocolType",
            "description": "Description",
            "route_selection_expression": "RouteSelectionExpression",
            "cors_configuration": "CorsConfiguration",
        },
    ),
    ("apigatewayv2", "stage"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Stage",
        attribute_map={
            "api_id": "ApiId",
            "name": "StageName",
            "auto_deploy": "AutoDeploy",
            "description": "Description",
        },
    ),
    ("apigatewayv2", "route"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Route",
        attribute_map={
            "api_id": "ApiId",
            "route_key": "RouteKey",
            "target": "Target",
        },
    ),
    ("apigatewayv2", "integration"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Integration",
        attribute_map={
            "api_id": "ApiId",
            "integration_type": "IntegrationType",
            "integration_uri": "IntegrationUri",
            "integration_method": "IntegrationMethod",
            "payload_format_version": "PayloadFormatVersion",
        },
    ),
    # --- Lambda function_url ------------------------------------------------
    ("lambda", "function_url"): CfnSpec(
        cfn_type="AWS::Lambda::Url",
        attribute_map={
            "function_name": "TargetFunctionArn",
            "authorization_type": "AuthType",
            "cors": "Cors",
        },
        emit_tags=False,
    ),
    # --- API Gateway v2 extensions ------------------------------------------
    ("apigatewayv2", "authorizer"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Authorizer",
        attribute_map={
            "api_id": "ApiId",
            "name": "Name",
            "authorizer_type": "AuthorizerType",
            "identity_sources": "IdentitySource",
            "authorizer_uri": "AuthorizerUri",
        },
    ),
    ("apigatewayv2", "deployment"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::Deployment",
        attribute_map={
            "api_id": "ApiId",
            "description": "Description",
        },
    ),
    ("apigatewayv2", "domain_name"): CfnSpec(
        cfn_type="AWS::ApiGatewayV2::DomainName",
        attribute_map={
            "domain_name": "DomainName",
        },
    ),
    # --- Cognito extensions -------------------------------------------------
    ("cognito", "user_pool_domain"): CfnSpec(
        cfn_type="AWS::Cognito::UserPoolDomain",
        attribute_map={
            "domain": "Domain",
            "user_pool_id": "UserPoolId",
        },
    ),
    ("cognito", "identity_provider"): CfnSpec(
        cfn_type="AWS::Cognito::UserPoolIdentityProvider",
        attribute_map={
            "user_pool_id": "UserPoolId",
            "provider_name": "ProviderName",
            "provider_type": "ProviderType",
            "provider_details": "ProviderDetails",
            "attribute_mapping": "AttributeMapping",
        },
    ),
    ("cognito", "user_group"): CfnSpec(
        cfn_type="AWS::Cognito::UserPoolGroup",
        attribute_map={
            "name": "GroupName",
            "user_pool_id": "UserPoolId",
            "description": "Description",
            "role_arn": "RoleArn",
            "precedence": "Precedence",
        },
    ),
    # --- SES extensions -----------------------------------------------------
    ("ses", "receipt_rule_set"): CfnSpec(
        cfn_type="AWS::SES::ReceiptRuleSet",
        attribute_map={"rule_set_name": "RuleSetName"},
    ),
    # --- Cognito -----------------------------------------------------------
    ("cognito", "user_pool"): CfnSpec(
        cfn_type="AWS::Cognito::UserPool",
        attribute_map={
            "name": "UserPoolName",
            "auto_verified_attributes": "AutoVerifiedAttributes",
            "username_attributes": "UsernameAttributes",
            "mfa_configuration": "MfaConfiguration",
        },
    ),
    ("cognito", "user_pool_client"): CfnSpec(
        cfn_type="AWS::Cognito::UserPoolClient",
        attribute_map={
            "name": "ClientName",
            "user_pool_id": "UserPoolId",
            "explicit_auth_flows": "ExplicitAuthFlows",
            "generate_secret": "GenerateSecret",
            "allowed_oauth_flows": "AllowedOAuthFlows",
            "allowed_oauth_scopes": "AllowedOAuthScopes",
            "callback_urls": "CallbackURLs",
            "logout_urls": "LogoutURLs",
            "supported_identity_providers": "SupportedIdentityProviders",
        },
    ),
    # --- SES ---------------------------------------------------------------
    ("ses", "email_identity"): CfnSpec(
        cfn_type="AWS::SES::EmailIdentity",
        attribute_map={"email_identity": "EmailIdentity"},
    ),
    ("ses", "template"): CfnSpec(
        cfn_type="AWS::SES::Template",
        attribute_map={},
        builder="_build_ses_template",
    ),
    ("ses", "configuration_set"): CfnSpec(
        cfn_type="AWS::SES::ConfigurationSet",
        attribute_map={"name": "Name"},
    ),
    # --- Route53 -----------------------------------------------------------
    ("route53", "zone"): CfnSpec(
        cfn_type="AWS::Route53::HostedZone",
        attribute_map={
            "name": "Name",
            "comment": "HostedZoneConfig",
        },
        builder="_build_route53_zone",
    ),
    ("route53", "record"): CfnSpec(
        cfn_type="AWS::Route53::RecordSet",
        attribute_map={
            "name": "Name",
            "type": "Type",
            "ttl": "TTL",
            "records": "ResourceRecords",
        },
        builder="_build_route53_record",
    ),
    ("route53", "health_check"): CfnSpec(
        cfn_type="AWS::Route53::HealthCheck",
        attribute_map={},
        builder="_build_route53_health_check",
    ),
    # --- ACM ---------------------------------------------------------------
    ("acm", "certificate"): CfnSpec(
        cfn_type="AWS::CertificateManager::Certificate",
        attribute_map={
            "domain_name": "DomainName",
            "subject_alternative_names": "SubjectAlternativeNames",
            "validation_method": "ValidationMethod",
        },
    ),
}


def _cfn_health_check(block: dict[str, Any]) -> dict[str, Any]:
    """Translate a TF-style ``health_check`` block into CFN properties."""
    props: dict[str, Any] = {}
    mapping = {
        "protocol": "HealthCheckProtocol",
        "port": "HealthCheckPort",
        "path": "HealthCheckPath",
        "interval": "HealthCheckIntervalSeconds",
        "timeout": "HealthCheckTimeoutSeconds",
        "healthy_threshold": "HealthyThresholdCount",
        "unhealthy_threshold": "UnhealthyThresholdCount",
        "enabled": "HealthCheckEnabled",
    }
    for src, dst in mapping.items():
        if src in block and block[src] is not None:
            props[dst] = block[src]
    return props


def _cfn_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for act in actions:
        if not isinstance(act, dict):
            continue
        entry: dict[str, Any] = {"Type": act.get("type") or "forward"}
        tg = act.get("target_group_arn")
        if tg is not None:
            entry["TargetGroupArn"] = tg
        out.append(entry)
    return out


def _cfn_conditions(conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cond in conditions:
        if not isinstance(cond, dict):
            continue
        if "path_pattern" in cond:
            out.append(
                {
                    "Field": "path-pattern",
                    "Values": list(
                        cond["path_pattern"].get("values") or []
                    ),
                }
            )
        elif "host_header" in cond:
            out.append(
                {
                    "Field": "host-header",
                    "Values": list(cond["host_header"].get("values") or []),
                }
            )
        elif "http_header" in cond:
            hh = cond["http_header"]
            out.append(
                {
                    "Field": "http-header",
                    "HttpHeaderConfig": {
                        "HttpHeaderName": hh.get("http_header_name"),
                        "Values": list(hh.get("values") or []),
                    },
                }
            )
    return out


def get_spec(service: str, resource_type: str) -> CfnSpec | None:
    """Return the :class:`CfnSpec` for ``(service, resource_type)`` or None.

    A ``None`` return means the writer should skip the resource (and emit
    a warning) rather than guess at a CFN type.
    """
    return CFN_SPECS.get((service, resource_type))


# ---------------------------------------------------------------------------
# Default (attribute_map-driven) Properties builder
# ---------------------------------------------------------------------------


def apply_attribute_map(
    spec: CfnSpec,
    resource: Resource,
    value_transformer: Callable[[Any], Any],
) -> dict[str, Any]:
    """Apply ``spec.attribute_map`` to ``resource.attributes``.

    Each :class:`Ref` instance inside the attribute tree is transformed via
    ``value_transformer`` (supplied by the writer, which knows the current
    logical-id table). Unknown attributes are dropped. Callable map entries
    may return either a ``dict`` (merged into Properties) or a scalar (in
    which case they are treated like string-rename entries).

    Returns a fresh dict — the caller owns it and can further mutate it.
    """
    props: dict[str, Any] = {}
    for ir_key, value in resource.attributes.items():
        mapping = spec.attribute_map.get(ir_key)
        if mapping is None:
            continue
        resolved_value = _walk_refs(value, value_transformer)
        if callable(mapping):
            expanded = mapping(resolved_value)
            if isinstance(expanded, dict):
                props.update(expanded)
            elif expanded is not None:
                # Callable returned a scalar — infer the CFN key by
                # capitalising the IR key (fallback; callers should prefer
                # returning a dict).
                props[_snake_to_pascal(ir_key)] = expanded
        else:
            if resolved_value is None:
                continue
            props[mapping] = resolved_value
    return props


def _walk_refs(value: Any, transformer: Callable[[Any], Any]) -> Any:
    """Recursively apply ``transformer`` to any :class:`Ref` leaves.

    Non-Ref scalars are returned unchanged; dicts and lists are walked
    (returning new containers) so the writer can freely mutate the output.
    """
    if isinstance(value, Ref):
        return transformer(value)
    if isinstance(value, dict):
        return {k: _walk_refs(v, transformer) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_refs(v, transformer) for v in value]
    return value


def _snake_to_pascal(name: str) -> str:
    """Convert ``snake_case`` to ``PascalCase`` (fallback key inference)."""
    return "".join(part[:1].upper() + part[1:] for part in name.split("_") if part)


# ---------------------------------------------------------------------------
# Lambda code helper (used by cloudformation.py builder)
# ---------------------------------------------------------------------------


def classify_lambda_code(
    code_value: Any,
) -> tuple[str, Any]:
    """Decide how to emit a Lambda function's ``Code`` property.

    Returns a tuple ``(mode, payload)`` where ``mode`` is one of:

    * ``"inline"`` — ``payload`` is a UTF-8 string to drop into
      ``Code.ZipFile`` (only for very small, text-only artefacts).
    * ``"sidecar"`` — ``payload`` is the raw ``bytes`` of the zip; the
      writer must stash it in ``stack-assets/`` and emit an
      S3Bucket/S3Key placeholder pointing at it.
    * ``"placeholder"`` — ``payload`` is ``None``; no usable code was
      available, emit a REPLACE_ME placeholder with a Metadata note.

    ``code_value`` can be a base64 string, raw ``bytes``, or ``None``.
    """
    if code_value is None:
        return "placeholder", None
    raw: bytes | None = None
    if isinstance(code_value, bytes):
        raw = code_value
    elif isinstance(code_value, str):
        # Prefer base64 decoding; fall back to UTF-8 treat-as-bytes.
        try:
            raw = base64.b64decode(code_value, validate=True)
        except Exception:
            raw = code_value.encode("utf-8", errors="replace")
    else:
        return "placeholder", None

    if raw is None:
        return "placeholder", None

    # Inline is only appropriate for small, plausibly-text payloads.
    # Zip files start with ``PK\x03\x04`` and are never valid inline source,
    # so they always take the sidecar path regardless of size.
    if len(raw) < LAMBDA_INLINE_CODE_MAX_BYTES and not raw.startswith(b"PK\x03\x04"):
        try:
            return "inline", raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return "sidecar", raw


__all__ = [
    "CFN_SPECS",
    "CfnSpec",
    "LAMBDA_INLINE_CODE_MAX_BYTES",
    "apply_attribute_map",
    "classify_lambda_code",
    "get_spec",
]
