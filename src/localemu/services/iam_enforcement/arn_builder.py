"""Service-specific resource ARN construction.

Builds the best-effort resource ARN from the request context for IAM
policy evaluation. Each service has its own ARN format.
"""


def build_resource_arn(
    service: str,
    operation: str,
    request_params: dict | None,
    region: str,
    account_id: str,
) -> str:
    """Build a resource ARN from the request context.

    Args:
        service: AWS service name (e.g., "s3", "dynamodb")
        operation: API operation name (e.g., "PutObject", "PutItem")
        request_params: Parsed service request parameters
        region: AWS region
        account_id: AWS account ID

    Returns:
        Best-effort resource ARN string
    """
    params = request_params or {}

    builder = _SERVICE_ARN_BUILDERS.get(service)
    if builder:
        return builder(params, region, account_id)

    # Generic fallback: build best-effort ARN from common parameter names
    # Try to find a resource identifier rather than using a wildcard
    for key in ("Name", "Id", "Arn", "ResourceArn", "FunctionName",
                "RoleName", "UserName", "PolicyArn", "GroupName",
                "InstanceId", "BucketName", "StreamName", "ClusterName",
                "TableName", "TopicArn", "QueueUrl", "RepositoryName",
                "CertificateArn", "DomainName", "HostedZoneId",
                "LoadBalancerArn", "TargetGroupArn", "ApiId"):
        val = params.get(key)
        if val and isinstance(val, str):
            if val.startswith("arn:"):
                return val
            return f"arn:aws:{service}:{region}:{account_id}:{val}"
    return f"arn:aws:{service}:{region}:{account_id}:*"


def _s3_arn(params: dict, region: str, account_id: str) -> str:
    bucket = params.get("Bucket", "*")
    key = params.get("Key", "")
    if key:
        return f"arn:aws:s3:::{bucket}/{key}"
    return f"arn:aws:s3:::{bucket}"


def _dynamodb_arn(params: dict, region: str, account_id: str) -> str:
    table = params.get("TableName", "*")
    return f"arn:aws:dynamodb:{region}:{account_id}:table/{table}"


def _lambda_arn(params: dict, region: str, account_id: str) -> str:
    func = params.get("FunctionName", "*")
    # If it's already an ARN, return it
    if func.startswith("arn:"):
        return func
    return f"arn:aws:lambda:{region}:{account_id}:function:{func}"


def _sqs_arn(params: dict, region: str, account_id: str) -> str:
    queue_url = params.get("QueueUrl", "")
    if queue_url:
        queue_name = queue_url.rstrip("/").split("/")[-1]
        return f"arn:aws:sqs:{region}:{account_id}:{queue_name}"
    queue_name = params.get("QueueName", "*")
    return f"arn:aws:sqs:{region}:{account_id}:{queue_name}"


def _sns_arn(params: dict, region: str, account_id: str) -> str:
    topic_arn = params.get("TopicArn", params.get("TargetArn", ""))
    if topic_arn:
        return topic_arn
    topic_name = params.get("Name", "*")
    return f"arn:aws:sns:{region}:{account_id}:{topic_name}"


def _kms_arn(params: dict, region: str, account_id: str) -> str:
    key_id = params.get("KeyId", "*")
    if key_id.startswith("arn:"):
        return key_id
    return f"arn:aws:kms:{region}:{account_id}:key/{key_id}"


def _secretsmanager_arn(params: dict, region: str, account_id: str) -> str:
    secret_id = params.get("SecretId", "*")
    if secret_id.startswith("arn:"):
        return secret_id
    return f"arn:aws:secretsmanager:{region}:{account_id}:secret:{secret_id}"


def _ec2_arn(params: dict, region: str, account_id: str) -> str:
    # EC2 has many resource types. Try common patterns.
    for key in ("InstanceId", "InstanceIds"):
        val = params.get(key)
        if val:
            instance_id = val[0] if isinstance(val, list) else val
            return f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    for key in ("SecurityGroupId", "GroupId"):
        val = params.get(key)
        if val:
            return f"arn:aws:ec2:{region}:{account_id}:security-group/{val}"
    return f"arn:aws:ec2:{region}:{account_id}:*"


def _ecs_arn(params: dict, region: str, account_id: str) -> str:
    cluster = params.get("cluster", "default")
    task_def = params.get("taskDefinition", "")
    if task_def:
        return f"arn:aws:ecs:{region}:{account_id}:task-definition/{task_def}"
    service_name = params.get("serviceName", "")
    if service_name:
        return f"arn:aws:ecs:{region}:{account_id}:service/{cluster}/{service_name}"
    return f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster}"


def _logs_arn(params: dict, region: str, account_id: str) -> str:
    log_group = params.get("logGroupName", "*")
    return f"arn:aws:logs:{region}:{account_id}:log-group:{log_group}"


def _events_arn(params: dict, region: str, account_id: str) -> str:
    rule_name = params.get("Name", "")
    event_bus = params.get("EventBusName", "default")
    if rule_name:
        return f"arn:aws:events:{region}:{account_id}:rule/{event_bus}/{rule_name}"
    return f"arn:aws:events:{region}:{account_id}:event-bus/{event_bus}"


def _states_arn(params: dict, region: str, account_id: str) -> str:
    sm_arn = params.get("stateMachineArn", "")
    if sm_arn:
        return sm_arn
    name = params.get("name", "*")
    return f"arn:aws:states:{region}:{account_id}:stateMachine:{name}"


def _rds_arn(params: dict, region: str, account_id: str) -> str:
    db_id = params.get("DBInstanceIdentifier", "*")
    return f"arn:aws:rds:{region}:{account_id}:db:{db_id}"


def _kinesis_arn(params: dict, region: str, account_id: str) -> str:
    stream = params.get("StreamName", params.get("StreamARN", "*"))
    if stream.startswith("arn:"):
        return stream
    return f"arn:aws:kinesis:{region}:{account_id}:stream/{stream}"


def _ssm_arn(params: dict, region: str, account_id: str) -> str:
    name = params.get("Name", "*")
    return f"arn:aws:ssm:{region}:{account_id}:parameter/{name.lstrip('/')}"


def _cloudformation_arn(params: dict, region: str, account_id: str) -> str:
    stack_name = params.get("StackName", "*")
    if stack_name.startswith("arn:"):
        return stack_name
    return f"arn:aws:cloudformation:{region}:{account_id}:stack/{stack_name}/*"


def _iam_arn(params: dict, region: str, account_id: str) -> str:
    """Build ARN for IAM resources (users, roles, policies, groups)."""
    user_name = params.get("UserName")
    if user_name:
        return f"arn:aws:iam::{account_id}:user/{user_name}"
    role_name = params.get("RoleName")
    if role_name:
        return f"arn:aws:iam::{account_id}:role/{role_name}"
    policy_arn = params.get("PolicyArn")
    if policy_arn:
        return policy_arn
    group_name = params.get("GroupName")
    if group_name:
        return f"arn:aws:iam::{account_id}:group/{group_name}"
    instance_profile = params.get("InstanceProfileName")
    if instance_profile:
        return f"arn:aws:iam::{account_id}:instance-profile/{instance_profile}"
    return f"arn:aws:iam::{account_id}:*"


def _sts_arn(params: dict, region: str, account_id: str) -> str:
    """Build ARN for STS resources."""
    role_arn = params.get("RoleArn")
    if role_arn:
        return role_arn
    return f"arn:aws:sts::{account_id}:*"


def _cognito_arn(params: dict, region: str, account_id: str) -> str:
    pool_id = params.get("UserPoolId") or params.get("IdentityPoolId", "*")
    if pool_id.startswith("arn:"):
        return pool_id
    return f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{pool_id}"


def _apigateway_arn(params: dict, region: str, account_id: str) -> str:
    rest_api_id = params.get("restApiId") or params.get("ApiId", "*")
    return f"arn:aws:apigateway:{region}::/restapis/{rest_api_id}"


def _cloudwatch_arn(params: dict, region: str, account_id: str) -> str:
    alarm_name = params.get("AlarmName")
    if alarm_name:
        return f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}"
    dashboard = params.get("DashboardName")
    if dashboard:
        return f"arn:aws:cloudwatch::{account_id}:dashboard/{dashboard}"
    return f"arn:aws:cloudwatch:{region}:{account_id}:*"


def _elasticache_arn(params: dict, region: str, account_id: str) -> str:
    cluster_id = params.get("CacheClusterId") or params.get("ReplicationGroupId", "*")
    return f"arn:aws:elasticache:{region}:{account_id}:cluster:{cluster_id}"


def _route53_arn(params: dict, region: str, account_id: str) -> str:
    zone_id = params.get("HostedZoneId") or params.get("Id", "*")
    # Route53 returns zone IDs as "/hostedzone/ZZZZZ" but accepts bare "ZZZZZ"
    # too. str.lstrip("/hostedzone/") would strip any character in that set and
    # mangle IDs like "hosted-zone-x" — use removeprefix for a true prefix strip.
    zone_id = zone_id.removeprefix("/hostedzone/")
    return f"arn:aws:route53:::hostedzone/{zone_id}"


def _acm_arn(params: dict, region: str, account_id: str) -> str:
    cert_arn = params.get("CertificateArn")
    if cert_arn:
        return cert_arn
    return f"arn:aws:acm:{region}:{account_id}:certificate/*"


def _cloudfront_arn(params: dict, region: str, account_id: str) -> str:
    """CloudFront is a global service — ARNs have no region segment.

    Shapes produced:
      - Distribution:        ``arn:aws:cloudfront::<acct>:distribution/<id>``
      - Origin Access Control: ``arn:aws:cloudfront::<acct>:origin-access-control/<id>``
      - Cache policy, OAC, etc. follow the same ``<type>/<id>`` form.
    """
    for key, prefix in (
        ("DistributionId", "distribution"),
        ("Id", "distribution"),  # some APIs just use "Id" to mean distribution
    ):
        val = params.get(key)
        if val:
            if val.startswith("arn:"):
                return val
            return f"arn:aws:cloudfront::{account_id}:{prefix}/{val}"
    return f"arn:aws:cloudfront::{account_id}:*"


_SERVICE_ARN_BUILDERS = {
    "s3": _s3_arn,
    "dynamodb": _dynamodb_arn,
    "lambda": _lambda_arn,
    "sqs": _sqs_arn,
    "sns": _sns_arn,
    "kms": _kms_arn,
    "secretsmanager": _secretsmanager_arn,
    "ec2": _ec2_arn,
    "ecs": _ecs_arn,
    "logs": _logs_arn,
    "events": _events_arn,
    "states": _states_arn,
    "rds": _rds_arn,
    "kinesis": _kinesis_arn,
    "ssm": _ssm_arn,
    "cloudformation": _cloudformation_arn,
    "iam": _iam_arn,
    "sts": _sts_arn,
    "cognito-idp": _cognito_arn,
    "apigateway": _apigateway_arn,
    "cloudwatch": _cloudwatch_arn,
    "elasticache": _elasticache_arn,
    "route53": _route53_arn,
    "acm": _acm_arn,
    "cloudfront": _cloudfront_arn,
}
