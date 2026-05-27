"""Service registry for the LocalEmu dashboard.

Single source of truth for per-service metadata: tier (Live / Metadata
only / Not emulated), label, group, icon, docs slug, columns, empty
state, copy command, banner copy.

Adding a new service is one entry in this file. The dispatch helpers
in ``api.py`` consult :data:`SERVICE_REGISTRY` to drive the sidebar
ordering and the per-service routing.

The frontend pulls the same data via ``GET /_localemu/api/registry``
so ``services.js`` does not duplicate the per-service maps. The legacy
JS maps are kept for backwards compatibility but populated from the
registry shim.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Tier(str, enum.Enum):
    """Honesty tier for a service.

    LIVE: a real engine emulates behaviour (S3 objects, Lambda exec,
    EC2-Docker, RDS-Docker, Athena-DuckDB, OpenSearch container,
    EventBridge rules+targets, Step Functions ASL, etc.).

    METADATA: moto stores Create/Get state but no real behaviour runs
    (Neptune, ElastiCache, Forecast, SageMaker, etc.).

    NOT_EMULATED: stub services that return canned responses
    (Storage Gateway, Transfer, MediaConvert, WAF Classic, Amplify,
    AppRunner, Translate, Rekognition).
    """

    LIVE = "live"
    METADATA = "metadata"
    NOT_EMULATED = "not_emulated"


@dataclass(frozen=True)
class ServiceSpec:
    """Per-service registration consumed by the dashboard."""

    name: str
    tier: Tier
    label: str
    group: str = "other"
    icon: str | None = None
    docs_slug: str | None = None
    always_show: bool = False
    columns: tuple[str, ...] = ()
    empty_state: str | None = None
    copy_cmd_template: str | None = None
    banner: str | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "tier": self.tier.value,
            "label": self.label,
            "group": self.group,
            "icon": self.icon,
            "docs_slug": self.docs_slug,
            "always_show": self.always_show,
            "columns": list(self.columns),
            "empty_state": self.empty_state,
            "copy_cmd_template": self.copy_cmd_template,
            "banner": self.banner,
        }


SERVICE_REGISTRY: dict[str, ServiceSpec] = {}


def _register(spec: ServiceSpec) -> ServiceSpec:
    SERVICE_REGISTRY[spec.name] = spec
    for alias in spec.aliases:
        SERVICE_REGISTRY[alias] = spec
    return spec


def get(name: str) -> ServiceSpec | None:
    return SERVICE_REGISTRY.get(name)


def all_specs() -> list[ServiceSpec]:
    seen: set[int] = set()
    out: list[ServiceSpec] = []
    for spec in SERVICE_REGISTRY.values():
        ident = id(spec)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(spec)
    return out


def by_tier(tier: Tier) -> list[ServiceSpec]:
    return [s for s in all_specs() if s.tier is tier]


# ---------------------------------------------------------------------------
# LIVE tier: real engines, real behaviour.
# ---------------------------------------------------------------------------
_register(ServiceSpec(
    name="s3", tier=Tier.LIVE, label="S3", group="storage",
    always_show=True, docs_slug="s3",
    columns=("Name", "Account", "Objects", "Region"),
    empty_state="awsemu s3 mb s3://my-first-bucket",
    copy_cmd_template="awsemu s3 ls s3://{name}/",
))
_register(ServiceSpec(
    name="dynamodb", tier=Tier.LIVE, label="DynamoDB", group="storage",
    always_show=True, docs_slug="dynamodb",
    columns=("Name", "Items", "Region"),
    empty_state="awsemu dynamodb create-table --table-name users \\\n  --attribute-definitions AttributeName=id,AttributeType=S \\\n  --key-schema AttributeName=id,KeyType=HASH \\\n  --billing-mode PAY_PER_REQUEST",
    copy_cmd_template="awsemu dynamodb describe-table --table-name {name}",
))
_register(ServiceSpec(
    name="lambda", tier=Tier.LIVE, label="Lambda", group="compute",
    always_show=True, docs_slug="lambda",
    columns=("Name", "Runtime", "Handler", "Memory", "Role", "State"),
    empty_state="echo 'def handler(e,_): return {\"ok\":True}' > h.py && zip h.zip h.py\nawsemu lambda create-function --function-name hello \\\n  --runtime python3.12 --handler h.handler \\\n  --role arn:aws:iam::000000000000:role/r --zip-file fileb://h.zip",
    copy_cmd_template="awsemu lambda get-function --function-name {name}",
))
_register(ServiceSpec(
    name="ec2", tier=Tier.LIVE, label="EC2", group="compute",
    always_show=True, docs_slug="ec2",
    columns=("Instance ID", "State", "Type", "Region"),
    empty_state="awsemu ec2 run-instances --image-id ami-localemu --instance-type t3.micro --count 1",
    copy_cmd_template="awsemu ec2 describe-instances --instance-ids {instance_id}",
    banner="Every EC2 instance is backed by a real Docker container; SSH and IMDS work.",
))
_register(ServiceSpec(
    name="ecs", tier=Tier.LIVE, label="ECS", group="compute",
    always_show=True, docs_slug="ecs",
    columns=("Cluster", "Tasks", "Status"),
    empty_state="awsemu ecs create-cluster --cluster-name dev",
    copy_cmd_template="awsemu ecs describe-clusters --clusters {cluster}",
    banner="Tasks run as real Docker containers.",
))
_register(ServiceSpec(
    name="eks", tier=Tier.LIVE, label="EKS", group="compute",
    columns=("Cluster", "Status", "Endpoint"),
    empty_state="awsemu eks create-cluster --name dev --role-arn arn:aws:iam::000000000000:role/eks \\\n  --resources-vpc-config subnetIds=subnet-1",
    copy_cmd_template="awsemu eks describe-cluster --name {cluster}",
    banner="Set EKS_K8S_PROVIDER=k3d for a real k3d cluster with a working kubectl.",
))
_register(ServiceSpec(
    name="rds", tier=Tier.LIVE, label="RDS", group="storage",
    always_show=True, docs_slug="rds-docker",
    columns=("Name", "Engine", "Status", "Endpoint", "User", "Database"),
    empty_state="RDS_DOCKER_BACKEND=1 is required for a reachable endpoint:\n\nRDS_DOCKER_BACKEND=1 awsemu rds create-db-instance \\\n  --db-instance-identifier app-db \\\n  --engine postgres --master-username admin --master-user-password admin123 \\\n  --db-instance-class db.t3.micro --allocated-storage 20",
    copy_cmd_template="awsemu rds describe-db-instances --db-instance-identifier {name}",
    banner="With RDS_DOCKER_BACKEND=1, every instance is a real Postgres/MySQL/MariaDB container.",
))
_register(ServiceSpec(
    name="sqs", tier=Tier.LIVE, label="SQS", group="messaging",
    always_show=True, docs_slug="sqs",
    columns=("Name", "Messages", "Region"),
    empty_state="awsemu sqs create-queue --queue-name jobs",
    copy_cmd_template="awsemu sqs get-queue-url --queue-name {name}",
))
_register(ServiceSpec(
    name="sns", tier=Tier.LIVE, label="SNS", group="messaging",
    always_show=True, docs_slug="sns",
    columns=("Name", "Subscriptions", "Region"),
    empty_state="awsemu sns create-topic --name notifications",
    copy_cmd_template="awsemu sns get-topic-attributes --topic-arn {arn}",
))
_register(ServiceSpec(
    name="events", tier=Tier.LIVE, label="EventBridge", group="messaging",
    always_show=True, docs_slug="eventbridge",
    columns=("Name", "Bus", "State", "Targets"),
    empty_state="awsemu events put-rule --name daily --schedule-expression 'rate(1 day)'",
    copy_cmd_template="awsemu events list-rules --event-bus-name {bus}",
))
_register(ServiceSpec(
    name="stepfunctions", tier=Tier.LIVE, label="Step Functions", group="messaging",
    always_show=True, docs_slug="stepfunctions",
    columns=("Name", "Type", "Status", "ARN"),
    empty_state="awsemu stepfunctions create-state-machine --name my-sm \\\n  --role-arn arn:aws:iam::000000000000:role/sm \\\n  --definition '{\"StartAt\":\"Pass\",\"States\":{\"Pass\":{\"Type\":\"Pass\",\"End\":true}}}'",
    copy_cmd_template="awsemu stepfunctions describe-state-machine --state-machine-arn {arn}",
))
_register(ServiceSpec(
    name="kms", tier=Tier.LIVE, label="KMS", group="security",
    always_show=True, docs_slug="kms",
    columns=("Name", "Key ID", "Alias", "State", "Spec", "Usage", "Origin", "Multi-Region", "Region"),
    empty_state="awsemu kms create-key --description 'my first key'",
    copy_cmd_template="awsemu kms describe-key --key-id {key_id}",
))
_register(ServiceSpec(
    name="secretsmanager", tier=Tier.LIVE, label="Secrets Manager", group="security",
    always_show=True, docs_slug="secretsmanager",
    columns=("Name", "Description", "Last Changed"),
    empty_state="awsemu secretsmanager create-secret --name prod/db/password \\\n  --secret-string '{\"username\":\"app\",\"password\":\"changeme\"}'",
    copy_cmd_template="awsemu secretsmanager describe-secret --secret-id {name}",
))
_register(ServiceSpec(
    name="cloudtrail", tier=Tier.LIVE, label="CloudTrail", group="security",
    always_show=True,
    columns=("Operation", "Source", "User", "Account", "Region", "Time", "Request ID"),
    empty_state="Activity is captured automatically on every AWS API call. Run any awsemu command to populate it.",
))
_register(ServiceSpec(
    name="logs", tier=Tier.LIVE, label="CloudWatch Logs", group="monitoring",
    always_show=True, docs_slug="logs",
    columns=("Name", "Streams", "Retention", "Stored Bytes"),
    empty_state="awsemu logs create-log-group --log-group-name /aws/lambda/hello",
    copy_cmd_template="awsemu logs describe-log-streams --log-group-name {name}",
))
_register(ServiceSpec(
    name="apigateway", tier=Tier.LIVE, label="API Gateway (REST)", group="networking",
    always_show=True, docs_slug="apigateway",
    columns=("Name", "API ID", "Protocol", "Region"),
    empty_state="awsemu apigateway create-rest-api --name my-api",
    copy_cmd_template="awsemu apigateway get-rest-api --rest-api-id {api_id}",
))
_register(ServiceSpec(
    name="apigatewayv2", tier=Tier.LIVE, label="API Gateway (HTTP/WebSocket)", group="networking",
    always_show=True, docs_slug="apigateway-v2",
    columns=("Name", "API ID", "Protocol", "Routes", "Stages", "Region"),
    empty_state="awsemu apigatewayv2 create-api --name my-http-api --protocol-type HTTP",
    copy_cmd_template="awsemu apigatewayv2 get-api --api-id {api_id}",
))
_register(ServiceSpec(
    name="iam", tier=Tier.LIVE, label="IAM", group="security",
    always_show=True, docs_slug="iam-enforcement",
    columns=("Type", "Name", "ARN", "Policies", "Detail"),
    empty_state="awsemu iam create-role --role-name lambda-role \\\n  --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'",
))
_register(ServiceSpec(
    name="opensearch", tier=Tier.LIVE, label="OpenSearch", group="analytics",
    docs_slug="opensearch-ref",
    columns=("Name", "Engine", "Status", "Endpoint", "Instance Type", "Instances"),
    empty_state="awsemu opensearch create-domain --domain-name search --engine-version Elasticsearch_7.10",
    copy_cmd_template="awsemu opensearch describe-domain --domain-name {name}",
    banner="With ATHENA_BACKEND=duckdb plus the standard OpenSearch Docker provider, queries hit a real container.",
))
_register(ServiceSpec(
    name="kinesis", tier=Tier.LIVE, label="Kinesis", group="messaging",
    always_show=True, docs_slug="kinesis",
    columns=("Name", "Shards", "Status"),
    empty_state="awsemu kinesis create-stream --stream-name events --shard-count 2",
    copy_cmd_template="awsemu kinesis describe-stream --stream-name {name}",
))
_register(ServiceSpec(
    name="route53", tier=Tier.LIVE, label="Route 53", group="networking",
    always_show=True,
    columns=("Name", "ID", "Type", "Records", "Region"),
    copy_cmd_template="awsemu route53 get-hosted-zone --id {id}",
))
_register(ServiceSpec(
    name="elbv2", tier=Tier.LIVE, label="ELBv2", group="networking",
    always_show=True,
    columns=("Name", "Type", "Scheme", "State", "DNS", "Region"),
    copy_cmd_template="awsemu elbv2 describe-load-balancers --names {name}",
))
_register(ServiceSpec(
    name="ssm", tier=Tier.LIVE, label="SSM", group="ops",
    always_show=True,
    columns=("Name", "Type", "Version", "Last Modified", "Region"),
    empty_state="awsemu ssm put-parameter --name /app/db/password --value 'changeme' --type SecureString",
    copy_cmd_template="awsemu ssm get-parameter --name {name} --with-decryption",
))
_register(ServiceSpec(
    name="ecr", tier=Tier.LIVE, label="ECR", group="storage",
    columns=("Name", "URI", "Images", "Tags", "Mutability", "Region"),
    empty_state="awsemu ecr create-repository --repository-name my-app",
    copy_cmd_template="awsemu ecr describe-repositories --repository-names {name}",
))
_register(ServiceSpec(
    name="vpc", tier=Tier.LIVE, label="VPC", group="networking",
    always_show=True,
    columns=("VPC ID", "CIDR", "Subnets", "IGW", "Default", "Docker network", "Region"),
    empty_state=(
        "awsemu ec2 create-vpc --cidr-block 10.0.0.0/16  "
        "# the default VPC is already there"
    ),
    copy_cmd_template="awsemu ec2 describe-vpcs --vpc-ids {name}",
    banner="LocalEmu materialises one Docker network per VPC (EC2_VM_MANAGER=docker).",
))
_register(ServiceSpec(
    name="cloudformation", tier=Tier.LIVE, label="CloudFormation", group="ops",
))
_register(ServiceSpec(
    name="athena", tier=Tier.LIVE, label="Athena", group="analytics",
    banner="ATHENA_BACKEND=duckdb runs queries on a real DuckDB engine.",
))
_register(ServiceSpec(
    name="cognito-idp", tier=Tier.LIVE, label="Cognito User Pools", group="security",
))
_register(ServiceSpec(
    name="transcribe", tier=Tier.LIVE, label="Transcribe", group="ml",
    banner="Real speech-to-text via Vosk (model downloads on first job per language).",
))
_register(ServiceSpec(
    name="cloudfront", tier=Tier.LIVE, label="CloudFront", group="networking",
))
_register(ServiceSpec(
    name="kafka", tier=Tier.LIVE, label="MSK (Kafka)", group="messaging",
    banner="Set MSK_DOCKER_BACKEND=1 for a real Kafka container (apache/kafka:3.7.1 KRaft).",
))
_register(ServiceSpec(
    name="mq", tier=Tier.LIVE, label="MQ", group="messaging",
    banner="Set MQ_DOCKER_BACKEND=1 for a real RabbitMQ/ActiveMQ container.",
))
_register(ServiceSpec(
    name="scheduler", tier=Tier.LIVE, label="EventBridge Scheduler", group="messaging",
    columns=("Name", "Group", "Expression", "State", "Next fire", "Target", "Region"),
    empty_state=(
        "awsemu scheduler create-schedule --name nightly "
        "--schedule-expression 'rate(1 hour)' "
        "--flexible-time-window Mode=OFF "
        "--target '{\"Arn\":\"arn:aws:sqs:us-east-1:000000000000:my-queue\",\"RoleArn\":\"arn:aws:iam::000000000000:role/svc\"}'"
    ),
    copy_cmd_template="awsemu scheduler get-schedule --name {name}",
))
_register(ServiceSpec(
    name="pipes", tier=Tier.LIVE, label="EventBridge Pipes", group="messaging",
    banner="Only SQS sources are implemented; other source types coming.",
    columns=("Name", "Source", "Target", "Desired", "Current", "Region"),
    empty_state=(
        "awsemu pipes create-pipe --name demo "
        "--source arn:aws:sqs:us-east-1:000000000000:src "
        "--target arn:aws:lambda:us-east-1:000000000000:function:dst "
        "--role-arn arn:aws:iam::000000000000:role/svc"
    ),
    copy_cmd_template="awsemu pipes describe-pipe --name {name}",
))
_register(ServiceSpec(
    name="firehose", tier=Tier.LIVE, label="Data Firehose", group="messaging",
))
_register(ServiceSpec(
    name="acm", tier=Tier.LIVE, label="ACM (Certificate Manager)", group="security",
))
_register(ServiceSpec(
    name="ses", tier=Tier.LIVE, label="SES", group="messaging",
))
_register(ServiceSpec(
    name="sesv2", tier=Tier.LIVE, label="SES v2", group="messaging",
))
_register(ServiceSpec(
    name="resource-groups", tier=Tier.LIVE, label="Resource Groups", group="ops",
))
_register(ServiceSpec(
    name="resourcegroupstaggingapi", tier=Tier.LIVE, label="Tag Editor", group="ops",
))
_register(ServiceSpec(
    name="batch", tier=Tier.METADATA, label="Batch", group="compute",
    banner="Metadata only: compute envs, queues, job defs, and jobs are stored but jobs are not executed.",
    columns=("Name", "Kind", "ARN", "Type", "State", "Region"),
    empty_state=(
        "awsemu batch create-compute-environment --compute-environment-name ce-1 "
        "--type MANAGED --state ENABLED "
        "--compute-resources type=EC2,minvCpus=0,maxvCpus=4,subnets=subnet-xxxx,securityGroupIds=sg-xxxx,instanceRole=ecsInstanceRole,instanceTypes=optimal "
        "--service-role arn:aws:iam::000000000000:role/AWSBatchServiceRole"
    ),
    copy_cmd_template="awsemu batch describe-compute-environments --compute-environments {name}",
))
_register(ServiceSpec(
    name="glue", tier=Tier.METADATA, label="Glue", group="analytics",
    banner=(
        "Data Catalog (databases, tables, partitions, schemas) is stored. "
        "Jobs, crawlers, triggers, and workflows are bookkeeping only: "
        "no Spark, no crawl, no schedule firing. Athena reads the catalog."
    ),
    columns=("Name", "Kind", "Details", "Status", "Region"),
    empty_state=(
        "awsemu glue create-database --database-input Name=sales  "
        "&& awsemu glue create-table --database-name sales "
        "--table-input Name=orders,StorageDescriptor={Location=s3://sales/orders/,Columns=[{Name=id,Type=int}]}"
    ),
    copy_cmd_template="awsemu glue get-database --name {name}",
))
_register(ServiceSpec(
    name="wafv2", tier=Tier.METADATA, label="WAFv2", group="security",
    banner="Metadata only: web ACLs, IP sets, regex sets, and rule groups are stored but no request inspection runs.",
    columns=("Name", "Kind", "Scope", "Rules", "Associated", "Region"),
    empty_state=(
        "awsemu wafv2 create-web-acl --name demo --scope REGIONAL "
        "--default-action Allow={} --visibility-config SampledRequestsEnabled=false,CloudWatchMetricsEnabled=false,MetricName=demo "
        "--rules '[]'"
    ),
    copy_cmd_template="awsemu wafv2 get-web-acl --name {name} --scope REGIONAL --id <id>",
))


# ---------------------------------------------------------------------------
# METADATA tier: moto persists Create/Get state but no real behaviour.
# ---------------------------------------------------------------------------
for _name, _label, _group in [
    ("ebs", "EBS", "storage"),
    ("autoscaling", "Auto Scaling", "compute"),
    ("application-autoscaling", "Application Auto Scaling", "compute"),
    ("elb", "ELB (Classic)", "networking"),
    ("efs", "EFS", "storage"),
    ("fsx", "FSx", "storage"),
    ("glacier", "S3 Glacier", "storage"),
    ("dax", "DynamoDB Accelerator", "storage"),
    ("elasticache", "ElastiCache", "storage"),
    ("memorydb", "MemoryDB", "storage"),
    ("dynamodbstreams", "DynamoDB Streams", "storage"),
    ("redshift", "Redshift", "storage"),
    ("rds-data", "RDS Data API", "storage"),
    ("redshift-data", "Redshift Data API", "storage"),
    ("neptune", "Neptune", "storage"),
    ("timestream-write", "Timestream", "storage"),
    ("s3control", "S3 Control", "storage"),
    ("backup", "AWS Backup", "ops"),
    ("datasync", "DataSync", "ops"),
    ("dms", "Database Migration Service", "ops"),
    ("ds", "Directory Service", "security"),
    ("identitystore", "IAM Identity Store", "security"),
    ("cognito-identity", "Cognito Identity Pools", "security"),
    ("organizations", "Organizations", "ops"),
    ("ram", "RAM", "security"),
    ("signer", "Signer", "security"),
    ("acm-pca", "ACM Private CA", "security"),
    ("cloudhsmv2", "CloudHSM v2", "security"),
    ("config", "AWS Config", "ops"),
    ("guardduty", "GuardDuty", "security"),
    ("inspector2", "Inspector", "security"),
    ("macie2", "Macie", "security"),
    ("securityhub", "Security Hub", "security"),
    ("shield", "Shield", "security"),
    ("cloudwatch", "CloudWatch", "monitoring"),
    ("xray", "X-Ray", "monitoring"),
    ("amp", "Managed Prometheus", "monitoring"),
    ("emr", "EMR", "analytics"),
    ("emr-containers", "EMR on EKS", "analytics"),
    ("emr-serverless", "EMR Serverless", "analytics"),
    ("lakeformation", "Lake Formation", "analytics"),
    ("databrew", "Glue DataBrew", "analytics"),
    ("opensearchserverless", "OpenSearch Serverless", "analytics"),
    ("es", "Elasticsearch (legacy)", "analytics"),
    ("sagemaker", "SageMaker", "ml"),
    ("sagemaker-runtime", "SageMaker Runtime", "ml"),
    ("bedrock", "Bedrock", "ml"),
    ("comprehend", "Comprehend", "ml"),
    ("forecast", "Forecast", "ml"),
    ("personalize", "Personalize", "ml"),
    ("polly", "Polly", "ml"),
    ("textract", "Textract", "ml"),
    ("mediaconnect", "Elemental MediaConnect", "media"),
    ("medialive", "Elemental MediaLive", "media"),
    ("mediapackage", "Elemental MediaPackage", "media"),
    ("mediapackagev2", "Elemental MediaPackage v2", "media"),
    ("route53domains", "Route 53 Domains", "networking"),
    ("route53resolver", "Route 53 Resolver", "networking"),
    ("directconnect", "Direct Connect", "networking"),
    ("servicediscovery", "Cloud Map", "networking"),
    ("appsync", "AppSync", "compute"),
    ("elasticbeanstalk", "Elastic Beanstalk", "compute"),
    ("appconfig", "AppConfig", "ops"),
    ("appmesh", "App Mesh", "compute"),
    ("codebuild", "CodeBuild", "devtools"),
    ("codecommit", "CodeCommit", "devtools"),
    ("codedeploy", "CodeDeploy", "devtools"),
    ("codepipeline", "CodePipeline", "devtools"),
    ("iot", "IoT Core", "iot"),
    ("iot-data", "IoT Data", "iot"),
    ("managedblockchain", "Managed Blockchain", "other"),
    ("service-quotas", "Service Quotas", "ops"),
    ("resiliencehub", "Resilience Hub", "ops"),
    ("support", "Support", "ops"),
    ("ce", "Cost Explorer", "billing"),
    ("budgets", "Budgets", "billing"),
    ("servicecatalog", "Service Catalog", "devtools"),
    ("swf", "SWF", "messaging"),
    ("pinpoint", "Pinpoint", "messaging"),
    ("quicksight", "QuickSight", "analytics"),
]:
    _register(ServiceSpec(name=_name, tier=Tier.METADATA, label=_label, group=_group))


# ---------------------------------------------------------------------------
# NOT_EMULATED tier: stubs and services with no moto backend.
# ---------------------------------------------------------------------------
for _name, _label, _group, _banner in [
    ("waf", "WAF Classic", "security",
     "WAF Classic is a stub. The newer WAFv2 has a real backend."),
    ("transfer", "Transfer Family", "networking",
     "Transfer Family is a stub: no servers or users persist."),
    ("amplify", "Amplify", "devtools",
     "Amplify is a stub: every list returns empty."),
    ("apprunner", "App Runner", "compute",
     "App Runner is a stub: every list returns empty."),
    ("storagegateway", "Storage Gateway", "storage",
     "Storage Gateway is not emulated. For file-share-over-S3 workflows, use S3 directly; for FSx workflows, use FSx."),
    ("snowball", "Snowball", "storage",
     "Snowball is a stub: no jobs or clusters persist."),
    ("mediaconvert", "Elemental MediaConvert", "media",
     "MediaConvert is a stub: no real CreateJob path."),
    ("translate", "Translate", "ml",
     "Translate is a stub: TranslateText echoes the input."),
    ("rekognition", "Rekognition", "ml",
     "Rekognition has no persistent state and returns fixed sample responses."),
]:
    _register(ServiceSpec(
        name=_name, tier=Tier.NOT_EMULATED, label=_label,
        group=_group, banner=_banner,
    ))
