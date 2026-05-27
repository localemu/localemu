// Service registry: labels, sidebar grouping, docs URLs, copy-as-awsemu
// command templates, empty-state guidance. Loaded after utils.js.
//
// LocalEmu exposes ~132 services. This file is the single source of
// truth that turns each service id into the metadata the UI needs.
// Anything missing from a table falls back to a generic default
// (auto-Title-Cased label, "Other" group, no docs link, generic
// list-style copy command, generic empty-state hint).
(function () {
  "use strict";

  // 21 anchor services: the top-20 ranked by AWS usage weight x
  // LocalEmu coverage (see coverage.json) plus EventBridge by
  // explicit request. Every anchor renders in the sidebar from the
  // first dashboard load even with zero resources, so a new
  // installation has a populated landing surface. The full 132
  // services that LocalEmu supports remain reachable: the sidebar
  // search box matches across every service name; anything with at
  // least one resource pops in automatically.
  //
  //   compute / containers      ec2, ecs, lambda
  //   storage / databases       s3, dynamodb, rds
  //   messaging / orchestration sqs, sns, events, stepfunctions
  //   networking / edge         apigateway, apigatewayv2, route53, elbv2
  //   security / audit          iam, kms, secretsmanager, cloudtrail
  //   observability / ops       logs, ssm
  var ALWAYS_SHOW = new Set([
    "s3", "dynamodb", "rds",
    "ec2", "vpc", "ecs", "lambda",
    "sqs", "sns", "events", "stepfunctions",
    "apigateway", "apigatewayv2", "route53", "elbv2",
    "iam", "kms", "secretsmanager", "cloudtrail",
    "logs", "ssm"
  ]);

  // AWS-branded labels. Anything not listed gets auto-humanized.
  var SERVICE_LABELS = {
    s3: "S3", sns: "SNS", sqs: "SQS", iam: "IAM", ec2: "EC2", ecs: "ECS",
    eks: "EKS", rds: "RDS", elb: "ELB", elbv2: "ELBv2", efs: "EFS",
    ebs: "EBS", emr: "EMR", dms: "DMS", ses: "SES", ssm: "SSM",
    sts: "STS", swf: "SWF", waf: "WAF", wafv2: "WAFv2", iot: "IoT",
    xray: "X-Ray", "iot-data": "IoT Data", dynamodb: "DynamoDB",
    dynamodbstreams: "DynamoDB Streams", cloudwatch: "CloudWatch",
    logs: "CloudWatch Logs", cloudtrail: "CloudTrail",
    cloudformation: "CloudFormation", cloudfront: "CloudFront",
    cloudhsmv2: "CloudHSM v2", secretsmanager: "Secrets Manager",
    stepfunctions: "Step Functions", events: "EventBridge",
    pipes: "EventBridge Pipes", scheduler: "EventBridge Scheduler",
    opensearch: "OpenSearch", opensearchserverless: "OpenSearch Serverless",
    es: "Elasticsearch (legacy)", elasticache: "ElastiCache",
    elasticbeanstalk: "Elastic Beanstalk", kms: "KMS", glue: "Glue",
    athena: "Athena", kafka: "MSK (Kafka)", mq: "MQ", neptune: "Neptune",
    redshift: "Redshift", "redshift-data": "Redshift Data API",
    "rds-data": "RDS Data API", apigateway: "API Gateway (REST)",
    apigatewayv2: "API Gateway (HTTP/WebSocket)", appmesh: "App Mesh",
    apprunner: "App Runner", appsync: "AppSync",
    "application-autoscaling": "Application Auto Scaling",
    autoscaling: "Auto Scaling", appconfig: "AppConfig",
    "acm": "ACM (Certificate Manager)", "acm-pca": "ACM Private CA",
    "cognito-idp": "Cognito User Pools",
    "cognito-identity": "Cognito Identity Pools",
    identitystore: "Identity Store", organizations: "Organizations",
    config: "AWS Config", "service-quotas": "Service Quotas",
    "resource-groups": "Resource Groups",
    "resourcegroupstaggingapi": "Resource Groups Tagging API",
    vpc: "VPC", "security-groups": "Security Groups",
    "nat-gateways": "NAT Gateways", "vpc-peering": "VPC Peering",
    "vpc-endpoints": "VPC Endpoints",
    route53: "Route 53", route53resolver: "Route 53 Resolver",
    route53domains: "Route 53 Domains", directconnect: "Direct Connect",
    servicediscovery: "Cloud Map (Service Discovery)",
    servicecatalog: "Service Catalog", lakeformation: "Lake Formation",
    sagemaker: "SageMaker", "sagemaker-runtime": "SageMaker Runtime",
    bedrock: "Bedrock", comprehend: "Comprehend", personalize: "Personalize",
    polly: "Polly", rekognition: "Rekognition", textract: "Textract",
    translate: "Translate", transcribe: "Transcribe",
    mediaconvert: "MediaConvert", medialive: "MediaLive",
    mediapackage: "MediaPackage", mediapackagev2: "MediaPackage v2",
    mediaconnect: "MediaConnect", codebuild: "CodeBuild",
    codecommit: "CodeCommit", codedeploy: "CodeDeploy",
    codepipeline: "CodePipeline", "emr-containers": "EMR on EKS",
    "emr-serverless": "EMR Serverless",
    managedblockchain: "Managed Blockchain", memorydb: "MemoryDB",
    "timestream-write": "Timestream", databrew: "Glue DataBrew",
    quicksight: "QuickSight", firehose: "Data Firehose",
    datasync: "DataSync", snowball: "Snowball", fsx: "FSx",
    glacier: "S3 Glacier", storagegateway: "Storage Gateway",
    shield: "Shield", signer: "Signer", ram: "RAM",
    transfer: "Transfer Family", guardduty: "GuardDuty",
    inspector2: "Inspector", macie2: "Macie", securityhub: "Security Hub",
    ds: "Directory Service", ce: "Cost Explorer", budgets: "Budgets",
    backup: "Backup", batch: "Batch", amp: "Managed Prometheus",
    amplify: "Amplify", support: "Support", sesv2: "SES v2",
    pinpoint: "Pinpoint", forecast: "Forecast",
    resiliencehub: "Resilience Hub", "s3control": "S3 Control",
    dax: "DynamoDB Accelerator", ecr: "ECR", lambda: "Lambda"
  };

  // Sidebar group list (ordered top-to-bottom).
  var GROUPS = [
    { id: "compute",    label: "Compute" },
    { id: "storage",    label: "Storage" },
    { id: "messaging",  label: "Messaging" },
    { id: "networking", label: "Networking" },
    { id: "security",   label: "Security" },
    { id: "ops",        label: "Operations" },
    { id: "analytics",  label: "Analytics" },
    { id: "ml",         label: "Machine Learning" },
    { id: "devtools",   label: "Developer Tools" },
    { id: "media",      label: "Media" },
    { id: "iot",        label: "IoT" },
    { id: "migration",  label: "Migration" },
    { id: "monitoring", label: "Monitoring" },
    { id: "billing",    label: "Cost & Billing" },
    { id: "other",      label: "Other" }
  ];

  var SERVICE_GROUP = {
    ec2: "compute", ecs: "compute", eks: "compute", lambda: "compute",
    batch: "compute", apprunner: "compute", autoscaling: "compute",
    "application-autoscaling": "compute", elasticbeanstalk: "compute",
    appsync: "compute",
    s3: "storage", s3control: "storage", dynamodb: "storage",
    dynamodbstreams: "storage", dax: "storage", rds: "storage",
    "rds-data": "storage", redshift: "storage", "redshift-data": "storage",
    neptune: "storage", elasticache: "storage", memorydb: "storage",
    "timestream-write": "storage", efs: "storage", ebs: "storage",
    fsx: "storage", glacier: "storage", storagegateway: "storage",
    backup: "storage", ecr: "storage",
    sqs: "messaging", sns: "messaging", kinesis: "messaging",
    events: "messaging", pipes: "messaging", scheduler: "messaging",
    stepfunctions: "messaging", kafka: "messaging", mq: "messaging",
    firehose: "messaging", ses: "messaging", sesv2: "messaging",
    pinpoint: "messaging", swf: "messaging",
    vpc: "networking", "security-groups": "networking",
    "nat-gateways": "networking", "vpc-peering": "networking",
    "vpc-endpoints": "networking", route53: "networking",
    route53resolver: "networking", route53domains: "networking",
    cloudfront: "networking", elb: "networking", elbv2: "networking",
    directconnect: "networking", apigateway: "networking",
    apigatewayv2: "networking", appmesh: "networking",
    servicediscovery: "networking", ram: "networking", transfer: "networking",
    iam: "security", secretsmanager: "security", kms: "security",
    cloudtrail: "security", "cognito-idp": "security",
    "cognito-identity": "security", acm: "security", "acm-pca": "security",
    identitystore: "security", cloudhsmv2: "security",
    guardduty: "security", inspector2: "security", macie2: "security",
    securityhub: "security", shield: "security", signer: "security",
    waf: "security", wafv2: "security", ds: "security",
    cloudwatch: "monitoring", logs: "monitoring", xray: "monitoring",
    cloudformation: "ops", ssm: "ops",
    organizations: "ops", config: "ops",
    "resource-groups": "ops", resourcegroupstaggingapi: "ops",
    "service-quotas": "ops", appconfig: "ops", resiliencehub: "ops",
    support: "ops",
    athena: "analytics", glue: "analytics", emr: "analytics",
    "emr-containers": "analytics", "emr-serverless": "analytics",
    opensearch: "analytics", opensearchserverless: "analytics",
    es: "analytics", quicksight: "analytics", databrew: "analytics",
    lakeformation: "analytics",
    sagemaker: "ml", "sagemaker-runtime": "ml", bedrock: "ml",
    comprehend: "ml", personalize: "ml", polly: "ml", rekognition: "ml",
    textract: "ml", translate: "ml", transcribe: "ml", forecast: "ml",
    codebuild: "devtools", codecommit: "devtools", codedeploy: "devtools",
    codepipeline: "devtools", servicecatalog: "devtools",
    amplify: "devtools",
    mediaconvert: "media", medialive: "media", mediapackage: "media",
    mediapackagev2: "media", mediaconnect: "media",
    iot: "iot", "iot-data": "iot",
    dms: "migration", datasync: "migration", snowball: "migration",
    amp: "monitoring",
    ce: "billing", budgets: "billing",
    managedblockchain: "other"
  };

  // Service -> doc page slug on localemu.cloud/docs/<slug>.
  var DOCS_BASE = "https://localemu.cloud/docs/";
  var SERVICE_DOCS = {
    lambda: "lambda", s3: "s3", dynamodb: "dynamodb", sqs: "sqs",
    sns: "sns", events: "eventbridge", stepfunctions: "stepfunctions",
    kms: "kms", secretsmanager: "secretsmanager", kinesis: "kinesis",
    ec2: "ec2", rds: "rds-docker", opensearch: "opensearch-ref",
    "security-groups": "security-groups", ecs: "ecs", iam: "iam-enforcement",
    apigateway: "apigateway", apigatewayv2: "apigateway-v2", logs: "logs"
  };

  // Per-service awsemu "describe" snippet driven from the resource row.
  var COPY_CMD = {
    s3: function (r) { return "awsemu s3 ls s3://" + (r.name || "") + "/"; },
    dynamodb: function (r) { return "awsemu dynamodb describe-table --table-name " + (r.name || ""); },
    sqs: function (r) { return "awsemu sqs get-queue-url --queue-name " + (r.name || ""); },
    lambda: function (r) { return "awsemu lambda get-function --function-name " + (r.name || ""); },
    sns: function (r) { return "awsemu sns get-topic-attributes --topic-arn arn:aws:sns:us-east-1:000000000000:" + (r.name || ""); },
    ec2: function (r) { return "awsemu ec2 describe-instances --instance-ids " + (r.instance_id || r.name || ""); },
    ecs: function (r) { return "awsemu ecs describe-clusters --clusters " + (r.cluster || r.name || ""); },
    eks: function (r) { return "awsemu eks describe-cluster --name " + (r.cluster || r.name || ""); },
    rds: function (r) { return "awsemu rds describe-db-instances --db-instance-identifier " + (r.name || ""); },
    opensearch: function (r) { return "awsemu opensearch describe-domain --domain-name " + (r.name || r.domain || ""); },
    secretsmanager: function (r) { return "awsemu secretsmanager describe-secret --secret-id " + (r.name || ""); },
    stepfunctions: function (r) { return "awsemu stepfunctions describe-state-machine --state-machine-arn " + (r.arn || r.name || ""); },
    kinesis: function (r) { return "awsemu kinesis describe-stream --stream-name " + (r.name || ""); },
    events: function (r) { return "awsemu events list-rules --event-bus-name " + (r.bus || r.name || "default"); },
    logs: function (r) { return "awsemu logs describe-log-streams --log-group-name " + (r.name || ""); },
    kms: function (r) { return "awsemu kms describe-key --key-id " + (r.name || ""); },
    apigateway: function (r) { return "awsemu apigateway get-rest-api --rest-api-id " + (r.id || r.name || ""); },
    apigatewayv2: function (r) { return "awsemu apigatewayv2 get-api --api-id " + (r.id || r.name || ""); },
    "cognito-idp": function (r) { return "awsemu cognito-idp describe-user-pool --user-pool-id " + (r.id || r.name || ""); },
    acm: function (r) { return "awsemu acm describe-certificate --certificate-arn " + (r.arn || ""); },
    athena: function (r) { return "awsemu athena get-work-group --work-group " + (r.name || ""); },
    glue: function (r) { return "awsemu glue get-database --name " + (r.name || ""); },
    vpc: function (r) { return "awsemu ec2 describe-vpcs --vpc-ids " + (r.name || ""); },
    route53: function (r) { return "awsemu route53 get-hosted-zone --id " + (r.id || r.name || ""); },
    elbv2: function (r) { return "awsemu elbv2 describe-load-balancers --names " + (r.name || ""); },
    ssm: function (r) { return "awsemu ssm get-parameter --name " + (r.name || "") + " --with-decryption"; },
  };

  // Per-service "no resources yet — here is how to create one" snippet.
  // Every command here must be COPY-PASTE-RUNNABLE as-is. Anything that
  // references another resource (a role, a subnet, ...) must include the
  // create-that-first step inline, otherwise the user pastes it, hits
  // ENOENT or AccessDenied, and gives up.
  var EMPTY_STATE = {
    s3: "awsemu s3 mb s3://my-first-bucket",
    dynamodb: "awsemu dynamodb create-table --table-name users \\\n  --attribute-definitions AttributeName=id,AttributeType=S \\\n  --key-schema AttributeName=id,KeyType=HASH \\\n  --billing-mode PAY_PER_REQUEST",
    sqs: "awsemu sqs create-queue --queue-name jobs",
    // 2-step: create the execution role first so this works under
    // IAM_ENFORCEMENT=1 too. Without the role, lambda create-function
    // raises InvalidParameterValueException when LocalEmu validates roles.
    lambda: "# 1) execution role\nawsemu iam create-role --role-name lambda-role \\\n  --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'\n\n# 2) tiny handler\necho 'def handler(e,_): return {\"ok\":True}' > h.py && zip h.zip h.py\n\n# 3) the function\nawsemu lambda create-function --function-name hello \\\n  --runtime python3.12 --handler h.handler \\\n  --role arn:aws:iam::000000000000:role/lambda-role \\\n  --zip-file fileb://h.zip",
    sns: "awsemu sns create-topic --name notifications",
    // ami-ubuntu-22.04 is the LocalEmu-managed base (sshd + iptables +
    // curl + awscli baked in). For SSH/SSM/user-data demos use it; bare
    // upstream images (ami-debian-12, etc.) do not ship sshd.
    // Requires EC2_VM_MANAGER=docker (default).
    ec2: "awsemu ec2 run-instances --image-id ami-ubuntu-22.04 --instance-type t3.micro --count 1",
    ecs: "awsemu ecs create-cluster --cluster-name dev",
    // 2-step: subnets do not need to exist on real AWS (k3d ignores
    // resourcesVpcConfig.subnetIds anyway), but the parameter is required
    // by the CreateCluster shape. Create one subnet inline so the command
    // also works against real AWS unchanged.
    eks: "# 1) subnet for the cluster's VPC config\nVPC=$(awsemu ec2 describe-vpcs --query 'Vpcs[?IsDefault].VpcId' --output text)\nSUBNET=$(awsemu ec2 create-subnet --vpc-id $VPC --cidr-block 172.31.99.0/24 --query 'Subnet.SubnetId' --output text)\n\n# 2) the cluster (requires k3d binary on PATH for a real kubectl endpoint;\n# without it, CreateCluster still returns ACTIVE but with no behind-the-scenes\n# Kubernetes cluster)\nawsemu eks create-cluster --name dev \\\n  --role-arn arn:aws:iam::000000000000:role/eks \\\n  --resources-vpc-config subnetIds=$SUBNET",
    rds: "RDS_DOCKER_BACKEND=1 is required for a reachable Postgres / MySQL endpoint:\n\nRDS_DOCKER_BACKEND=1 awsemu rds create-db-instance \\\n  --db-instance-identifier app-db \\\n  --engine postgres --master-username admin --master-user-password admin123 \\\n  --db-instance-class db.t3.micro --allocated-storage 20\n\nWithout RDS_DOCKER_BACKEND=1 the create call succeeds but the endpoint is unreachable.",
    // Docker backend auto-enables when Docker is reachable. No env var
    // needed. Bare 'opensearch:2.11' would also work.
    opensearch: "awsemu opensearch create-domain --domain-name search --engine-version OpenSearch_2.11",
    secretsmanager: "awsemu secretsmanager create-secret --name prod/db/password \\\n  --secret-string '{\"username\":\"app\",\"password\":\"changeme\"}'",
    // 2-step: state-machine role first, otherwise create-state-machine
    // fails under IAM_ENFORCEMENT=1.
    stepfunctions: "# 1) state-machine role\nawsemu iam create-role --role-name sm-role \\\n  --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"states.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'\n\n# 2) state machine (minimal Pass state)\nawsemu stepfunctions create-state-machine --name my-sm \\\n  --role-arn arn:aws:iam::000000000000:role/sm-role \\\n  --definition '{\"StartAt\":\"Pass\",\"States\":{\"Pass\":{\"Type\":\"Pass\",\"End\":true}}}'",
    kinesis: "awsemu kinesis create-stream --stream-name events --shard-count 2",
    events: "awsemu events put-rule --name daily --schedule-expression 'rate(1 day)'",
    logs: "awsemu logs create-log-group --log-group-name /aws/lambda/hello",
    iam: "awsemu iam create-role --role-name lambda-role \\\n  --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'",
    cloudformation: "# template.yaml: minimal stack with one S3 bucket\ncat > template.yaml <<'YAML'\nAWSTemplateFormatVersion: '2010-09-09'\nResources:\n  DemoBucket:\n    Type: AWS::S3::Bucket\nYAML\n\nawsemu cloudformation create-stack --stack-name demo --template-body file://template.yaml",
    cloudtrail: "Activity is captured automatically on every AWS API call. Run any awsemu command to populate it.",
    kms: "awsemu kms create-key --description 'my first key'",
    apigateway: "awsemu apigateway create-rest-api --name my-api",
    apigatewayv2: "awsemu apigatewayv2 create-api --name my-http-api --protocol-type HTTP",
    route53: "awsemu route53 create-hosted-zone --name example.local --caller-reference $(date +%s)",
    // 2-step: ELBv2 CreateLoadBalancer requires real subnets and a
    // security group. The previous example referenced subnet-1 / sg-1
    // which never exist and the call failed immediately. Use the
    // default VPC's first two subnets.
    elbv2: "# 1) discover the default VPC's subnets in two AZs + its default SG\nVPC=$(awsemu ec2 describe-vpcs --query 'Vpcs[?IsDefault].VpcId' --output text)\nSUBNETS=$(awsemu ec2 describe-subnets --filters Name=vpc-id,Values=$VPC \\\n  --query 'Subnets[0:2].SubnetId' --output text)\nSG=$(awsemu ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC Name=group-name,Values=default \\\n  --query 'SecurityGroups[0].GroupId' --output text)\n\n# 2) the load balancer\nawsemu elbv2 create-load-balancer --name my-alb --type application \\\n  --subnets $SUBNETS --security-groups $SG",
    ssm: "awsemu ssm put-parameter --name /app/db/password --value 'changeme' --type SecureString",
  };

  // Per-service columns for the resource table. Anything missing falls
  // back to the generic ["Name", "Region"].
  var SERVICE_COLUMNS = {
    s3:        ["Name", "Objects", "Region"],
    dynamodb:  ["Name", "Items", "Region"],
    sqs:       ["Name", "Messages", "Region"],
    lambda:    ["Name", "Runtime", "Handler", "Memory", "Role", "State"],
    sns:       ["Name", "Subscriptions", "Region"],
    ec2:       ["Instance ID", "State", "Type", "Region"],
    ecs:       ["Cluster", "Tasks", "Status"],
    eks:       ["Cluster", "Status", "Endpoint"],
    rds:       ["Name", "Engine", "Status", "Endpoint", "User", "Database"],
    opensearch: ["Name", "Engine", "Status", "Endpoint", "Instance Type", "Instances"],
    iam:       ["Type", "Name", "ARN", "Policies", "Detail"],
    logs:      ["Name", "Streams", "Retention", "Stored Bytes"],
    secretsmanager: ["Name", "Description", "Last Changed"],
    stepfunctions: ["Name", "Status", "ARN"],
    kinesis:   ["Name", "Shards", "Status"],
    events:    ["Name", "Bus", "State", "Targets"],
    apigateway:   ["Name", "API ID", "Protocol", "Region"],
    apigatewayv2: ["Name", "API ID", "Protocol", "Routes", "Stages", "Region"],
    route53:   ["Name", "ID", "Type", "Records", "Region"],
    elbv2:     ["Name", "Type", "Scheme", "State", "DNS", "Region"],
    kms:       ["Name", "Key ID", "Alias", "State", "Usage", "Region"],
    ssm:       ["Name", "Type", "Version", "Last Modified", "Region"],
    cloudtrail:["Name", "Source", "User", "Request ID", "Time", "Region"],
    vpc:       ["Name", "CIDR", "Subnets", "IGW", "Default", "Docker Network"],
    "security-groups": ["Name", "ID", "VPC", "Ingress", "Egress", "Detail"],
    "nat-gateways":    ["Name", "VPC", "Subnet", "State", "Public IP", "Type"],
    "vpc-peering":     ["Name", "Requester", "Accepter", "Status"],
    "vpc-endpoints":   ["Name", "VPC", "Service", "Type", "State", "Proxy"]
  };
  var DEFAULT_COLUMNS = ["Name", "Region"];

  function label(svc) {
    if (SERVICE_LABELS[svc]) return SERVICE_LABELS[svc];
    return svc.split(/[-_]/).map(function (p) {
      return p ? p[0].toUpperCase() + p.slice(1) : p;
    }).join(" ");
  }

  function group(svc) { return SERVICE_GROUP[svc] || "other"; }
  function docsUrl(svc) {
    var slug = SERVICE_DOCS[svc];
    return slug ? (DOCS_BASE + slug) : null;
  }
  function copyCommand(svc, row) {
    var fn = COPY_CMD[svc];
    return fn ? fn(row) : null;
  }
  function emptyStateText(svc) { return EMPTY_STATE[svc] || ""; }
  function columns(svc) { return SERVICE_COLUMNS[svc] || DEFAULT_COLUMNS; }
  function alwaysShow(svc) { return ALWAYS_SHOW.has(svc); }

  // Empty-state cross-references. Returns an HTML fragment (already
  // escaped where dynamic) to inject when the listed service has no
  // resources but a sibling service does. Today this is the API
  // Gateway v1 <-> v2 confusion: a fresh Terraform deploy with
  // aws_apigatewayv2_* leaves the v1 page empty even though "API
  // Gateway" is a natural first click.
  function crossRef(svc, overview) {
    overview = overview || {};
    function n(name) {
      var entry = overview[name] || {};
      return entry.resources || 0;
    }
    if (svc === "apigateway" && n("apigatewayv2") > 0) {
      return 'Looking for your HTTP API? You have <strong>' + n("apigatewayv2")
        + '</strong> entr' + (n("apigatewayv2") === 1 ? 'y' : 'ies')
        + ' under <a href="#/apigatewayv2">API Gateway (HTTP/WebSocket)</a>.';
    }
    if (svc === "apigatewayv2" && n("apigateway") > 0) {
      return 'Looking for your REST API? You have <strong>' + n("apigateway")
        + '</strong> entr' + (n("apigateway") === 1 ? 'y' : 'ies')
        + ' under <a href="#/apigateway">API Gateway (REST)</a>.';
    }
    return "";
  }

  window.DASH.services = {
    GROUPS: GROUPS,
    label: label,
    group: group,
    docsUrl: docsUrl,
    copyCommand: copyCommand,
    emptyStateText: emptyStateText,
    columns: columns,
    alwaysShow: alwaysShow,
    crossRef: crossRef,
    hasCopyCommand: function (svc) { return !!COPY_CMD[svc]; }
  };
})();
