"""
Service registry for persistence — maps service names to their state stores
and defines the topological load order.
"""

# Native stores: service_name -> (module_path, variable_name)
# Each is an AccountRegionBundle that serializes with dill.
NATIVE_STORES = {
    "s3":              ("localemu.services.s3.models", "s3_stores"),
    "sqs":             ("localemu.services.sqs.models", "sqs_stores"),
    "sns":             ("localemu.services.sns.models", "sns_stores"),
    "lambda_":         ("localemu.services.lambda_.invocation.models", "lambda_stores"),
    "events":          ("localemu.services.events.models", "events_stores"),
    "dynamodb":        ("localemu.services.dynamodb.models", "dynamodb_stores"),
    "dynamodbstreams": ("localemu.services.dynamodbstreams.models", "dynamodbstreams_stores"),
    "kms":             ("localemu.services.kms.models", "kms_stores"),
    "cloudwatch":      ("localemu.services.cloudwatch.models", "cloudwatch_stores"),
    "logs":            ("localemu.services.logs.models", "logs_stores"),
    "firehose":        ("localemu.services.firehose.models", "firehose_stores"),
    "kinesis":         ("localemu.services.kinesis.models", "kinesis_stores"),
    "stepfunctions":   ("localemu.services.stepfunctions.backend.models", "sfn_stores"),
    "apigateway":      ("localemu.services.apigateway.models", "apigateway_stores"),
    "cloudformation":  ("localemu.services.cloudformation.stores", "cloudformation_stores"),
    "route53":         ("localemu.services.route53.models", "route53_stores"),
    "route53resolver": ("localemu.services.route53resolver.models", "route53resolver_stores"),
    "opensearch":      ("localemu.services.opensearch.models", "opensearch_stores"),
    "transcribe":      ("localemu.services.transcribe.models", "transcribe_stores"),
    "events_v1":       ("localemu.services.events.v1.models", "events_stores"),
    "sts":             ("localemu.services.sts.models", "sts_stores"),
    # CloudFront keeps a native sidecar store with the OAC / OAI bucket
    # bindings and per-distribution cache stats. Moto owns the
    # distribution records themselves, but the S3 data-plane guard reads
    # the OAC bindings — if we don't persist them, every cross-restart
    # bucket-access check silently allows direct S3 hits that should be
    # denied. See services/cloudfront/models.py for the schema.
    "cloudfront":      ("localemu.services.cloudfront.models", "cloudfront_stores"),
}

# Moto backends — every instantiated moto backend is serialized via dill.dumps(backend).
MOTO_SERVICES = [
    "iam", "sts", "secretsmanager", "ssm", "cognito-idp", "cognito-identity",
    "ecr", "ecs", "eks", "acm", "scheduler", "ses", "sesv2", "wafv2",
    "redshift", "glue", "athena", "efs", "batch", "cloudfront",
    "elasticache", "servicediscovery", "appsync", "backup", "pipes",
    "codebuild", "codecommit", "codepipeline", "config", "guardduty",
    "inspector2", "iot", "iot-data", "kafka", "medialive", "mq",
    "neptune", "organizations", "quicksight", "ram", "rds", "rds-data",
    "rekognition", "resourcegroupstaggingapi", "sagemaker", "signer",
    "support", "swf", "textract", "transfer", "xray",
    "s3", "ec2", "lambda", "dynamodb", "sqs", "sns", "events",
    "logs", "cloudwatch", "kinesis", "firehose", "stepfunctions",
    "route53", "apigateway", "apigatewayv2", "cloudformation", "cloudtrail",
    "opensearch", "es",
]

# Topological load order — each tier loads before the next.
# Hard dependencies: Lambda -> S3 (code), CloudFormation -> everything.
LOAD_ORDER = [
    # Tier 0: no dependencies
    ["iam", "sts", "kms"],
    # Tier 1: depends on IAM/KMS only
    ["s3", "sqs", "sns", "dynamodb", "dynamodbstreams", "kinesis",
     "secretsmanager", "ssm", "route53", "route53resolver"],
    # Tier 2: depends on S3 (Lambda code) + Tier 0-1
    ["lambda_", "cloudwatch", "logs", "opensearch", "transcribe"],
    # Tier 3: depends on Lambda + messaging
    ["apigateway", "events", "events_v1", "stepfunctions",
     "cloudtrail", "firehose", "scheduler",
     # CloudFront's native sidecar references S3 bucket ARNs in
     # oac_bucket_bindings; load after S3 to keep the implicit ordering
     # honest (no key resolution actually fires during load, but the
     # convention matters for future joiners).
     "cloudfront"],
    # Tier 4: depends on everything
    ["cloudformation"],
]
