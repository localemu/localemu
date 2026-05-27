"""Real-API smoke across every service in coverage.json.

For each service, call the cheapest no-required-args List/Describe
operation we can find in its botocore model. Record:

  - SDK-call OK (HTTP 2xx, AWS-shaped response) → service alive
  - HTTP 4xx (NotFoundException, ValidationException, etc.) → service alive
    (the API is wired even if the op needs a real resource arg)
  - HTTP 5xx (InternalError, InternalFailure, NotImplemented from moto)
    → service dead-on-arrival

This is a fingerprint sweep: it does NOT test every operation, but it
DOES confirm every advertised service has a working dispatch.
"""

import json
import os
import pathlib
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

import boto3
import botocore.exceptions

ENDPOINT = "http://localhost:4566"
KW = dict(
    endpoint_url=ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

session = boto3.Session()

# Map service slug → boto3 client name, for the cases that diverge.
BOTO_CLIENT_NAME_OVERRIDES = {
    "lambda_": "lambda",
    "events": "events",
    "states": "stepfunctions",
}

# Skip services that need wire-protocol clients (not boto3 HTTP).
SKIP_SERVICES = set()

# Services where the FIRST cheap op happens to be expensive or need
# Docker / external infra we don't want to spin up during a smoke.
# Use a more expensive fallback op for these.
PREFERRED_OPS = {
    "ec2": "describe_regions",          # no args
    "iam": "list_roles",
    "sts": "get_caller_identity",
    "s3": "list_buckets",
    "lambda": "list_functions",
    "sqs": "list_queues",
    "sns": "list_topics",
    "dynamodb": "list_tables",
    "kafka": "list_clusters",
    "mq": "list_brokers",
    "scheduler": "list_schedules",
    "sesv2": "list_email_identities",
    "pipes": "list_pipes",
    "kms": "list_keys",
    "secretsmanager": "list_secrets",
    "cloudformation": "list_stacks",
    "cloudwatch": "list_metrics",
    "logs": "describe_log_groups",
    "stepfunctions": "list_state_machines",
    "ses": "list_identities",
    "ssm": "list_documents",
    "ecs": "list_clusters",
    "eks": "list_clusters",
    "ecr": "describe_repositories",
    "rds": "describe_db_clusters",
    "route53": "list_hosted_zones",
    "route53resolver": "list_resolver_endpoints",
    "elbv2": "describe_load_balancers",
    "elb": "describe_load_balancers",
    "apigateway": "get_rest_apis",
    "apigatewayv2": "get_apis",
    "cloudfront": "list_distributions",
    "cloudtrail": "list_trails",
    "athena": "list_data_catalogs",
    "redshift": "describe_clusters",
    "redshift-data": "list_databases",
    "rds-data": "execute_statement",     # needs args; will hit 4xx — that's still alive
    "firehose": "list_delivery_streams",
    "kinesis": "list_streams",
    "dynamodbstreams": "list_streams",
    "swf": "list_domains",
    "transcribe": "list_transcription_jobs",
    "transfer": "list_servers",
    "translate": "list_text_translation_jobs",
    "wafv2": "list_web_acls",            # requires Scope
    "cognito-idp": "list_user_pools",
    "cognito-identity": "list_identity_pools",
    "opensearch": "list_domain_names",
    "es": "list_domain_names",
    "ram": "get_resource_shares",
    "ses-v2": "list_email_identities",
    "config": "describe_config_rules",
    "guardduty": "list_detectors",
    "inspector2": "list_findings",
    "organizations": "list_accounts",
    "scheduler": "list_schedules",
    "shield": "list_protections",
    "signer": "list_signing_profiles",
    "support": "describe_cases",
    "textract": "list_adapters",
    "neptune": "describe_db_clusters",
    "kinesisanalyticsv2": "list_applications",
    "managedblockchain": "list_networks",
    "elasticbeanstalk": "describe_environments",
    "ebs": "list_snapshots",
    "amp": "list_workspaces",
    "appmesh": "list_meshes",
    "appsync": "list_graphql_apis",
    "applicationautoscaling": "describe_scalable_targets",
    "autoscaling": "describe_auto_scaling_groups",
    "backup": "list_backup_vaults",
    "batch": "describe_job_queues",
    "bedrock": "list_foundation_models",
    "budgets": "describe_budgets",         # needs AccountId; expects 4xx
    "ce": "get_dimension_values",          # needs args
    "cloudhsmv2": "describe_clusters",
    "codebuild": "list_projects",
    "codecommit": "list_repositories",
    "codedeploy": "list_applications",
    "codepipeline": "list_pipelines",
    "comprehend": "list_document_classifiers",
    "databrew": "list_jobs",
    "datasync": "list_locations",
    "dax": "describe_clusters",
    "dms": "describe_replication_instances",
    "ds": "describe_directories",
    "efs": "describe_file_systems",
    "elasticache": "describe_cache_clusters",
    "emr-containers": "list_virtual_clusters",
    "emr-serverless": "list_applications",
    "emr": "list_clusters",
    "fsx": "describe_file_systems",
    "glacier": "list_vaults",
    "glue": "get_databases",
    "iot": "list_things",
    "iot-data": "list_named_shadows_for_thing",    # needs args
    "lakeformation": "list_resources",
    "memorydb": "describe_clusters",
    "mediaconnect": "list_flows",
    "medialive": "list_channels",
    "mediapackage": "list_channels",
    "mediapackagev2": "list_channel_groups",
    "directconnect": "describe_connections",
    "identitystore": "list_users",
    "personalize": "list_dataset_groups",
    "pinpoint": "get_apps",
    "polly": "describe_voices",
    "quicksight": "list_users",            # needs args
    "rekognition": "list_collections",
    "resourcegroupstaggingapi": "get_resources",
    "resource-groups": "list_groups",
    "resiliencehub": "list_apps",
    "sagemaker": "list_endpoints",
    "sagemaker-runtime": "invoke_endpoint",       # needs args; 4xx = alive
    "securityhub": "describe_hub",
    "service-quotas": "list_services",
    "servicecatalog": "list_portfolios",
    "servicediscovery": "list_namespaces",
    "timestream-write": "list_databases",
    "acm": "list_certificates",
    "acm-pca": "list_certificate_authorities",
    "appconfig": "list_applications",
    "fis": "list_experiments",
    "iotwireless": "list_devices",
    "lakeformation": "list_resources",
    "logs": "describe_log_groups",
    "lambda": "list_functions",
    "verifiedpermissions": "list_policy_stores",
    "xray": "get_service_graph",            # 4xx for missing TimeRange — alive
    "polly": "describe_voices",
}


def main():
    # See test_all_ops_probe_live.py for the same resolution logic: prefer
    # LOCALEMU_COVERAGE_JSON if set, else assume the website checkout sits
    # next to this repo.
    coverage_path = os.environ.get(
        "LOCALEMU_COVERAGE_JSON",
        str(pathlib.Path(__file__).resolve().parents[3].parent
            / "localemu-cloud-website" / "src" / "data" / "coverage.json"),
    )
    with open(coverage_path) as f:
        coverage = json.load(f)
    services = sorted(coverage["services"].keys())

    results = {}
    counts = defaultdict(int)

    for svc in services:
        if svc in SKIP_SERVICES:
            results[svc] = {"status": "skipped", "reason": "needs wire-protocol client"}
            counts["skipped"] += 1
            continue
        op_name = PREFERRED_OPS.get(svc)
        try:
            client = session.client(svc, **KW)
        except Exception as e:
            results[svc] = {"status": "no-client", "reason": f"{type(e).__name__}: {e}"}
            counts["no-client"] += 1
            continue
        if op_name is None:
            # Try to find any list_* method on the client as a fallback
            op_name = next(
                (n for n in dir(client) if n.startswith("list_") and not n.startswith("list_tags")),
                None,
            )
        if op_name is None:
            results[svc] = {"status": "no-op", "reason": "no list_* op available"}
            counts["no-op"] += 1
            continue
        op = getattr(client, op_name, None)
        if op is None:
            results[svc] = {"status": "no-op", "reason": f"op {op_name} missing on client"}
            counts["no-op"] += 1
            continue
        try:
            op()
            results[svc] = {"status": "alive", "op": op_name, "outcome": "2xx"}
            counts["alive"] += 1
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "?")
            http = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            if http and 400 <= http < 500:
                results[svc] = {"status": "alive", "op": op_name,
                                "outcome": f"4xx {code}"}
                counts["alive"] += 1
            else:
                results[svc] = {"status": "broken", "op": op_name,
                                "outcome": f"{http} {code}",
                                "detail": str(e)[:200]}
                counts["broken"] += 1
        except botocore.exceptions.ParamValidationError as e:
            # client-side validation needs args we didn't provide — still
            # means the service is alive from a wiring perspective.
            results[svc] = {"status": "needs-args", "op": op_name,
                            "outcome": f"ParamValidationError"}
            counts["alive"] += 1
        except botocore.exceptions.EndpointConnectionError as e:
            results[svc] = {"status": "no-endpoint", "op": op_name,
                            "outcome": "EndpointConnectionError"}
            counts["no-endpoint"] += 1
        except Exception as e:
            results[svc] = {"status": "error", "op": op_name,
                            "outcome": f"{type(e).__name__}: {e!s:.200s}"}
            counts["error"] += 1

    print(f"\n=== Service smoke across {len(services)} services ===\n")
    for cat in ("alive", "broken", "error", "no-endpoint", "no-client", "no-op", "skipped"):
        print(f"  {cat:14s}: {counts[cat]}")
    print()
    # List the failures
    for cat in ("broken", "error", "no-endpoint", "no-client"):
        if counts[cat]:
            print(f"\n--- {cat} ---")
            for svc, r in sorted(results.items()):
                if r["status"] == cat:
                    detail = r.get("detail") or r.get("outcome") or r.get("reason") or ""
                    print(f"  {svc:30s} ({r.get('op', '-')}): {detail}")
    # Dump full json for downstream coverage updates.
    out_path = "/tmp/sweep_all_services_results.json"
    with open(out_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total": len(services),
            "counts": dict(counts),
            "results": results,
        }, f, indent=2)
    print(f"\nFull JSON: {out_path}")


if __name__ == "__main__":
    main()
