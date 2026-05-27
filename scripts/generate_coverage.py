#!/usr/bin/env python
"""Generate API coverage data for LocalEmu services.

Introspects the LocalEmu codebase to determine which AWS API operations
are implemented (custom handler, Moto fallback, or not implemented).

Usage:
    python scripts/generate_coverage.py > coverage.json
"""

import ast
import importlib
import inspect
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Display names for well-known services
# ---------------------------------------------------------------------------

DISPLAY_NAMES = {
    "acm": "ACM",
    "acm-pca": "ACM PCA",
    "amp": "AMP",
    "apigateway": "API Gateway",
    "apigatewayv2": "API Gateway V2",
    "appconfig": "AppConfig",
    "application-autoscaling": "Application Auto Scaling",
    "appmesh": "App Mesh",
    "appsync": "AppSync",
    "athena": "Athena",
    "autoscaling": "Auto Scaling",
    "backup": "Backup",
    "batch": "Batch",
    "bedrock": "Bedrock",
    "budgets": "Budgets",
    "ce": "Cost Explorer",
    "cloudformation": "CloudFormation",
    "cloudfront": "CloudFront",
    "cloudhsmv2": "CloudHSM V2",
    "cloudtrail": "CloudTrail",
    "cloudwatch": "CloudWatch",
    "codebuild": "CodeBuild",
    "codecommit": "CodeCommit",
    "codedeploy": "CodeDeploy",
    "codepipeline": "CodePipeline",
    "cognito-identity": "Cognito Identity",
    "cognito-idp": "Cognito User Pools",
    "comprehend": "Comprehend",
    "config": "Config",
    "databrew": "DataBrew",
    "datasync": "DataSync",
    "dax": "DAX",
    "directconnect": "Direct Connect",
    "dms": "DMS",
    "ds": "Directory Service",
    "dynamodb": "DynamoDB",
    "dynamodbstreams": "DynamoDB Streams",
    "ebs": "EBS",
    "ec2": "EC2",
    "ecr": "ECR",
    "ecs": "ECS",
    "efs": "EFS",
    "eks": "EKS",
    "elasticache": "ElastiCache",
    "elasticbeanstalk": "Elastic Beanstalk",
    "elb": "ELB",
    "elbv2": "ELB V2",
    "emr": "EMR",
    "emr-containers": "EMR Containers",
    "emr-serverless": "EMR Serverless",
    "es": "Elasticsearch",
    "events": "EventBridge",
    "firehose": "Kinesis Firehose",
    "fsx": "FSx",
    "glacier": "Glacier",
    "glue": "Glue",
    "guardduty": "GuardDuty",
    "iam": "IAM",
    "identitystore": "Identity Store",
    "inspector2": "Inspector V2",
    "iot": "IoT",
    "iot-data": "IoT Data",
    "kafka": "MSK",
    "kinesis": "Kinesis",
    "kms": "KMS",
    "lakeformation": "Lake Formation",
    "lambda": "Lambda",
    "logs": "CloudWatch Logs",
    "managedblockchain": "Managed Blockchain",
    "mediaconnect": "MediaConnect",
    "medialive": "MediaLive",
    "mediapackage": "MediaPackage",
    "mediapackagev2": "MediaPackage V2",
    "memorydb": "MemoryDB",
    "mq": "MQ",
    "neptune": "Neptune",
    "opensearch": "OpenSearch",
    "opensearchserverless": "OpenSearch Serverless",
    "organizations": "Organizations",
    "personalize": "Personalize",
    "pinpoint": "Pinpoint",
    "pipes": "EventBridge Pipes",
    "polly": "Polly",
    "quicksight": "QuickSight",
    "ram": "RAM",
    "rds": "RDS",
    "rds-data": "RDS Data",
    "redshift": "Redshift",
    "redshift-data": "Redshift Data",
    "rekognition": "Rekognition",
    "resiliencehub": "Resilience Hub",
    "resource-groups": "Resource Groups",
    "resourcegroupstaggingapi": "Resource Groups Tagging",
    "route53": "Route 53",
    "route53domains": "Route 53 Domains",
    "route53resolver": "Route 53 Resolver",
    "s3": "S3",
    "s3control": "S3 Control",
    "sagemaker": "SageMaker",
    "sagemaker-runtime": "SageMaker Runtime",
    "scheduler": "EventBridge Scheduler",
    "secretsmanager": "Secrets Manager",
    "securityhub": "Security Hub",
    "service-quotas": "Service Quotas",
    "servicecatalog": "Service Catalog",
    "servicediscovery": "Cloud Map",
    "ses": "SES",
    "sesv2": "SES V2",
    "shield": "Shield",
    "signer": "Signer",
    "sns": "SNS",
    "sqs": "SQS",
    "ssm": "SSM",
    "stepfunctions": "Step Functions",
    "sts": "STS",
    "support": "Support",
    "swf": "SWF",
    "textract": "Textract",
    "timestream-write": "Timestream Write",
    "transcribe": "Transcribe",
    "transfer": "Transfer",
    "wafv2": "WAF V2",
    "xray": "X-Ray",
}


def _warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# 1. Enumerate registered services from providers.py via AST
# ---------------------------------------------------------------------------

def _parse_providers() -> dict[str, dict]:
    """Parse providers.py with AST to classify each @aws_provider function.

    Returns a dict mapping service_name -> {
        "pattern": "moto_only" | "custom_dispatch" | "asf_pure" | "asf_moto_fallback",
        "func_name": str,          # Python function name in the module
        "moto_service_arg": str,   # for moto_only: the argument to _moto_service()
        "create_func": str,        # for custom_dispatch: e.g. "create_ecs_service"
        "import_path": str,        # for custom_dispatch: dotted module path
    }

    Only default entry points are included (name="default" or the unnamed default).
    """
    providers_path = Path(__file__).resolve().parent.parent / "src" / "localemu" / "services" / "providers.py"
    source = providers_path.read_text()
    tree = ast.parse(source, filename=str(providers_path))

    services: dict[str, dict] = {}

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        # Check for @aws_provider(...) decorator
        api_name = None
        provider_name = "default"
        is_aws_provider = False

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Name) and func.id == "aws_provider":
                    is_aws_provider = True
                    for kw in decorator.keywords:
                        if kw.arg == "api" and isinstance(kw.value, ast.Constant):
                            api_name = kw.value.value
                        elif kw.arg == "name" and isinstance(kw.value, ast.Constant):
                            provider_name = kw.value.value
            elif isinstance(decorator, ast.Name) and decorator.id == "aws_provider":
                is_aws_provider = True

        if not is_aws_provider:
            continue

        if api_name is None:
            api_name = node.name.rstrip("_")

        # Only include the default provider for each service
        if provider_name != "default":
            continue

        # Skip if we already have this service (first default wins)
        if api_name in services:
            continue

        # Analyze the function body to determine the pattern
        body_source = ast.get_source_segment(source, node)
        info = {"func_name": node.name}

        # Pattern C: _moto_service("xxx")
        if _body_contains_call(node, "_moto_service"):
            moto_arg = _extract_moto_service_arg(node)
            info["pattern"] = "moto_only"
            info["moto_service_arg"] = moto_arg or api_name
            services[api_name] = info
            continue

        # Pattern D: create_xxx_service()
        create_func_name = _extract_create_service_call(node)
        if create_func_name:
            import_path = _extract_import_path(node, create_func_name)
            info["pattern"] = "custom_dispatch"
            info["create_func"] = create_func_name
            info["import_path"] = import_path
            services[api_name] = info
            continue

        # Pattern A or B: Service.for_provider(...)
        if _body_contains_name(node, "MotoFallbackDispatcher"):
            info["pattern"] = "asf_moto_fallback"
        else:
            info["pattern"] = "asf_pure"

        # Extract provider import info for ASF patterns
        provider_import = _extract_provider_import(node)
        if provider_import:
            info["provider_module"] = provider_import["module"]
            info["provider_class"] = provider_import["name"]

        services[api_name] = info

    return services


def _body_contains_call(func_node: ast.FunctionDef, func_name: str) -> bool:
    """Check if the function body contains a call to a function with the given name."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == func_name:
                return True
    return False


def _body_contains_name(func_node: ast.FunctionDef, name: str) -> bool:
    """Check if the function body references a name."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Name) and node.id == name:
            return True
    return False


def _extract_moto_service_arg(func_node: ast.FunctionDef) -> str | None:
    """Extract the string argument from _moto_service("xxx")."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "_moto_service":
                if node.args and isinstance(node.args[0], ast.Constant):
                    return node.args[0].value
    return None


def _extract_create_service_call(func_node: ast.FunctionDef) -> str | None:
    """Extract the name of a create_xxx_service() call if present."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id.startswith("create_") and node.func.id.endswith("_service"):
                return node.func.id
    return None


def _extract_import_path(func_node: ast.FunctionDef, name: str) -> str | None:
    """Find the import path for a given name imported inside the function body."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                actual_name = alias.asname or alias.name
                if actual_name == name:
                    return node.module
    return None


def _extract_provider_import(func_node: ast.FunctionDef) -> dict | None:
    """Extract the module and class name of the provider imported in the function."""
    for node in ast.walk(func_node):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                actual_name = alias.asname or alias.name
                if "Provider" in actual_name and "Dispatcher" not in actual_name:
                    return {"module": node.module, "name": actual_name}
    return None


# ---------------------------------------------------------------------------
# 2. Get operations for each pattern
# ---------------------------------------------------------------------------

def _get_service_operations(service_name: str) -> list[str]:
    """Load the botocore service model and return sorted operation names."""
    from localemu.aws.spec import load_service
    model = load_service(service_name)
    return sorted(model.operation_names)


def get_operations_moto_only(service_name: str) -> list[dict]:
    """Pattern C: all operations are 'moto'."""
    ops = _get_service_operations(service_name)
    return [{"name": op, "status": "moto"} for op in ops]


def get_operations_custom_dispatch(service_name: str, info: dict) -> list[dict]:
    """Pattern D: ``create_xxx_service()`` factories.

    Two styles in practice:
      * Old style: the module exposes ``_INTERCEPTED_OPS = {Op: fn, ...}``
        and we classify each op as ``custom`` iff it's a key.
      * New style: the factory returns ``Service.for_provider(provider,
        dispatch_table_factory=MotoFallbackDispatcher)``. There is no
        ``_INTERCEPTED_OPS`` to inspect — the dispatch table is built
        from method overrides on the provider class. We fall through
        to actually calling the factory and inspecting the resulting
        service's dispatch table the same way the ASF path does.
    """
    ops = _get_service_operations(service_name)

    intercepted_ops: set[str] = set()
    import_path = info.get("import_path")
    create_func = info.get("create_func")
    if import_path:
        try:
            mod = importlib.import_module(import_path)
            intercepted_dict = getattr(mod, "_INTERCEPTED_OPS", None)
            if intercepted_dict and isinstance(intercepted_dict, dict):
                intercepted_ops = set(intercepted_dict.keys())
            elif create_func:
                # Try the factory path: instantiate the service, look
                # inside the dispatch table, and treat any op whose
                # handler resides on the provider class (rather than
                # the MotoFallbackDispatcher) as ``custom``.
                intercepted_ops = _custom_ops_from_factory(mod, create_func)
        except Exception as exc:
            _warn(f"Failed to import {import_path} for {service_name}: {exc}")

    has_any_custom = bool(intercepted_ops)
    return [
        {
            "name": op,
            "status": (
                "custom" if op in intercepted_ops
                else "moto" if has_any_custom
                else "moto"
            ),
        }
        for op in ops
    ]


def _custom_ops_from_factory(module, create_func: str) -> set[str]:
    """Find the *Provider class exported alongside ``create_xxx_service``
    and inspect its un-wrapped dispatch table.

    The Service returned by the factory carries the post-wrapping
    dispatch table (each entry is the closure ``_wrap_with_fallthrough.
    <locals>._call``), so we can't read the underlying handler qualname
    from there. Instead, locate the provider class in the same module
    (or via the factory's source code), instantiate it directly, and
    let ``create_dispatch_table(provider)`` give us the pre-wrapping
    handlers whose qualnames identify the provider class.
    """
    from localemu.aws.skeleton import create_dispatch_table

    provider_cls = None
    for attr in dir(module):
        if attr.endswith("Provider") and not attr.startswith("_"):
            cls = getattr(module, attr, None)
            if isinstance(cls, type):
                provider_cls = cls
                break
    if provider_cls is None:
        return set()
    try:
        provider = provider_cls()
        table = create_dispatch_table(provider)
    except Exception:
        return set()
    provider_class_name = type(provider).__name__
    custom_ops: set[str] = set()
    for op_name, dispatcher in table.items():
        fn = getattr(dispatcher, "fn", None) or dispatcher
        qualname = getattr(fn, "__qualname__", "")
        if provider_class_name in qualname:
            custom_ops.add(op_name)
    return custom_ops


def get_operations_asf(service_name: str, info: dict, has_moto_fallback: bool) -> list[dict]:
    """Pattern A/B: inspect the dispatch table created from the provider."""
    from localemu.aws.skeleton import create_dispatch_table

    module_path = info.get("provider_module")
    class_name = info.get("provider_class")

    if not module_path or not class_name:
        _warn(f"Missing provider info for {service_name}, treating all ops as unknown")
        ops = _get_service_operations(service_name)
        status = "moto" if has_moto_fallback else "not_implemented"
        return [{"name": op, "status": status} for op in ops]

    try:
        mod = importlib.import_module(module_path)
        provider_cls = getattr(mod, class_name)
        provider = provider_cls()
    except Exception as exc:
        _warn(f"Failed to instantiate {class_name} from {module_path} for {service_name}: {exc}")
        ops = _get_service_operations(service_name)
        status = "moto" if has_moto_fallback else "not_implemented"
        return [{"name": op, "status": status} for op in ops]

    try:
        dispatch_table = create_dispatch_table(provider)
    except Exception as exc:
        _warn(f"Failed to create dispatch table for {service_name}: {exc}")
        ops = _get_service_operations(service_name)
        status = "moto" if has_moto_fallback else "not_implemented"
        return [{"name": op, "status": status} for op in ops]

    provider_class_name = type(provider).__name__

    # We need all operations from the service model, not just what's in the dispatch table
    all_ops = _get_service_operations(service_name)

    results = []
    for op in all_ops:
        dispatcher = dispatch_table.get(op)
        if dispatcher is None:
            # Operation not in dispatch table at all
            status = "moto" if has_moto_fallback else "not_implemented"
        else:
            handler_fn = dispatcher.fn
            qualname = handler_fn.__qualname__
            if provider_class_name in qualname:
                status = "custom"
            elif has_moto_fallback:
                status = "moto"
            else:
                status = "not_implemented"
        results.append({"name": op, "status": status})

    return results


# ---------------------------------------------------------------------------
# 3. Main generation
# ---------------------------------------------------------------------------

def generate_coverage() -> dict:
    """Generate the full coverage JSON structure."""
    services_info = _parse_providers()

    coverage_services = {}
    total_operations = 0
    total_implemented = 0

    for service_name in sorted(services_info.keys()):
        info = services_info[service_name]
        pattern = info["pattern"]

        try:
            if pattern == "moto_only":
                operations = get_operations_moto_only(
                    info.get("moto_service_arg", service_name)
                )
            elif pattern == "custom_dispatch":
                operations = get_operations_custom_dispatch(service_name, info)
            elif pattern == "asf_moto_fallback":
                operations = get_operations_asf(service_name, info, has_moto_fallback=True)
            elif pattern == "asf_pure":
                operations = get_operations_asf(service_name, info, has_moto_fallback=False)
            else:
                _warn(f"Unknown pattern {pattern!r} for {service_name}, skipping")
                continue
        except Exception as exc:
            _warn(f"Failed to introspect {service_name}: {exc}")
            continue

        custom_count = sum(1 for op in operations if op["status"] == "custom")
        moto_count = sum(1 for op in operations if op["status"] == "moto")
        not_impl_count = sum(1 for op in operations if op["status"] == "not_implemented")
        total_ops = len(operations)

        total_operations += total_ops
        total_implemented += custom_count + moto_count

        display_name = DISPLAY_NAMES.get(service_name, service_name)

        coverage_services[service_name] = {
            "display_name": display_name,
            "total": total_ops,
            "custom": custom_count,
            "moto": moto_count,
            "not_implemented": not_impl_count,
            "operations": operations,
        }

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_services": len(coverage_services),
        "total_operations": total_operations,
        "total_implemented": total_implemented,
        "services": coverage_services,
    }


def main() -> None:
    coverage = generate_coverage()
    json.dump(coverage, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
