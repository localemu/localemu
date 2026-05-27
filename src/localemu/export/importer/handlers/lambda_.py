"""AWS Lambda function import handler.

Lambda is the most complex handler in the MVP: code bytes come from a
sidecar zip (by convention ``lambda/<function-name>.zip`` in
``Snapshot.sidecar_files``), the ``role`` attribute may be a :class:`Ref`
that must be resolved to an IAM role ARN in the target account, and
``create_function`` is eventually consistent — a follow-up call made
immediately after can race.

The module uses a thread-local cache for the caller identity so parallel
waves don't spam ``sts:GetCallerIdentity``.
"""

from __future__ import annotations

import json
import logging
import threading
import time

from botocore.exceptions import ClientError

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.handlers import register_handler
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

_WAIT_TIMEOUT_S = 120
_caller_cache: dict[str, str] = {}
_caller_cache_lock = threading.Lock()


def _caller_account(client_factory: ClientFactory, region: str) -> str:
    with _caller_cache_lock:
        cached = _caller_cache.get(region)
        if cached is not None:
            return cached
    sts = client_factory.get_client("sts", region)
    account = sts.get_caller_identity()["Account"]
    with _caller_cache_lock:
        _caller_cache[region] = account
    return account


def _resolve_role(role_value: object, client_factory: ClientFactory, region: str) -> str | None:
    """Resolve the ``role`` attribute of a Lambda to an ARN on the target."""
    if isinstance(role_value, Ref):
        # Assume IAM role in the current account/region.
        try:
            account = _caller_account(client_factory, region)
        except ClientError as exc:
            LOG.warning("could not resolve caller account: %s", exc)
            return None
        return f"arn:aws:iam::{account}:role/{role_value.resource_id}"
    if isinstance(role_value, str):
        return role_value
    return None


def _get_function(client, name: str):  # type: ignore[no-untyped-def]
    try:
        return client.get_function(FunctionName=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            return None
        raise


def _wait_function_active(client, name: str) -> None:  # type: ignore[no-untyped-def]
    deadline = time.time() + _WAIT_TIMEOUT_S
    while time.time() < deadline:
        try:
            cfg = client.get_function_configuration(FunctionName=name)
        except ClientError:
            return
        state = cfg.get("State")
        if state in ("Active", None):
            return
        if state == "Failed":
            LOG.warning("Lambda %s entered Failed state: %s", name, cfg.get("StateReason"))
            return
        time.sleep(1.0)


def _lookup_code_bytes(resource: Resource, sidecar_files: dict[str, bytes]) -> bytes | None:
    """Find zipped code bytes in ``sidecar_files`` for this function."""
    attrs = resource.attributes
    # Explicit sidecar path wins.
    for key in ("code_sidecar_path", "sidecar_path"):
        path = attrs.get(key)
        if isinstance(path, str) and path in sidecar_files:
            return sidecar_files[path]
    # Conventional paths.
    conventional = [
        f"lambda/{resource.resource_id}.zip",
        f"lambda/{resource.region}/{resource.resource_id}.zip",
        f"{resource.resource_id}.zip",
    ]
    for path in conventional:
        if path in sidecar_files:
            return sidecar_files[path]
    return None


@register_handler("lambda", "function")
def handle_function(
    resource: Resource,
    client_factory: ClientFactory,
    mode: object,
    dry_run: bool,
) -> tuple[str, str, str | None]:
    from localemu.export.importer.replay import ImportMode, _CURRENT_SNAPSHOT

    assert isinstance(mode, ImportMode)
    name = resource.resource_id
    attrs = resource.attributes

    if dry_run:
        return ("applied", name, "dry-run")

    client = client_factory.get_client("lambda", resource.region)

    try:
        existing = _get_function(client, name)
    except ClientError as exc:
        return ("failed", name, f"get_function failed: {exc}")

    if existing is not None:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", name, "already exists and mode=fail-on-existing")
        try:
            client.delete_function(FunctionName=name)
        except ClientError as exc:
            return ("failed", name, f"delete before replace failed: {exc}")

    snapshot = _CURRENT_SNAPSHOT.get()
    sidecar_files = snapshot.sidecar_files if snapshot is not None else {}

    code_bytes = _lookup_code_bytes(resource, sidecar_files)
    image_uri = attrs.get("code", {}).get("ImageUri") if isinstance(attrs.get("code"), dict) else None
    package_type = attrs.get("package_type") or attrs.get("PackageType") or (
        "Image" if image_uri else "Zip"
    )

    if package_type == "Zip" and code_bytes is None:
        return ("failed", name, "no zipped code bytes found in snapshot sidecar_files")

    role_arn = _resolve_role(attrs.get("role") or attrs.get("Role"), client_factory, resource.region)
    if role_arn is None and package_type == "Zip":
        return ("failed", name, "could not resolve execution role ARN")

    kwargs: dict[str, object] = {
        "FunctionName": name,
        "Role": role_arn,
        "PackageType": package_type,
    }
    if package_type == "Zip":
        kwargs["Runtime"] = attrs.get("runtime") or attrs.get("Runtime", "python3.11")
        kwargs["Handler"] = attrs.get("handler") or attrs.get("Handler", "index.handler")
        kwargs["Code"] = {"ZipFile": code_bytes}
    else:
        kwargs["Code"] = {"ImageUri": image_uri}

    for src, dst in (
        ("description", "Description"),
        ("timeout", "Timeout"),
        ("memory_size", "MemorySize"),
        ("architectures", "Architectures"),
    ):
        val = attrs.get(src) if attrs.get(src) is not None else attrs.get(dst)
        if val is not None:
            kwargs[dst] = val

    env = attrs.get("environment") or attrs.get("Environment")
    if isinstance(env, dict):
        variables = env.get("Variables") if "Variables" in env else env
        if isinstance(variables, dict) and variables:
            # Coerce non-string values to strings; Lambda rejects non-str.
            kwargs["Environment"] = {"Variables": {k: str(v) for k, v in variables.items()}}

    if resource.tags:
        kwargs["Tags"] = dict(resource.tags)

    try:
        client.create_function(**kwargs)
        _wait_function_active(client, name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceConflictException" and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists (ResourceConflictException)")
        return ("failed", name, f"{code}: {exc}")

    # Best-effort: function URL, if the snapshot carried one.
    url_config = attrs.get("function_url_config")
    if isinstance(url_config, dict) and url_config.get("AuthType"):
        try:
            client.create_function_url_config(
                FunctionName=name,
                AuthType=url_config["AuthType"],
                Cors=url_config.get("Cors") or {},
            )
        except ClientError as exc:
            LOG.warning("create_function_url_config(%s) failed: %s", name, exc)

    # Best-effort: event source mappings referenced inline.
    for mapping in attrs.get("event_source_mappings", []) or []:
        if not isinstance(mapping, dict):
            continue
        esm_kwargs = {
            "FunctionName": name,
            "EventSourceArn": _resolve_esm_arn(mapping.get("EventSourceArn"), client_factory, resource.region),
            "Enabled": mapping.get("Enabled", True),
        }
        if mapping.get("BatchSize"):
            esm_kwargs["BatchSize"] = mapping["BatchSize"]
        try:
            client.create_event_source_mapping(**esm_kwargs)
        except ClientError as exc:
            LOG.warning("create_event_source_mapping(%s) failed: %s", name, exc)

    return ("applied", name, None)


def _resolve_esm_arn(value: object, client_factory: ClientFactory, region: str) -> str:
    if isinstance(value, Ref):
        try:
            account = _caller_account(client_factory, region)
        except ClientError:
            account = "000000000000"
        # Heuristic per-service ARN shapes — sufficient for SQS/DDB/Kinesis.
        svc = value.service
        rt = value.resource_type
        if svc == "sqs" and rt == "queue":
            return f"arn:aws:sqs:{region}:{account}:{value.resource_id}"
        if svc == "dynamodb" and rt == "table":
            return f"arn:aws:dynamodb:{region}:{account}:table/{value.resource_id}/stream/latest"
        if svc == "kinesis" and rt == "stream":
            return f"arn:aws:kinesis:{region}:{account}:stream/{value.resource_id}"
        return f"arn:aws:{svc}:{region}:{account}:{value.resource_id}"
    if isinstance(value, str):
        return value
    return json.dumps(value)
