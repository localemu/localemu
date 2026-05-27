"""DynamoDB table import handler.

DynamoDB's ``create_table`` is particular: it wants only the attributes
that are actually used by a key or index, billing mode affects whether
``ProvisionedThroughput`` is required, and GSIs must carry their own
throughput when the table is provisioned. We filter/shape the exported
attributes to match, rather than blindly forwarding them.
"""

from __future__ import annotations

import logging
import time

from botocore.exceptions import ClientError

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.handlers import register_handler
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

_WAIT_TIMEOUT_S = 120


def _describe(client, name: str):  # type: ignore[no-untyped-def]
    try:
        return client.describe_table(TableName=name)["Table"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            return None
        raise


def _wait_active(client, name: str) -> None:  # type: ignore[no-untyped-def]
    deadline = time.time() + _WAIT_TIMEOUT_S
    while time.time() < deadline:
        t = _describe(client, name)
        if t is None:
            return
        if t.get("TableStatus") == "ACTIVE":
            return
        time.sleep(1.0)
    LOG.warning("timed out waiting for DynamoDB table %s to become ACTIVE", name)


def _wait_gone(client, name: str) -> None:  # type: ignore[no-untyped-def]
    deadline = time.time() + _WAIT_TIMEOUT_S
    while time.time() < deadline:
        if _describe(client, name) is None:
            return
        time.sleep(1.0)
    LOG.warning("timed out waiting for DynamoDB table %s to be deleted", name)


def _build_create_kwargs(resource: Resource) -> dict[str, object]:
    """Shape ``attributes`` into a valid ``create_table`` payload."""
    attrs = resource.attributes
    key_schema = attrs.get("key_schema") or attrs.get("KeySchema") or []
    attribute_definitions = attrs.get("attribute_definitions") or attrs.get("AttributeDefinitions") or []
    billing_mode = attrs.get("billing_mode") or attrs.get("BillingMode") or "PAY_PER_REQUEST"

    # Keep only attribute defs that appear in a key (schema or index key);
    # DynamoDB rejects create_table otherwise.
    used_names: set[str] = set()
    for k in key_schema:
        if isinstance(k, dict) and "AttributeName" in k:
            used_names.add(k["AttributeName"])
    gsis = attrs.get("global_secondary_indexes") or attrs.get("GlobalSecondaryIndexes") or []
    lsis = attrs.get("local_secondary_indexes") or attrs.get("LocalSecondaryIndexes") or []
    for idx in list(gsis) + list(lsis):
        for k in idx.get("KeySchema", []) or []:
            if isinstance(k, dict) and "AttributeName" in k:
                used_names.add(k["AttributeName"])
    filtered_defs = [
        d for d in attribute_definitions if isinstance(d, dict) and d.get("AttributeName") in used_names
    ]

    kwargs: dict[str, object] = {
        "TableName": resource.resource_id,
        "KeySchema": key_schema,
        "AttributeDefinitions": filtered_defs,
        "BillingMode": billing_mode,
    }
    if billing_mode == "PROVISIONED":
        prov = attrs.get("provisioned_throughput") or attrs.get("ProvisionedThroughput") or {
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        }
        # describe_table returns extra read-only keys (NumberOfDecreasesToday
        # LastDecreaseDateTime, ...) — strip them.
        kwargs["ProvisionedThroughput"] = {
            "ReadCapacityUnits": int(prov.get("ReadCapacityUnits", 5)),
            "WriteCapacityUnits": int(prov.get("WriteCapacityUnits", 5)),
        }

    if gsis:
        clean_gsis = []
        for idx in gsis:
            clean = {
                "IndexName": idx["IndexName"],
                "KeySchema": idx["KeySchema"],
                "Projection": idx.get("Projection", {"ProjectionType": "ALL"}),
            }
            if billing_mode == "PROVISIONED":
                p = idx.get("ProvisionedThroughput") or {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
                clean["ProvisionedThroughput"] = {
                    "ReadCapacityUnits": int(p.get("ReadCapacityUnits", 5)),
                    "WriteCapacityUnits": int(p.get("WriteCapacityUnits", 5)),
                }
            clean_gsis.append(clean)
        kwargs["GlobalSecondaryIndexes"] = clean_gsis

    if lsis:
        kwargs["LocalSecondaryIndexes"] = [
            {
                "IndexName": idx["IndexName"],
                "KeySchema": idx["KeySchema"],
                "Projection": idx.get("Projection", {"ProjectionType": "ALL"}),
            }
            for idx in lsis
        ]

    stream = attrs.get("stream_specification") or attrs.get("StreamSpecification")
    if isinstance(stream, dict) and stream.get("StreamEnabled"):
        kwargs["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream.get("StreamViewType", "NEW_AND_OLD_IMAGES"),
        }

    if resource.tags:
        kwargs["Tags"] = [{"Key": k, "Value": v} for k, v in resource.tags.items()]

    return kwargs


@register_handler("dynamodb", "table")
def handle_table(
    resource: Resource,
    client_factory: ClientFactory,
    mode: object,
    dry_run: bool,
) -> tuple[str, str, str | None]:
    from localemu.export.importer.replay import ImportMode

    assert isinstance(mode, ImportMode)
    name = resource.resource_id

    if dry_run:
        return ("applied", name, "dry-run")

    client = client_factory.get_client("dynamodb", resource.region)

    try:
        existing = _describe(client, name)
    except ClientError as exc:
        return ("failed", name, f"describe_table failed: {exc}")

    if existing is not None:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", name, "already exists and mode=fail-on-existing")
        try:
            client.delete_table(TableName=name)
            _wait_gone(client, name)
        except ClientError as exc:
            return ("failed", name, f"delete before replace failed: {exc}")

    try:
        kwargs = _build_create_kwargs(resource)
        client.create_table(**kwargs)
        _wait_active(client, name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceInUseException" and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists (ResourceInUseException)")
        return ("failed", name, f"{code}: {exc}")
    except Exception as exc:  # malformed snapshot attributes, etc.
        return ("failed", name, f"create_table error: {exc}")

    return ("applied", name, None)
