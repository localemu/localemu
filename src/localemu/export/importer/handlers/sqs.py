"""SQS queue import handler.

Replays FIFO vs. standard queues by inspecting the ``.fifo`` suffix and
the collected attributes. ``QueueUrl`` is derived after creation; we do
not attempt to round-trip the exact URL from the source account because
it contains the source account id.
"""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError

from localemu.export.importer.clients import ClientFactory
from localemu.export.importer.handlers import register_handler
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

# Attributes that SQS's ``create_queue``/``set_queue_attributes`` accept.
# Anything else returned by ``get_queue_attributes`` at export time (e.g.
# ``QueueArn``, ``ApproximateNumberOfMessages``) is read-only and must be
# filtered out before replay.
_CREATABLE_ATTRS = {
    "DelaySeconds",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "Policy",
    "ReceiveMessageWaitTimeSeconds",
    "RedrivePolicy",
    "RedriveAllowPolicy",
    "VisibilityTimeout",
    "KmsMasterKeyId",
    "KmsDataKeyReusePeriodSeconds",
    "SqsManagedSseEnabled",
    "FifoQueue",
    "ContentBasedDeduplication",
    "DeduplicationScope",
    "FifoThroughputLimit",
}


def _get_queue_url(client, name: str) -> str | None:  # type: ignore[no-untyped-def]
    try:
        return client.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            return None
        raise


def _filter_attrs(attrs: dict[str, object]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in attrs.items():
        if key not in _CREATABLE_ATTRS:
            continue
        # SQS attributes are all strings on the wire.
        out[key] = value if isinstance(value, str) else str(value)
    return out


@register_handler("sqs", "queue")
def handle_queue(
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

    client = client_factory.get_client("sqs", resource.region)

    try:
        existing_url = _get_queue_url(client, name)
    except ClientError as exc:
        return ("failed", name, f"get_queue_url failed: {exc}")

    if existing_url is not None:
        if mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists")
        if mode is ImportMode.FAIL_ON_EXISTING:
            return ("failed", name, "already exists and mode=fail-on-existing")
        try:
            client.delete_queue(QueueUrl=existing_url)
        except ClientError as exc:
            return ("failed", name, f"delete before replace failed: {exc}")

    raw_attrs = resource.attributes.get("attributes")
    if not isinstance(raw_attrs, dict):
        raw_attrs = {}
    create_attrs = _filter_attrs(raw_attrs)
    # FIFO queues require the FifoQueue attribute explicitly.
    if name.endswith(".fifo") and "FifoQueue" not in create_attrs:
        create_attrs["FifoQueue"] = "true"

    kwargs: dict[str, object] = {"QueueName": name}
    if create_attrs:
        kwargs["Attributes"] = create_attrs
    if resource.tags:
        kwargs["tags"] = dict(resource.tags)

    try:
        client.create_queue(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "QueueAlreadyExists" and mode is ImportMode.SKIP_EXISTING:
            return ("skipped", name, "already exists (QueueAlreadyExists)")
        return ("failed", name, f"{code}: {exc}")

    return ("applied", name, None)
