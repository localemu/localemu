"""SQS collector: enumerate queues (no messages) from LocalEmu.

Messages are runtime state — exporting them would be as wrong as
exporting TCP sockets. Only queue definitions are emitted.

A queue's dead-letter target is surfaced as a :class:`Ref` when the DLQ
lives in the same (account, region); cross-account DLQs keep their raw
ARN. Same story for ``KmsMasterKeyId`` — refs if the key is local,
literal otherwise.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


@register_collector("sqs")
class SqsCollector(BaseCollector):
    """Collect SQS queues for a single (account, region)."""

    service = "sqs"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            from localemu.services.sqs.models import sqs_stores
        except Exception:  # pragma: no cover
            LOG.warning("Failed to import sqs_stores; skipping SQS", exc_info=True)
            return []

        try:
            store = sqs_stores[account_id][region]
        except Exception:
            LOG.warning(
                "No SQS store for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        queues = getattr(store, "queues", {}) or {}
        resources: list[Resource] = []
        for qname, queue in dict(queues).items():
            try:
                resources.append(
                    self._build_queue_resource(qname, queue, account_id, region)
                )
                policy_resource = self._build_queue_policy_resource(
                    qname, queue, account_id, region,
                )
                if policy_resource is not None:
                    resources.append(policy_resource)
            except Exception:
                LOG.warning(
                    "Failed to serialize SQS queue %r; skipping", qname, exc_info=True
                )
        return resources

    # ------------------------------------------------------------------

    def _build_queue_resource(
        self, qname: str, queue: Any, account_id: str, region: str
    ) -> Resource:
        is_fifo = qname.endswith(".fifo") or type(queue).__name__ == "FifoQueue"

        attrs: dict[str, Any] = {
            "name": qname,
            "fifo": is_fifo,
            "arn": getattr(queue, "arn", None),
            "visibility_timeout": _int_or_none(
                getattr(queue, "visibility_timeout", None)
            ),
            "message_retention_period": _int_or_none(
                getattr(queue, "message_retention_period", None)
            ),
            "maximum_message_size": _int_or_none(
                getattr(queue, "maximum_message_size", None)
            ),
            "receive_message_wait_time_seconds": _int_or_none(
                getattr(queue, "wait_time_seconds", None)
            ),
            "delay_seconds": _int_or_none(getattr(queue, "delay_seconds", None)),
        }

        # Redrive policy: dict with ``deadLetterTargetArn`` + ``maxReceiveCount``.
        redrive = getattr(queue, "redrive_policy", None)
        if redrive:
            attrs["redrive_policy"] = _redrive_with_ref(
                redrive, account_id, region
            )

        # Queue-level resource policy is NOT emitted inline — the
        # Terraform / CFN idiom is a separate ``aws_sqs_queue_policy`` /
        # ``AWS::SQS::QueuePolicy`` resource (see
        # :meth:`_build_queue_policy_resource`).

        # KMS
        kms_key = _queue_attr(queue, "KmsMasterKeyId")
        if kms_key:
            attrs["kms_master_key_id"] = _kms_ref_or_literal(
                kms_key, account_id, region
            )
        kms_reuse = _queue_attr(queue, "KmsDataKeyReusePeriodSeconds")
        if kms_reuse is not None:
            attrs["kms_data_key_reuse_period_seconds"] = _int_or_none(kms_reuse)

        # FIFO-specific
        if is_fifo:
            attrs["content_based_deduplication"] = _bool_attr(
                _queue_attr(queue, "ContentBasedDeduplication")
            )
            fifo_throughput = _queue_attr(queue, "FifoThroughputLimit")
            if fifo_throughput:
                attrs["fifo_throughput_limit"] = fifo_throughput
            dedup_scope = _queue_attr(queue, "DeduplicationScope")
            if dedup_scope:
                attrs["deduplication_scope"] = dedup_scope

        # Managed SSE
        sqs_managed_sse = _queue_attr(queue, "SqsManagedSseEnabled")
        if sqs_managed_sse is not None:
            attrs["sqs_managed_sse_enabled"] = _bool_attr(sqs_managed_sse)

        tags = _tags_to_dict(getattr(queue, "tags", None))
        created_ts = _queue_attr(queue, "CreatedTimestamp")
        created_at = _ts_to_iso(created_ts)

        return Resource(
            service="sqs",
            resource_type="queue",
            resource_id=qname,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )

    def _build_queue_policy_resource(
        self, qname: str, queue: Any, account_id: str, region: str,
    ) -> Resource | None:
        """Emit ``aws_sqs_queue_policy`` when the queue carries a user
        Policy attribute. SQS does not auto-create a queue policy, so any
        non-empty value here is operator-supplied and must round-trip.
        """
        policy_raw = _queue_attr(queue, "Policy")
        if not policy_raw:
            return None
        policy = _json_or_passthrough(policy_raw)
        return Resource(
            service="sqs",
            resource_type="queue_policy",
            resource_id=qname,
            account_id=account_id,
            region=region,
            attributes={
                # aws_sqs_queue's URL is exposed as ``.id`` in Terraform
                # (the AWS provider documents ``id`` and ``arn`` only;
                # ``id`` is the queue URL). CFN's AWS::SQS::QueuePolicy
                # uses Queues = [Ref(QueueName)] which also resolves to
                # the URL.
                "queue_url": Ref("sqs", "queue", qname, attribute="id"),
                "policy": policy,
            },
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _queue_attr(queue: Any, name: str) -> Any:
    """Read a value from the queue's attribute map, tolerating missing keys."""
    attributes = getattr(queue, "attributes", None)
    if not isinstance(attributes, dict):
        return None
    # Keys may be enum values — stringify for comparison.
    if name in attributes:
        return attributes[name]
    for k, v in attributes.items():
        if str(k) == name or getattr(k, "value", None) == name:
            return v
    return None


def _redrive_with_ref(
    redrive: Any, account_id: str, region: str
) -> dict[str, Any]:
    if isinstance(redrive, str):
        try:
            redrive = json.loads(redrive)
        except Exception:
            return {"raw": redrive}
    if not isinstance(redrive, dict):
        return {}
    out = dict(redrive)
    dlq_arn = out.get("deadLetterTargetArn")
    if isinstance(dlq_arn, str):
        ref = _queue_ref_from_arn(dlq_arn, account_id, region)
        if ref is not None:
            out["deadLetterTargetArn"] = ref
    # AWS normalizes ``maxReceiveCount`` to an integer in describe results,
    # but boto callers commonly pass it as a string. The Terraform AWS
    # provider compares the rendered JSON byte-for-byte during its post-
    # create attribute-converge wait — ``"5"`` vs ``5`` never settles, and
    # apply times out after 3 minutes. Normalize once here so the same
    # IR is shape-correct for every downstream writer.
    mrc = out.get("maxReceiveCount")
    if isinstance(mrc, str) and mrc.isdigit():
        out["maxReceiveCount"] = int(mrc)
    return out


def _queue_ref_from_arn(arn: str, account_id: str, region: str) -> Ref | None:
    # arn:aws:sqs:REGION:ACCOUNT:NAME
    parts = arn.split(":")
    if len(parts) < 6 or parts[2] != "sqs":
        return None
    if parts[3] != region or parts[4] != account_id:
        return None
    return Ref(service="sqs", resource_type="queue", resource_id=parts[5])


def _kms_ref_or_literal(
    value: str, account_id: str, region: str
) -> Ref | str:
    # alias/aws/* is AWS-managed — leave literal.
    if value.startswith("alias/aws/"):
        return value
    if value.startswith("arn:"):
        parts = value.split(":")
        if len(parts) >= 6 and parts[2] == "kms" and parts[3] == region and parts[
            4
        ] == account_id:
            # arn:aws:kms:region:account:key/<uuid>  or  :alias/<name>
            tail = parts[5]
            if tail.startswith("key/"):
                return Ref(
                    service="kms", resource_type="key", resource_id=tail[4:]
                )
            if tail.startswith("alias/"):
                return Ref(
                    service="kms", resource_type="alias", resource_id=tail[6:]
                )
        return value
    if value.startswith("alias/"):
        return Ref(
            service="kms", resource_type="alias", resource_id=value[len("alias/") :]
        )
    # Bare key id — assume local.
    return Ref(service="kms", resource_type="key", resource_id=value)


def _json_or_passthrough(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _tags_to_dict(tags: Any) -> dict[str, str]:
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        out: dict[str, str] = {}
        for entry in tags:
            if isinstance(entry, dict) and "Key" in entry and "Value" in entry:
                out[str(entry["Key"])] = str(entry["Value"])
        return out
    return {}


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_attr(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def _ts_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        import datetime as _dt

        return _dt.datetime.utcfromtimestamp(int(value)).isoformat() + "Z"
    except Exception:
        return None
