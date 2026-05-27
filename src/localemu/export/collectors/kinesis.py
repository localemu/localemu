"""Kinesis Data Streams collector.

Exports streams and stream consumers. Records are *not* exported — they
are ephemeral by design (24h-365d retention) and reproducing them on
the import side is rarely what the user wants. If a user really needs
record-level replay they should rely on a downstream archival layer
(Firehose to S3, DynamoDB Streams + logging, etc.).
"""

from __future__ import annotations

import logging
from typing import Any

import moto.backends as moto_backends

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


@register_collector("kinesis")
class KinesisCollector(BaseCollector):
    """Collect Kinesis streams and stream consumers from the moto backend."""

    service = "kinesis"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate streams and consumers for the given scope."""
        resources: list[Resource] = []
        try:
            backend_dict = moto_backends.get_backend("kinesis")
            backend = backend_dict[account_id][region]
        except Exception:  # noqa: BLE001
            LOG.warning(
                "Kinesis backend unavailable for %s/%s",
                account_id,
                region,
                exc_info=True,
            )
            return resources

        raw_streams = getattr(backend, "streams", None) or {}
        for stream_name, stream in list(raw_streams.items()):
            try:
                resources.append(
                    self._stream_resource(stream_name, stream, account_id, region)
                )
                resources.extend(
                    self._consumers_for_stream(
                        stream_name, stream, account_id, region
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed Kinesis stream %r",
                    stream_name,
                    exc_info=True,
                )
                continue

        return resources

    # ------------------------------------------------------------------
    def _stream_resource(
        self, stream_name: str, stream: Any, account_id: str, region: str
    ) -> Resource:
        """Build a :class:`Resource` for one Kinesis stream."""
        attrs: dict[str, Any] = {"name": stream_name}

        # Shard count: prefer an explicit attribute, otherwise count the
        # live shards list. Closed shards do not count towards capacity.
        shard_count = getattr(stream, "shard_count", None)
        if shard_count is None:
            shards = getattr(stream, "shards", None) or {}
            if isinstance(shards, dict):
                shard_count = sum(
                    1
                    for s in shards.values()
                    if getattr(s, "is_open", True)
                )
            elif isinstance(shards, list):
                shard_count = len(shards)
        if shard_count is not None:
            attrs["shard_count"] = int(shard_count)

        retention = getattr(stream, "retention_period_hours", None) or getattr(
            stream, "retention_period", None
        )
        if retention is not None:
            attrs["retention_period_hours"] = int(retention)

        stream_mode = getattr(stream, "stream_mode", None) or getattr(
            stream, "stream_mode_details", None
        )
        if isinstance(stream_mode, dict):
            # moto sometimes stores ``{"StreamMode": "PROVISIONED"}``.
            stream_mode = stream_mode.get("StreamMode") or stream_mode.get(
                "stream_mode"
            )
        if stream_mode is not None:
            attrs["stream_mode"] = str(stream_mode)

        encryption_type = getattr(stream, "encryption_type", None)
        if encryption_type is not None:
            attrs["encryption_type"] = str(encryption_type)

        key_id = getattr(stream, "key_id", None) or getattr(stream, "kms_key_id", None)
        if key_id:
            attrs["key_id"] = Ref(
                service="kms",
                resource_type="key",
                resource_id=str(key_id),
            )

        arn = getattr(stream, "arn", None) or getattr(stream, "stream_arn", None)
        if arn is not None:
            attrs["arn"] = arn

        return Resource(
            service="kinesis",
            resource_type="stream",
            resource_id=str(stream_name),
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=_normalise_tags(getattr(stream, "tags", None)),
        )

    def _consumers_for_stream(
        self, stream_name: str, stream: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Collect enhanced-fan-out consumers attached to ``stream``."""
        out: list[Resource] = []
        raw = getattr(stream, "consumers", None) or []
        iterable = raw.values() if isinstance(raw, dict) else raw
        for consumer in list(iterable):
            try:
                name = getattr(consumer, "consumer_name", None) or getattr(
                    consumer, "name", None
                )
                if not name:
                    continue
                attrs: dict[str, Any] = {
                    "name": name,
                    "stream_arn": Ref(
                        service="kinesis",
                        resource_type="stream",
                        resource_id=str(stream_name),
                    ),
                }
                status = getattr(consumer, "consumer_status", None) or getattr(
                    consumer, "status", None
                )
                if status is not None:
                    attrs["status"] = str(status)
                consumer_arn = getattr(consumer, "consumer_arn", None) or getattr(
                    consumer, "arn", None
                )
                if consumer_arn is not None:
                    attrs["arn"] = consumer_arn

                out.append(
                    Resource(
                        service="kinesis",
                        resource_type="stream_consumer",
                        resource_id=f"{stream_name}/{name}",
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags={},
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed Kinesis consumer on stream %r",
                    stream_name,
                    exc_info=True,
                )
                continue
        return out


def _normalise_tags(raw: Any) -> dict[str, str]:
    """Coerce moto's varied tag shapes into a ``dict[str, str]``."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict):
                key = item.get("Key") or item.get("key")
                value = item.get("Value") or item.get("value")
                if key is not None:
                    out[str(key)] = "" if value is None else str(value)
        return out
    return {}
