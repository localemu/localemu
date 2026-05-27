"""Kinesis Firehose collector: delivery streams."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("firehose")
class FirehoseCollector(BaseCollector):
    service = "firehose"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("firehose")[account_id][region]
        except Exception:
            LOG.warning("Firehose unavailable", exc_info=True); return []
        out: list[Resource] = []
        streams = getattr(backend, "delivery_streams", {}) or {}
        for name, stream in dict(streams).items():
            try:
                attrs: dict[str, Any] = {
                    "name": getattr(stream, "name", name) or name,
                    "arn": getattr(stream, "arn", None),
                }
                dest = getattr(stream, "destinations", None)
                if dest:
                    attrs["destination"] = dest if isinstance(dest, (list, dict)) else str(dest)
                dest_type = getattr(stream, "delivery_stream_type", None)
                if dest_type:
                    attrs["delivery_stream_type"] = dest_type
                tags = _tags(stream)
                out.append(Resource(
                    service="firehose", resource_type="delivery_stream",
                    resource_id=attrs["name"],
                    account_id=account_id, region=region,
                    attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping delivery stream %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
