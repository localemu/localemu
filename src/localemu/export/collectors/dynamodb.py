"""DynamoDB collector: enumerate tables (and optionally items) via moto.

LocalEmu delegates DynamoDB to moto's in-memory backend. We access it
through the public ``moto.backends.get_backend`` façade rather than
importing private state, which keeps us decoupled from moto's internal
storage shape.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

# Sample size for ``include_data=True``. Full table dumps are deliberately
# out of scope for the v1 snapshot format.
_ITEM_SAMPLE_LIMIT = 1_000


@register_collector("dynamodb")
class DynamoDBCollector(BaseCollector):
    """Collect DynamoDB tables for a single (account, region)."""

    service = "dynamodb"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            import moto.backends as moto_backends
        except Exception:  # pragma: no cover
            LOG.warning("moto is unavailable; skipping DynamoDB", exc_info=True)
            return []

        try:
            backend = moto_backends.get_backend("dynamodb")[account_id][region]
        except Exception:
            LOG.warning(
                "No DynamoDB backend for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        tables = getattr(backend, "tables", {}) or {}
        resources: list[Resource] = []
        for table_name, table in dict(tables).items():
            try:
                resources.append(
                    self._build_table_resource(
                        table_name, table, account_id, region, include_data
                    )
                )
            except Exception:
                LOG.warning(
                    "Failed to serialize DynamoDB table %r; skipping",
                    table_name,
                    exc_info=True,
                )
        return resources

    # ------------------------------------------------------------------

    def _build_table_resource(
        self,
        table_name: str,
        table: Any,
        account_id: str,
        region: str,
        include_data: bool,
    ) -> Resource:
        key_schema = _coerce_list(getattr(table, "schema", None))
        attribute_definitions = _coerce_list(getattr(table, "attr", None))

        hash_key = None
        range_key = None
        for elem in key_schema:
            if not isinstance(elem, dict):
                continue
            if elem.get("KeyType") == "HASH":
                hash_key = elem.get("AttributeName")
            elif elem.get("KeyType") == "RANGE":
                range_key = elem.get("AttributeName")

        # Moto stores the billing_mode verbatim from the create call. When
        # the user supplied ``PAY_PER_REQUEST`` it's recorded literally;
        # otherwise moto leaves it None and the (possibly-zeroed)
        # throughput dict signals PROVISIONED. We never default to
        # PROVISIONED when the table was actually on-demand — that would
        # silently change semantics on re-import.
        raw_billing_mode = getattr(table, "billing_mode", None)
        throughput = _coerce_dict(getattr(table, "throughput", None))
        if raw_billing_mode == "PAY_PER_REQUEST":
            billing_mode = "PAY_PER_REQUEST"
        elif raw_billing_mode:
            billing_mode = str(raw_billing_mode)
        else:
            # No explicit billing_mode recorded. If there's a non-zero
            # provisioned throughput it's PROVISIONED; otherwise fall back
            # to PAY_PER_REQUEST which is the AWS default for new tables.
            rcu = int(throughput.get("ReadCapacityUnits", 0) or 0)
            wcu = int(throughput.get("WriteCapacityUnits", 0) or 0)
            billing_mode = "PROVISIONED" if (rcu or wcu) else "PAY_PER_REQUEST"

        attrs: dict[str, Any] = {
            "name": table_name,
            "key_schema": key_schema,
            "hash_key": hash_key,
            "range_key": range_key,
            "attribute_definitions": attribute_definitions,
            "billing_mode": billing_mode,
        }

        if billing_mode == "PROVISIONED":
            attrs["provisioned_throughput"] = {
                "ReadCapacityUnits": int(throughput.get("ReadCapacityUnits", 0) or 0),
                "WriteCapacityUnits": int(
                    throughput.get("WriteCapacityUnits", 0) or 0
                ),
            }

        attrs["global_secondary_indexes"] = [
            _index_to_dict(idx) for idx in getattr(table, "global_indexes", []) or []
        ]
        attrs["local_secondary_indexes"] = [
            _index_to_dict(idx) for idx in getattr(table, "indexes", []) or []
        ]

        attrs["stream_specification"] = _coerce_dict(
            getattr(table, "stream_specification", None)
        )
        attrs["sse_specification"] = _coerce_dict(
            getattr(table, "sse_specification", None)
        )

        # Point-in-time recovery lives under ``continuous_backups``.
        continuous = _coerce_dict(getattr(table, "continuous_backups", None))
        pitr = (
            continuous.get("PointInTimeRecoveryDescription", {})
            if isinstance(continuous, dict)
            else {}
        )
        attrs["point_in_time_recovery"] = {
            "enabled": pitr.get("PointInTimeRecoveryStatus") == "ENABLED"
        }

        attrs["deletion_protection_enabled"] = bool(
            getattr(table, "deletion_protection_enabled", False)
        )
        attrs["ttl"] = _coerce_dict(getattr(table, "ttl", None))

        if include_data:
            attrs["items"] = self._collect_items(table_name, table)

        tags = _tag_list_to_dict(getattr(table, "tags", None))

        created_at_raw = getattr(table, "created_at", None)
        created_at = created_at_raw.isoformat() if created_at_raw else None

        return Resource(
            service="dynamodb",
            resource_type="table",
            resource_id=table_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )

    def _collect_items(self, table_name: str, table: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        try:
            all_items_fn = getattr(table, "all_items", None)
            raw_items = list(all_items_fn()) if callable(all_items_fn) else []
        except Exception:
            LOG.warning(
                "Failed to enumerate items for DynamoDB table %r",
                table_name,
                exc_info=True,
            )
            return []

        if len(raw_items) > _ITEM_SAMPLE_LIMIT:
            LOG.warning(
                "DynamoDB table %r has %d items; sampling the first %d",
                table_name,
                len(raw_items),
                _ITEM_SAMPLE_LIMIT,
            )
            raw_items = raw_items[:_ITEM_SAMPLE_LIMIT]

        for item in raw_items:
            try:
                items.append(_item_to_plain(item))
            except Exception:
                LOG.warning(
                    "Skipping unserializable item in table %r", table_name, exc_info=True
                )
                continue
        return items


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    try:
        return list(value)
    except Exception:
        return []


def _coerce_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            result = to_dict()
            if isinstance(result, dict):
                return result
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return {}


def _index_to_dict(idx: Any) -> dict[str, Any]:
    if isinstance(idx, dict):
        return idx
    # moto index types expose a ``describe`` / ``to_dict`` method.
    for meth in ("describe", "to_dict"):
        fn = getattr(idx, meth, None)
        if callable(fn):
            try:
                out = fn()
                if isinstance(out, dict):
                    return out
            except Exception:
                pass
    return _coerce_dict(idx)


def _tag_list_to_dict(tags: Any) -> dict[str, str]:
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


def _item_to_plain(item: Any) -> dict[str, Any]:
    """Convert a moto Item to a JSON-friendly dict using typed DDB values.

    Output preserves DynamoDB's typed-value format (``{"S": "..."}``,
    ``{"N": "..."}``, ``{"B": ...}``, ...) so the snapshot can be replayed
    with standard DDB APIs. Binary values are base64-encoded and tagged
    with ``type_hint`` to disambiguate from strings.
    """
    # moto items expose ``attrs`` as ``{name: DynamoType}``. We keep the
    # typed form rather than collapsing to native python so readers see
    # the exact DDB type.
    attrs = getattr(item, "attrs", None)
    if attrs is None and isinstance(item, dict):
        attrs = item
    if not isinstance(attrs, dict):
        return {}
    out: dict[str, Any] = {}
    for name, dynamo_type in attrs.items():
        out[name] = _dynamo_value_to_plain(dynamo_type)
    return out


def _dynamo_value_to_plain(value: Any) -> Any:
    """Serialize a single moto DynamoType node."""
    if value is None:
        return None
    if isinstance(value, dict):
        # Already in typed form; recurse into nested M/L types.
        return {k: _dynamo_value_to_plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_dynamo_value_to_plain(v) for v in value]

    type_ = getattr(value, "type", None)
    raw = getattr(value, "value", None)

    if type_ == "B":
        # Binary: moto stores either bytes or a base64 str. Always emit
        # base64 + type hint for unambiguous round-trip.
        if isinstance(raw, (bytes, bytearray)):
            return {"B": base64.b64encode(raw).decode("ascii"), "type_hint": "binary"}
        return {"B": str(raw), "type_hint": "binary"}
    if type_ == "BS":
        encoded = []
        for item in raw or []:
            if isinstance(item, (bytes, bytearray)):
                encoded.append(base64.b64encode(item).decode("ascii"))
            else:
                encoded.append(str(item))
        return {"BS": encoded, "type_hint": "binary_set"}
    if type_ == "M":
        return {
            "M": {k: _dynamo_value_to_plain(v) for k, v in (raw or {}).items()}
        }
    if type_ == "L":
        return {"L": [_dynamo_value_to_plain(v) for v in (raw or [])]}
    if type_ in ("S", "N", "BOOL", "NULL", "SS", "NS"):
        return {type_: raw}
    # Fallback for unknown / plain python values — emit as string.
    if type_ is None:
        return str(value)
    return {type_: raw}
