"""CloudWatch Logs collector — log groups, subscription filters, metric filters.

Walks the moto ``logs`` backend. Log events themselves are ephemeral and
are *never* exported — only structural resources are emitted. Subscription
filter destinations (Lambda / Kinesis / Firehose) are opportunistically
resolved to :class:`Ref` so writers can emit proper inter-resource links.
"""

from __future__ import annotations

import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _arn_last_segment(arn: str) -> str:
    """Return the resource id portion of ``arn`` (final ``:`` or ``/`` segment)."""
    if not isinstance(arn, str):
        return ""
    last = arn
    if ":" in last:
        last = last.rsplit(":", 1)[1]
    if "/" in last:
        last = last.rsplit("/", 1)[1]
    return last


_DEST_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "lambda": ("lambda", "function"),
    "kinesis": ("kinesis", "stream"),
    "firehose": ("firehose", "delivery_stream"),
    "logs": ("logs", "log_group"),
}


def _destination_ref(arn: Any) -> Ref | Any:
    """Resolve a subscription destination ARN to a :class:`Ref` when recognized."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return arn
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return arn
    service = parts[2]
    mapping = _DEST_SERVICE_MAP.get(service)
    if mapping is None:
        return arn
    export_service, resource_type = mapping
    resource_id = _arn_last_segment(arn)
    if not resource_id:
        return arn
    return Ref(
        service=export_service, resource_type=resource_type, resource_id=resource_id
    )


def _role_ref(role_arn: Any) -> Ref | Any:
    """Return a :class:`Ref` for an IAM role ARN, or pass-through."""
    if not role_arn or not isinstance(role_arn, str) or not role_arn.startswith("arn:"):
        return role_arn
    role_name = _arn_last_segment(role_arn)
    if not role_name:
        return role_arn
    return Ref(service="iam", resource_type="role", resource_id=role_name)


def _kms_ref(kms_key_id: Any) -> Ref | Any:
    """Return a :class:`Ref` for a KMS key id/arn, or pass-through."""
    if not kms_key_id or not isinstance(kms_key_id, str):
        return kms_key_id
    if kms_key_id.startswith("alias/aws/"):
        return kms_key_id
    key_id = _arn_last_segment(kms_key_id) or kms_key_id
    return Ref(service="kms", resource_type="key", resource_id=key_id)


@register_collector("logs")
class LogsCollector(BaseCollector):
    """Collect CloudWatch Logs structural resources (not log events)."""

    service = "logs"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Return log groups / subscription filters / metric filters."""
        resources: list[Resource] = []
        try:
            import moto.backends as moto_backends
        except Exception:  # pragma: no cover - import guard
            LOG.warning("moto not importable; skipping logs export", exc_info=True)
            return resources

        try:
            backend_dict = moto_backends.get_backend("logs")
        except Exception:
            LOG.warning("No moto logs backend available", exc_info=True)
            return resources

        # Iterate moto's BackendDict via ``.items()`` so we only walk
        # already-instantiated entries. Using subscript / ``.get()`` on
        # the BackendDict creates a fresh empty backend (see dashboard's
        # ``_iter_moto_backends`` helper) which silently masks real state.
        backend = None
        try:
            for acct, region_map in list(backend_dict.items()):
                if acct != account_id:
                    continue
                for reg, b in list(region_map.items()):
                    if reg == region:
                        backend = b
                        break
                break
        except Exception:
            return resources
        if backend is None:
            return resources
        self._collect_backend(backend, account_id, region, resources)
        return resources

    def _collect_backend(
        self,
        backend: Any,
        account_id: str,
        region: str,
        resources: list[Resource],
    ) -> None:
        """Walk a single account/region logs backend."""
        groups = getattr(backend, "groups", {}) or {}
        for group_name, group in list(groups.items()):
            try:
                resources.append(
                    self._build_group_resource(account_id, region, group_name, group)
                )
            except Exception:
                LOG.warning(
                    "Skipping malformed log group %s", group_name, exc_info=True
                )
                continue

            # Subscription filters (moto: LogGroup.subscription_filters).
            sub_filters = getattr(group, "subscription_filters", {}) or {}
            if hasattr(sub_filters, "items"):
                iterable = sub_filters.items()
            else:
                iterable = ((getattr(sf, "name", str(i)), sf) for i, sf in enumerate(sub_filters))
            for sf_name, sf in list(iterable):
                try:
                    resources.append(
                        self._build_subscription_filter(
                            account_id, region, group_name, sf_name, sf
                        )
                    )
                except Exception:
                    LOG.warning(
                        "Skipping malformed subscription filter %s on %s",
                        sf_name,
                        group_name,
                        exc_info=True,
                    )

            # Metric filters (moto: stored on backend.filters or group).
            metric_filters = getattr(group, "metric_filters", None) or []
            for mf in list(metric_filters):
                try:
                    resources.append(
                        self._build_metric_filter(
                            account_id, region, group_name, mf
                        )
                    )
                except Exception:
                    LOG.warning(
                        "Skipping malformed metric filter on %s",
                        group_name,
                        exc_info=True,
                    )

        # Some moto versions keep metric filters at backend level.
        backend_filters = getattr(backend, "filters", None)
        if backend_filters is not None:
            metric_filters = getattr(backend_filters, "metric_filters", None) or []
            for mf in list(metric_filters):
                group_name = (
                    mf.get("logGroupName") if isinstance(mf, dict)
                    else getattr(mf, "log_group_name", "")
                )
                try:
                    resources.append(
                        self._build_metric_filter(
                            account_id, region, group_name or "", mf
                        )
                    )
                except Exception:
                    LOG.warning(
                        "Skipping malformed backend-level metric filter",
                        exc_info=True,
                    )

    # --- builders --------------------------------------------------------

    def _build_group_resource(
        self, account_id: str, region: str, group_name: str, group: Any
    ) -> Resource:
        """Build a log-group :class:`Resource`."""
        retention = getattr(group, "retention_in_days", None)
        kms_key_id = getattr(group, "kms_key_id", None)
        tags = _normalize_tags(getattr(group, "tags", None))
        attrs: dict[str, Any] = {
            "name": group_name,
            "arn": getattr(group, "arn", None),
            "retention_in_days": retention,
            "kms_key_id": _kms_ref(kms_key_id),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="logs",
            resource_type="log_group",
            resource_id=group_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
        )

    def _build_subscription_filter(
        self,
        account_id: str,
        region: str,
        group_name: str,
        sf_name: str,
        sf: Any,
    ) -> Resource:
        """Build a subscription-filter :class:`Resource`."""
        dest = _get(sf, "destination_arn", "destinationArn")
        role = _get(sf, "role_arn", "roleArn")
        attrs: dict[str, Any] = {
            "name": _get(sf, "name") or sf_name,
            "log_group_name": Ref(
                service="logs", resource_type="log_group", resource_id=group_name
            ),
            "filter_pattern": _get(sf, "filter_pattern", "filterPattern"),
            "destination_arn": _destination_ref(dest),
            "role_arn": _role_ref(role),
            "distribution": _get(sf, "distribution"),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        rid = f"{group_name}:{sf_name}"
        return Resource(
            service="logs",
            resource_type="subscription_filter",
            resource_id=rid,
            account_id=account_id,
            region=region,
            attributes=attrs,
        )

    def _build_metric_filter(
        self, account_id: str, region: str, group_name: str, mf: Any
    ) -> Resource:
        """Build a metric-filter :class:`Resource`."""
        name = _get(mf, "filter_name", "filterName", "name") or ""
        transformations = (
            _get(mf, "metric_transformations", "metricTransformations") or []
        )
        attrs: dict[str, Any] = {
            "name": name,
            "log_group_name": Ref(
                service="logs", resource_type="log_group", resource_id=group_name
            )
            if group_name
            else None,
            "filter_pattern": _get(mf, "filter_pattern", "filterPattern"),
            "metric_transformations": transformations,
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        rid = f"{group_name}:{name}" if group_name else name
        return Resource(
            service="logs",
            resource_type="metric_filter",
            resource_id=rid or "unnamed",
            account_id=account_id,
            region=region,
            attributes=attrs,
        )


def _get(obj: Any, *keys: str) -> Any:
    """Return the first non-None attribute or dict key from ``obj``."""
    for k in keys:
        if isinstance(obj, dict):
            if k in obj and obj[k] is not None:
                return obj[k]
        else:
            v = getattr(obj, k, None)
            if v is not None:
                return v
    return None


def _normalize_tags(tags: Any) -> dict[str, str]:
    """Normalize tags to a ``dict[str, str]``."""
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        out: dict[str, str] = {}
        for item in tags:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}
