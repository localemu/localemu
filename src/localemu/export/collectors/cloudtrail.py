"""CloudTrail collector: trails."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

@register_collector("cloudtrail")
class CloudTrailCollector(BaseCollector):
    service = "cloudtrail"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("cloudtrail")[account_id][region]
        except Exception:
            LOG.warning("CloudTrail unavailable", exc_info=True); return []
        out: list[Resource] = []
        trails = getattr(backend, "trails", {}) or {}
        for name, trail in dict(trails).items():
            try:
                # moto's ``Trail`` exposes the bucket as ``bucket_name`` —
                # not ``s3_bucket_name`` as an earlier guess assumed. The
                # field is REQUIRED by ``aws_cloudtrail.s3_bucket_name``;
                # missing it caused terraform plan to fail before any
                # apply. Same story for the CW log group / role attrs
                # (moto uses ``cw_*``, not ``cloud_watch_logs_*``).
                trail_name = (getattr(trail, "trail_name", None)
                              or getattr(trail, "name", None) or name)
                bucket = (getattr(trail, "bucket_name", None)
                          or getattr(trail, "s3_bucket_name", None))
                attrs: dict[str, Any] = {
                    "name": trail_name,
                    "arn": getattr(trail, "arn", None) or getattr(trail, "trail_arn", None),
                    "s3_bucket_name": bucket,
                    "s3_key_prefix": getattr(trail, "s3_key_prefix", None),
                    "include_global_service_events": getattr(trail, "include_global_service_events", True),
                    "is_multi_region_trail": (getattr(trail, "is_multi_region", None)
                                               or getattr(trail, "is_multi_region_trail", False)),
                    "enable_logging": getattr(getattr(trail, "status", None), "is_logging", True),
                    "enable_log_file_validation": (getattr(trail, "log_validation", None)
                                                    or getattr(trail, "log_file_validation_enabled", None)),
                }
                sns_topic = (getattr(trail, "sns_topic_arn", None)
                             or getattr(trail, "sns_topic_name", None))
                if sns_topic:
                    attrs["sns_topic_name"] = sns_topic
                cw_log_group = (getattr(trail, "cw_log_group_arn", None)
                                or getattr(trail, "cloud_watch_logs_log_group_arn", None))
                if cw_log_group:
                    attrs["cloud_watch_logs_group_arn"] = cw_log_group
                cw_role = (getattr(trail, "cw_role_arn", None)
                           or getattr(trail, "cloud_watch_logs_role_arn", None))
                if cw_role:
                    attrs["cloud_watch_logs_role_arn"] = cw_role
                kms_key = getattr(trail, "kms_key_id", None)
                if kms_key:
                    attrs["kms_key_id"] = kms_key
                attrs = {k: v for k, v in attrs.items() if v is not None}
                tags = _tags(trail)
                out.append(Resource(
                    service="cloudtrail", resource_type="trail",
                    resource_id=attrs.get("name", name),
                    account_id=account_id, region=region,
                    attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping trail %r", name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags_list", None) or getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
