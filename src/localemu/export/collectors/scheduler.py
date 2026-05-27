"""EventBridge Scheduler collector: schedules + schedule groups."""
from __future__ import annotations
import logging
from typing import Any
from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)

@register_collector("scheduler")
class SchedulerCollector(BaseCollector):
    service = "scheduler"
    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as mb
            backend = mb.get_backend("scheduler")[account_id][region]
        except Exception:
            LOG.warning("Scheduler unavailable", exc_info=True); return []
        out: list[Resource] = []
        # Schedule groups
        groups = getattr(backend, "schedule_groups", {}) or {}
        for name, grp in dict(groups).items():
            if name == "default":
                continue  # built-in, always exists
            try:
                attrs: dict[str, Any] = {
                    "name": getattr(grp, "name", name) or name,
                    "arn": getattr(grp, "arn", None),
                }
                tags = _tags(grp)
                out.append(Resource(
                    service="scheduler", resource_type="schedule_group",
                    resource_id=attrs["name"],
                    account_id=account_id, region=region,
                    attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping schedule group %r", name, exc_info=True)
        # Schedules — moto stores them INSIDE each schedule group
        # (``backend.schedule_groups[group].schedules``), not as a flat
        # dict at ``backend.schedules`` (that attribute is an unused list
        # leftover). Walk per-group so every schedule is surfaced.
        for grp_name, grp in dict(groups).items():
            grp_schedules = getattr(grp, "schedules", {}) or {}
            for sched_name, sched in dict(grp_schedules).items():
                try:
                    name = getattr(sched, "name", None) or sched_name
                    attrs: dict[str, Any] = {
                        "name": name,
                        "arn": getattr(sched, "arn", None),
                        "schedule_expression": getattr(sched, "schedule_expression", None),
                        "schedule_expression_timezone": getattr(sched, "schedule_expression_timezone", None),
                        "flexible_time_window": getattr(sched, "flexible_time_window", None),
                        "state": getattr(sched, "state", None),
                        "group_name": getattr(sched, "group_name", None) or grp_name,
                        "description": getattr(sched, "description", None),
                        "kms_key_arn": getattr(sched, "kms_key_arn", None),
                        "start_date": getattr(sched, "start_date", None),
                        "end_date": getattr(sched, "end_date", None),
                    }
                    target = getattr(sched, "target", None)
                    if target:
                        attrs["target"] = target if isinstance(target, dict) else {"arn": str(target)}
                    attrs = {k: v for k, v in attrs.items() if v is not None}
                    out.append(Resource(
                        service="scheduler", resource_type="schedule",
                        resource_id=f"{grp_name}/{name}",
                        account_id=account_id, region=region,
                        attributes=attrs,
                    ))
                except Exception:
                    LOG.warning("Skipping schedule %s/%s", grp_name, sched_name, exc_info=True)
        return out

def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw: return {}
    if isinstance(raw, dict): return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list): return {str(t.get("Key","")): str(t.get("Value","")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
