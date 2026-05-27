"""CloudWatch collector — alarms and dashboards (not metrics).

Walks the moto ``cloudwatch`` backend. Metric data points are ephemeral
and are *never* exported — only alarm and dashboard definitions. Alarm
action ARNs (SNS / Lambda / Auto Scaling / etc.) are opportunistically
resolved to :class:`Ref` so writers can emit proper inter-resource links.
"""

from __future__ import annotations

import json
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


# Mapping of AWS service -> (export_service, resource_type) for action Refs.
_ACTION_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "sns": ("sns", "topic"),
    "lambda": ("lambda", "function"),
    "sqs": ("sqs", "queue"),
    "autoscaling": ("autoscaling", "policy"),
    "ssm": ("ssm", "document"),
}


def _action_ref(arn: Any) -> Ref | Any:
    """Resolve an alarm-action ARN to a :class:`Ref` when recognized."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return arn
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return arn
    service = parts[2]
    mapping = _ACTION_SERVICE_MAP.get(service)
    if mapping is None:
        return arn
    export_service, resource_type = mapping
    resource_id = _arn_last_segment(arn)
    if not resource_id:
        return arn
    return Ref(
        service=export_service, resource_type=resource_type, resource_id=resource_id
    )


def _resolve_actions(actions: Any) -> list[Any]:
    """Return a list of :class:`Ref`/str for a list of action ARNs."""
    if not actions:
        return []
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, (list, tuple)):
        return []
    return [_action_ref(a) for a in actions]


@register_collector("cloudwatch")
class CloudWatchCollector(BaseCollector):
    """Collect CloudWatch alarms and dashboards (not metric data)."""

    service = "cloudwatch"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Return alarm and dashboard resources for ``account_id``/``region``.

        LocalEmu's CloudWatch provider stores alarms in its own
        ``CloudWatchStore`` (see ``services/cloudwatch/models.py``), not in
        moto's backend. Reading from moto returned empty.
        """
        resources: list[Resource] = []
        try:
            from localemu.services.cloudwatch.models import cloudwatch_stores
        except Exception:
            LOG.warning(
                "Failed to import cloudwatch_stores; skipping cloudwatch",
                exc_info=True,
            )
            return resources
        if account_id not in cloudwatch_stores:
            return resources
        try:
            backend = cloudwatch_stores[account_id][region]
        except Exception:
            LOG.warning(
                "No CloudWatch store for %s/%s", account_id, region, exc_info=True,
            )
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
        """Walk a single account/region cloudwatch backend."""
        # LocalEmu's ``CloudWatchStore.alarms`` is keyed by ARN; each value
        # is a :class:`LocalEmuMetricAlarm` (or composite) wrapping the
        # actual AWS API dict in ``.alarm`` (CamelCase keys). Unwrap so
        # the downstream builder can read CamelCase fields the same way
        # it reads moto's snake_case attrs.
        alarms = getattr(backend, "alarms", {}) or {}
        for key, wrapper in list(alarms.items()):
            inner = getattr(wrapper, "alarm", None)
            alarm = inner if isinstance(inner, dict) else wrapper
            # Derive a stable resource name from the wrapped dict.
            label = (alarm.get("AlarmName") if isinstance(alarm, dict) else None) or str(key)
            try:
                resources.append(
                    self._build_alarm_resource(account_id, region, label, alarm)
                )
            except Exception:
                LOG.warning("Skipping malformed alarm %s", label, exc_info=True)

        # Dashboards: moto stores them in ``dashboards`` dict keyed by name.
        dashboards = getattr(backend, "dashboards", {}) or {}
        for name, dash in list(dashboards.items()):
            try:
                resources.append(
                    self._build_dashboard_resource(account_id, region, name, dash)
                )
            except Exception:
                LOG.warning(
                    "Skipping malformed dashboard %s", name, exc_info=True
                )

    # --- builders --------------------------------------------------------

    def _build_alarm_resource(
        self, account_id: str, region: str, name: str, alarm: Any
    ) -> Resource:
        """Build an alarm :class:`Resource` (metric or composite)."""
        # Detect composite vs metric: composite alarms have an alarm_rule.
        alarm_rule = _get(alarm, "alarm_rule", "alarmRule", "AlarmRule", "rule")
        is_composite = bool(alarm_rule)

        dimensions = _get(alarm, "dimensions", "Dimensions") or []
        # Normalize dimensions into list of {name, value} dicts.
        dims_out: list[dict[str, Any]] = []
        for d in list(dimensions):
            if isinstance(d, dict):
                dim_name = d.get("name") or d.get("Name")
                dim_value = d.get("value") or d.get("Value")
                if dim_name is not None:
                    dims_out.append({"name": dim_name, "value": dim_value})
            else:
                dims_out.append(
                    {
                        "name": getattr(d, "name", None),
                        "value": getattr(d, "value", None),
                    }
                )

        alarm_actions = _resolve_actions(_get(alarm, "alarm_actions", "alarmActions", "AlarmActions"))
        ok_actions = _resolve_actions(_get(alarm, "ok_actions", "okActions", "OKActions"))
        insuf_actions = _resolve_actions(
            _get(alarm, "insufficient_data_actions", "insufficientDataActions", "InsufficientDataActions")
        )

        # Accept moto snake_case, AWS API CamelCase, and the
        # ``AlarmName``/``AlarmArn``/``AlarmDescription`` variants used by
        # LocalEmu's CloudWatchStore (where alarms are inner AWS-API dicts).
        attrs: dict[str, Any] = {
            "name": _get(alarm, "name", "alarm_name", "AlarmName") or name,
            "arn": _get(alarm, "arn", "alarm_arn", "AlarmArn"),
            "description": _get(alarm, "description", "alarm_description", "AlarmDescription"),
            "state_value": _get(alarm, "state_value", "state", "StateValue"),
            "treat_missing_data": _get(alarm, "treat_missing_data", "treatMissingData", "TreatMissingData"),
            "alarm_actions": alarm_actions,
            "ok_actions": ok_actions,
            "insufficient_data_actions": insuf_actions,
            "actions_enabled": _get(alarm, "actions_enabled", "actionsEnabled", "ActionsEnabled"),
        }

        if is_composite:
            attrs["alarm_rule"] = alarm_rule
            resource_type = "composite_alarm"
        else:
            attrs.update(
                {
                    "metric_name": _get(alarm, "metric_name", "metricName", "MetricName"),
                    "namespace": _get(alarm, "namespace", "Namespace"),
                    "statistic": _get(alarm, "statistic", "Statistic"),
                    "extended_statistic": _get(
                        alarm, "extended_statistic", "extendedStatistic", "ExtendedStatistic",
                    ),
                    "period": _get(alarm, "period", "Period"),
                    "evaluation_periods": _get(
                        alarm, "evaluation_periods", "evaluationPeriods", "EvaluationPeriods",
                    ),
                    "datapoints_to_alarm": _get(
                        alarm, "datapoints_to_alarm", "datapointsToAlarm", "DatapointsToAlarm",
                    ),
                    "threshold": _get(alarm, "threshold", "Threshold"),
                    "comparison_operator": _get(
                        alarm, "comparison_operator", "comparisonOperator", "ComparisonOperator",
                    ),
                    "unit": _get(alarm, "unit", "Unit"),
                    "dimensions": dims_out,
                    "metrics": _get(alarm, "metrics", "Metrics"),
                }
            )
            resource_type = "alarm"

        attrs = {k: v for k, v in attrs.items() if v not in (None, [], {})}
        return Resource(
            service="cloudwatch",
            resource_type=resource_type,
            resource_id=attrs.get("name", name),
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=_normalize_tags(_get(alarm, "tags")),
        )

    def _build_dashboard_resource(
        self, account_id: str, region: str, name: str, dash: Any
    ) -> Resource:
        """Build a dashboard :class:`Resource` with parsed body JSON."""
        body_raw = _get(dash, "body", "dashboard_body", "dashboardBody")
        body_parsed: Any = body_raw
        if isinstance(body_raw, str):
            try:
                body_parsed = json.loads(body_raw)
            except (TypeError, ValueError):
                body_parsed = body_raw
        attrs: dict[str, Any] = {
            "name": _get(dash, "name", "dashboard_name") or name,
            "arn": _get(dash, "arn", "dashboard_arn"),
            "body": body_parsed,
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="cloudwatch",
            resource_type="dashboard",
            resource_id=attrs.get("name", name),
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
