"""Step Functions collector.

Exports state machines and activities. Execution history is ephemeral —
re-running a workflow on the imported emulator regenerates it — so we
only collect definitions and metadata.

The ASL state-machine *definition* is stored on moto as a JSON string;
we parse it into a dict so writers can round-trip to YAML or re-embed
it into Terraform modules without re-serialising.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

# ``arn:aws:iam::<account>:role/<path><name>``
_IAM_ROLE_ARN_PREFIX = "arn:aws:iam::"


def _role_ref(role_arn: str | None) -> Ref | str | None:
    """Return a :class:`Ref` to the IAM role named in ``role_arn``."""
    if not role_arn or not isinstance(role_arn, str):
        return role_arn
    if not role_arn.startswith(_IAM_ROLE_ARN_PREFIX):
        return role_arn
    # Extract the bit after ``:role/`` and use the last path segment as the
    # role name (IAM role names are unique per-account).
    marker = ":role/"
    idx = role_arn.find(marker)
    if idx < 0:
        return role_arn
    name = role_arn[idx + len(marker) :].rsplit("/", 1)[-1]
    if not name:
        return role_arn
    return Ref(service="iam", resource_type="role", resource_id=name)


def _parse_definition(definition: Any) -> Any:
    """Parse ASL JSON definition into a dict; fall back to the raw value."""
    if isinstance(definition, dict):
        return definition
    if isinstance(definition, str):
        try:
            return json.loads(definition)
        except (ValueError, TypeError):
            LOG.warning("State machine definition is not valid JSON")
            return definition
    return definition


@register_collector("stepfunctions")
class StepFunctionsCollector(BaseCollector):
    """Collect Step Functions state machines and activities."""

    service = "stepfunctions"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate state machines and activities for the given scope.

        LocalEmu's Step Functions provider keeps state in its own
        :class:`SFNStore` rather than in moto's backend dict, so reading
        from ``moto.backends.get_backend("stepfunctions")`` returned an
        always-empty store and silently dropped every activity. Use the
        provider's own ``sfn_stores`` bundle.
        """
        resources: list[Resource] = []
        try:
            from localemu.services.stepfunctions.backend.models import sfn_stores
        except Exception:  # noqa: BLE001
            LOG.warning(
                "Failed to import sfn_stores; skipping Step Functions",
                exc_info=True,
            )
            return resources

        if account_id not in sfn_stores:
            return resources
        try:
            backend = sfn_stores[account_id][region]
        except Exception:  # noqa: BLE001
            LOG.warning(
                "No Step Functions store for %s/%s",
                account_id, region, exc_info=True,
            )
            return resources

        resources.extend(self._collect_state_machines(backend, account_id, region))
        resources.extend(self._collect_activities(backend, account_id, region))
        return resources

    # ------------------------------------------------------------------
    def _collect_state_machines(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``stepfunctions:state_machine`` resources."""
        out: list[Resource] = []
        raw = getattr(backend, "state_machines", None) or []
        # moto typically stores these as a list of StateMachine objects.
        iterable = raw.values() if isinstance(raw, dict) else raw
        for sm in list(iterable):
            try:
                name = getattr(sm, "name", None) or getattr(sm, "id", None)
                if not name:
                    continue
                attrs: dict[str, Any] = {"name": name}
                for field in (
                    "arn",
                    "type",
                    "status",
                    "logging_configuration",
                    "tracing_configuration",
                ):
                    value = getattr(sm, field, None)
                    if value is not None:
                        attrs[field] = value

                role_arn = getattr(sm, "roleArn", None) or getattr(
                    sm, "role_arn", None
                )
                if role_arn is not None:
                    attrs["role_arn"] = _role_ref(role_arn)

                definition = getattr(sm, "definition", None)
                if definition is not None:
                    attrs["definition"] = _parse_definition(definition)

                creation = getattr(sm, "creation_date", None) or getattr(
                    sm, "create_date", None
                )
                created_at = _iso(creation)

                out.append(
                    Resource(
                        service="stepfunctions",
                        resource_type="state_machine",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_normalise_tags(getattr(sm, "tags", None)),
                        created_at=created_at,
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed Step Functions state machine",
                    exc_info=True,
                )
                continue
        return out

    # ------------------------------------------------------------------
    def _collect_activities(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``stepfunctions:activity`` resources."""
        out: list[Resource] = []
        raw = getattr(backend, "activities", None) or []
        iterable = raw.values() if isinstance(raw, dict) else raw
        for activity in list(iterable):
            try:
                name = getattr(activity, "name", None)
                if not name:
                    continue
                attrs: dict[str, Any] = {"name": name}
                arn = getattr(activity, "arn", None) or getattr(
                    activity, "activity_arn", None
                )
                if arn is not None:
                    attrs["arn"] = arn
                creation = getattr(activity, "creation_date", None) or getattr(
                    activity, "create_date", None
                )
                created_at = _iso(creation)

                out.append(
                    Resource(
                        service="stepfunctions",
                        resource_type="activity",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_normalise_tags(getattr(activity, "tags", None)),
                        created_at=created_at,
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed Step Functions activity",
                    exc_info=True,
                )
                continue
        return out


def _iso(value: Any) -> str | None:
    """Return an ISO 8601 string for a datetime-like ``value``, else None."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        try:
            return isoformat()
        except Exception:  # noqa: BLE001
            return None
    return None


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
                key = item.get("Key") or item.get("key") or item.get("tagKey")
                value = item.get("Value") or item.get("value") or item.get("tagValue")
                if key is not None:
                    out[str(key)] = "" if value is None else str(value)
        return out
    return {}
