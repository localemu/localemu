"""SSM (Systems Manager) collector.

Exports Parameter Store parameters and SSM documents. Patch baselines,
associations, and maintenance windows are deliberately out of scope for
v1 — they carry little standalone value without the EC2 fleet state that
usually accompanies them.

Secret handling:
    SecureString parameter *values* are never emitted from this collector.
    The redaction pass (``_SERVICE_FORCED_PATHS`` in
    :mod:`localemu.export.redaction`) additionally redacts ``value`` on
    every parameter resource when ``include_secrets=False``; we rely on
    that for non-SecureString parameters that still contain secrets.
"""

from __future__ import annotations

import logging
from typing import Any

import moto.backends as moto_backends

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource
from localemu.export.redaction import REDACTED

LOG = logging.getLogger(__name__)

# Whitelist of parameter fields we serialise. Anything else moto keeps on
# the object (internal history lists, etc.) is ignored on purpose.
_PARAM_FIELDS = (
    "name",
    "type",
    "description",
    "tier",
    "policies",
    "version",
    "data_type",
)

_DOC_FIELDS = (
    "name",
    "document_type",
    "document_format",
    "document_version",
    "target_type",
    "status",
)


def _getattr_any(obj: Any, *names: str, default: Any = None) -> Any:
    """Return the first attribute of ``obj`` in ``names`` that exists."""
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


@register_collector("ssm")
class SsmCollector(BaseCollector):
    """Collect SSM parameters and documents from the moto backend."""

    service = "ssm"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Enumerate SSM parameters and documents for the given scope."""
        resources: list[Resource] = []
        try:
            backend_dict = moto_backends.get_backend("ssm")
            backend = backend_dict[account_id][region]
        except Exception:  # noqa: BLE001 - backend may be absent
            LOG.warning(
                "SSM backend unavailable for %s/%s", account_id, region, exc_info=True
            )
            return resources

        resources.extend(self._collect_parameters(backend, account_id, region))
        resources.extend(self._collect_documents(backend, account_id, region))
        resources.extend(self._collect_maintenance_windows(backend, account_id, region))
        return resources

    # ------------------------------------------------------------------
    # Maintenance windows
    # ------------------------------------------------------------------
    def _collect_maintenance_windows(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``ssm:maintenance_window`` resources.

        Moto stores them as ``backend.windows`` keyed by ``mw-…`` id.
        Terraform / CFN identify the window by ``Name`` rather than id,
        so we use ``Name`` as the IR's ``resource_id`` for stable refs.
        """
        out: list[Resource] = []
        raw = getattr(backend, "windows", {}) or {}
        for window_id, window in dict(raw).items():
            try:
                name = getattr(window, "name", None) or window_id
                # ``allow_unassociated_targets`` is REQUIRED by CFN's
                # AWS::SSM::MaintenanceWindow but moto's
                # ``FakeMaintenanceWindow`` doesn't persist it, so always
                # fall back to AWS's documented default of ``False`` rather
                # than dropping the key. Same for ``Enabled`` which AWS
                # always defaults to True.
                attrs: dict[str, Any] = {
                    "name": name,
                    "window_id": window_id,
                    "schedule": getattr(window, "schedule", None),
                    "duration": getattr(window, "duration", None),
                    "cutoff": getattr(window, "cutoff", None),
                    "allow_unassociated_targets": bool(getattr(
                        window, "allow_unassociated_targets", False
                    )),
                    "description": getattr(window, "description", None),
                    "enabled": bool(getattr(window, "enabled", True)),
                    "schedule_timezone": getattr(
                        window, "schedule_timezone", None
                    ),
                    "schedule_offset": getattr(window, "schedule_offset", None),
                    "start_date": getattr(window, "start_date", None),
                    "end_date": getattr(window, "end_date", None),
                }
                attrs = {k: v for k, v in attrs.items() if v is not None}
                out.append(Resource(
                    service="ssm",
                    resource_type="maintenance_window",
                    resource_id=name,
                    account_id=account_id,
                    region=region,
                    attributes=attrs,
                ))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed SSM maintenance window %r",
                    window_id, exc_info=True,
                )
        return out

    # ------------------------------------------------------------------
    # Parameters
    # ------------------------------------------------------------------
    def _collect_parameters(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``ssm:parameter`` resources."""
        out: list[Resource] = []
        # Moto stores parameters as a dict[name, list[versions]] on either
        # ``_parameters`` or ``parameters``; history means the last entry
        # is the current version.
        raw = _getattr_any(backend, "_parameters", "parameters", default={}) or {}
        for name, versions in raw.items():
            try:
                if not versions:
                    continue
                current = versions[-1] if isinstance(versions, list) else versions
                out.append(self._parameter_resource(name, current, account_id, region))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed SSM parameter %r", name, exc_info=True
                )
                continue
        return out

    def _parameter_resource(
        self, name: str, param: Any, account_id: str, region: str
    ) -> Resource:
        """Build a :class:`Resource` for a single SSM parameter."""
        attrs: dict[str, Any] = {}
        for field in _PARAM_FIELDS:
            value = getattr(param, field, None)
            if value is not None:
                attrs[field] = value

        # Always include ``name`` — moto may store it as ``Name`` as well.
        attrs.setdefault("name", name)

        param_type = attrs.get("type") or getattr(param, "parameter_type", "String")
        attrs["type"] = param_type

        # Defence in depth: never surface a SecureString *value* from the
        # collector itself. Non-secure values are included; the redaction
        # pass will still blank them when include_secrets=False.
        raw_value = getattr(param, "value", None)
        if param_type == "SecureString":
            attrs["value"] = REDACTED
        else:
            attrs["value"] = raw_value

        kms_key_id = getattr(param, "keyid", None) or getattr(param, "key_id", None)
        if kms_key_id:
            attrs["kms_key_id"] = Ref(
                service="kms", resource_type="key", resource_id=str(kms_key_id)
            )

        tags = _parameter_tags(param, name)

        return Resource(
            service="ssm",
            resource_type="parameter",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
        )

    # ------------------------------------------------------------------
    # Documents
    # ------------------------------------------------------------------
    def _collect_documents(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate ``ssm:document`` resources."""
        out: list[Resource] = []
        raw = _getattr_any(backend, "_documents", "documents", default={}) or {}
        for name, entry in raw.items():
            try:
                doc = _resolve_document(entry)
                if doc is None:
                    continue
                out.append(self._document_resource(name, doc, entry, account_id, region))
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed SSM document %r", name, exc_info=True
                )
                continue
        return out

    def _document_resource(
        self,
        name: str,
        doc: Any,
        entry: Any,
        account_id: str,
        region: str,
    ) -> Resource:
        """Build a :class:`Resource` for an SSM document."""
        attrs: dict[str, Any] = {"name": name}
        for field in _DOC_FIELDS:
            value = getattr(doc, field, None)
            if value is not None:
                attrs[field] = value
        content = getattr(doc, "content", None)
        if content is not None:
            attrs["content"] = content

        tags = _document_tags(entry, doc)

        return Resource(
            service="ssm",
            resource_type="document",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
        )


def _resolve_document(entry: Any) -> Any:
    """Extract the current version object from a moto document entry."""
    # Moto shapes: Documents object holding ``versions`` dict, or a bare
    # Document, or a list of versions.
    if entry is None:
        return None
    if hasattr(entry, "versions") and isinstance(entry.versions, dict):
        default_version = getattr(entry, "default_version", None)
        if default_version and default_version in entry.versions:
            return entry.versions[default_version]
        if entry.versions:
            return next(iter(entry.versions.values()))
    if isinstance(entry, list) and entry:
        return entry[-1]
    return entry


def _parameter_tags(param: Any, name: str) -> dict[str, str]:
    """Return tags for a parameter, handling list-of-dicts and dict shapes."""
    raw = getattr(param, "tags", None)
    return _normalise_tags(raw)


def _document_tags(entry: Any, doc: Any) -> dict[str, str]:
    """Return tags for a document, checking the entry and the version."""
    raw = getattr(entry, "tags", None)
    if raw is None:
        raw = getattr(doc, "tags", None)
    return _normalise_tags(raw)


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
