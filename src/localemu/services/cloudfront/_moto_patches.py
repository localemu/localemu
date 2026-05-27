"""Moto patches for CloudFront gaps.

Moto's CloudFront models and response templates don't round-trip every
field a real AWS caller expects. This module applies a minimum set of
defensive patches at import time so the behaviour LocalEmu advertises
matches what users actually need.

Patches applied (all defensively — if moto changes shape, we log and
continue without raising):

  1. ``Origin.__init__`` captures ``OriginAccessControlId`` on the model
     object. Without this the field is silently dropped on create.
  2. The ``DIST_CONFIG_TEMPLATE`` XML body is rewritten to emit
     ``<OriginAccessControlId>`` inside each ``<Origin>`` element so
     ``GetDistribution`` / ``ListDistributions`` return the field.

The patch module is imported exactly once per process from
``services.cloudfront.__init__``. Re-importing is safe (guarded by a
flag).
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)

_applied = False

# The anchor string we search for in moto's DIST_CONFIG_TEMPLATE. If moto
# changes this line we fail loud (in logs) and leave the template alone —
# callers still work via the request-payload-derived binding registry.
_TEMPLATE_ANCHOR = "<Id>{{ origin.id }}</Id>"
_TEMPLATE_ADDITION = (
    "<Id>{{ origin.id }}</Id>\n"
    "            {% if origin.origin_access_control_id %}"
    "<OriginAccessControlId>{{ origin.origin_access_control_id }}"
    "</OriginAccessControlId>{% endif %}"
)


def apply() -> None:
    """Apply all moto patches. Idempotent."""
    global _applied
    if _applied:
        return
    _applied = True

    _patch_origin_init()
    _patch_dist_config_template()
    _patch_cache_behaviour_lambda_associations()


def _patch_origin_init() -> None:
    """Extend ``moto.cloudfront.models.Origin.__init__`` to capture the
    ``OriginAccessControlId`` field that moto otherwise drops.
    """
    try:
        from moto.cloudfront import models as _cf_models
    except ImportError:
        LOG.warning("moto.cloudfront.models not importable; OAC patch skipped")
        return

    origin_cls = getattr(_cf_models, "Origin", None)
    if origin_cls is None:
        LOG.warning("moto.cloudfront.models.Origin not found; OAC patch skipped")
        return

    original_init = origin_cls.__init__
    if getattr(original_init, "_localemu_oac_patched", False):
        return

    def _patched_init(self, origin):
        original_init(self, origin)
        # Preserve the OAC id on the model instance so the template (also
        # patched below) can emit it on serialization. Falls back to an
        # empty string so the template's `{% if %}` gate is deterministic.
        self.origin_access_control_id = origin.get("OriginAccessControlId") or ""

    _patched_init._localemu_oac_patched = True  # type: ignore[attr-defined]
    origin_cls.__init__ = _patched_init


def _patch_cache_behaviour_lambda_associations() -> None:
    """Extend ``DefaultCacheBehaviour.__init__`` to populate
    ``lambda_function_associations`` from the request config.

    Moto declares the attribute but never fills it from the incoming
    ``DistributionConfig`` payload, which means Lambda@Edge associations
    are silently dropped. Our Phase 3 chain runner needs them on the
    behaviour object to know which functions to invoke.
    """
    try:
        from moto.cloudfront import models as _cf_models
    except ImportError:
        return

    default_cb = getattr(_cf_models, "DefaultCacheBehaviour", None)
    lfa_cls = getattr(_cf_models, "LambdaFunctionAssociation", None)
    if default_cb is None or lfa_cls is None:
        LOG.warning("moto DefaultCacheBehaviour/LambdaFunctionAssociation not found; "
                    "Lambda@Edge associations will be dropped")
        return

    original_init = default_cb.__init__
    if getattr(original_init, "_localemu_lambda_assoc_patched", False):
        return

    def _patched_init(self, config):
        original_init(self, config)
        wrapper = (config or {}).get("LambdaFunctionAssociations") or {}
        items = wrapper.get("Items") or []
        if isinstance(items, dict):
            # XML deserializers sometimes wrap a single item as a dict.
            items = [items]
        if isinstance(items, list):
            # Flatten any ``{"LambdaFunctionAssociation": <...>}`` wrappers.
            flattened = []
            for entry in items:
                if isinstance(entry, dict) and "LambdaFunctionAssociation" in entry:
                    sub = entry["LambdaFunctionAssociation"]
                    if isinstance(sub, list):
                        flattened.extend(sub)
                    else:
                        flattened.append(sub)
                else:
                    flattened.append(entry)
            for raw in flattened:
                if not isinstance(raw, dict):
                    continue
                assoc = lfa_cls()
                assoc.arn = raw.get("LambdaFunctionARN") or ""
                assoc.event_type = raw.get("EventType") or ""
                assoc.include_body = str(raw.get("IncludeBody") or "").lower() == "true"
                if assoc.arn and assoc.event_type:
                    self.lambda_function_associations.append(assoc)

    _patched_init._localemu_lambda_assoc_patched = True  # type: ignore[attr-defined]
    default_cb.__init__ = _patched_init


def _patch_dist_config_template() -> None:
    """Insert an ``<OriginAccessControlId>`` element into moto's XML
    templates so response bodies round-trip the field.

    Moto concatenates ``DIST_CONFIG_TEMPLATE`` into several higher-level
    templates at module import time (``CREATE_DISTRIBUTION_TEMPLATE``,
    ``GET_DISTRIBUTION_TEMPLATE``, ``UPDATE_DISTRIBUTION_TEMPLATE``,
    ``DISTRIBUTION_TEMPLATE``). Patching only the base string is
    insufficient because the concatenated copies already contain the
    pre-patch content. We patch every template that carries the anchor.

    The patch is a string replacement anchored on ``<Id>`` — the most
    stable marker in the Origin element. If a future moto version drops
    that anchor, we log and skip; the wrapper's request-payload binding
    registry still works for the OAC S3 guard.
    """
    try:
        from moto.cloudfront import responses as _cf_responses
    except ImportError:
        LOG.warning("moto.cloudfront.responses not importable; OAC template patch skipped")
        return

    _template_attrs = (
        "DIST_CONFIG_TEMPLATE",
        "DISTRIBUTION_TEMPLATE",
        "CREATE_DISTRIBUTION_TEMPLATE",
        "GET_DISTRIBUTION_TEMPLATE",
        "GET_DISTRIBUTION_CONFIG_TEMPLATE",
        "LIST_TEMPLATE",
        "UPDATE_DISTRIBUTION_TEMPLATE",
    )
    patched_count = 0
    for attr in _template_attrs:
        template = getattr(_cf_responses, attr, None)
        if not isinstance(template, str):
            continue
        if "origin.origin_access_control_id" in template:
            # Already carries the patch (idempotent call, or moto version
            # adopted the field natively).
            continue
        if _TEMPLATE_ANCHOR not in template:
            continue
        setattr(_cf_responses, attr, template.replace(
            _TEMPLATE_ANCHOR, _TEMPLATE_ADDITION, 1,
        ))
        patched_count += 1

    if patched_count == 0:
        LOG.warning(
            "No CloudFront templates were patched for OriginAccessControlId. "
            "Likely a moto version change; the wrapper's request-payload "
            "binding still works so the OAC S3 guard is unaffected.",
        )
