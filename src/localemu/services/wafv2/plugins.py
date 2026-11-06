"""Plux hook: wires the queryable WAFv2 decision log endpoint into the
internal API router at ``/_localemu/wafv2/decisions``.

Mirrors ``localemu.services.iam_enforcement.plugins:register_iam_decision_log``
exactly.
"""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def register_wafv2_decision_log() -> None:
    try:
        from localemu.http import Resource
        from localemu.services.internal import get_internal_apis
        from localemu.services.wafv2.decision_log_http_api import (
            WafDecisionLogClearResource,
            WafDecisionLogResource,
        )

        router = get_internal_apis()
        router.add(Resource("/_localemu/wafv2/decisions", WafDecisionLogResource()))
        router.add(Resource("/_localemu/wafv2/decisions/clear", WafDecisionLogClearResource()))
        LOG.info("LocalEmu WAFv2 decision log endpoint registered at /_localemu/wafv2/decisions")
    except Exception:
        LOG.error("Failed to register LocalEmu WAFv2 decision log endpoint", exc_info=True)


__all__ = ["register_wafv2_decision_log"]
