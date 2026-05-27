"""Plux hook: wires the infrastructure-export HTTP endpoint into the
internal API router at ``/_localemu/api/export``.

This follows the same registration pattern as
``localemu.dashboard.plugins:register_dashboard``.
"""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def register() -> None:
    """Register :class:`ExportResource` on the internal APIs router."""
    try:
        from localemu.export.http_api import ExportResourceApp
        from localemu.http import Resource
        from localemu.services.internal import get_internal_apis

        router = get_internal_apis()
        router.add(Resource("/_localemu/api/export", ExportResourceApp()))
        LOG.info("LocalEmu export endpoint registered at /_localemu/api/export")
    except Exception:
        # Log with exc_info so operators can see why the feature did not
        # come up. We deliberately do not re-raise: a broken export plugin
        # must not prevent LocalEmu itself from starting.
        LOG.error("Failed to register LocalEmu export endpoint", exc_info=True)


__all__ = ["register"]
