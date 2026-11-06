"""Plux hook: wires the queryable IAM decision log endpoint into the
internal API router at ``/_localemu/iam/decisions``.

Follows the same registration pattern as
``localemu.services.sts.plugins:register_oidc_mint_token``.
"""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def register_iam_decision_log() -> None:
    try:
        from localemu.http import Resource
        from localemu.services.iam_enforcement.decision_log_http_api import (
            IamDecisionLogClearResource,
            IamDecisionLogResource,
        )
        from localemu.services.internal import get_internal_apis

        router = get_internal_apis()
        router.add(Resource("/_localemu/iam/decisions", IamDecisionLogResource()))
        router.add(Resource("/_localemu/iam/decisions/clear", IamDecisionLogClearResource()))
        LOG.info("LocalEmu IAM decision log endpoint registered at /_localemu/iam/decisions")
    except Exception:
        LOG.error("Failed to register LocalEmu IAM decision log endpoint", exc_info=True)


__all__ = ["register_iam_decision_log"]
