"""HTTP endpoint for the queryable IAM authorization decision log.
Mounted by :mod:`localemu.services.iam_enforcement.plugins` at
``/_localemu/iam/decisions``.
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


class IamDecisionLogResource:
    """``GET /_localemu/iam/decisions``.

    Query params (all optional): ``limit`` (default 100, max 2000),
    ``principal_arn``, ``action``, ``resource``, ``decision``
    (``ALLOW``/``EXPLICIT_DENY``/``IMPLICIT_DENY``).

    Response: ``{"decisions": [...], "total": <int>}``, newest first.
    Each entry: ``id``, ``timestamp`` (unix seconds), ``decision``,
    ``principal_arn``, ``account_id``, ``action``, ``resource``,
    ``reason`` (plain-English), ``source`` (which policy type decided
    it: scp/identity/resource/boundary/session/None), ``matched_statement``
    (the actual policy statement, or null when there isn't one - e.g. an
    implicit deny has no matching statement by definition).
    """

    def on_get(self, request):
        from localemu.services.iam_enforcement.decision_log import query_decisions

        args = request.args

        def _int_arg(name: str, default: int) -> int:
            try:
                return int(args.get(name, default))
            except (TypeError, ValueError):
                return default

        decisions = query_decisions(
            limit=_int_arg("limit", 100),
            principal_arn=args.get("principal_arn"),
            action=args.get("action"),
            resource=args.get("resource"),
            decision=args.get("decision"),
        )
        return {"decisions": decisions, "total": len(decisions)}


class IamDecisionLogClearResource:
    """``POST /_localemu/iam/decisions/clear`` - empties the ring buffer.
    Useful for a lab that wants a clean slate right before the sequence
    of calls it's about to assert on."""

    def on_post(self, request):
        from localemu.services.iam_enforcement.decision_log import clear_decisions

        clear_decisions()
        return {"ok": True}
