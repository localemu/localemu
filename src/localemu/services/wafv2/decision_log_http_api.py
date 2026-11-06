"""HTTP endpoint for the queryable WAFv2 decision log. Mounted by
:mod:`localemu.services.wafv2.plugins` at ``/_localemu/wafv2/decisions``.
Mirrors ``iam_enforcement.decision_log_http_api`` exactly."""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)


class WafDecisionLogResource:
    """``GET /_localemu/wafv2/decisions``.

    Query params (all optional): ``limit`` (default 100, max 2000),
    ``resource_arn``, ``decision`` (``ALLOW``/``BLOCK``/``COUNT``).

    Response: ``{"decisions": [...], "total": <int>}``, newest first.
    Each entry: ``id``, ``timestamp``, ``decision``, ``web_acl_arn``,
    ``resource_arn``, ``matched_rule`` (None when DefaultAction applied),
    ``method``, ``uri_path``, ``source_ip``, ``counted_rules`` (names of
    every Count rule that fired on this request, regardless of the final
    terminating decision).
    """

    def on_get(self, request):
        from localemu.services.wafv2.decision_log import query_decisions

        args = request.args

        def _int_arg(name: str, default: int) -> int:
            try:
                return int(args.get(name, default))
            except (TypeError, ValueError):
                return default

        decisions = query_decisions(
            limit=_int_arg("limit", 100),
            resource_arn=args.get("resource_arn"),
            decision=args.get("decision"),
        )
        return {"decisions": decisions, "total": len(decisions)}


class WafDecisionLogClearResource:
    """``POST /_localemu/wafv2/decisions/clear`` - empties the ring buffer."""

    def on_post(self, request):
        from localemu.services.wafv2.decision_log import clear_decisions

        clear_decisions()
        return {"ok": True}
