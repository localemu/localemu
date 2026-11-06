"""Wires the WAFv2 evaluator into the ALB listener proxy.

``services.elbv2.listener_router`` calls ``evaluate_for_alb`` once per
request, right before target-group selection, passing the load
balancer's ARN and the raw HTTP request. This module is the only place
that knows about moto's wafv2 backend - the evaluator itself
(``evaluator.py``) has zero moto dependency.
"""

from __future__ import annotations

import logging
import os
import threading

LOG = logging.getLogger(__name__)

# Default ON: a Web ACL the user explicitly created and associated to an
# ALB, with Block rules, should actually block - matching
# CLOUDFRONT_OAC_ENFORCE's precedent (services/cloudfront/auth/oac_guard.py).
# Set WAFV2_ALB_ENFORCE=0 to fall back to today's pre-existing behavior
# (Web ACL associations recorded but never evaluated).
def _enforcement_enabled() -> bool:
    raw = os.environ.get("WAFV2_ALB_ENFORCE", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _backend(account_id: str, region: str):
    from moto.wafv2.models import wafv2_backends

    return wafv2_backends[account_id][region]


def _account_and_region_from_arn(arn: str) -> tuple[str, str]:
    # arn:aws:wafv2:<region>:<account>:... / arn:aws:elasticloadbalancing:<region>:<account>:...
    parts = arn.split(":")
    region = parts[3] if len(parts) > 3 else "us-east-1"
    account_id = parts[4] if len(parts) > 4 else "000000000000"
    return account_id, region


# Associating a Web ACL with a global/CLOUDFRONT-scope resource stores it
# under moto's special "global" region key rather than the resource's own
# region - mirror that lookup order: try the ALB's own region first (the
# REGIONAL scope ALBs actually use), then moto's GLOBAL_REGION as a
# fallback for safety.
_GLOBAL_REGION = "global"


def _resolve_web_acl_dict(lb_arn: str) -> dict | None:
    account_id, region = _account_and_region_from_arn(lb_arn)
    for candidate_region in (region, _GLOBAL_REGION):
        try:
            backend = _backend(account_id, candidate_region)
        except Exception:
            continue
        web_acl = backend.get_web_acl_for_resource(lb_arn)
        if web_acl is not None:
            return web_acl.to_dict()
    return None


def _make_ip_set_resolver(account_id: str, region: str):
    def _resolve(arn: str) -> list[str]:
        for candidate_region in (region, _GLOBAL_REGION):
            try:
                backend = _backend(account_id, candidate_region)
                ip_set = backend.ip_sets.get(arn)
            except Exception:
                ip_set = None
            if ip_set is not None:
                return list(ip_set.addresses or [])
        return []

    return _resolve


def _make_regex_pattern_set_resolver(account_id: str, region: str):
    def _resolve(arn: str) -> list[str]:
        for candidate_region in (region, _GLOBAL_REGION):
            try:
                backend = _backend(account_id, candidate_region)
                pattern_set = backend.regex_pattern_sets.get(arn)
            except Exception:
                pattern_set = None
            if pattern_set is not None:
                return [
                    entry.get("RegexString", "")
                    for entry in (pattern_set.regular_expressions or [])
                    if entry.get("RegexString")
                ]
        return []

    return _resolve


# One warning per (lb_arn) for the "no enforcement configured" case would
# be noise on every single request if logged at INFO; this just avoids
# re-resolving nothing over and over in a hot path by short-circuiting
# fast when there's no Web ACL - no caching of the ACL itself, since a
# user editing their Web ACL's rules mid-session must take effect on the
# very next request, not after some TTL.
_no_acl_cache_lock = threading.Lock()


def evaluate_for_alb(lb_arn: str, req) -> "object":
    """Returns an ``evaluator.EvaluationResult``, or None if there is no
    Web ACL associated with this ALB (the overwhelmingly common case -
    zero evaluation cost, never blocks) or if enforcement is disabled via
    WAFV2_ALB_ENFORCE=0.

    ``req`` is an ``evaluator.WafRequestView``.
    """
    if not _enforcement_enabled():
        return None

    web_acl = _resolve_web_acl_dict(lb_arn)
    if web_acl is None:
        return None

    from . import decision_log
    from .evaluator import evaluate_web_acl

    account_id, region = _account_and_region_from_arn(lb_arn)
    result = evaluate_web_acl(
        web_acl,
        req,
        resolve_ip_set=_make_ip_set_resolver(account_id, region),
        resolve_regex_pattern_set=_make_regex_pattern_set_resolver(account_id, region),
        on_count=lambda rule_name: decision_log.record_decision(
            decision="COUNT",
            web_acl_arn=web_acl.get("ARN", ""),
            resource_arn=lb_arn,
            rule_name=rule_name,
            method=req.method,
            uri_path=req.uri_path,
            source_ip=req.source_ip,
        ),
    )

    try:
        decision_log.record_decision(
            decision=result.action,
            web_acl_arn=web_acl.get("ARN", ""),
            resource_arn=lb_arn,
            rule_name=result.matched_rule,
            method=req.method,
            uri_path=req.uri_path,
            source_ip=req.source_ip,
            counted_rules=result.counted_rules,
        )
    except Exception:
        LOG.debug("WAFv2: failed to record decision log entry", exc_info=True)

    return result
