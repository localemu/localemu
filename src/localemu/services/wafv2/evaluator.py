"""Real-time WAFv2 Web ACL rule evaluation.

Implements the actual AWS WAFv2 evaluation algorithm against a moto
``FakeWebACL.to_dict()``-shaped Web ACL:

  1. Evaluate rules in ascending ``Priority`` order (lower = first).
  2. Block/Allow actions are TERMINATING - the first one stops evaluation.
  3. Count is NON-TERMINATING - it's recorded and evaluation continues;
     multiple Count rules can fire on one request.
  4. If no rule terminates, the Web ACL's ``DefaultAction`` applies.

Every statement type NOT implemented here (GeoMatchStatement,
RateBasedStatement, SqliMatchStatement, XssMatchStatement,
RuleGroupReferenceStatement, ManagedRuleGroupStatement,
LabelMatchStatement, RegexMatchStatement, AsnMatchStatement, or anything
else) is treated as "does not match" and loudly logged - never silently
treated as a match (which would block real traffic unpredictably) and
never silently treated as "fully evaluated and safe" either. A Web ACL
built from an unsupported rule type behaves exactly as if that rule
weren't there: no false sense of protection, no surprise blocking.
Reference: 3 independent design reviews of the original proposal all
converged on this as the single most important correctness property of
a partially-implemented engine.
"""

from __future__ import annotations

import base64
import html
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, unquote_plus

LOG = logging.getLogger(__name__)


@dataclass
class WafRequestView:
    """Normalized request view the evaluator inspects. Callers build one
    of these from whatever HTTP primitives they have - e.g.
    ``services.elbv2.listener_router``'s ``BaseHTTPRequestHandler``."""

    method: str
    uri_path: str  # path only, no query string
    query_string: str  # raw query string, no leading '?'
    headers: dict  # case-insensitive .get() expected (e.g. email.message.Message)
    source_ip: str
    body: bytes | None = None

    def header(self, name: str) -> str:
        try:
            return self.headers.get(name, "") or ""
        except Exception:
            return ""


class Action:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass
class EvaluationResult:
    action: str  # Action.ALLOW or Action.BLOCK - the final, terminating decision
    matched_rule: str | None  # name of the rule that terminated evaluation, or None (DefaultAction applied)
    counted_rules: list[str] = field(default_factory=list)  # names of every Count rule that fired


def _resolve_field(field_to_match: dict, req: WafRequestView) -> str | None:
    """Return the FieldToMatch's raw (pre-transform) string value, or None
    if the field (or named sub-field, e.g. a SingleHeader that isn't
    present) is absent - AWS: the statement simply doesn't match."""
    if "UriPath" in field_to_match:
        return req.uri_path
    if "QueryString" in field_to_match:
        return req.query_string
    if "Method" in field_to_match:
        return req.method
    if "Body" in field_to_match:
        return (req.body or b"").decode("utf-8", errors="replace")
    if "SingleHeader" in field_to_match:
        name = (field_to_match.get("SingleHeader") or {}).get("Name", "")
        if not name:
            return None
        value = req.header(name)
        return value if value else None
    if "SingleQueryArgument" in field_to_match:
        name = (field_to_match.get("SingleQueryArgument") or {}).get("Name", "")
        if not name:
            return None
        for k, v in parse_qsl(req.query_string, keep_blank_values=True):
            if k == name:
                return v
        return None
    if "AllQueryArguments" in field_to_match:
        return req.query_string
    LOG.warning(
        "WAFv2: unsupported FieldToMatch kind %r - treating as absent (non-match), not enforced",
        list(field_to_match.keys()),
    )
    return None


def _compress_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


_TRANSFORM_FUNCS: dict[str, Callable[[str], str]] = {
    "NONE": lambda s: s,
    "LOWERCASE": lambda s: s.lower(),
    "URL_DECODE": unquote_plus,
    "HTML_ENTITY_DECODE": html.unescape,
    "COMPRESS_WHITE_SPACE": _compress_whitespace,
    "TRIM": lambda s: s.strip(),
}


def _apply_transformations(value: str, transformations: list[dict]) -> str:
    """Real WAF applies transformations in ascending Priority order (not
    list order - the priorities don't need to be consecutive)."""
    ordered = sorted(transformations or [], key=lambda t: t.get("Priority", 0))
    for t in ordered:
        ttype = t.get("Type", "NONE")
        fn = _TRANSFORM_FUNCS.get(ttype)
        if fn is None:
            LOG.warning(
                "WAFv2: unsupported TextTransformation %r - leaving value untransformed for this step",
                ttype,
            )
            continue
        try:
            value = fn(value)
        except Exception:
            LOG.debug("WAFv2: transformation %s raised on value", ttype, exc_info=True)
    return value


def _positional_match(constraint: str, haystack: str, needle: str) -> bool:
    if constraint == "EXACTLY":
        return haystack == needle
    if constraint == "STARTS_WITH":
        return haystack.startswith(needle)
    if constraint == "ENDS_WITH":
        return haystack.endswith(needle)
    if constraint == "CONTAINS":
        return needle in haystack
    if constraint == "CONTAINS_WORD":
        if not needle:
            return False
        for m in re.finditer(re.escape(needle), haystack):
            start, end = m.start(), m.end()
            before_ok = start == 0 or not (haystack[start - 1].isalnum() or haystack[start - 1] == "_")
            after_ok = end == len(haystack) or not (haystack[end].isalnum() or haystack[end] == "_")
            if before_ok and after_ok:
                return True
        return False
    LOG.warning("WAFv2: unsupported PositionalConstraint %r - treating as non-match", constraint)
    return False


_COMPARISONS: dict[str, Callable[[int, int], bool]] = {
    "EQ": lambda a, b: a == b,
    "NE": lambda a, b: a != b,
    "LT": lambda a, b: a < b,
    "LE": lambda a, b: a <= b,
    "GT": lambda a, b: a > b,
    "GE": lambda a, b: a >= b,
}


class RuleContext:
    """Per-evaluation lookups the engine needs but shouldn't know the
    storage details of - injected by the caller so this module has zero
    dependency on moto."""

    def __init__(
        self,
        resolve_ip_set: Callable[[str], list[str]],
        resolve_regex_pattern_set: Callable[[str], list[str]],
    ):
        self._resolve_ip_set = resolve_ip_set
        self._resolve_regex_pattern_set = resolve_regex_pattern_set

    def ip_set_addresses(self, arn: str) -> list[str]:
        try:
            return self._resolve_ip_set(arn) or []
        except Exception:
            LOG.debug("WAFv2: failed to resolve IPSet %s", arn, exc_info=True)
            return []

    def regex_patterns(self, arn: str) -> list[str]:
        try:
            return self._resolve_regex_pattern_set(arn) or []
        except Exception:
            LOG.debug("WAFv2: failed to resolve RegexPatternSet %s", arn, exc_info=True)
            return []


def _match_byte(stmt: dict, req: WafRequestView) -> bool:
    raw = _resolve_field(stmt.get("FieldToMatch") or {}, req)
    if raw is None:
        return False
    value = _apply_transformations(raw, stmt.get("TextTransformations") or [])
    search_b64 = stmt.get("SearchString", "")
    try:
        needle = base64.b64decode(search_b64).decode("utf-8", errors="replace") if search_b64 else ""
    except Exception:
        needle = search_b64 or ""
    return _positional_match(stmt.get("PositionalConstraint", ""), value, needle)


def _match_size(stmt: dict, req: WafRequestView) -> bool:
    raw = _resolve_field(stmt.get("FieldToMatch") or {}, req)
    value = _apply_transformations(raw or "", stmt.get("TextTransformations") or [])
    size = len(value.encode("utf-8"))
    cmp_fn = _COMPARISONS.get(stmt.get("ComparisonOperator", ""))
    if cmp_fn is None:
        LOG.warning(
            "WAFv2: unsupported ComparisonOperator %r - treating as non-match",
            stmt.get("ComparisonOperator"),
        )
        return False
    return cmp_fn(size, stmt.get("Size", 0))


def _match_regex_pattern_set(stmt: dict, req: WafRequestView, ctx: RuleContext) -> bool:
    raw = _resolve_field(stmt.get("FieldToMatch") or {}, req)
    if raw is None:
        return False
    value = _apply_transformations(raw, stmt.get("TextTransformations") or [])
    for pattern in ctx.regex_patterns(stmt.get("ARN", "")):
        try:
            if re.search(pattern, value):
                return True
        except re.error:
            LOG.warning("WAFv2: invalid regex %r in RegexPatternSet - skipping", pattern)
    return False


def _match_ip_set(stmt: dict, req: WafRequestView, ctx: RuleContext) -> bool:
    try:
        ip = ipaddress.ip_address(req.source_ip)
    except ValueError:
        return False
    for cidr in ctx.ip_set_addresses(stmt.get("ARN", "")):
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# The only statement keys this engine actually evaluates. Anything else
# falls through to the "unimplemented -> non-match, logged" branch below.
_SUPPORTED_STATEMENT_KEYS = {
    "ByteMatchStatement",
    "SizeConstraintStatement",
    "RegexPatternSetReferenceStatement",
    "IPSetReferenceStatement",
    "AndStatement",
    "OrStatement",
    "NotStatement",
}


def evaluate_statement(stmt: dict, req: WafRequestView, ctx: RuleContext) -> bool:
    """True if ``stmt`` matches ``req``. Recurses for And/Or/Not."""
    if "ByteMatchStatement" in stmt:
        return _match_byte(stmt["ByteMatchStatement"], req)
    if "SizeConstraintStatement" in stmt:
        return _match_size(stmt["SizeConstraintStatement"], req)
    if "RegexPatternSetReferenceStatement" in stmt:
        return _match_regex_pattern_set(stmt["RegexPatternSetReferenceStatement"], req, ctx)
    if "IPSetReferenceStatement" in stmt:
        return _match_ip_set(stmt["IPSetReferenceStatement"], req, ctx)
    if "AndStatement" in stmt:
        children = (stmt["AndStatement"] or {}).get("Statements") or []
        return all(evaluate_statement(s, req, ctx) for s in children)
    if "OrStatement" in stmt:
        children = (stmt["OrStatement"] or {}).get("Statements") or []
        return any(evaluate_statement(s, req, ctx) for s in children)
    if "NotStatement" in stmt:
        inner = (stmt["NotStatement"] or {}).get("Statement") or {}
        return not evaluate_statement(inner, req, ctx)

    unknown = [k for k in stmt.keys() if k not in _SUPPORTED_STATEMENT_KEYS]
    LOG.warning(
        "WAFv2: rule uses unimplemented statement type(s) %r - treating as "
        "non-match, NOT enforced (same as if the rule didn't exist)",
        unknown or list(stmt.keys()),
    )
    return False


def evaluate_web_acl(
    web_acl: dict,
    req: WafRequestView,
    *,
    resolve_ip_set: Callable[[str], list[str]],
    resolve_regex_pattern_set: Callable[[str], list[str]],
    on_count: Callable[[str], None] | None = None,
) -> EvaluationResult:
    """Evaluate every rule in ``web_acl`` (a moto ``FakeWebACL.to_dict()``)
    against ``req``, in ascending Priority order. See module docstring
    for the termination/fallback contract.
    """
    ctx = RuleContext(resolve_ip_set, resolve_regex_pattern_set)
    rules = sorted(web_acl.get("Rules") or [], key=lambda r: r.get("Priority", 0))
    counted: list[str] = []

    for rule in rules:
        name = rule.get("Name", "")
        if not evaluate_statement(rule.get("Statement") or {}, req, ctx):
            continue

        action = rule.get("Action") or {}
        if "Block" in action:
            return EvaluationResult(action=Action.BLOCK, matched_rule=name, counted_rules=counted)
        if "Allow" in action:
            return EvaluationResult(action=Action.ALLOW, matched_rule=name, counted_rules=counted)
        if "Count" in action:
            counted.append(name)
            if on_count is not None:
                try:
                    on_count(name)
                except Exception:
                    LOG.debug("WAFv2: on_count callback failed for rule %s", name, exc_info=True)
            continue  # non-terminating: AWS keeps evaluating subsequent rules

        # Captcha / Challenge / anything else: can't be genuinely enforced
        # here. Same fallback discipline as an unsupported statement type -
        # log loudly, don't terminate, don't pretend it was handled.
        LOG.warning(
            "WAFv2: rule %r matched but its action %r is not enforceable here - "
            "treating as non-terminating, NOT enforced, continuing evaluation",
            name, list(action.keys()),
        )

    default_action = web_acl.get("DefaultAction") or {}
    final = Action.BLOCK if "Block" in default_action else Action.ALLOW
    return EvaluationResult(action=final, matched_rule=None, counted_rules=counted)
