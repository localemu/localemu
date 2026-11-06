"""Unit tests for localemu.services.wafv2.evaluator.

Covers the real-time rule-evaluation engine in isolation (no moto, no
HTTP, no listener_router) - leaf statement matchers, text transformations,
positional constraints, And/Or/Not nesting, Block/Allow-terminates vs.
Count-continues control flow, DefaultAction fallback, and the
unsupported-statement-type fallback contract (log + non-match, never a
silent block or a silent pass)."""
from __future__ import annotations

import base64
import logging

import pytest

from localemu.services.wafv2.evaluator import (
    EvaluationResult,
    WafRequestView,
    evaluate_statement,
    evaluate_web_acl,
)


def _req(
    method="GET", uri_path="/", query_string="", headers=None, source_ip="203.0.113.1", body=None,
) -> WafRequestView:
    return WafRequestView(
        method=method, uri_path=uri_path, query_string=query_string,
        headers=headers or {}, source_ip=source_ip, body=body,
    )


def _byte_match(field, search, constraint, transforms=None):
    return {
        "ByteMatchStatement": {
            "FieldToMatch": field,
            "SearchString": base64.b64encode(search.encode()).decode(),
            "PositionalConstraint": constraint,
            "TextTransformations": transforms or [{"Priority": 0, "Type": "NONE"}],
        }
    }


def _no_resolvers():
    return dict(resolve_ip_set=lambda arn: [], resolve_regex_pattern_set=lambda arn: [])


class TestByteMatchStatement:
    def test_uri_path_contains(self):
        stmt = _byte_match({"UriPath": {}}, "admin", "CONTAINS")
        assert evaluate_statement(stmt, _req(uri_path="/admin/users"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/public"), _ctx()) is False

    def test_exactly(self):
        stmt = _byte_match({"UriPath": {}}, "/exact", "EXACTLY")
        assert evaluate_statement(stmt, _req(uri_path="/exact"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/exact/more"), _ctx()) is False

    def test_starts_with(self):
        stmt = _byte_match({"UriPath": {}}, "/api/", "STARTS_WITH")
        assert evaluate_statement(stmt, _req(uri_path="/api/v1/users"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/v1/api/"), _ctx()) is False

    def test_ends_with(self):
        stmt = _byte_match({"UriPath": {}}, ".php", "ENDS_WITH")
        assert evaluate_statement(stmt, _req(uri_path="/shell.php"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/shell.php.txt"), _ctx()) is False

    def test_contains_word_respects_boundaries(self):
        stmt = _byte_match({"UriPath": {}}, "admin", "CONTAINS_WORD")
        assert evaluate_statement(stmt, _req(uri_path="/admin/x"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/superadmin/x"), _ctx()) is False

    def test_method_field(self):
        stmt = _byte_match({"Method": {}}, "DELETE", "EXACTLY")
        assert evaluate_statement(stmt, _req(method="DELETE"), _ctx()) is True
        assert evaluate_statement(stmt, _req(method="GET"), _ctx()) is False

    def test_single_header_field(self):
        stmt = _byte_match({"SingleHeader": {"Name": "User-Agent"}}, "sqlmap", "CONTAINS")
        assert evaluate_statement(stmt, _req(headers={"User-Agent": "sqlmap/1.6"}), _ctx()) is True
        assert evaluate_statement(stmt, _req(headers={"User-Agent": "curl/8.0"}), _ctx()) is False

    def test_single_header_absent_is_non_match(self):
        stmt = _byte_match({"SingleHeader": {"Name": "X-Custom"}}, "x", "CONTAINS")
        assert evaluate_statement(stmt, _req(headers={}), _ctx()) is False

    def test_query_string_field(self):
        stmt = _byte_match({"QueryString": {}}, "' OR 1=1", "CONTAINS")
        assert evaluate_statement(stmt, _req(query_string="id=1' OR 1=1--"), _ctx()) is True
        assert evaluate_statement(stmt, _req(query_string="id=1"), _ctx()) is False

    def test_single_query_argument_field(self):
        stmt = _byte_match({"SingleQueryArgument": {"Name": "redirect"}}, "evil.com", "CONTAINS")
        assert evaluate_statement(stmt, _req(query_string="redirect=http://evil.com"), _ctx()) is True
        assert evaluate_statement(stmt, _req(query_string="redirect=http://ok.com"), _ctx()) is False

    def test_body_field(self):
        stmt = _byte_match({"Body": {}}, "DROP TABLE", "CONTAINS")
        assert evaluate_statement(stmt, _req(body=b"q=DROP TABLE users"), _ctx()) is True
        assert evaluate_statement(stmt, _req(body=b"q=hello"), _ctx()) is False


class TestTextTransformations:
    def test_lowercase(self):
        stmt = _byte_match(
            {"UriPath": {}}, "admin", "CONTAINS", [{"Priority": 0, "Type": "LOWERCASE"}],
        )
        assert evaluate_statement(stmt, _req(uri_path="/ADMIN/x"), _ctx()) is True

    def test_url_decode(self):
        stmt = _byte_match(
            {"UriPath": {}}, "../etc/passwd", "CONTAINS", [{"Priority": 0, "Type": "URL_DECODE"}],
        )
        assert evaluate_statement(stmt, _req(uri_path="%2e%2e%2fetc%2fpasswd"), _ctx()) is True

    def test_html_entity_decode(self):
        stmt = _byte_match(
            {"UriPath": {}}, "<script>", "CONTAINS", [{"Priority": 0, "Type": "HTML_ENTITY_DECODE"}],
        )
        assert evaluate_statement(stmt, _req(uri_path="&lt;script&gt;"), _ctx()) is True

    def test_transformations_applied_in_priority_order_not_list_order(self):
        # Listed here in LIST order as LOWERCASE-then-URL_DECODE, but given
        # PRIORITY order URL_DECODE(0) then LOWERCASE(1). If list order
        # governed, "%41DMIN".lower() = "%41dmin" -> decode -> "Admin",
        # which does NOT contain "admin" (case-sensitive). Only the
        # correct priority order (decode "%41DMIN" -> "ADMIN", then
        # lowercase -> "admin") makes this match.
        stmt = _byte_match(
            {"UriPath": {}}, "admin", "CONTAINS",
            [{"Priority": 1, "Type": "LOWERCASE"}, {"Priority": 0, "Type": "URL_DECODE"}],
        )
        assert evaluate_statement(stmt, _req(uri_path="%41DMIN"), _ctx()) is True

    def test_unsupported_transformation_logs_and_leaves_value_unchanged(self, caplog):
        stmt = _byte_match(
            {"UriPath": {}}, "/x", "EXACTLY", [{"Priority": 0, "Type": "CSS_DECODE"}],
        )
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            assert evaluate_statement(stmt, _req(uri_path="/x"), _ctx()) is True
        assert any("CSS_DECODE" in m for m in caplog.messages)


class TestSizeConstraintStatement:
    def _stmt(self, field, op, size):
        return {
            "SizeConstraintStatement": {
                "FieldToMatch": field, "ComparisonOperator": op, "Size": size,
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }

    def test_gt(self):
        stmt = self._stmt({"UriPath": {}}, "GT", 10)
        assert evaluate_statement(stmt, _req(uri_path="/a-very-long-path"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/x"), _ctx()) is False

    def test_eq(self):
        stmt = self._stmt({"UriPath": {}}, "EQ", 2)
        assert evaluate_statement(stmt, _req(uri_path="/x"), _ctx()) is True

    def test_le_and_ge(self):
        assert evaluate_statement(self._stmt({"UriPath": {}}, "LE", 2), _req(uri_path="/x"), _ctx()) is True
        assert evaluate_statement(self._stmt({"UriPath": {}}, "GE", 2), _req(uri_path="/x"), _ctx()) is True

    def test_ne_and_lt(self):
        assert evaluate_statement(self._stmt({"UriPath": {}}, "NE", 99), _req(uri_path="/x"), _ctx()) is True
        assert evaluate_statement(self._stmt({"UriPath": {}}, "LT", 99), _req(uri_path="/x"), _ctx()) is True


class TestIPSetReferenceStatement:
    def test_matches_cidr(self):
        stmt = {"IPSetReferenceStatement": {"ARN": "arn:ipset:1"}}
        ctx = _ctx(ip_sets={"arn:ipset:1": ["198.51.100.0/24"]})
        assert evaluate_statement(stmt, _req(source_ip="198.51.100.42"), ctx) is True
        assert evaluate_statement(stmt, _req(source_ip="203.0.113.1"), ctx) is False

    def test_exact_ip(self):
        stmt = {"IPSetReferenceStatement": {"ARN": "arn:ipset:1"}}
        ctx = _ctx(ip_sets={"arn:ipset:1": ["192.0.2.55/32"]})
        assert evaluate_statement(stmt, _req(source_ip="192.0.2.55"), ctx) is True
        assert evaluate_statement(stmt, _req(source_ip="192.0.2.56"), ctx) is False


class TestRegexPatternSetReferenceStatement:
    def test_matches_pattern(self):
        stmt = {
            "RegexPatternSetReferenceStatement": {
                "ARN": "arn:regex:1", "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            }
        }
        ctx = _ctx(regex_sets={"arn:regex:1": [r"/\d{4}-\d{2}-\d{2}/secret"]})
        assert evaluate_statement(stmt, _req(uri_path="/2024-01-01/secret"), ctx) is True
        assert evaluate_statement(stmt, _req(uri_path="/not-a-date/secret"), ctx) is False

    def test_invalid_regex_is_skipped_not_fatal(self):
        stmt = {
            "RegexPatternSetReferenceStatement": {
                "ARN": "arn:regex:1", "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [],
            }
        }
        ctx = _ctx(regex_sets={"arn:regex:1": ["(unbalanced[", r"/ok/"]})
        assert evaluate_statement(stmt, _req(uri_path="/ok/"), ctx) is True


class TestCompoundStatements:
    def test_and_requires_all(self):
        stmt = {"AndStatement": {"Statements": [
            _byte_match({"UriPath": {}}, "/admin", "STARTS_WITH"),
            {"IPSetReferenceStatement": {"ARN": "arn:ipset:1"}},
        ]}}
        ctx = _ctx(ip_sets={"arn:ipset:1": ["198.51.100.0/24"]})
        assert evaluate_statement(stmt, _req(uri_path="/admin/x", source_ip="198.51.100.5"), ctx) is True
        assert evaluate_statement(stmt, _req(uri_path="/admin/x", source_ip="203.0.113.1"), ctx) is False
        assert evaluate_statement(stmt, _req(uri_path="/public", source_ip="198.51.100.5"), ctx) is False

    def test_or_requires_any(self):
        stmt = {"OrStatement": {"Statements": [
            _byte_match({"UriPath": {}}, "/admin", "STARTS_WITH"),
            _byte_match({"UriPath": {}}, "/secret", "STARTS_WITH"),
        ]}}
        assert evaluate_statement(stmt, _req(uri_path="/admin/x"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/secret/x"), _ctx()) is True
        assert evaluate_statement(stmt, _req(uri_path="/public"), _ctx()) is False

    def test_not_inverts(self):
        inner = {"IPSetReferenceStatement": {"ARN": "arn:ipset:1"}}
        stmt = {"NotStatement": {"Statement": inner}}
        ctx = _ctx(ip_sets={"arn:ipset:1": ["198.51.100.0/24"]})
        # NOT(in allow-list) -> block everyone NOT in the allow-list
        assert evaluate_statement(stmt, _req(source_ip="203.0.113.1"), ctx) is True
        assert evaluate_statement(stmt, _req(source_ip="198.51.100.5"), ctx) is False

    def test_nested_and_or_not(self):
        stmt = {"AndStatement": {"Statements": [
            {"NotStatement": {"Statement": {"IPSetReferenceStatement": {"ARN": "arn:ipset:1"}}}},
            {"OrStatement": {"Statements": [
                _byte_match({"UriPath": {}}, "/admin", "STARTS_WITH"),
                _byte_match({"UriPath": {}}, "/internal", "STARTS_WITH"),
            ]}},
        ]}}
        ctx = _ctx(ip_sets={"arn:ipset:1": ["198.51.100.0/24"]})
        # Not-allow-listed AND (admin or internal path) -> True
        assert evaluate_statement(stmt, _req(uri_path="/admin/x", source_ip="203.0.113.1"), ctx) is True
        # Allow-listed -> False regardless of path
        assert evaluate_statement(stmt, _req(uri_path="/admin/x", source_ip="198.51.100.5"), ctx) is False
        # Not allow-listed but public path -> False
        assert evaluate_statement(stmt, _req(uri_path="/public", source_ip="203.0.113.1"), ctx) is False


class TestUnsupportedStatementFallback:
    """The single most important correctness property: an unimplemented
    statement type must behave EXACTLY like a non-match, never a silent
    block and never a silent pass-as-if-evaluated."""

    def test_unsupported_statement_type_is_non_match_and_logs(self, caplog):
        stmt = {"GeoMatchStatement": {"CountryCodes": ["CN"]}}
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            assert evaluate_statement(stmt, _req(), _ctx()) is False
        assert any("GeoMatchStatement" in m for m in caplog.messages)

    def test_sqli_statement_unsupported(self, caplog):
        stmt = {"SqliMatchStatement": {"FieldToMatch": {"Body": {}}, "TextTransformations": []}}
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            assert evaluate_statement(stmt, _req(body=b"' OR 1=1"), _ctx()) is False
        assert any("SqliMatchStatement" in m for m in caplog.messages)

    def test_rate_based_statement_unsupported(self, caplog):
        stmt = {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP"}}
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            assert evaluate_statement(stmt, _req(), _ctx()) is False

    def test_rule_group_reference_unsupported(self, caplog):
        stmt = {"RuleGroupReferenceStatement": {"ARN": "arn:rulegroup:1"}}
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            assert evaluate_statement(stmt, _req(), _ctx()) is False

    def test_unsupported_inside_and_does_not_silently_grant_match(self):
        # And([unsupported, True]) must be False, not True - an
        # unsupported leaf must not be treated as "vacuously satisfied".
        stmt = {"AndStatement": {"Statements": [
            {"GeoMatchStatement": {}},
            _byte_match({"UriPath": {}}, "/x", "EXACTLY"),
        ]}}
        assert evaluate_statement(stmt, _req(uri_path="/x"), _ctx()) is False


class TestWebACLEvaluationControlFlow:
    """Priority ordering, Block/Allow-terminates, Count-continues,
    DefaultAction fallback."""

    def _acl(self, rules, default="ALLOW"):
        return {
            "Rules": rules,
            "DefaultAction": {"Block": {}} if default == "BLOCK" else {"Allow": {}},
        }

    def _rule(self, name, priority, statement, action):
        return {"Name": name, "Priority": priority, "Statement": statement, "Action": action}

    def test_block_terminates_immediately(self):
        acl = self._acl([
            self._rule("r1", 1, _byte_match({"UriPath": {}}, "/bad", "CONTAINS"), {"Block": {}}),
            self._rule("r2", 2, _byte_match({"UriPath": {}}, "/bad", "CONTAINS"), {"Count": {}}),
        ])
        result = evaluate_web_acl(acl, _req(uri_path="/bad"), **_no_resolvers())
        assert result.action == "BLOCK"
        assert result.matched_rule == "r1"
        assert result.counted_rules == []  # r2 never evaluated - r1 terminated first

    def test_allow_terminates_immediately(self):
        acl = self._acl([
            self._rule("r1", 1, _byte_match({"UriPath": {}}, "/", "EXACTLY"), {"Allow": {}}),
        ], default="BLOCK")
        result = evaluate_web_acl(acl, _req(uri_path="/"), **_no_resolvers())
        assert result.action == "ALLOW"
        assert result.matched_rule == "r1"

    def test_count_does_not_terminate_evaluation_continues(self):
        acl = self._acl([
            self._rule("counter", 1, _byte_match({"UriPath": {}}, "/", "STARTS_WITH"), {"Count": {}}),
            self._rule("blocker", 2, _byte_match({"UriPath": {}}, "/admin", "STARTS_WITH"), {"Block": {}}),
        ])
        result = evaluate_web_acl(acl, _req(uri_path="/admin/x"), **_no_resolvers())
        assert result.action == "BLOCK"
        assert result.matched_rule == "blocker"
        assert result.counted_rules == ["counter"]  # Count rule fired AND evaluation continued

    def test_multiple_count_rules_can_all_fire(self):
        acl = self._acl([
            self._rule("c1", 1, _byte_match({"UriPath": {}}, "/", "STARTS_WITH"), {"Count": {}}),
            self._rule("c2", 2, _byte_match({"UriPath": {}}, "/x", "STARTS_WITH"), {"Count": {}}),
        ])
        result = evaluate_web_acl(acl, _req(uri_path="/x"), **_no_resolvers())
        assert result.action == "ALLOW"  # nothing terminated -> DefaultAction
        assert result.matched_rule is None
        assert result.counted_rules == ["c1", "c2"]

    def test_priority_order_governs_evaluation_not_list_order(self):
        acl = self._acl([
            self._rule("second", 5, _byte_match({"UriPath": {}}, "/x", "EXACTLY"), {"Allow": {}}),
            self._rule("first", 1, _byte_match({"UriPath": {}}, "/x", "EXACTLY"), {"Block": {}}),
        ], default="ALLOW")
        result = evaluate_web_acl(acl, _req(uri_path="/x"), **_no_resolvers())
        assert result.matched_rule == "first"  # priority 1 evaluated before priority 5
        assert result.action == "BLOCK"

    def test_default_action_allow_when_nothing_matches(self):
        acl = self._acl([
            self._rule("r1", 1, _byte_match({"UriPath": {}}, "/nomatch", "EXACTLY"), {"Block": {}}),
        ], default="ALLOW")
        result = evaluate_web_acl(acl, _req(uri_path="/other"), **_no_resolvers())
        assert result.action == "ALLOW"
        assert result.matched_rule is None

    def test_default_action_block_when_nothing_matches(self):
        acl = self._acl([], default="BLOCK")
        result = evaluate_web_acl(acl, _req(uri_path="/anything"), **_no_resolvers())
        assert result.action == "BLOCK"
        assert result.matched_rule is None

    def test_unsupported_rule_action_is_non_terminating_and_logged(self, caplog):
        acl = self._acl([
            self._rule("captcha_rule", 1, _byte_match({"UriPath": {}}, "/x", "EXACTLY"), {"Captcha": {}}),
        ], default="ALLOW")
        with caplog.at_level(logging.WARNING, logger="localemu.services.wafv2.evaluator"):
            result = evaluate_web_acl(acl, _req(uri_path="/x"), **_no_resolvers())
        assert result.action == "ALLOW"  # fell through to DefaultAction, not blocked by Captcha
        assert any("Captcha" in m or "not enforceable" in m for m in caplog.messages)

    def test_no_rules_at_all_uses_default_action(self):
        acl = self._acl([], default="ALLOW")
        result = evaluate_web_acl(acl, _req(), **_no_resolvers())
        assert result.action == "ALLOW"
        assert isinstance(result, EvaluationResult)


def _ctx(ip_sets=None, regex_sets=None):
    from localemu.services.wafv2.evaluator import RuleContext

    ip_sets = ip_sets or {}
    regex_sets = regex_sets or {}
    return RuleContext(
        resolve_ip_set=lambda arn: ip_sets.get(arn, []),
        resolve_regex_pattern_set=lambda arn: regex_sets.get(arn, []),
    )
