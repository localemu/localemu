"""Unit tests for localemu.services.iam_enforcement.condition_evaluator."""

import pytest

from localemu.services.iam_enforcement.condition_evaluator import matches_conditions


def _stmt(condition: dict) -> dict:
    """Helper: wrap a Condition block in a minimal statement dict."""
    return {"Condition": condition}


class TestStringOperators:
    """Tests for StringEquals, StringNotEquals, StringLike, etc."""

    def test_string_equals_match(self):
        stmt = _stmt({"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "us-east-1"}) is True

    def test_string_equals_no_match(self):
        stmt = _stmt({"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "eu-west-1"}) is False

    def test_string_not_equals(self):
        stmt = _stmt({"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "eu-west-1"}) is True
        assert matches_conditions(stmt, {"aws:RequestedRegion": "us-east-1"}) is False

    def test_string_equals_ignore_case(self):
        stmt = _stmt({"StringEqualsIgnoreCase": {"s3:prefix": "Logs/"}})
        assert matches_conditions(stmt, {"s3:prefix": "logs/"}) is True
        assert matches_conditions(stmt, {"s3:prefix": "LOGS/"}) is True

    @pytest.mark.parametrize(
        "pattern, value, expected",
        [
            ("*.txt", "readme.txt", True),
            ("*.txt", "readme.md", False),
            ("project-*", "project-alpha", True),
            ("project-*", "other-alpha", False),
            ("*", "anything", True),
        ],
        ids=["suffix-match", "suffix-no-match", "prefix-match", "prefix-no-match", "star-all"],
    )
    def test_string_like(self, pattern, value, expected):
        stmt = _stmt({"StringLike": {"s3:prefix": pattern}})
        assert matches_conditions(stmt, {"s3:prefix": value}) is expected

    def test_string_not_like(self):
        stmt = _stmt({"StringNotLike": {"s3:prefix": "secret-*"}})
        assert matches_conditions(stmt, {"s3:prefix": "public-file"}) is True
        assert matches_conditions(stmt, {"s3:prefix": "secret-data"}) is False


class TestNumericOperators:
    """Tests for NumericEquals, NumericLessThan, etc."""

    def test_numeric_equals(self):
        stmt = _stmt({"NumericEquals": {"s3:max-keys": "10"}})
        assert matches_conditions(stmt, {"s3:max-keys": "10"}) is True
        assert matches_conditions(stmt, {"s3:max-keys": "5"}) is False

    def test_numeric_less_than(self):
        stmt = _stmt({"NumericLessThan": {"s3:max-keys": "100"}})
        assert matches_conditions(stmt, {"s3:max-keys": "50"}) is True
        assert matches_conditions(stmt, {"s3:max-keys": "100"}) is False
        assert matches_conditions(stmt, {"s3:max-keys": "150"}) is False

    def test_numeric_greater_than(self):
        stmt = _stmt({"NumericGreaterThan": {"s3:max-keys": "0"}})
        assert matches_conditions(stmt, {"s3:max-keys": "1"}) is True
        assert matches_conditions(stmt, {"s3:max-keys": "0"}) is False

    def test_numeric_less_than_equals(self):
        stmt = _stmt({"NumericLessThanEquals": {"s3:max-keys": "100"}})
        assert matches_conditions(stmt, {"s3:max-keys": "100"}) is True
        assert matches_conditions(stmt, {"s3:max-keys": "101"}) is False


class TestIpAddressOperators:
    """Tests for IpAddress and NotIpAddress with CIDR ranges."""

    def test_ip_in_cidr(self):
        stmt = _stmt({"IpAddress": {"aws:SourceIp": "192.168.1.0/24"}})
        assert matches_conditions(stmt, {"aws:SourceIp": "192.168.1.100"}) is True
        assert matches_conditions(stmt, {"aws:SourceIp": "10.0.0.1"}) is False

    def test_not_ip_address(self):
        stmt = _stmt({"NotIpAddress": {"aws:SourceIp": "192.168.1.0/24"}})
        assert matches_conditions(stmt, {"aws:SourceIp": "10.0.0.1"}) is True
        assert matches_conditions(stmt, {"aws:SourceIp": "192.168.1.50"}) is False

    def test_ip_exact_host(self):
        stmt = _stmt({"IpAddress": {"aws:SourceIp": "10.0.0.1/32"}})
        assert matches_conditions(stmt, {"aws:SourceIp": "10.0.0.1"}) is True
        assert matches_conditions(stmt, {"aws:SourceIp": "10.0.0.2"}) is False

    def test_ip_broad_range(self):
        stmt = _stmt({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})
        assert matches_conditions(stmt, {"aws:SourceIp": "192.168.1.1"}) is True
        assert matches_conditions(stmt, {"aws:SourceIp": "8.8.8.8"}) is True


class TestBoolOperator:
    """Tests for Bool condition operator."""

    def test_bool_true(self):
        stmt = _stmt({"Bool": {"aws:SecureTransport": "true"}})
        assert matches_conditions(stmt, {"aws:SecureTransport": "true"}) is True
        assert matches_conditions(stmt, {"aws:SecureTransport": "True"}) is True
        assert matches_conditions(stmt, {"aws:SecureTransport": "false"}) is False

    def test_bool_false(self):
        stmt = _stmt({"Bool": {"aws:SecureTransport": "false"}})
        assert matches_conditions(stmt, {"aws:SecureTransport": "false"}) is True
        assert matches_conditions(stmt, {"aws:SecureTransport": "true"}) is False


class TestNullOperator:
    """Tests for Null condition operator."""

    def test_null_true_key_absent(self):
        """Null: true matches when the key is not present."""
        stmt = _stmt({"Null": {"aws:TokenIssueTime": "true"}})
        assert matches_conditions(stmt, {}) is True

    def test_null_true_key_present(self):
        """Null: true does NOT match when the key is present."""
        stmt = _stmt({"Null": {"aws:TokenIssueTime": "true"}})
        assert matches_conditions(stmt, {"aws:TokenIssueTime": "2024-01-01"}) is False

    def test_null_false_key_present(self):
        """Null: false matches when the key IS present."""
        stmt = _stmt({"Null": {"aws:TokenIssueTime": "false"}})
        assert matches_conditions(stmt, {"aws:TokenIssueTime": "2024-01-01"}) is True

    def test_null_false_key_absent(self):
        """Null: false does NOT match when the key is absent."""
        stmt = _stmt({"Null": {"aws:TokenIssueTime": "false"}})
        assert matches_conditions(stmt, {}) is False


class TestIfExistsVariant:
    """Tests for IfExists suffix on operators."""

    def test_if_exists_key_present_matches(self):
        stmt = _stmt({"StringEqualsIfExists": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "us-east-1"}) is True

    def test_if_exists_key_present_no_match(self):
        stmt = _stmt({"StringEqualsIfExists": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "eu-west-1"}) is False

    def test_if_exists_key_absent_passes(self):
        """When the key is absent, IfExists skips the condition (passes)."""
        stmt = _stmt({"StringEqualsIfExists": {"aws:RequestedRegion": "us-east-1"}})
        assert matches_conditions(stmt, {}) is True

    def test_numeric_if_exists_absent(self):
        stmt = _stmt({"NumericLessThanIfExists": {"s3:max-keys": "100"}})
        assert matches_conditions(stmt, {}) is True


class TestSetOperators:
    """Tests for ForAllValues and ForAnyValue set operators."""

    def test_for_all_values_all_match(self):
        stmt = _stmt({"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}})
        ctx = {"aws:TagKeys": ["env", "team"]}
        assert matches_conditions(stmt, ctx) is True

    def test_for_all_values_subset_match(self):
        stmt = _stmt({"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team", "project"]}})
        ctx = {"aws:TagKeys": ["env", "team"]}
        assert matches_conditions(stmt, ctx) is True

    def test_for_all_values_extra_value_fails(self):
        """Context has a value not in the allowed set."""
        stmt = _stmt({"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}})
        ctx = {"aws:TagKeys": ["env", "team", "secret"]}
        assert matches_conditions(stmt, ctx) is False

    def test_for_any_value_one_matches(self):
        stmt = _stmt({"ForAnyValue:StringEquals": {"aws:TagKeys": ["env", "team"]}})
        ctx = {"aws:TagKeys": ["env", "other"]}
        assert matches_conditions(stmt, ctx) is True

    def test_for_any_value_none_match(self):
        stmt = _stmt({"ForAnyValue:StringEquals": {"aws:TagKeys": ["env", "team"]}})
        ctx = {"aws:TagKeys": ["alpha", "beta"]}
        assert matches_conditions(stmt, ctx) is False

    def test_for_all_values_empty_context_treated_as_absent(self):
        """Empty list in context is treated as absent key."""
        stmt = _stmt({"ForAllValues:StringEquals": {"aws:TagKeys": ["env"]}})
        ctx = {"aws:TagKeys": []}
        assert matches_conditions(stmt, ctx) is False

    def test_for_any_value_single_context_value(self):
        """Single (non-list) context value is wrapped in a list."""
        stmt = _stmt({"ForAnyValue:StringEquals": {"aws:TagKeys": ["env", "team"]}})
        ctx = {"aws:TagKeys": "env"}
        assert matches_conditions(stmt, ctx) is True


class TestPolicyVariableSubstitutionInConditions:
    """Tests that policy variables in condition values are substituted."""

    def test_variable_in_condition_value(self):
        stmt = _stmt({"StringEquals": {"s3:prefix": "${aws:username}/"}})
        ctx = {"s3:prefix": "alice/", "aws:username": "alice"}
        assert matches_conditions(stmt, ctx) is True

    def test_variable_in_condition_value_no_match(self):
        stmt = _stmt({"StringEquals": {"s3:prefix": "${aws:username}/"}})
        ctx = {"s3:prefix": "bob/", "aws:username": "alice"}
        assert matches_conditions(stmt, ctx) is False


class TestNoConditionBlock:
    """Statements without a Condition block always pass."""

    def test_no_condition(self):
        assert matches_conditions({"Effect": "Allow"}, {"any": "context"}) is True

    def test_empty_condition(self):
        assert matches_conditions({"Condition": {}}, {"any": "context"}) is True


class TestMultipleConditionsAndLogic:
    """Multiple operators in a Condition block must ALL match (AND logic)."""

    def test_all_conditions_must_match(self):
        stmt = _stmt({
            "StringEquals": {"aws:RequestedRegion": "us-east-1"},
            "Bool": {"aws:SecureTransport": "true"},
        })
        ctx = {"aws:RequestedRegion": "us-east-1", "aws:SecureTransport": "true"}
        assert matches_conditions(stmt, ctx) is True

    def test_one_fails_whole_fails(self):
        stmt = _stmt({
            "StringEquals": {"aws:RequestedRegion": "us-east-1"},
            "Bool": {"aws:SecureTransport": "true"},
        })
        ctx = {"aws:RequestedRegion": "us-east-1", "aws:SecureTransport": "false"}
        assert matches_conditions(stmt, ctx) is False


class TestOrLogicWithinKey:
    """Multiple values for a single condition key use OR logic."""

    def test_multiple_values_or(self):
        stmt = _stmt({"StringEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}})
        assert matches_conditions(stmt, {"aws:RequestedRegion": "us-east-1"}) is True
        assert matches_conditions(stmt, {"aws:RequestedRegion": "us-west-2"}) is True
        assert matches_conditions(stmt, {"aws:RequestedRegion": "eu-west-1"}) is False
