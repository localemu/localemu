"""Unit tests for localemu.services.iam_enforcement.resource_matcher."""

import pytest

from localemu.services.iam_enforcement.resource_matcher import (
    arn_matches,
    matches_resource,
    _substitute_policy_variables,
)


class TestArnMatches:
    """Tests for arn_matches() wildcard and segment matching."""

    @pytest.mark.parametrize(
        "pattern, arn, expected",
        [
            # Star matches everything
            ("*", "arn:aws:s3:::bucket", True),
            ("*", "arn:aws:iam::123456789012:user/alice", True),
            # Exact match
            ("arn:aws:s3:::bucket", "arn:aws:s3:::bucket", True),
            ("arn:aws:s3:::bucket", "arn:aws:s3:::other", False),
            # Wildcard in resource segment
            ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key", True),
            ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c", True),
            ("arn:aws:s3:::bucket/*", "arn:aws:s3:::other/key", False),
            # Wildcard in service segment
            ("arn:aws:*:::bucket", "arn:aws:s3:::bucket", True),
            # Wildcard in region segment
            ("arn:aws:s3:*:123456789012:table/orders", "arn:aws:s3:us-east-1:123456789012:table/orders", True),
            ("arn:aws:s3:us-*:123456789012:table/orders", "arn:aws:s3:us-east-1:123456789012:table/orders", True),
            ("arn:aws:s3:eu-*:123456789012:table/orders", "arn:aws:s3:us-east-1:123456789012:table/orders", False),
            # Wildcard in account segment
            ("arn:aws:s3:us-east-1:*:table/orders", "arn:aws:s3:us-east-1:123456789012:table/orders", True),
            # Question mark wildcard (single char)
            ("arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-a", True),
            ("arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-ab", False),
            # Resource with colons (colons after index 5 rejoin)
            ("arn:aws:iam::123456789012:user/*", "arn:aws:iam::123456789012:user/alice", True),
            # Mismatch in prefix segments
            ("arn:aws:s3:::bucket", "arn:aws:dynamodb:::bucket", False),
        ],
        ids=[
            "star-matches-s3",
            "star-matches-iam",
            "exact-match",
            "exact-no-match",
            "wildcard-resource-match",
            "wildcard-resource-deep-path",
            "wildcard-resource-no-match",
            "wildcard-service-segment",
            "wildcard-region-star",
            "wildcard-region-prefix",
            "wildcard-region-no-match",
            "wildcard-account-segment",
            "question-mark-single-char",
            "question-mark-too-many-chars",
            "resource-with-path",
            "service-mismatch",
        ],
    )
    def test_arn_matches(self, pattern, arn, expected):
        result = arn_matches(pattern, arn)
        assert result is expected, (
            f"arn_matches({pattern!r}, {arn!r}) returned {result}, expected {expected}"
        )

    def test_malformed_arn_no_match(self):
        """A pattern that starts with arn: but has too few segments should not match."""
        assert arn_matches("arn:aws:s3", "arn:aws:s3:::bucket") is False

    def test_non_arn_wildcard_fallback(self):
        """When neither string is an ARN, fall back to simple wildcard match."""
        assert arn_matches("bucket-*", "bucket-test") is True
        assert arn_matches("bucket-*", "other-test") is False


class TestSubstitutePolicyVariables:
    """Tests for _substitute_policy_variables()."""

    def test_username_substitution(self):
        pattern = "arn:aws:s3:::bucket/${aws:username}/*"
        context = {"aws:username": "alice"}
        result = _substitute_policy_variables(pattern, context)
        assert result == "arn:aws:s3:::bucket/alice/*"

    def test_userid_substitution(self):
        pattern = "arn:aws:iam::123456789012:user/${aws:userid}"
        context = {"aws:userid": "AIDEXAMPLE"}
        result = _substitute_policy_variables(pattern, context)
        assert result == "arn:aws:iam::123456789012:user/AIDEXAMPLE"

    def test_multiple_variables(self):
        pattern = "arn:aws:s3:::${aws:PrincipalAccount}/${aws:username}/*"
        context = {"aws:PrincipalAccount": "123456789012", "aws:username": "bob"}
        result = _substitute_policy_variables(pattern, context)
        assert result == "arn:aws:s3:::123456789012/bob/*"

    def test_unknown_variable_replaced_with_empty(self):
        pattern = "arn:aws:s3:::bucket/${aws:nonexistent}/*"
        context = {"aws:username": "alice"}
        result = _substitute_policy_variables(pattern, context)
        assert result == "arn:aws:s3:::bucket//*"

    def test_no_context_returns_pattern_unchanged(self):
        pattern = "arn:aws:s3:::bucket/${aws:username}/*"
        assert _substitute_policy_variables(pattern, None) == pattern
        assert _substitute_policy_variables(pattern, {}) == pattern

    def test_no_variables_returns_pattern_unchanged(self):
        pattern = "arn:aws:s3:::bucket/key"
        context = {"aws:username": "alice"}
        assert _substitute_policy_variables(pattern, context) == pattern

    def test_case_insensitive_lookup(self):
        pattern = "arn:aws:s3:::bucket/${aws:Username}/*"
        context = {"aws:username": "alice"}
        result = _substitute_policy_variables(pattern, context)
        assert result == "arn:aws:s3:::bucket/alice/*"


class TestMatchesResource:
    """Tests for matches_resource() with Resource and NotResource."""

    def test_resource_match_single(self):
        stmt = {"Resource": "arn:aws:s3:::bucket/*"}
        assert matches_resource(stmt, "arn:aws:s3:::bucket/key") is True

    def test_resource_no_match(self):
        stmt = {"Resource": "arn:aws:s3:::bucket/*"}
        assert matches_resource(stmt, "arn:aws:s3:::other/key") is False

    def test_resource_match_list(self):
        stmt = {"Resource": ["arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*"]}
        assert matches_resource(stmt, "arn:aws:s3:::bucket-a/key") is True
        assert matches_resource(stmt, "arn:aws:s3:::bucket-b/key") is True
        assert matches_resource(stmt, "arn:aws:s3:::bucket-c/key") is False

    def test_resource_star(self):
        stmt = {"Resource": "*"}
        assert matches_resource(stmt, "arn:aws:s3:::anything") is True

    def test_neither_resource_nor_not_resource_is_malformed(self):
        """AWS rejects such statements at CreatePolicy time with
        MalformedPolicyDocument. The evaluator treats them as non-matching so
        a malformed Allow does not grant and a malformed Deny does not block.
        """
        stmt = {"Effect": "Allow", "Action": "s3:*"}
        assert matches_resource(stmt, "arn:aws:s3:::bucket/key") is False

    def test_both_resource_and_not_resource_is_malformed(self):
        stmt = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::pub/*",
            "NotResource": "arn:aws:s3:::pub/secret/*",
        }
        assert matches_resource(stmt, "arn:aws:s3:::pub/file") is False
        assert matches_resource(stmt, "arn:aws:s3:::pub/secret/x") is False

    def test_not_resource_excludes(self):
        stmt = {"NotResource": "arn:aws:s3:::secret-bucket/*"}
        assert matches_resource(stmt, "arn:aws:s3:::public-bucket/key") is True
        assert matches_resource(stmt, "arn:aws:s3:::secret-bucket/key") is False

    def test_not_resource_list(self):
        stmt = {"NotResource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]}
        assert matches_resource(stmt, "arn:aws:s3:::c/key") is True
        assert matches_resource(stmt, "arn:aws:s3:::a/key") is False
        assert matches_resource(stmt, "arn:aws:s3:::b/key") is False

    def test_resource_with_policy_variable(self):
        stmt = {"Resource": "arn:aws:s3:::bucket/${aws:username}/*"}
        context = {"aws:username": "alice"}
        assert matches_resource(stmt, "arn:aws:s3:::bucket/alice/doc.txt", context) is True
        assert matches_resource(stmt, "arn:aws:s3:::bucket/bob/doc.txt", context) is False
