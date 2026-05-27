"""Unit tests for localemu.services.iam_enforcement.action_matcher."""

import pytest

from localemu.services.iam_enforcement.action_matcher import matches_action


class TestExactActionMatch:
    """Tests for exact action matching."""

    def test_exact_match(self):
        stmt = {"Action": "s3:GetObject"}
        assert matches_action(stmt, "s3:GetObject") is True

    def test_exact_no_match(self):
        stmt = {"Action": "s3:GetObject"}
        assert matches_action(stmt, "s3:PutObject") is False

    def test_case_insensitive(self):
        stmt = {"Action": "s3:GetObject"}
        assert matches_action(stmt, "S3:getobject") is True
        assert matches_action(stmt, "s3:GETOBJECT") is True


class TestWildcardActionMatch:
    """Tests for wildcard patterns in Action lists."""

    @pytest.mark.parametrize(
        "pattern, action, expected",
        [
            ("s3:*", "s3:GetObject", True),
            ("s3:*", "s3:PutObject", True),
            ("s3:*", "dynamodb:GetItem", False),
            ("s3:Get*", "s3:GetObject", True),
            ("s3:Get*", "s3:GetBucketAcl", True),
            ("s3:Get*", "s3:PutObject", False),
            ("*", "s3:GetObject", True),
            ("*", "iam:CreateUser", True),
            ("s3:*Object", "s3:GetObject", True),
            ("s3:*Object", "s3:PutObject", True),
            ("s3:*Object", "s3:ListBuckets", False),
        ],
        ids=[
            "s3-star-get",
            "s3-star-put",
            "s3-star-other-service",
            "s3-get-star-getobject",
            "s3-get-star-getbucketacl",
            "s3-get-star-putobject",
            "global-star-s3",
            "global-star-iam",
            "suffix-wildcard-get",
            "suffix-wildcard-put",
            "suffix-wildcard-no-match",
        ],
    )
    def test_wildcard_patterns(self, pattern, action, expected):
        stmt = {"Action": pattern}
        result = matches_action(stmt, action)
        assert result is expected, (
            f"matches_action(Action={pattern!r}, {action!r}) returned {result}, expected {expected}"
        )


class TestActionList:
    """Tests for Action as a list of patterns."""

    def test_list_any_matches(self):
        stmt = {"Action": ["s3:GetObject", "s3:PutObject"]}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "s3:PutObject") is True

    def test_list_none_matches(self):
        stmt = {"Action": ["s3:GetObject", "s3:PutObject"]}
        assert matches_action(stmt, "s3:DeleteObject") is False

    def test_list_with_wildcards(self):
        stmt = {"Action": ["s3:Get*", "s3:List*"]}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "s3:ListBuckets") is True
        assert matches_action(stmt, "s3:PutObject") is False


class TestNotAction:
    """Tests for NotAction (inverse matching)."""

    def test_not_action_excludes(self):
        stmt = {"NotAction": "s3:DeleteObject"}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "s3:DeleteObject") is False

    def test_not_action_wildcard(self):
        stmt = {"NotAction": "s3:*"}
        assert matches_action(stmt, "dynamodb:GetItem") is True
        assert matches_action(stmt, "s3:GetObject") is False

    def test_not_action_list(self):
        stmt = {"NotAction": ["s3:Delete*", "s3:Put*"]}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "s3:DeleteObject") is False
        assert matches_action(stmt, "s3:PutObject") is False

    def test_not_action_case_insensitive(self):
        stmt = {"NotAction": "s3:DeleteObject"}
        assert matches_action(stmt, "S3:DELETEOBJECT") is False
        assert matches_action(stmt, "S3:GetObject") is True


class TestMalformedStatements:
    """AWS rejects these at CreatePolicy time — evaluator treats them as
    non-matching so malformed Allow doesn't grant and malformed Deny doesn't
    block."""

    def test_both_action_and_not_action_is_malformed(self):
        stmt = {"Action": "s3:GetObject", "NotAction": "s3:DeleteObject"}
        assert matches_action(stmt, "s3:GetObject") is False
        assert matches_action(stmt, "s3:DeleteObject") is False
        assert matches_action(stmt, "s3:PutObject") is False

    def test_neither_action_nor_not_action_is_malformed(self):
        stmt = {"Effect": "Allow", "Resource": "*"}
        assert matches_action(stmt, "s3:GetObject") is False


class TestEdgeCases:
    """Edge cases and special patterns."""

    def test_empty_action_list(self):
        """Empty Action list matches nothing."""
        stmt = {"Action": []}
        assert matches_action(stmt, "s3:GetObject") is False

    def test_question_mark_wildcard(self):
        """Question mark matches a single character."""
        stmt = {"Action": "s3:Get?bject"}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "s3:Getobject") is True

    def test_multiple_services_in_list(self):
        stmt = {"Action": ["s3:*", "dynamodb:*", "sqs:SendMessage"]}
        assert matches_action(stmt, "s3:GetObject") is True
        assert matches_action(stmt, "dynamodb:PutItem") is True
        assert matches_action(stmt, "sqs:SendMessage") is True
        assert matches_action(stmt, "sqs:ReceiveMessage") is False
