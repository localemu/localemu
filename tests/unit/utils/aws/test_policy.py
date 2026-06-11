"""Unit tests for ``localemu.utils.aws.policy`` helpers.

These pin the behaviour of :func:`iter_policy_statements` /
:func:`normalize_policy_statements` against every shape of input the
production code has historically had to deal with: single-dict
``Statement``, list-of-dicts ``Statement``, missing ``Statement``,
malformed types (str/int/list of non-dicts), and complete garbage at the
policy level.
"""
from __future__ import annotations

from localemu.utils.aws.policy import (
    iter_policy_statements,
    normalize_policy_statements,
)


# --- single-dict Statement form -------------------------------------------


def test_single_dict_statement_yields_one_dict():
    policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
    }
    statements = normalize_policy_statements(policy)
    assert len(statements) == 1
    assert statements[0]["Effect"] == "Allow"
    assert statements[0]["Action"] == "s3:*"


# --- list-of-dicts Statement form -----------------------------------------


def test_list_statement_yields_each_dict_in_order():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject"},
            {"Effect": "Deny", "Action": "s3:DeleteObject"},
        ],
    }
    statements = normalize_policy_statements(policy)
    assert len(statements) == 2
    assert statements[0]["Action"] == "s3:GetObject"
    assert statements[1]["Action"] == "s3:DeleteObject"


def test_empty_list_statement_yields_nothing():
    policy = {"Version": "2012-10-17", "Statement": []}
    assert normalize_policy_statements(policy) == []


# --- missing / malformed Statement ---------------------------------------


def test_missing_statement_yields_nothing():
    policy = {"Version": "2012-10-17"}
    assert normalize_policy_statements(policy) == []


def test_none_statement_yields_nothing():
    policy = {"Version": "2012-10-17", "Statement": None}
    assert normalize_policy_statements(policy) == []


def test_string_statement_yields_nothing():
    policy = {"Version": "2012-10-17", "Statement": "garbage"}
    assert normalize_policy_statements(policy) == []


def test_int_statement_yields_nothing():
    policy = {"Version": "2012-10-17", "Statement": 42}
    assert normalize_policy_statements(policy) == []


def test_list_with_non_dict_elements_skips_them():
    """Mixed list: keep the dicts, skip the rest, never crash."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject"},
            "this-is-not-a-dict",
            42,
            None,
            {"Effect": "Deny", "Action": "s3:DeleteObject"},
        ],
    }
    statements = normalize_policy_statements(policy)
    assert len(statements) == 2
    assert statements[0]["Action"] == "s3:GetObject"
    assert statements[1]["Action"] == "s3:DeleteObject"


# --- non-dict policy: no crash, no statements -----------------------------


def test_non_dict_policy_yields_nothing():
    for bad in ["not-a-policy", 42, None, ["list", "instead"]]:
        assert normalize_policy_statements(bad) == [], (
            f"non-dict policy ({type(bad).__name__}) should yield no statements"
        )


# --- iterator vs list interface -------------------------------------------


def test_iter_policy_statements_is_a_generator():
    """``iter_policy_statements`` must be lazy, not materialised."""
    import types

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*"},
        ],
    }
    it = iter_policy_statements(policy)
    assert isinstance(it, types.GeneratorType)
    assert next(it)["Effect"] == "Allow"


def test_normalize_returns_list_for_indexable_callers():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "a"},
            {"Effect": "Deny", "Action": "b"},
        ],
    }
    statements = normalize_policy_statements(policy)
    # callers that index, slice, or call len() must work
    assert statements[1]["Action"] == "b"
    assert len(statements) == 2
    assert statements[:1] == [{"Effect": "Allow", "Action": "a"}]
