"""Regression tests for the helper that rejects FilterExpression references
to primary-key attributes — matching real-AWS DynamoDB behaviour.

Before the fix, LocalEmu forwarded the request anyway and happily returned
rows, which silently masked a class of bug in user code that only surfaced
on real AWS.
"""

from __future__ import annotations

import pytest

from localemu.services.dynamodb.provider import (
    ValidationException,
    _referenced_attributes,
    _validate_filter_expression_not_using_keys,
)


class TestReferencedAttributes:
    def test_literal_names(self):
        assert _referenced_attributes("status = :s", None) == {"status"}

    def test_placeholder_resolves_through_expr_attr_names(self):
        got = _referenced_attributes(
            "#n = :v", {"#n": "run_id"},
        )
        assert got == {"run_id"}

    def test_multiple_refs_and_reserved_words(self):
        got = _referenced_attributes(
            "attribute_exists(foo) AND bar = :b OR begins_with(baz, :p)", None,
        )
        assert got == {"foo", "bar", "baz"}

    def test_unresolved_placeholder_falls_back_to_token(self):
        # If the user forgets to declare #n, we leave the token as-is (not
        # our job to fail — the DDB engine will complain).
        assert _referenced_attributes("#n = :v", None) == {"#n"}

    def test_empty_expression_returns_empty_set(self):
        assert _referenced_attributes("", None) == set()
        assert _referenced_attributes(None, None) == set()


class TestValidateFilterExpression:
    def test_rejects_hash_key(self):
        with pytest.raises(ValidationException) as ei:
            _validate_filter_expression_not_using_keys(
                "secret_name = :n", None, {"secret_name", "run_id"},
            )
        assert "Primary key attribute: secret_name" in str(ei.value)

    def test_rejects_sort_key(self):
        with pytest.raises(ValidationException) as ei:
            _validate_filter_expression_not_using_keys(
                "run_id = :r", None, {"secret_name", "run_id"},
            )
        assert "Primary key attribute: run_id" in str(ei.value)

    def test_rejects_key_accessed_via_placeholder(self):
        with pytest.raises(ValidationException):
            _validate_filter_expression_not_using_keys(
                "#k = :v", {"#k": "run_id"}, {"secret_name", "run_id"},
            )

    def test_allows_non_key_attribute(self):
        # Should not raise.
        _validate_filter_expression_not_using_keys(
            "status = :s", None, {"secret_name", "run_id"},
        )

    def test_no_op_when_no_filter_expression(self):
        _validate_filter_expression_not_using_keys(None, None, {"secret_name"})
        _validate_filter_expression_not_using_keys("", None, {"secret_name"})

    def test_no_op_when_table_has_no_keys(self):
        # e.g. SchemaExtractor couldn't resolve the schema — don't block.
        _validate_filter_expression_not_using_keys(
            "run_id = :r", None, set(),
        )

    def test_reserved_words_are_not_attribute_refs(self):
        # "AND", "BETWEEN", "size" etc. must not be treated as attribute names
        # even if the key schema happens to use those names.
        _validate_filter_expression_not_using_keys(
            "status = :a AND size(blob) > :s", None, {"pk", "sk"},
        )

    def test_rejects_first_key_reference_when_multiple_keys_present(self):
        with pytest.raises(ValidationException) as ei:
            _validate_filter_expression_not_using_keys(
                "status = :s AND run_id = :r", None, {"secret_name", "run_id"},
            )
        # Error mentions the rejected key, exact wording matches AWS.
        msg = str(ei.value)
        assert "Filter Expression can only contain non-primary key attributes" in msg
        assert "run_id" in msg
