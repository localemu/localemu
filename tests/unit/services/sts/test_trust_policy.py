"""Unit tests for ``_evaluate_trust_policy`` Statement-shape handling.

AWS IAM policy grammar lets ``Statement`` be either a single statement object
OR a list of statement objects. Both forms are equivalent on real AWS. An
earlier ``_evaluate_trust_policy`` only handled the list form: on the
single-dict form, ``for statement in trust_doc["Statement"]`` iterated over
the dict's *keys* (``"Effect"``, ``"Principal"`` ...) and the immediate
``statement.get("Effect", "")`` raised ``AttributeError: 'str' object has no
attribute 'get'`` for every ``AssumeRole`` call against such a role. The
regression cascaded across the scenario suite because most fixtures create
their Lambda execution role with the single-dict form.

These tests pin:
  * single-dict Statement -> evaluated like a one-element list
  * list Statement -> evaluated as before (regression)
  * malformed Statement (string / int) -> deny, no crash
  * non-dict element inside list Statement -> deny, no crash
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from localemu.services.sts.provider import _evaluate_trust_policy


def _role_with_trust_doc(trust_doc: dict | str) -> SimpleNamespace:
    """Build a minimal role-like object exposing assume_role_policy_document."""
    if isinstance(trust_doc, dict):
        trust_doc = json.dumps(trust_doc)
    return SimpleNamespace(
        name="test-role",
        assume_role_policy_document=trust_doc,
    )


# --- single-dict Statement (the bug) --------------------------------------


def test_single_dict_statement_allows_matching_principal():
    """``Statement`` as a single dict must be evaluated, not iterated as keys."""
    trust = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "sts:AssumeRole",
        },
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is True


def test_single_dict_statement_denies_non_matching_principal():
    """Single-dict form must still deny when the principal does not match."""
    trust = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
            "Action": "sts:AssumeRole",
        },
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/bob",
        caller_account_id="000000000000",
    ) is False


# --- list Statement (the previously-working path, regression pin) ---------


def test_list_statement_allows_matching_principal():
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is True


def test_list_statement_with_multiple_entries():
    """Multiple statements: any matching Allow grants access."""
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:user/alice"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:user/bob"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/bob",
        caller_account_id="000000000000",
    ) is True


# --- malformed Statement: deny, never crash ------------------------------


def test_string_statement_denies_no_crash():
    """``Statement`` of the wrong type (string) must deny instead of crashing."""
    trust = {
        "Version": "2012-10-17",
        "Statement": "not-a-valid-statement",
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False


def test_int_statement_denies_no_crash():
    trust = {
        "Version": "2012-10-17",
        "Statement": 42,
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False


def test_non_dict_item_in_list_statement_denies_no_crash():
    """A list ``Statement`` whose elements are not dicts must deny safely."""
    trust = {
        "Version": "2012-10-17",
        "Statement": ["not-a-statement-dict"],
    }
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False


def test_missing_statement_denies():
    trust = {"Version": "2012-10-17"}
    role = _role_with_trust_doc(trust)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False


def test_empty_assume_role_policy_document_denies():
    role = SimpleNamespace(name="test-role", assume_role_policy_document=None)

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False


def test_invalid_json_trust_doc_denies():
    role = SimpleNamespace(name="test-role", assume_role_policy_document="not json {")

    assert _evaluate_trust_policy(
        role,
        caller_arn="arn:aws:iam::000000000000:user/alice",
        caller_account_id="000000000000",
    ) is False
