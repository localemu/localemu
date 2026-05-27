"""Unit tests for _resolve_kms_key_id — alias / ARN / bare id handling.

Moto's ``key_to_aliases`` storage orientation has flipped between versions;
the resolver must handle both shapes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from localemu.services.iam_enforcement.enforcer import _resolve_kms_key_id


KEY_UUID = "c0b1bb4a-1234-4567-89ab-cdef01234567"
ALIAS = "alias/my-app-key"


def _backend(key_to_aliases):
    return SimpleNamespace(key_to_aliases=key_to_aliases)


class TestAliasToKeyId:
    """Either dict orientation is supported."""

    def test_alias_keyed_storage(self):
        """moto layout {alias: {key_id}}."""
        backend = _backend({ALIAS: {KEY_UUID}})
        assert _resolve_kms_key_id(backend, ALIAS) == KEY_UUID

    def test_key_id_keyed_storage(self):
        """Alternate moto layout {key_id: {alias, ...}}."""
        backend = _backend({KEY_UUID: {ALIAS}})
        assert _resolve_kms_key_id(backend, ALIAS) == KEY_UUID

    def test_alias_arn_form(self):
        backend = _backend({ALIAS: {KEY_UUID}})
        arn = f"arn:aws:kms:us-east-1:000000000000:{ALIAS}"
        assert _resolve_kms_key_id(backend, arn) == KEY_UUID

    def test_unknown_alias_returns_none(self):
        backend = _backend({"alias/other-key": {KEY_UUID}})
        assert _resolve_kms_key_id(backend, ALIAS) is None


class TestKeyIdForms:
    def test_bare_uuid(self):
        backend = _backend({})
        assert _resolve_kms_key_id(backend, KEY_UUID) == KEY_UUID

    def test_key_arn_form(self):
        backend = _backend({})
        arn = f"arn:aws:kms:us-east-1:000000000000:key/{KEY_UUID}"
        assert _resolve_kms_key_id(backend, arn) == KEY_UUID

    def test_key_slash_form_without_arn_prefix(self):
        backend = _backend({})
        assert _resolve_kms_key_id(backend, f"key/{KEY_UUID}") == KEY_UUID


class TestEdgeCases:
    def test_empty_arn_returns_none(self):
        assert _resolve_kms_key_id(_backend({}), "") is None

    def test_missing_alias_map_attribute(self):
        """Backend without key_to_aliases attr — must not crash."""
        backend = SimpleNamespace()  # no attributes
        assert _resolve_kms_key_id(backend, ALIAS) is None
