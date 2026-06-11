"""Unit tests for the central account registry.

The registry is the canonical list of accounts known to a LocalEmu
instance, queryable via ``GET /_localemu/api/accounts`` and updated by
the auth chain on every inbound request.
"""

from __future__ import annotations

import pytest

from localemu.accounts.registry import (
    AccountRecord,
    AccountRegistry,
    accounts_stores,
    get_registry,
)
from localemu.constants import DEFAULT_AWS_ACCOUNT_ID


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Reset the shared registry between tests so order doesn't matter."""
    accounts_stores.reset()
    yield
    accounts_stores.reset()


# --------------------------------------------------------------------------
# AccountRecord shape
# --------------------------------------------------------------------------


class TestAccountRecord:
    def test_to_dict_uses_organizations_aws_field_names(self):
        rec = AccountRecord(
            Id="111122223333",
            Arn="arn:aws:organizations::111122223333:account/111122223333",
            Email="x@example.test", Name="x",
        )
        d = rec.to_dict()
        # The shape MUST match the AWS Organizations.Account members so the
        # admin endpoint and the Organizations service can share consumers.
        assert set(d) == {"Id", "Arn", "Email", "Name", "Status",
                          "JoinedMethod", "JoinedTimestamp"}
        assert d["Id"] == "111122223333"
        assert d["Status"] == "ACTIVE"          # default
        assert d["JoinedMethod"] == "CREATED"   # default


# --------------------------------------------------------------------------
# Insert / list / get / delete
# --------------------------------------------------------------------------


class TestEnsure:
    def test_ensure_inserts_a_new_account(self):
        r = get_registry()
        record = r.ensure("111122223333")
        assert record.Id == "111122223333"
        assert record.JoinedMethod == "IMPLICIT"  # default for auto-population
        assert "111122223333" in r

    def test_ensure_is_idempotent(self):
        r = get_registry()
        first = r.ensure("111122223333")
        second = r.ensure("111122223333")
        # Same record returned both times (not a new one).
        assert first is second
        assert len(r.list()) == 1

    def test_ensure_with_org_id_sets_org_scoped_arn(self):
        r = get_registry()
        record = r.ensure("111122223333", org_id="o-abc123")
        assert record.Arn == \
            "arn:aws:organizations::111122223333:account/o-abc123/111122223333"

    def test_ensure_without_org_id_sets_org_less_arn(self):
        r = get_registry()
        record = r.ensure("111122223333")
        assert record.Arn == \
            "arn:aws:organizations::111122223333:account/111122223333"

    @pytest.mark.parametrize("bad", [
        "not-12-digits", "12345", "1234567890123",  # too short / too long
        "abc123def456",                              # contains letters
        "111-122-2233",                              # has separators
        "",
    ])
    def test_ensure_rejects_non_12_digit_input(self, bad):
        with pytest.raises(ValueError):
            get_registry().ensure(bad)


class TestCreate:
    def test_create_adds_a_new_account_with_explicit_joined_method(self):
        r = get_registry()
        record = r.create("111122223333", name="prod", email="p@x.test")
        assert record.JoinedMethod == "CREATED"
        assert record.Name == "prod"
        assert record.Email == "p@x.test"

    def test_create_rejects_duplicates(self):
        r = get_registry()
        r.create("111122223333")
        with pytest.raises(ValueError):
            r.create("111122223333")

    def test_create_rejects_invalid_account_id(self):
        with pytest.raises(ValueError):
            get_registry().create("not-numeric")


class TestListAndGet:
    def test_list_empty_initially(self):
        assert get_registry().list() == []

    def test_list_returns_every_inserted_record(self):
        r = get_registry()
        r.ensure("111122223333")
        r.ensure("222233334444")
        r.ensure("333344445555")
        ids = sorted(rec.Id for rec in r.list())
        assert ids == ["111122223333", "222233334444", "333344445555"]

    def test_get_returns_the_record(self):
        r = get_registry()
        r.ensure("111122223333", name="acme")
        record = r.get("111122223333")
        assert record is not None
        assert record.Name == "acme"

    def test_get_returns_none_for_unknown(self):
        assert get_registry().get("999988887777") is None

    def test_contains_matches_get(self):
        r = get_registry()
        r.ensure("111122223333")
        assert "111122223333" in r
        assert "999988887777" not in r


class TestSuspendAndDelete:
    def test_suspend_flips_status(self):
        r = get_registry()
        r.ensure("111122223333")
        suspended = r.suspend("111122223333")
        assert suspended is not None
        assert suspended.Status == "SUSPENDED"
        # Re-read confirms the change is persistent.
        assert r.get("111122223333").Status == "SUSPENDED"

    def test_suspend_unknown_account_returns_none(self):
        assert get_registry().suspend("999988887777") is None

    def test_delete_removes_record(self):
        r = get_registry()
        r.ensure("111122223333")
        assert r.delete("111122223333") is True
        assert r.get("111122223333") is None

    def test_delete_unknown_returns_false(self):
        assert get_registry().delete("999988887777") is False


class TestUpdateArn:
    def test_update_arn_to_org_scoped_form(self):
        r = get_registry()
        r.ensure("111122223333")
        r.update_arn("111122223333", "o-newer")
        record = r.get("111122223333")
        assert record.Arn == \
            "arn:aws:organizations::111122223333:account/o-newer/111122223333"

    def test_update_arn_unknown_is_silent(self):
        # No-op (caller shouldn't need to check existence first).
        get_registry().update_arn("999988887777", "o-x")


# --------------------------------------------------------------------------
# Singleton accessor
# --------------------------------------------------------------------------


class TestSingleton:
    def test_get_registry_returns_same_instance(self):
        a = get_registry()
        b = get_registry()
        assert a is b

    def test_default_account_id_constant_format(self):
        # Smoke: the default the auth chain falls back to is a valid
        # 12-digit ID the registry would accept.
        get_registry().ensure(DEFAULT_AWS_ACCOUNT_ID)
        assert DEFAULT_AWS_ACCOUNT_ID in get_registry()
