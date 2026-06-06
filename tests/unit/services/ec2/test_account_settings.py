"""Unit tests for the EC2 account-level settings (Snapshot Block Public Access
and Serial Console Access), plus the Snapshot-BPA enforcement on
``ModifySnapshotAttribute``.

The store lives in ``localemu.services.ec2.account_settings`` and is wired into
the provider's six new handlers + the ``ModifySnapshotAttribute`` override.
"""

from __future__ import annotations

from unittest import mock

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.ec2 import provider as ec2_provider_module
from localemu.services.ec2.account_settings import (
    Ec2AccountSettingsStore,
    ec2_account_settings_stores,
)


ACCT = "000000000000"
REGION = "us-east-1"


def _store():
    """Reset the per-account-region store and return a fresh handle."""
    bundle = ec2_account_settings_stores
    if ACCT in bundle:
        bundle[ACCT].pop(REGION, None)
    return bundle[ACCT][REGION]


def _ctx(account=ACCT, region=REGION):
    ctx = mock.MagicMock()
    ctx.account_id = account
    ctx.region = region
    return ctx


def _provider():
    return ec2_provider_module.Ec2Provider()


# ---------- store-level invariants ----------


def test_store_defaults_match_aws_brand_new_account():
    s = _store()
    assert s.snapshot_bpa_state == "unblocked"
    assert s.snapshot_bpa_managed_by == "account"
    assert s.serial_console_enabled is False
    assert s.serial_console_managed_by == "account"


def test_store_is_per_account_per_region():
    """Setting a value in one account-region must not leak into another."""
    s1 = ec2_account_settings_stores["111111111111"]["us-east-1"]
    s2 = ec2_account_settings_stores["222222222222"]["us-east-1"]
    s3 = ec2_account_settings_stores["111111111111"]["eu-west-1"]
    s1.snapshot_bpa_state = "block-all-sharing"
    s1.serial_console_enabled = True
    assert s2.snapshot_bpa_state == "unblocked"
    assert s2.serial_console_enabled is False
    assert s3.snapshot_bpa_state == "unblocked"
    assert s3.serial_console_enabled is False


def test_store_class_is_a_BaseStore():
    """Sanity: the store class wires into the LocalAttribute descriptor
    so dill-based persistence can round-trip it like every other native store."""
    s = Ec2AccountSettingsStore()
    # Reading an attribute the first time materializes the default.
    assert s.snapshot_bpa_state == "unblocked"
    s.snapshot_bpa_state = "block-new-sharing"
    assert s.snapshot_bpa_state == "block-new-sharing"


# ---------- Snapshot Block Public Access handlers ----------


def test_get_snapshot_bpa_returns_unblocked_for_new_account():
    _store()  # reset
    p = _provider()
    r = p.get_snapshot_block_public_access_state(_ctx(), {})
    assert r == {"State": "unblocked", "ManagedBy": "account"}


def test_enable_snapshot_bpa_block_all_sharing():
    _store()
    p = _provider()
    r = p.enable_snapshot_block_public_access(_ctx(), {"State": "block-all-sharing"})
    assert r == {"State": "block-all-sharing"}
    assert (
        p.get_snapshot_block_public_access_state(_ctx(), {})["State"]
        == "block-all-sharing"
    )


def test_enable_snapshot_bpa_block_new_sharing():
    _store()
    p = _provider()
    r = p.enable_snapshot_block_public_access(_ctx(), {"State": "block-new-sharing"})
    assert r == {"State": "block-new-sharing"}


def test_enable_snapshot_bpa_rejects_unblocked():
    """AWS docs: ``unblocked`` is NOT an accepted value for the Enable call,
    even though it appears in the enum. The user must call DisableSnapshotBlockPublicAccess."""
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.enable_snapshot_block_public_access(_ctx(), {"State": "unblocked"})
    assert exc.value.code == "InvalidParameterValue"


def test_enable_snapshot_bpa_rejects_garbage():
    _store()
    p = _provider()
    with pytest.raises(CommonServiceException):
        p.enable_snapshot_block_public_access(_ctx(), {"State": "open-to-everyone"})
    with pytest.raises(CommonServiceException):
        p.enable_snapshot_block_public_access(_ctx(), {})


def test_disable_snapshot_bpa_returns_to_unblocked():
    _store()
    p = _provider()
    p.enable_snapshot_block_public_access(_ctx(), {"State": "block-all-sharing"})
    r = p.disable_snapshot_block_public_access(_ctx(), {})
    assert r == {"State": "unblocked"}
    assert p.get_snapshot_block_public_access_state(_ctx(), {})["State"] == "unblocked"


# ---------- Serial Console Access handlers ----------


def test_get_serial_console_returns_disabled_for_new_account():
    _store()
    p = _provider()
    r = p.get_serial_console_access_status(_ctx(), {})
    assert r == {"SerialConsoleAccessEnabled": False, "ManagedBy": "account"}


def test_enable_serial_console_sets_true():
    _store()
    p = _provider()
    r = p.enable_serial_console_access(_ctx(), {})
    assert r == {"SerialConsoleAccessEnabled": True}
    assert p.get_serial_console_access_status(_ctx(), {})[
        "SerialConsoleAccessEnabled"
    ] is True


def test_disable_serial_console_sets_false():
    _store()
    p = _provider()
    p.enable_serial_console_access(_ctx(), {})
    r = p.disable_serial_console_access(_ctx(), {})
    assert r == {"SerialConsoleAccessEnabled": False}
    assert p.get_serial_console_access_status(_ctx(), {})[
        "SerialConsoleAccessEnabled"
    ] is False


# ---------- ModifySnapshotAttribute enforcement ----------


def _patched_call_moto():
    return mock.patch.object(ec2_provider_module, "call_moto", return_value={})


def test_modify_snapshot_attribute_delegates_to_moto_when_bpa_disabled():
    """BPA disabled means even public-share requests must reach moto."""
    _store()
    p = _provider()
    with _patched_call_moto() as cm:
        out = p.modify_snapshot_attribute(
            _ctx(),
            {
                "SnapshotId": "snap-123",
                "Attribute": "createVolumePermission",
                "OperationType": "add",
                "UserIds": ["all"],
            },
        )
    assert out == {}
    assert cm.called


def test_modify_snapshot_attribute_blocks_public_share_modern_form_when_bpa_on():
    """``CreateVolumePermission={"Add":[{"Group":"all"}]}`` is the modern form
    that must be rejected when BPA is enabled."""
    s = _store()
    s.snapshot_bpa_state = "block-all-sharing"
    p = _provider()
    with _patched_call_moto() as cm, pytest.raises(CommonServiceException) as exc:
        p.modify_snapshot_attribute(
            _ctx(),
            {
                "SnapshotId": "snap-123",
                "CreateVolumePermission": {"Add": [{"Group": "all"}]},
            },
        )
    assert exc.value.code == "OperationNotPermitted"
    assert cm.called is False  # short-circuited, never delegated


def test_modify_snapshot_attribute_blocks_public_share_legacy_form_when_bpa_on():
    s = _store()
    s.snapshot_bpa_state = "block-new-sharing"
    p = _provider()
    with _patched_call_moto() as cm, pytest.raises(CommonServiceException) as exc:
        p.modify_snapshot_attribute(
            _ctx(),
            {
                "SnapshotId": "snap-123",
                "Attribute": "createVolumePermission",
                "OperationType": "add",
                "UserIds": ["all"],
            },
        )
    assert exc.value.code == "OperationNotPermitted"
    assert cm.called is False


def test_modify_snapshot_attribute_allows_non_public_changes_when_bpa_on():
    """A specific account-id add (not ``all``) is not a public-share request
    and must still go through even when BPA is enabled."""
    s = _store()
    s.snapshot_bpa_state = "block-all-sharing"
    p = _provider()
    with _patched_call_moto() as cm:
        out = p.modify_snapshot_attribute(
            _ctx(),
            {
                "SnapshotId": "snap-123",
                "CreateVolumePermission": {"Add": [{"UserId": "111111111111"}]},
            },
        )
    assert out == {}
    assert cm.called  # delegated to moto


def test_modify_snapshot_attribute_per_region_isolation():
    """BPA enforcement is per-region. Enabling it in us-east-1 must not affect
    a call from eu-west-1."""
    ec2_account_settings_stores["000000000000"]["us-east-1"].snapshot_bpa_state = (
        "block-all-sharing"
    )
    # eu-west-1 stays unblocked by default
    p = _provider()
    with _patched_call_moto() as cm:
        out = p.modify_snapshot_attribute(
            _ctx(account="000000000000", region="eu-west-1"),
            {
                "SnapshotId": "snap-123",
                "CreateVolumePermission": {"Add": [{"Group": "all"}]},
            },
        )
    assert out == {}
    assert cm.called
