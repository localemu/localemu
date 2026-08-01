"""Unit tests for ENI-level SG re-apply.

Before this change the SG data plane only tracked instance-level SG
mutations (``ModifyInstanceAttribute --groups=...``). The ENI-level
control-plane operations that terraform / cdk / the console actually
generate - ``AttachNetworkInterface``, ``DetachNetworkInterface``,
``ModifyNetworkInterfaceAttribute --groups=...`` - updated moto and
the AddressIndex but never touched the running container's iptables.
The instance ran with the SG set it had at launch until re-created.

The fix is a resolver that pulls the union of SGs across every
attached ENI from the :class:`AddressIndex`, and a hook that the
three ENI handlers call after their state mutation succeeds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_reapply


@dataclass
class _FakeEni:
    """Minimal EniEntry stand-in that satisfies the resolver's shape."""
    eni_id: str
    instance_id: str | None = None
    sg_ids: list[str] = field(default_factory=list)


class _FakeIndex:
    """Just enough of :class:`AddressIndex` for the resolver."""

    def __init__(self, enis_by_instance: dict[str, list[_FakeEni]]):
        self._by_iid = enis_by_instance

    def get_enis_for_instance(self, instance_id: str) -> list[_FakeEni]:
        return list(self._by_iid.get(instance_id, []))

    def get_eni(self, eni_id: str) -> _FakeEni | None:
        for enis in self._by_iid.values():
            for eni in enis:
                if eni.eni_id == eni_id:
                    return eni
        return None


@pytest.fixture(autouse=True)
def _clean_state():
    with sg_reapply._sg_mapping_lock:
        sg_reapply._sg_mapping.clear()
    yield
    with sg_reapply._sg_mapping_lock:
        sg_reapply._sg_mapping.clear()


# ---- resolve_union_sgs_for_instance --------------------------------


def test_resolve_returns_empty_when_no_enis_attached():
    fake_index = _FakeIndex({})
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-none") == []


def test_resolve_single_eni_single_sg():
    fake_index = _FakeIndex({
        "i-01": [_FakeEni("eni-a", instance_id="i-01", sg_ids=["sg-1"])],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-01") == ["sg-1"]


def test_resolve_multi_eni_disjoint_sgs_is_ordered_union():
    fake_index = _FakeIndex({
        "i-01": [
            _FakeEni("eni-primary", instance_id="i-01", sg_ids=["sg-A", "sg-B"]),
            _FakeEni("eni-second", instance_id="i-01", sg_ids=["sg-C"]),
        ],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-01") == [
            "sg-A", "sg-B", "sg-C",
        ]


def test_resolve_multi_eni_overlapping_sgs_dedupes_on_first_sight():
    fake_index = _FakeIndex({
        "i-02": [
            _FakeEni("eni-p", instance_id="i-02", sg_ids=["sg-A", "sg-B"]),
            _FakeEni("eni-s", instance_id="i-02", sg_ids=["sg-B", "sg-C"]),
        ],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-02") == [
            "sg-A", "sg-B", "sg-C",
        ]


def test_resolve_ignores_empty_string_sg_ids():
    """Defensive: an ENI with an accidental ``""`` in sg_ids must not
    leak into the union - iptables would fail on the empty group id."""
    fake_index = _FakeIndex({
        "i-03": [_FakeEni("eni-p", instance_id="i-03", sg_ids=["", "sg-1"])],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-03") == ["sg-1"]


def test_resolve_returns_empty_on_index_lookup_failure():
    """The resolver is a best-effort hook ; a broken index must not
    take down the handler."""
    def _boom(*_a, **_kw):
        raise RuntimeError("index dead")

    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        side_effect=_boom,
    ):
        assert sg_reapply.resolve_union_sgs_for_instance("i-xx") == []


# ---- reapply_sgs_for_instance_after_eni_change ---------------------


def test_reapply_after_eni_change_calls_apply_with_union():
    fake_index = _FakeIndex({
        "i-10": [
            _FakeEni("eni-p", instance_id="i-10", sg_ids=["sg-A"]),
            _FakeEni("eni-s", instance_id="i-10", sg_ids=["sg-B"]),
        ],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ), mock.patch(
        "localemu.services.ec2.docker.sg_reapply.apply_sg_to_container",
        return_value=True,
    ) as apply_fn:
        ok = sg_reapply.reapply_sgs_for_instance_after_eni_change(
            "i-10", "000000000000", "us-east-1",
        )
    assert ok is True
    # apply called once, with the union in ENI order
    assert apply_fn.call_count == 1
    _, args, kwargs = apply_fn.mock_calls[0]
    assert args == (
        "localemu-ec2-i-10", ["sg-A", "sg-B"], "000000000000", "us-east-1",
    )
    assert kwargs == {"instance_id": "i-10"}


def test_reapply_after_eni_change_updates_the_instance_sg_mapping():
    """The in-memory mapping must be updated too so a subsequent
    ``AuthorizeSecurityGroupIngress`` on sg-B finds i-11 in the
    lookup.
    """
    fake_index = _FakeIndex({
        "i-11": [_FakeEni("eni-s", instance_id="i-11", sg_ids=["sg-X", "sg-Y"])],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ), mock.patch(
        "localemu.services.ec2.docker.sg_reapply.apply_sg_to_container",
        return_value=True,
    ):
        sg_reapply.reapply_sgs_for_instance_after_eni_change(
            "i-11", "000000000000", "us-east-1",
        )
    with sg_reapply._sg_mapping_lock:
        assert sg_reapply._sg_mapping[
            ("000000000000", "us-east-1", "i-11")
        ] == ["sg-X", "sg-Y"]


def test_reapply_after_detach_empties_when_last_eni_gone():
    """After detach removes the last ENI, the resolver should return
    an empty list and the apply still fires - with an empty ruleset
    the SG_IN / SG_OUT chains collapse to the fail-closed default
    DROP, which is the right posture for an instance with no
    attached ENIs.
    """
    fake_index = _FakeIndex({"i-12": []})
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ), mock.patch(
        "localemu.services.ec2.docker.sg_reapply.apply_sg_to_container",
        return_value=True,
    ) as apply_fn:
        sg_reapply.reapply_sgs_for_instance_after_eni_change(
            "i-12", "000000000000", "us-east-1",
        )
    assert apply_fn.call_count == 1
    _, args, _ = apply_fn.mock_calls[0]
    assert args[1] == []  # empty union → fail-closed DROP


def test_reapply_returns_false_on_apply_exception_and_does_not_raise():
    fake_index = _FakeIndex({
        "i-13": [_FakeEni("eni-p", instance_id="i-13", sg_ids=["sg-1"])],
    })

    def _boom(*_a, **_kw):
        raise RuntimeError("iptables missing")

    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ), mock.patch(
        "localemu.services.ec2.docker.sg_reapply.apply_sg_to_container",
        side_effect=_boom,
    ):
        ok = sg_reapply.reapply_sgs_for_instance_after_eni_change(
            "i-13", "000000000000", "us-east-1",
        )
    assert ok is False


def test_reapply_call_shape_matches_apply_sg_to_container_signature():
    """Pin the positional shape ; a refactor of
    ``apply_sg_to_container`` should not silently break this hook.
    """
    fake_index = _FakeIndex({
        "i-14": [_FakeEni("eni-p", instance_id="i-14", sg_ids=["sg-1"])],
    })
    with mock.patch(
        "localemu.services.ec2.docker.address_index.get_address_index",
        return_value=fake_index,
    ), mock.patch(
        "localemu.services.ec2.docker.sg_reapply.apply_sg_to_container",
        return_value=True,
    ) as apply_fn:
        sg_reapply.reapply_sgs_for_instance_after_eni_change(
            "i-14", "acct", "us-east-1",
        )
    call = apply_fn.mock_calls[0]
    # (container_name, sg_ids, account_id, region), instance_id=...
    _, args, kwargs = call
    assert len(args) == 4
    assert args[0].startswith("localemu-ec2-")
    assert isinstance(args[1], list)
    assert args[2] == "acct"
    assert args[3] == "us-east-1"
    assert kwargs.get("instance_id") == "i-14"
