"""Unit tests for IGW-driven network recreate (fix #81).

Two bugs fixed in ``vpc_network._recreate_network``:

  1. Only the tracked EC2 containers were disconnected before the
     ``docker network rm``. The per-VPC IMDS sidecar (and any other
     service container that attaches to the VPC) was left behind,
     so Docker refused to delete the network. The recreate would
     then silently fail to clear the ``--internal`` flag, and
     ``attach_internet_gateway`` would return success and set
     ``has_igw=True`` even though Docker still had the old flag —
     a correctness lie.

  2. ``_recreate_network`` returned ``None`` for every branch,
     including the silent-failure branch where it couldn't create
     the temp network at all. Callers had no way to detect that
     the recreate had not happened; ``attach_internet_gateway`` /
     ``detach_internet_gateway`` would then claim success.

After the fix:
  - All endpoints on the old network are disconnected (not just
    tracked EC2s), so the ``docker network rm`` succeeds even when
    the IMDS sidecar (or VPC endpoint proxy) was attached.
  - ``_recreate_network`` returns a bool; ``attach_internet_gateway``
    / ``detach_internet_gateway`` propagate it; the EC2 provider
    logs at ERROR when False so operators see the failure.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import vpc_network as vpc_mod


@pytest.fixture
def mgr():
    m = vpc_mod.VpcNetworkManager.__new__(vpc_mod.VpcNetworkManager)
    m._lock = __import__("threading").Lock()
    m._vpcs = {}
    m._container_subnets = {}
    return m


class TestRecreateDisconnectsAllEndpoints:
    def test_sidecar_endpoint_disconnected_then_net_removed(self, mgr):
        """Before fix: only tracked EC2 containers were disconnected;
        the untracked IMDS sidecar (and any other service-owned
        attachment) blocked ``network rm``. Now every endpoint
        ``inspect_network`` lists gets disconnected, then reconnected
        to the recreated network so the sidecar keeps serving."""
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.0.0.0/16",
            "containers": {"localemu-ec2-i-1", "localemu-ec2-i-2"},
            "has_igw": False,
        }
        dc = mock.MagicMock()
        dc.create_network.return_value = "id-new"
        dc.inspect_network.return_value = {
            "Containers": {
                "c1": {"Name": "localemu-ec2-i-1"},
                "c2": {"Name": "localemu-ec2-i-2"},
                "c3": {"Name": "localemu-imds-vpc-vpc-xyz"},
            },
        }
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", dc):
            result = mgr._recreate_network(
                "vpc-xyz",
                "localemu-vpc-vpc-xyz",
                "10.0.0.0/16",
                ["localemu-ec2-i-1", "localemu-ec2-i-2"],
                internal=False,
            )
        assert result is True
        disconnected = {
            call.args[1] for call in dc.disconnect_container_from_network.call_args_list
            if call.args[0] == "localemu-vpc-vpc-xyz"
        }
        assert "localemu-imds-vpc-vpc-xyz" in disconnected, (
            f"sidecar was not disconnected from old network: "
            f"disconnected={disconnected}"
        )
        # And the sidecar must have been reconnected to the recreated
        # network (same name, new internal flag) so IMDS keeps serving.
        reconnected = {
            call.args[1] for call in dc.connect_container_to_network.call_args_list
            if call.args[0] == "localemu-vpc-vpc-xyz"
        }
        assert "localemu-imds-vpc-vpc-xyz" in reconnected, (
            f"sidecar was not reconnected to recreated network: "
            f"reconnected={reconnected}"
        )


class TestRecreateRespectsDockerCidrInvariant:
    """Docker forbids two bridge networks sharing a CIDR pool. The
    previous implementation tried to create a ``-new`` network with
    the SAME CIDR while the old one still existed, which Docker
    refused every single call with::

        Pool overlaps with other one on this address space

    The implementation then silently fell back to creating the temp
    network *without* a subnet, so Docker auto-assigned a random
    CIDR. The final-name create then succeeded because the old
    network had been deleted by then — so the end state was usually
    correct, but every IGW attach printed an ERROR log and burned an
    extra ~hundred ms on the doomed first attempt. Worse, the silent
    fallback could leave the VPC's Docker network with the wrong CIDR
    if any later step failed.

    The fix: never make the impossible call. Disconnect endpoints,
    delete the old network (freeing the CIDR), then create the new
    one with the same name + same CIDR + new internal flag. One
    create call, no fallback, no overlap.
    """

    def test_no_create_call_overlaps_existing_cidr(self, mgr):
        """Reproduces the bug: any ``create_network(subnet=X)`` call
        made while another network already holds X must be rejected
        by Docker. The recreate must not make such a call."""
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.99.0.0/24",
            "containers": set(),
            "has_igw": False,
        }
        # Track which networks exist (by name -> cidr). Start with the
        # old network already present.
        live: dict[str, str] = {"localemu-vpc-vpc-xyz": "10.99.0.0/24"}
        cidr_overlap_calls: list[tuple[str, str]] = []

        def fake_create(network_name, subnet=None, internal=False, **kw):
            if subnet is not None:
                # Docker invariant: refuse if any live network has this CIDR
                for existing_name, existing_cidr in live.items():
                    if existing_cidr == subnet:
                        cidr_overlap_calls.append((network_name, subnet))
                        raise RuntimeError(
                            "Error response from daemon: invalid pool "
                            "request: Pool overlaps with other one on "
                            "this address space"
                        )
            live[network_name] = subnet or "auto"
            return f"id-{network_name}"

        def fake_delete(network_name):
            live.pop(network_name, None)

        def fake_inspect(network_name):
            if network_name not in live:
                return None
            return {"Containers": {}}

        dc = mock.MagicMock()
        dc.create_network.side_effect = fake_create
        dc.delete_network.side_effect = fake_delete
        dc.inspect_network.side_effect = fake_inspect

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", dc):
            result = mgr._recreate_network(
                "vpc-xyz",
                "localemu-vpc-vpc-xyz",
                "10.99.0.0/24",
                [],
                internal=False,
            )

        # The recreate must succeed.
        assert result is True, "recreate returned False on a clean case"

        # The recreate must NOT have made any overlapping-CIDR call.
        # On the broken impl this fails because the temp-name create
        # with subnet=10.99.0.0/24 is made while the old network still
        # holds that CIDR.
        assert cidr_overlap_calls == [], (
            f"Recreate made {len(cidr_overlap_calls)} create_network "
            f"call(s) that overlap with an existing CIDR — Docker would "
            f"reject each one: {cidr_overlap_calls}"
        )

        # The final network must end up with the requested CIDR
        # (not a Docker-auto-assigned pool).
        assert live.get("localemu-vpc-vpc-xyz") == "10.99.0.0/24", (
            f"Final network has wrong CIDR: live={live}"
        )


class TestRecreateReturnsFalseOnFailure:
    def test_temp_create_failure_returns_false(self, mgr):
        """If Docker can't create the temp network (e.g. bridge IPAM
        pool exhausted), ``_recreate_network`` must return False so
        callers know the state change did NOT take effect."""
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.0.0.0/16",
            "containers": set(),
            "has_igw": False,
        }
        dc = mock.MagicMock()
        dc.create_network.side_effect = RuntimeError(
            "all predefined address pools have been fully subnetted"
        )
        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", dc):
            result = mgr._recreate_network(
                "vpc-xyz",
                "localemu-vpc-vpc-xyz",
                "10.0.0.0/16",
                [],
                internal=False,
            )
        assert result is False


class TestAttachDetachPropagateFailure:
    def test_attach_returns_false_when_recreate_fails(self, mgr):
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.0.0.0/16",
            "containers": set(),
            "has_igw": False,
        }
        with mock.patch.object(
            mgr, "_recreate_network", return_value=False,
        ):
            result = mgr.attach_internet_gateway("vpc-xyz")
        assert result is False
        # has_igw must NOT have been set to True — that would be
        # the correctness lie we're preventing.
        assert mgr._vpcs["vpc-xyz"]["has_igw"] is False

    def test_attach_returns_true_and_sets_flag_on_success(self, mgr):
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.0.0.0/16",
            "containers": set(),
            "has_igw": False,
        }
        with mock.patch.object(
            mgr, "_recreate_network", return_value=True,
        ):
            result = mgr.attach_internet_gateway("vpc-xyz")
        assert result is True
        assert mgr._vpcs["vpc-xyz"]["has_igw"] is True

    def test_detach_returns_false_when_recreate_fails(self, mgr):
        mgr._vpcs["vpc-xyz"] = {
            "network_id": "id-old",
            "network_name": "localemu-vpc-vpc-xyz",
            "cidr": "10.0.0.0/16",
            "containers": set(),
            "has_igw": True,
        }
        with mock.patch.object(
            mgr, "_recreate_network", return_value=False,
        ):
            result = mgr.detach_internet_gateway("vpc-xyz")
        assert result is False
        # has_igw must stay True since Docker still has non-internal
        assert mgr._vpcs["vpc-xyz"]["has_igw"] is True
