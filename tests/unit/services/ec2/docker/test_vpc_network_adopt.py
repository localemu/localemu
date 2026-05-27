"""Unit tests for the VPC network reliability fixes.

Covers:
- get_network_for_vpc is pure-read (no docker calls on miss)
- ensure_network_for_vpc creates on first call
- Failure cooldown suppresses retries within FAILED_CREATE_RETRY_TTL_SECONDS
- _pick_free_subnet returns a /16 that does not overlap existing networks
- adopt_vpc_networks_from_docker registers VPCs whose ID matches moto
- adopt deletes orphan bridges whose VPC ID is not in moto and has no containers
- adopt leaves orphan bridges alone when they still have containers attached
"""
from __future__ import annotations

import time
from unittest import mock

import pytest

from localemu.services.ec2.docker import vpc_network as vpc_mod


@pytest.fixture
def fresh_manager():
    """A VpcNetworkManager with empty state and no auto-adoption."""
    m = vpc_mod.VpcNetworkManager()
    m._adopted = True  # Prevent the singleton helper from re-running adoption
    return m


@pytest.fixture
def patch_docker_client(monkeypatch):
    """Provide a MagicMock as the module-level DOCKER_CLIENT."""
    dc = mock.MagicMock()
    monkeypatch.setattr(vpc_mod, "DOCKER_CLIENT", dc)
    return dc


@pytest.fixture
def patch_moto_backends(monkeypatch):
    """Stub moto's ec2_backends with a dict[acct][region] -> backend."""
    fake_backends = {}

    def _setup(vpcs_by_region: dict[str, dict[str, str]]):
        """vpcs_by_region: {region: {vpc_id: cidr}}"""
        fake_backends.clear()
        acct = {}
        for region, vpcs in vpcs_by_region.items():
            be = mock.MagicMock()
            be.vpcs = {
                vid: mock.MagicMock(cidr_block=cidr)
                for vid, cidr in vpcs.items()
            }
            acct[region] = be
        fake_backends["000000000000"] = acct

    def fake_get(name):
        return fake_backends

    # The code uses `from moto.ec2.models import ec2_backends`. Patch the
    # attribute on the module so the import inside the method gets the
    # stub.
    import moto.ec2.models as moto_models
    monkeypatch.setattr(moto_models, "ec2_backends", fake_backends)
    return _setup


class TestPureReadVsEnsure:
    def test_get_network_for_vpc_miss_returns_none_no_docker_call(
        self, fresh_manager, patch_docker_client,
    ):
        result = fresh_manager.get_network_for_vpc("vpc-unknown")
        assert result is None
        # The whole point of the refactor: ZERO docker calls on a read miss.
        patch_docker_client.create_network.assert_not_called()
        patch_docker_client.inspect_network.assert_not_called()

    def test_get_network_for_vpc_hit_returns_tracked_name(
        self, fresh_manager, patch_docker_client,
    ):
        fresh_manager._vpcs["vpc-abc"] = {
            "network_name": "localemu-vpc-vpc-abc",
            "cidr": "10.0.0.0/16",
            "docker_cidr": "10.0.0.0/16",
            "network_id": "net-id",
            "has_igw": False,
            "containers": set(),
        }
        assert fresh_manager.get_network_for_vpc("vpc-abc") == "localemu-vpc-vpc-abc"
        patch_docker_client.create_network.assert_not_called()

    def test_ensure_network_creates_when_vpc_in_moto(
        self, fresh_manager, patch_docker_client, patch_moto_backends,
    ):
        patch_moto_backends({"us-east-1": {"vpc-newly-created": "10.5.0.0/16"}})
        patch_docker_client.create_network.return_value = "net-id-new"

        result = fresh_manager.ensure_network_for_vpc("vpc-newly-created")

        assert result == "localemu-vpc-vpc-newly-created"
        patch_docker_client.create_network.assert_called_once()
        call_kwargs = patch_docker_client.create_network.call_args.kwargs
        assert call_kwargs["subnet"] == "10.5.0.0/16"
        assert call_kwargs["internal"] is True
        assert "vpc-newly-created" in fresh_manager._vpcs

    def test_ensure_network_returns_none_when_vpc_not_in_moto(
        self, fresh_manager, patch_docker_client, patch_moto_backends,
    ):
        patch_moto_backends({})
        result = fresh_manager.ensure_network_for_vpc("vpc-phantom")
        assert result is None
        patch_docker_client.create_network.assert_not_called()


class TestFailureCooldown:
    def test_failed_create_records_timestamp(
        self, fresh_manager, patch_docker_client,
    ):
        patch_docker_client.create_network.side_effect = Exception("pool exhausted")

        result = fresh_manager.create_vpc_network("vpc-fail", "10.99.0.0/16")

        # Returns a stable network_name even on failure so callers don't
        # branch on None.
        assert result == "localemu-vpc-vpc-fail"
        assert "vpc-fail" in fresh_manager._failed_creates
        assert "vpc-fail" not in fresh_manager._vpcs

    def test_cooldown_skips_docker_within_ttl(
        self, fresh_manager, patch_docker_client,
    ):
        patch_docker_client.create_network.side_effect = Exception("pool exhausted")
        # First attempt actually calls Docker (2 calls: AWS CIDR + fallback).
        fresh_manager.create_vpc_network("vpc-fail", "10.99.0.0/16")
        first_call_count = patch_docker_client.create_network.call_count
        assert first_call_count >= 1

        # Second attempt within TTL: Docker is not touched at all.
        fresh_manager.create_vpc_network("vpc-fail", "10.99.0.0/16")
        assert patch_docker_client.create_network.call_count == first_call_count

    def test_cooldown_expires_after_ttl(
        self, fresh_manager, patch_docker_client, monkeypatch,
    ):
        # Move "now" forward by 2x the TTL between calls so the second
        # call passes the gate.
        patch_docker_client.create_network.side_effect = Exception("nope")
        fresh_manager.create_vpc_network("vpc-fail", "10.99.0.0/16")
        baseline = patch_docker_client.create_network.call_count

        old_ts = fresh_manager._failed_creates["vpc-fail"]
        fresh_manager._failed_creates["vpc-fail"] = (
            old_ts - vpc_mod.FAILED_CREATE_RETRY_TTL_SECONDS - 1
        )

        fresh_manager.create_vpc_network("vpc-fail", "10.99.0.0/16")
        assert patch_docker_client.create_network.call_count > baseline

    def test_successful_create_clears_failure_cache(
        self, fresh_manager, patch_docker_client,
    ):
        # Seed a recorded failure for vpc-1
        fresh_manager._failed_creates["vpc-1"] = time.time() - 1
        # Reset adoption-related fields so create runs the path.
        # The cooldown gate fires inside the lock, so a recent failure
        # blocks until expired. Force-expire it for this scenario.
        fresh_manager._failed_creates["vpc-1"] = (
            time.time() - vpc_mod.FAILED_CREATE_RETRY_TTL_SECONDS - 1
        )
        patch_docker_client.create_network.return_value = "net-id"

        fresh_manager.create_vpc_network("vpc-1", "10.6.0.0/16")

        assert "vpc-1" not in fresh_manager._failed_creates
        assert "vpc-1" in fresh_manager._vpcs


class TestSmartSubnetPicker:
    def _stub_subprocess(self, monkeypatch, network_names):
        import subprocess as _sp

        class _R:
            returncode = 0
            stdout = "\n".join(network_names)

        monkeypatch.setattr(_sp, "run", lambda *a, **kw: _R())

    def test_pick_free_subnet_avoids_existing(
        self, fresh_manager, patch_docker_client, monkeypatch,
    ):
        self._stub_subprocess(monkeypatch, ["net-a", "net-b"])
        patch_docker_client.inspect_network.side_effect = lambda name: {
            "net-a": {"IPAM": {"Config": [{"Subnet": "10.0.0.0/16"}]}},
            "net-b": {"IPAM": {"Config": [{"Subnet": "10.1.0.0/16"}]}},
        }[name]

        cidr = fresh_manager._pick_free_subnet()
        # First two /16s are taken; expect 10.2.0.0/16.
        assert cidr == "10.2.0.0/16"

    def test_pick_free_subnet_when_pool_empty(
        self, fresh_manager, patch_docker_client, monkeypatch,
    ):
        self._stub_subprocess(monkeypatch, [])
        cidr = fresh_manager._pick_free_subnet()
        assert cidr == "10.0.0.0/16"

    def test_create_uses_fallback_when_aws_cidr_collides(
        self, fresh_manager, patch_docker_client, monkeypatch,
    ):
        # Simulate AWS CIDR collision: first call fails, fallback succeeds.
        calls = []

        def fake_create(**kw):
            calls.append(kw["subnet"])
            if kw["subnet"] == "172.31.0.0/16":
                raise Exception("Pool overlaps")
            return "net-id-fallback"

        patch_docker_client.create_network.side_effect = fake_create

        # Stub the subnet enumeration so the fallback picker returns 10.0.0.0/16.
        self._stub_subprocess(monkeypatch, [])

        result = fresh_manager.create_vpc_network("vpc-default", "172.31.0.0/16")

        assert result == "localemu-vpc-vpc-default"
        assert "vpc-default" in fresh_manager._vpcs
        assert fresh_manager._vpcs["vpc-default"]["cidr"] == "172.31.0.0/16"
        # docker_cidr should be the fallback, not the AWS CIDR.
        assert fresh_manager._vpcs["vpc-default"]["docker_cidr"] == "10.0.0.0/16"
        assert calls == ["172.31.0.0/16", "10.0.0.0/16"]


class TestAdoptVpcNetworksFromDocker:
    def _stub_subprocess(self, monkeypatch, network_names):
        import subprocess as _sp

        class _R:
            returncode = 0
            stdout = "\n".join(network_names)

        monkeypatch.setattr(_sp, "run", lambda *a, **kw: _R())

    def test_adopt_registers_existing_bridge_when_vpc_in_moto(
        self, patch_docker_client, patch_moto_backends, monkeypatch,
    ):
        m = vpc_mod.VpcNetworkManager()  # adopted=False
        patch_moto_backends({"us-east-1": {"vpc-default": "172.31.0.0/16"}})
        self._stub_subprocess(monkeypatch, ["localemu-vpc-vpc-default"])
        patch_docker_client.inspect_network.return_value = {
            "Id": "net-id-default",
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.42.0.0/16"}]},
            "Containers": {},
        }

        adopted, deleted = m.adopt_vpc_networks_from_docker()

        assert adopted == 1
        assert deleted == 0
        assert "vpc-default" in m._vpcs
        assert m._vpcs["vpc-default"]["docker_cidr"] == "10.42.0.0/16"
        # Critically: zero create_network calls during adoption.
        patch_docker_client.create_network.assert_not_called()

    def test_adopt_deletes_orphan_when_vpc_not_in_moto_no_containers(
        self, patch_docker_client, patch_moto_backends, monkeypatch,
    ):
        m = vpc_mod.VpcNetworkManager()
        patch_moto_backends({"us-east-1": {}})
        self._stub_subprocess(monkeypatch, ["localemu-vpc-vpc-orphan-aaa"])
        patch_docker_client.inspect_network.return_value = {
            "Id": "net-id-orphan",
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.99.0.0/16"}]},
            "Containers": {},  # no attached containers => safe to delete
        }

        adopted, deleted = m.adopt_vpc_networks_from_docker()

        assert adopted == 0
        assert deleted == 1
        patch_docker_client.delete_network.assert_called_once_with(
            "localemu-vpc-vpc-orphan-aaa"
        )

    def test_adopt_reclaims_orphan_when_only_localemu_containers_attached(
        self, patch_docker_client, patch_moto_backends, monkeypatch,
    ):
        """Orphan VPC bridges holding only LocalEmu-owned leftovers (an
        IMDS sidecar or EC2 container from a crashed prior session) get
        reclaimed: the leftover container is stopped + removed, then the
        bridge is deleted. Previously adoption skipped this case, which
        meant a single leftover sidecar would keep a /16 reserved across
        every subsequent session and eventually exhaust the fallback
        pools."""
        m = vpc_mod.VpcNetworkManager()
        patch_moto_backends({"us-east-1": {}})
        self._stub_subprocess(monkeypatch, ["localemu-vpc-vpc-attached"])
        patch_docker_client.inspect_network.return_value = {
            "Id": "net-id-attached",
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.50.0.0/16"}]},
            "Containers": {"container-id-1": {"Name": "localemu-ec2-i-foo"}},
        }

        adopted, deleted = m.adopt_vpc_networks_from_docker()

        assert adopted == 0
        assert deleted == 1
        patch_docker_client.stop_container.assert_called_with(
            "localemu-ec2-i-foo", timeout=5,
        )
        patch_docker_client.remove_container.assert_called_with(
            "localemu-ec2-i-foo", force=True,
        )
        patch_docker_client.delete_network.assert_called_with(
            "localemu-vpc-vpc-attached",
        )

    def test_adopt_leaves_orphan_alone_when_external_container_attached(
        self, patch_docker_client, patch_moto_backends, monkeypatch,
    ):
        """If any non-localemu container is attached to an orphan VPC
        bridge, something external is using it and adoption must stay
        hands-off — even though the VPC ID is gone from moto."""
        m = vpc_mod.VpcNetworkManager()
        patch_moto_backends({"us-east-1": {}})
        self._stub_subprocess(monkeypatch, ["localemu-vpc-vpc-external"])
        patch_docker_client.inspect_network.return_value = {
            "Id": "net-id-external",
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.51.0.0/16"}]},
            "Containers": {"container-id-1": {"Name": "some-third-party-app"}},
        }

        adopted, deleted = m.adopt_vpc_networks_from_docker()

        assert adopted == 0
        assert deleted == 0
        patch_docker_client.stop_container.assert_not_called()
        patch_docker_client.remove_container.assert_not_called()
        patch_docker_client.delete_network.assert_not_called()

    def test_adopt_is_idempotent(
        self, patch_docker_client, patch_moto_backends, monkeypatch,
    ):
        m = vpc_mod.VpcNetworkManager()
        patch_moto_backends({"us-east-1": {"vpc-x": "10.7.0.0/16"}})
        self._stub_subprocess(monkeypatch, ["localemu-vpc-vpc-x"])
        patch_docker_client.inspect_network.return_value = {
            "Id": "net-id-x",
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "10.7.0.0/16"}]},
            "Containers": {},
        }

        m.adopt_vpc_networks_from_docker()
        first_inspect_count = patch_docker_client.inspect_network.call_count

        # Second call should be a no-op.
        m.adopt_vpc_networks_from_docker()
        assert patch_docker_client.inspect_network.call_count == first_inspect_count


class TestEcsNetworkInterfaceProperty:
    def test_property_is_settable_after_patch(self):
        from localemu.services.ecs.provider import _patch_moto_eni_private_dns_name
        from moto.ec2.models.elastic_network_interfaces import NetworkInterface

        _patch_moto_eni_private_dns_name()

        eni = NetworkInterface.__new__(NetworkInterface)
        eni.private_ip_address = "10.1.2.3"
        # Moto's __init__ does this assignment when enable_dns_hostnames=True;
        # the read-only property previously raised AttributeError here.
        eni.private_dns_name = "ip-10-1-2-3.ec2.internal"
        assert eni.private_dns_name == "ip-10-1-2-3.ec2.internal"

    def test_property_derives_from_ip_when_unset(self):
        from localemu.services.ecs.provider import _patch_moto_eni_private_dns_name
        from moto.ec2.models.elastic_network_interfaces import NetworkInterface

        _patch_moto_eni_private_dns_name()

        eni = NetworkInterface.__new__(NetworkInterface)
        eni.private_ip_address = "10.4.5.6"
        # Fargate path: no assignment happens through moto __init__.
        assert eni.private_dns_name == "ip-10-4-5-6.ec2.internal"

    def test_property_returns_empty_when_no_ip(self):
        from localemu.services.ecs.provider import _patch_moto_eni_private_dns_name
        from moto.ec2.models.elastic_network_interfaces import NetworkInterface

        _patch_moto_eni_private_dns_name()

        eni = NetworkInterface.__new__(NetworkInterface)
        eni.private_ip_address = None
        assert eni.private_dns_name == ""
