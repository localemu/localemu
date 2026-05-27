"""Unit tests for AddressIndex.

Covers:
  - derive_mac determinism (same IP -> same MAC; Docker OUI prefix)
  - register_eni / delete_eni round-trip
  - attach / detach lifecycle
  - secondary IP add / remove
  - SG membership update (sg_to_enis bucket maintenance)
  - get_eni_for_ip via primary and secondary
  - get_ips_for_sg returns union across ENIs
  - get_primary_ip_for_instance (primary ENI first)
  - Persistence round-trip
  - Schema / corrupt / missing handling
"""
from __future__ import annotations

import ipaddress
import json

import pytest

from localemu.services.ec2.docker.address_index import (
    AddressIndex,
    derive_mac,
    get_address_index,
    reset_address_index_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_address_index_for_tests()
    yield
    reset_address_index_for_tests()


# ---------------------------------------------------------------------------
# MAC derivation
# ---------------------------------------------------------------------------
class TestDeriveMac:
    def test_known_ip(self):
        assert derive_mac("10.0.0.5") == "02:42:0a:00:00:05"

    def test_uses_docker_oui(self):
        mac = derive_mac("192.168.1.1")
        assert mac.startswith("02:42:")

    def test_deterministic(self):
        assert derive_mac("10.0.7.42") == derive_mac("10.0.7.42")

    def test_different_ips_give_different_macs(self):
        assert derive_mac("10.0.0.1") != derive_mac("10.0.0.2")

    def test_accepts_ipv4_address_object(self):
        addr = ipaddress.IPv4Address("172.16.5.10")
        assert derive_mac(addr) == "02:42:ac:10:05:0a"


# ---------------------------------------------------------------------------
# register / delete
# ---------------------------------------------------------------------------
class TestRegister:
    def test_register_then_get(self):
        idx = AddressIndex()
        e = idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web"], instance_id="i-1", iface_name="eth0",
        )
        assert e.mac == "02:42:0a:00:00:05"  # derived
        assert idx.get_eni("eni-1") is e
        assert idx.get_eni_for_ip("10.0.0.5") is e

    def test_register_with_explicit_mac(self):
        idx = AddressIndex()
        e = idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            mac="aa:bb:cc:dd:ee:ff",
        )
        assert e.mac == "aa:bb:cc:dd:ee:ff"

    def test_register_duplicate_raises(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        with pytest.raises(ValueError):
            idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.6")

    def test_register_with_secondaries(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            secondary_ips=["10.0.0.6", "10.0.0.7"],
        )
        assert idx.get_eni_for_ip("10.0.0.5").eni_id == "eni-1"
        assert idx.get_eni_for_ip("10.0.0.6").eni_id == "eni-1"
        assert idx.get_eni_for_ip("10.0.0.7").eni_id == "eni-1"

    def test_delete_eni_clears_all_indexes(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web"], instance_id="i-1",
            secondary_ips=["10.0.0.6"],
        )
        removed = idx.delete_eni("eni-1")
        assert removed is not None
        assert removed.eni_id == "eni-1"
        assert idx.get_eni("eni-1") is None
        assert idx.get_eni_for_ip("10.0.0.5") is None
        assert idx.get_eni_for_ip("10.0.0.6") is None
        assert idx.get_enis_for_instance("i-1") == []
        assert idx.get_ips_for_sg("sg-web") == set()

    def test_delete_unknown_returns_none(self):
        idx = AddressIndex()
        assert idx.delete_eni("eni-nope") is None


# ---------------------------------------------------------------------------
# attach / detach
# ---------------------------------------------------------------------------
class TestAttachDetach:
    def test_attach_when_detached(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        idx.attach_eni("eni-1", "i-1", "eth1")
        assert idx.get_eni("eni-1").instance_id == "i-1"
        assert idx.get_eni("eni-1").iface_name == "eth1"
        assert idx.get_enis_for_instance("i-1")[0].eni_id == "eni-1"

    def test_attach_when_already_attached_to_same(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            instance_id="i-1", iface_name="eth0",
        )
        idx.attach_eni("eni-1", "i-1", "eth0")  # idempotent
        assert idx.get_enis_for_instance("i-1")[0].eni_id == "eni-1"

    def test_attach_moves_from_one_instance_to_another(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            instance_id="i-1", iface_name="eth1",
        )
        idx.attach_eni("eni-1", "i-2", "eth1")
        assert idx.get_enis_for_instance("i-1") == []
        assert idx.get_enis_for_instance("i-2")[0].eni_id == "eni-1"

    def test_detach_clears_instance(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", instance_id="i-1",
        )
        idx.detach_eni("eni-1")
        assert idx.get_eni("eni-1").instance_id is None
        assert idx.get_enis_for_instance("i-1") == []

    def test_attach_unknown_eni_raises(self):
        idx = AddressIndex()
        with pytest.raises(KeyError):
            idx.attach_eni("eni-nope", "i-1", "eth0")


# ---------------------------------------------------------------------------
# Secondary IPs
# ---------------------------------------------------------------------------
class TestSecondaryIps:
    def test_add_then_lookup(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        idx.add_secondary_ip("eni-1", "10.0.0.6")
        assert idx.get_eni_for_ip("10.0.0.6").eni_id == "eni-1"

    def test_add_idempotent(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        idx.add_secondary_ip("eni-1", "10.0.0.6")
        idx.add_secondary_ip("eni-1", "10.0.0.6")  # no raise
        assert idx.get_eni("eni-1").secondary_ips == [
            ipaddress.IPv4Address("10.0.0.6"),
        ]

    def test_add_primary_is_noop(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        idx.add_secondary_ip("eni-1", "10.0.0.5")  # primary, ignore
        assert idx.get_eni("eni-1").secondary_ips == []

    def test_remove(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            secondary_ips=["10.0.0.6"],
        )
        idx.remove_secondary_ip("eni-1", "10.0.0.6")
        assert idx.get_eni_for_ip("10.0.0.6") is None
        assert idx.get_eni("eni-1").secondary_ips == []

    def test_remove_missing_is_noop(self):
        idx = AddressIndex()
        idx.register_eni("eni-1", "vpc-1", "sub-a", "10.0.0.5")
        idx.remove_secondary_ip("eni-1", "10.99.99.99")  # no raise


# ---------------------------------------------------------------------------
# SG membership (this is the path that fixes the silent-allow bug)
# ---------------------------------------------------------------------------
class TestSgMembership:
    def test_get_ips_for_sg_returns_all_members(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", sg_ids=["sg-web", "sg-shared"],
        )
        idx.register_eni(
            "eni-2", "vpc-1", "sub-a", "10.0.0.6", sg_ids=["sg-web"],
        )
        idx.register_eni(
            "eni-3", "vpc-1", "sub-b", "10.0.1.5", sg_ids=["sg-shared"],
        )
        web = idx.get_ips_for_sg("sg-web")
        assert web == {
            ipaddress.IPv4Address("10.0.0.5"),
            ipaddress.IPv4Address("10.0.0.6"),
        }
        shared = idx.get_ips_for_sg("sg-shared")
        assert shared == {
            ipaddress.IPv4Address("10.0.0.5"),
            ipaddress.IPv4Address("10.0.1.5"),
        }
        assert idx.get_ips_for_sg("sg-nonexistent") == set()

    def test_get_ips_for_sg_includes_secondary_ips(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web"],
            secondary_ips=["10.0.0.50", "10.0.0.51"],
        )
        members = idx.get_ips_for_sg("sg-web")
        assert ipaddress.IPv4Address("10.0.0.5") in members
        assert ipaddress.IPv4Address("10.0.0.50") in members
        assert ipaddress.IPv4Address("10.0.0.51") in members

    def test_update_sgs_replaces(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", sg_ids=["sg-web"],
        )
        idx.update_sgs("eni-1", ["sg-app", "sg-db"])
        assert idx.get_ips_for_sg("sg-web") == set()
        assert ipaddress.IPv4Address("10.0.0.5") in idx.get_ips_for_sg("sg-app")
        assert ipaddress.IPv4Address("10.0.0.5") in idx.get_ips_for_sg("sg-db")
        assert idx.get_eni("eni-1").sg_ids == ["sg-app", "sg-db"]

    def test_update_sgs_unknown_eni_raises(self):
        idx = AddressIndex()
        with pytest.raises(KeyError):
            idx.update_sgs("eni-nope", ["sg-x"])


# ---------------------------------------------------------------------------
# Per-instance ENI ordering
# ---------------------------------------------------------------------------
class TestPerInstance:
    def test_primary_first(self):
        idx = AddressIndex()
        # Register the implicit primary first
        idx.register_eni(
            "eni-primary", "vpc-1", "sub-a", "10.0.0.5",
            instance_id="i-1", iface_name="eth0",
        )
        # Then a hot-attached secondary
        idx.register_eni(
            "eni-secondary", "vpc-1", "sub-a", "10.0.0.6",
        )
        idx.attach_eni("eni-secondary", "i-1", "eth1")
        enis = idx.get_enis_for_instance("i-1")
        assert [e.eni_id for e in enis] == ["eni-primary", "eni-secondary"]

    def test_get_primary_ip_for_instance(self):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5", instance_id="i-1",
        )
        idx.register_eni(
            "eni-2", "vpc-1", "sub-a", "10.0.0.6", instance_id="i-1",
        )
        assert idx.get_primary_ip_for_instance("i-1") == ipaddress.IPv4Address(
            "10.0.0.5",
        )

    def test_get_primary_ip_for_instance_no_enis(self):
        idx = AddressIndex()
        assert idx.get_primary_ip_for_instance("i-orphan") is None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_round_trip(self, tmp_path):
        idx = AddressIndex()
        idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
            sg_ids=["sg-web", "sg-app"], instance_id="i-1", iface_name="eth0",
            secondary_ips=["10.0.0.50"],
        )
        idx.register_eni(
            "eni-2", "vpc-1", "sub-a", "10.0.0.6",
            sg_ids=["sg-db"], instance_id="i-2", iface_name="eth0",
        )
        path = tmp_path / "addr.state"
        idx.save_to_file(str(path))
        assert path.exists()

        loaded = AddressIndex()
        assert loaded.load_from_file(str(path)) is True
        e1 = loaded.get_eni("eni-1")
        assert e1.primary_ip == ipaddress.IPv4Address("10.0.0.5")
        assert e1.secondary_ips == [ipaddress.IPv4Address("10.0.0.50")]
        assert e1.sg_ids == ["sg-web", "sg-app"]
        assert e1.instance_id == "i-1"
        assert e1.iface_name == "eth0"
        # Reverse indexes rebuilt
        assert loaded.get_eni_for_ip("10.0.0.50").eni_id == "eni-1"
        assert ipaddress.IPv4Address("10.0.0.5") in loaded.get_ips_for_sg("sg-web")
        assert loaded.get_enis_for_instance("i-2")[0].eni_id == "eni-2"

    def test_load_missing(self, tmp_path):
        assert AddressIndex().load_from_file(str(tmp_path / "missing")) is False

    def test_load_corrupt(self, tmp_path):
        path = tmp_path / "addr.state"
        path.write_text("{{ not json")
        idx = AddressIndex()
        assert idx.load_from_file(str(path)) is False
        assert idx.all_enis() == []

    def test_load_wrong_schema(self, tmp_path):
        path = tmp_path / "addr.state"
        path.write_text(json.dumps({"schema_version": 999, "enis": []}))
        idx = AddressIndex()
        idx.load_from_file(str(path))
        assert idx.all_enis() == []


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
class TestSingleton:
    def test_same_instance(self):
        assert get_address_index() is get_address_index()

    def test_reset_clears(self):
        a = get_address_index()
        reset_address_index_for_tests()
        b = get_address_index()
        assert a is not b
