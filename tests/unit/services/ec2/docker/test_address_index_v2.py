"""v2 schema bump tests for EniEntry.

Adds three fields needed by the ENI design:
  - source_dest_check (default True, matches AWS NetworkInterface default)
  - delete_on_termination (default True for primary, False for explicit
    standalone ENIs — the handler sets it explicitly)
  - device_index (None when detached, int when attached at that index)

Persistence must accept v1 snapshots and fill the new fields with
AWS-default values so users upgrading don't lose their ENI state.
"""
from __future__ import annotations

import json

import pytest

from localemu.services.ec2.docker.address_index import (
    AddressIndex,
    EniEntry,
    SCHEMA_VERSION,
    reset_address_index_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_address_index_for_tests()
    yield
    reset_address_index_for_tests()


class TestV2Fields:
    def test_schema_version_is_2(self):
        assert SCHEMA_VERSION == 2

    def test_defaults_match_aws(self):
        """New EniEntry without explicit v2 kwargs has AWS-default values."""
        idx = AddressIndex()
        e = idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
        )
        assert e.source_dest_check is True
        assert e.delete_on_termination is True
        assert e.device_index is None  # detached on register

    def test_v2_fields_round_trip(self, tmp_path):
        idx = AddressIndex()
        e = idx.register_eni(
            "eni-1", "vpc-1", "sub-a", "10.0.0.5",
        )
        e.source_dest_check = False
        e.delete_on_termination = False
        e.device_index = 2

        path = tmp_path / "v2.state"
        idx.save_to_file(str(path))

        loaded = AddressIndex()
        assert loaded.load_from_file(str(path)) is True
        e2 = loaded.get_eni("eni-1")
        assert e2.source_dest_check is False
        assert e2.delete_on_termination is False
        assert e2.device_index == 2


class TestV1Migration:
    def test_loads_v1_snapshot_with_aws_defaults(self, tmp_path):
        """A v1 snapshot has no source_dest_check / delete_on_termination /
        device_index. Loading must succeed and fill with AWS defaults."""
        v1_data = {
            "schema_version": 1,
            "enis": [
                {
                    "eni_id": "eni-from-v1",
                    "vpc_id": "vpc-old",
                    "subnet_id": "sub-old",
                    "primary_ip": "10.99.0.5",
                    "mac": "02:42:0a:63:00:05",
                    "secondary_ips": ["10.99.0.6"],
                    "sg_ids": ["sg-legacy"],
                    "instance_id": "i-legacy",
                    "iface_name": "eth1",
                    # no v2 fields
                },
            ],
        }
        path = tmp_path / "v1.state"
        path.write_text(json.dumps(v1_data))

        idx = AddressIndex()
        assert idx.load_from_file(str(path)) is True
        e = idx.get_eni("eni-from-v1")
        assert e is not None
        # v1 fields preserved
        assert str(e.primary_ip) == "10.99.0.5"
        assert e.instance_id == "i-legacy"
        assert e.iface_name == "eth1"
        # v2 fields defaulted per AWS
        assert e.source_dest_check is True
        assert e.delete_on_termination is True
        assert e.device_index is None

    def test_unknown_schema_still_rejected(self, tmp_path):
        """Schema > 2 (a future version we don't know) is still ignored
        with a WARN log (matches existing semantics)."""
        future_data = {"schema_version": 99, "enis": []}
        path = tmp_path / "future.state"
        path.write_text(json.dumps(future_data))

        idx = AddressIndex()
        idx.load_from_file(str(path))
        assert idx.all_enis() == []


class TestDataclassConstruction:
    def test_can_set_v2_fields_at_construct(self):
        import ipaddress
        e = EniEntry(
            eni_id="eni-x",
            vpc_id="vpc-x",
            subnet_id="sub-x",
            primary_ip=ipaddress.IPv4Address("10.0.0.10"),
            mac="02:42:0a:00:00:0a",
            source_dest_check=False,
            delete_on_termination=False,
            device_index=3,
        )
        assert e.source_dest_check is False
        assert e.delete_on_termination is False
        assert e.device_index == 3
