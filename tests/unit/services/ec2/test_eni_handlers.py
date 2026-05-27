"""Tests for the ENI handlers in Ec2Provider.

Each handler:
  1. Calls call_moto (we mock it)
  2. If LOCALEMU_ENI_REAL=1 (and prereq LOCALEMU_VPC_IP_PINNING=1),
     delegates the Docker-side work to EniManager
  3. Translates EniManager exceptions to AWS-shape CommonServiceException

These tests cover the orchestration glue without exercising the
underlying Docker operations (which have their own tests in
test_eni_manager.py + the real-Docker integration test).
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2 import provider as ec2_provider
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.eni_manager import (
    EniInUse,
    EniNotFound,
    InvalidEniState,
    get_eni_manager,
    reset_eni_manager_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    ec2_provider._ENI_FLAG_WARNED = False
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    ec2_provider._ENI_FLAG_WARNED = False


def _make_provider():
    """Build an Ec2Provider with the dependencies the handlers need."""
    p = ec2_provider.Ec2Provider()
    return p


def _ctx(account_id="000000000000", region="us-east-1"):
    """Minimal RequestContext stub."""
    ctx = mock.MagicMock()
    ctx.account_id = account_id
    ctx.region = region
    ctx.request = mock.MagicMock()
    ctx.request.values = {}
    return ctx


def _populate_subnet():
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
    )


# ---------------------------------------------------------------------------
# _eni_real_enabled flag gating
# ---------------------------------------------------------------------------
class TestFlagGating:
    def test_disabled_when_both_off(self):
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", False), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            assert ec2_provider._eni_real_enabled() is False

    def test_disabled_when_only_addressing_on(self):
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", False), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            assert ec2_provider._eni_real_enabled() is False

    def test_disabled_when_eni_set_but_prereq_off(self):
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", False):
            assert ec2_provider._eni_real_enabled() is False

    def test_enabled_when_both_on(self):
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True):
            assert ec2_provider._eni_real_enabled() is True


# ---------------------------------------------------------------------------
# CreateNetworkInterface
# ---------------------------------------------------------------------------
class TestCreateNetworkInterface:
    def test_flag_off_is_pure_moto(self):
        _populate_subnet()
        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", False), \
             mock.patch.object(
                 ec2_provider, "call_moto",
                 return_value={"NetworkInterface": {"NetworkInterfaceId": "eni-1"}},
             ):
            result = p.create_network_interface(_ctx(), {})
        # Allocator untouched (flag off path)
        assert get_subnet_allocator().describe("vpc-1")[0].allocated == {}
        # AddressIndex empty
        assert get_address_index().get_eni("eni-1") is None

    def test_flag_on_reserves_ip_and_registers_index(self):
        _populate_subnet()
        p = _make_provider()
        moto_response = {
            "NetworkInterface": {
                "NetworkInterfaceId": "eni-real",
                "SubnetId": "sub-a",
                "VpcId": "vpc-1",
                "Groups": [{"GroupId": "sg-web"}],
            },
        }
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 ec2_provider, "call_moto", return_value=moto_response,
             ), \
             mock.patch.object(ec2_provider, "_patch_moto_eni"):
            result = p.create_network_interface(_ctx(), {})
        # Allocator + index populated
        entry = get_address_index().get_eni("eni-real")
        assert entry is not None
        assert get_subnet_allocator().lookup(entry.primary_ip) == (
            "vpc-1", "sub-a", "eni:eni-real",
        )
        # Response shape updated with our IP + MAC
        eni = result["NetworkInterface"]
        assert eni["PrivateIpAddress"] == str(entry.primary_ip)
        assert eni["MacAddress"] == entry.mac
        assert eni["PrivateIpAddresses"] == [
            {"Primary": True, "PrivateIpAddress": str(entry.primary_ip)},
        ]

    def test_invalid_subnet_rolls_back_moto(self):
        # No subnet registered with allocator -> InvalidEniState
        p = _make_provider()
        moto_response = {
            "NetworkInterface": {
                "NetworkInterfaceId": "eni-bad",
                "SubnetId": "sub-unknown",
                "VpcId": "vpc-1",
                "Groups": [],
            },
        }
        rollback_called = []
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 ec2_provider, "call_moto", return_value=moto_response,
             ), \
             mock.patch.object(
                 ec2_provider.Ec2Provider, "_call_moto_op",
                 side_effect=lambda *a, **kw: rollback_called.append(a),
             ):
            from localemu.aws.api import CommonServiceException
            with pytest.raises(CommonServiceException):
                p.create_network_interface(_ctx(), {})
        # Rollback was attempted
        assert len(rollback_called) == 1


# ---------------------------------------------------------------------------
# AttachNetworkInterface
# ---------------------------------------------------------------------------
class TestAttachNetworkInterface:
    def test_flag_off_is_pure_moto(self):
        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", False), \
             mock.patch.object(
                 ec2_provider, "call_moto",
                 return_value={"AttachmentId": "eni-attach-1"},
             ):
            result = p.attach_network_interface(
                _ctx(),
                {"NetworkInterfaceId": "eni-1", "InstanceId": "i-1",
                 "DeviceIndex": "2"},
            )
        assert result["AttachmentId"] == "eni-attach-1"

    def test_flag_on_delegates_to_eni_manager(self):
        _populate_subnet()
        # Pre-register a detached ENI (as if CreateNetworkInterface ran)
        from localemu.services.ec2.docker.eni_manager import EniManager
        mgr = EniManager()
        mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )

        p = _make_provider()
        p._vm_manager = mock.MagicMock()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 ec2_provider, "call_moto",
                 return_value={"AttachmentId": "eni-attach-1"},
             ), \
             mock.patch(
                 "localemu.services.ec2.docker.eni_manager.get_eni_manager",
                 return_value=mgr,
             ), \
             mock.patch.object(mgr, "attach") as mock_attach:
            p.attach_network_interface(
                _ctx(),
                {"NetworkInterfaceId": "eni-1", "InstanceId": "i-1",
                 "DeviceIndex": "2"},
            )
            mock_attach.assert_called_once_with(
                eni_id="eni-1", instance_id="i-1", device_index=2,
            )


# ---------------------------------------------------------------------------
# DeleteNetworkInterface
# ---------------------------------------------------------------------------
class TestDeleteNetworkInterface:
    def test_flag_on_attached_raises_in_use(self):
        _populate_subnet()
        from localemu.services.ec2.docker.eni_manager import EniManager
        mgr = EniManager()
        mgr.create(
            eni_id="eni-1", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        # Force into attached state
        entry = get_address_index().get_eni("eni-1")
        entry.instance_id = "i-x"

        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch(
                 "localemu.services.ec2.docker.eni_manager.get_eni_manager",
                 return_value=mgr,
             ):
            from localemu.aws.api import CommonServiceException
            with pytest.raises(CommonServiceException) as excinfo:
                p.delete_network_interface(
                    _ctx(), {"NetworkInterfaceId": "eni-1"},
                )
            assert excinfo.value.code == "InvalidParameterValue"


# ---------------------------------------------------------------------------
# DescribeNetworkInterfaces enrichment
# ---------------------------------------------------------------------------
class TestDescribeNetworkInterfaces:
    def test_flag_off_returns_moto_unchanged(self):
        moto_resp = {
            "NetworkInterfaces": [
                {"NetworkInterfaceId": "eni-x", "PrivateIpAddress": "1.2.3.4"},
            ],
        }
        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", False), \
             mock.patch.object(
                 ec2_provider, "call_moto", return_value=moto_resp,
             ):
            result = p.describe_network_interfaces(_ctx(), {})
        # No enrichment
        assert result["NetworkInterfaces"][0]["PrivateIpAddress"] == "1.2.3.4"

    def test_flag_on_enriches_with_address_index_values(self):
        _populate_subnet()
        from localemu.services.ec2.docker.eni_manager import EniManager
        mgr = EniManager()
        ip, mac = mgr.create(
            eni_id="eni-real", vpc_id="vpc-1", subnet_id="sub-a", sg_ids=[],
        )
        # Add a secondary so the enrichment list includes it
        get_address_index().add_secondary_ip("eni-real", "10.0.5.55")

        moto_resp = {
            "NetworkInterfaces": [{
                "NetworkInterfaceId": "eni-real",
                "PrivateIpAddress": "wrong-moto-value",
                "MacAddress": "wrong-mac",
            }],
        }
        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 ec2_provider, "call_moto", return_value=moto_resp,
             ):
            result = p.describe_network_interfaces(_ctx(), {})
        eni = result["NetworkInterfaces"][0]
        assert eni["PrivateIpAddress"] == str(ip)
        assert eni["MacAddress"] == mac
        assert eni["SourceDestCheck"] is True  # default
        pias = eni["PrivateIpAddresses"]
        assert {"Primary": True, "PrivateIpAddress": str(ip)} in pias
        assert {"Primary": False, "PrivateIpAddress": "10.0.5.55"} in pias

    def test_flag_on_unknown_eni_left_alone(self):
        moto_resp = {
            "NetworkInterfaces": [
                {"NetworkInterfaceId": "eni-not-in-index",
                 "PrivateIpAddress": "1.2.3.4"},
            ],
        }
        p = _make_provider()
        with mock.patch("localemu.config.LOCALEMU_ENI_REAL", True), \
             mock.patch("localemu.config.LOCALEMU_VPC_IP_PINNING", True), \
             mock.patch.object(
                 ec2_provider, "call_moto", return_value=moto_resp,
             ):
            result = p.describe_network_interfaces(_ctx(), {})
        # No entry in index -> not touched
        assert result["NetworkInterfaces"][0]["PrivateIpAddress"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Error translation
# ---------------------------------------------------------------------------
class TestErrorTranslation:
    def test_eni_not_found_to_invalid_id(self):
        cse = ec2_provider._translate_eni_error(EniNotFound("oops"))
        assert cse.code == "InvalidNetworkInterfaceID.NotFound"

    def test_in_use_to_invalid_parameter(self):
        cse = ec2_provider._translate_eni_error(EniInUse("attached"))
        assert cse.code == "InvalidParameterValue"

    def test_invalid_state_to_invalid_parameter(self):
        cse = ec2_provider._translate_eni_error(InvalidEniState("bad cidr"))
        assert cse.code == "InvalidParameterValue"

    def test_unknown_exception_to_internal_error(self):
        cse = ec2_provider._translate_eni_error(RuntimeError("???"))
        assert cse.code == "InternalError"
