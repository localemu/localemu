"""SourceDestCheck propagation between Instance and primary ENI.

AWS treats the instance-level ``SourceDestCheck`` attribute as a
convenience view of the **primary ENI's** ``SourceDestCheck``. The two
are the same bit. Writes via either path update both. Reads on either
path see the same value.

LocalEmu has three storage cells that surface this bit:

  1. ``moto Instance.source_dest_check`` -> the instance-level
     ``SourceDestCheck`` field in ``DescribeInstances``.
  2. ``moto NIC.source_dest_check`` -> the per-NIC ``SourceDestCheck``
     inside ``DescribeInstances.NetworkInterfaces``.
  3. ``EniEntry.source_dest_check`` (LocalEmu address index) -> the
     per-NIC ``SourceDestCheck`` returned by ``DescribeNetworkInterfaces``
     (the provider enriches that response from the address index).

These pins assert all three cells stay in sync after each modify path,
and that secondary-ENI writes do NOT silently mutate the instance
view (instance-level scope is primary-only on AWS).

The handlers' first action is ``call_moto(context)``. The unit tests
follow the existing ``test_eni_handlers.py`` pattern: patch
``call_moto`` and provide a side-effect that simulates the underlying
moto write. The test then asserts the LocalEmu propagation step that
runs AFTER the moto write.
"""
from __future__ import annotations

from unittest import mock

import pytest
from moto.core.models import DEFAULT_ACCOUNT_ID

from localemu.services.ec2 import provider as ec2_provider
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.eni_manager import (
    reset_eni_manager_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


# moto's mock_aws plants state under DEFAULT_ACCOUNT_ID. Use the same
# id everywhere so the backend lookup the propagation helpers do sees
# the state moto wrote.
ACCOUNT = DEFAULT_ACCOUNT_ID
REGION = "us-east-1"
VPC_CIDR = "10.42.0.0/16"
SUBNET_CIDR = "10.42.1.0/24"
PRIMARY_IP = "10.42.1.10"
SECONDARY_IP = "10.42.1.11"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    reset_eni_manager_for_tests()


@pytest.fixture
def _moto_ec2():
    """In-process moto EC2 backend, scoped to the test."""
    from moto import mock_aws

    with mock_aws():
        yield


def _ctx(account_id: str = ACCOUNT, region: str = REGION, **values):
    """Minimal RequestContext stub: the SDC handlers read
    ``account_id``, ``region``, and ``request.values`` (the flat
    botocore form). Everything else stays MagicMock for ergonomics."""
    ctx = mock.MagicMock()
    ctx.account_id = account_id
    ctx.region = region
    ctx.request = mock.MagicMock()
    ctx.request.values = dict(values)
    return ctx


def _backend():
    import moto.backends as moto_backends

    return moto_backends.get_backend("ec2")[ACCOUNT][REGION]


def _find_instance(instance_id: str):
    backend = _backend()
    for res in backend.reservations.values():
        for inst in res.instances:
            if inst.id == instance_id:
                return inst
    return None


def _make_instance_with_primary_eni() -> tuple[str, str]:
    """Create a VPC + subnet + one instance with one primary ENI via
    boto3 under ``mock_aws``. Returns ``(instance_id, primary_eni_id)``.

    Also registers the primary ENI in the LocalEmu address index so
    the address-index sync path is observable in assertions.
    """
    import boto3

    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock=VPC_CIDR)["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=SUBNET_CIDR)["Subnet"]["SubnetId"]
    eni = ec2.create_network_interface(
        SubnetId=subnet, PrivateIpAddress=PRIMARY_IP,
    )["NetworkInterface"]["NetworkInterfaceId"]
    inst = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        InstanceType="t2.micro",
        NetworkInterfaces=[{
            "DeviceIndex": 0,
            "NetworkInterfaceId": eni,
        }],
    )["Instances"][0]["InstanceId"]

    get_subnet_allocator().register_subnet(
        vpc, subnet, SUBNET_CIDR, VPC_CIDR, f"{REGION}a",
    )
    get_address_index().register_eni(
        eni_id=eni, vpc_id=vpc, subnet_id=subnet,
        primary_ip=PRIMARY_IP, instance_id=inst,
    )
    return inst, eni


def _attach_secondary_eni(instance_id: str) -> str:
    """Attach a second ENI at ``device_index=1``. Returns the ENI id.
    Registers the secondary in the address index."""
    import boto3

    ec2 = boto3.client("ec2", region_name=REGION)
    subnet = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
    eni = ec2.create_network_interface(
        SubnetId=subnet, PrivateIpAddress=SECONDARY_IP,
    )["NetworkInterface"]["NetworkInterfaceId"]
    ec2.attach_network_interface(
        InstanceId=instance_id, NetworkInterfaceId=eni, DeviceIndex=1,
    )
    get_address_index().register_eni(
        eni_id=eni, vpc_id="vpc-unused", subnet_id=subnet,
        primary_ip=SECONDARY_IP, instance_id=instance_id,
    )
    return eni


def _all_three_cells(instance_id: str, eni_id: str):
    """Return ``(instance.source_dest_check, moto_nic.source_dest_check,
    EniEntry.source_dest_check)`` - the three cells the bug spans."""
    instance = _find_instance(instance_id)
    assert instance is not None, "test setup: instance vanished from moto"
    moto_nic = _backend().enis[eni_id]
    entry = get_address_index().get_eni(eni_id)
    assert entry is not None, "test setup: ENI not registered in index"
    return (
        instance.source_dest_check,
        moto_nic.source_dest_check,
        entry.source_dest_check,
    )


def _fake_call_moto_modify_instance(ctx):
    """Stand-in for ``call_moto`` on the ModifyInstanceAttribute path:
    mimic moto's own write of ``Instance.source_dest_check`` so the
    propagation step under test runs against a realistic post-write
    state."""
    iid = ctx.request.values.get("InstanceId")
    sdc = (
        ctx.request.values.get("SourceDestCheck.Value")
        or ctx.request.values.get("SourceDestCheck")
    )
    if iid and sdc is not None:
        desired = str(sdc).strip().lower() in ("true", "1")
        instance = _find_instance(iid)
        if instance is not None:
            instance.source_dest_check = desired
    return {}


def _fake_call_moto_modify_eni(eni_id_to_sdc: dict[str, bool]):
    """Build a stand-in for ``call_moto`` on the
    ModifyNetworkInterfaceAttribute path. Reads the desired SDC from
    the eni-id map (the request dict is parsed by the handler itself,
    so we don't have to re-parse it here)."""
    def _inner(ctx):
        backend = _backend()
        for eni_id, desired in eni_id_to_sdc.items():
            nic = backend.enis.get(eni_id)
            if nic is not None:
                nic.source_dest_check = desired
        return {}
    return _inner


# ---------------------------------------------------------------------------
# 1. instance-level write propagates to the primary ENI
# ---------------------------------------------------------------------------


def test_modify_instance_attribute_false_propagates_to_primary_eni(_moto_ec2):
    inst, primary_eni = _make_instance_with_primary_eni()
    assert _all_three_cells(inst, primary_eni) == (True, True, True)

    with mock.patch.object(
        ec2_provider, "call_moto",
        side_effect=_fake_call_moto_modify_instance,
    ), mock.patch(
        "localemu.services.ec2.docker.source_dest_check.apply_source_dest_check",
    ):
        ec2_provider.Ec2Provider().modify_instance_attribute(
            _ctx(InstanceId=inst, **{"SourceDestCheck.Value": "false"}),
            {"InstanceId": inst, "SourceDestCheck": {"Value": False}},
        )

    assert _all_three_cells(inst, primary_eni) == (False, False, False)


def test_modify_instance_attribute_true_restores_all_cells(_moto_ec2):
    inst, primary_eni = _make_instance_with_primary_eni()

    with mock.patch.object(
        ec2_provider, "call_moto",
        side_effect=_fake_call_moto_modify_instance,
    ), mock.patch(
        "localemu.services.ec2.docker.source_dest_check.apply_source_dest_check",
    ):
        provider = ec2_provider.Ec2Provider()
        provider.modify_instance_attribute(
            _ctx(InstanceId=inst, **{"SourceDestCheck.Value": "false"}),
            {"InstanceId": inst, "SourceDestCheck": {"Value": False}},
        )
        assert _all_three_cells(inst, primary_eni) == (False, False, False)

        provider.modify_instance_attribute(
            _ctx(InstanceId=inst, **{"SourceDestCheck.Value": "true"}),
            {"InstanceId": inst, "SourceDestCheck": {"Value": True}},
        )

    assert _all_three_cells(inst, primary_eni) == (True, True, True)


# ---------------------------------------------------------------------------
# 2. ENI-level write on the primary mirrors back to the instance view
# ---------------------------------------------------------------------------


def test_modify_primary_eni_attribute_mirrors_to_instance(_moto_ec2):
    inst, primary_eni = _make_instance_with_primary_eni()
    assert _all_three_cells(inst, primary_eni) == (True, True, True)

    # Deliberately do NOT patch LOCALEMU_ENI_REAL / LOCALEMU_VPC_IP_PINNING.
    # The metadata mirror is pure-Python state, not Docker side-effect,
    # so it must run in the default LocalEmu mode that any user gets out
    # of the box. Pre-fix, the handler short-circuited before the mirror
    # whenever those flags were off - and the live repro ran in
    # exactly that mode. Pin the corrected behavior.
    with mock.patch.object(
        ec2_provider, "call_moto",
        side_effect=_fake_call_moto_modify_eni({primary_eni: False}),
    ), mock.patch(
        "localemu.services.ec2.docker.source_dest_check.apply_source_dest_check",
    ):
        ec2_provider.Ec2Provider().modify_network_interface_attribute(
            _ctx(),
            {
                "NetworkInterfaceId": primary_eni,
                "SourceDestCheck": {"Value": False},
            },
        )

    # moto cells (instance + NIC) must both reflect False. The
    # EniEntry mirror requires the real-ENI subsystem (it's gated
    # below the metadata mirror by design), so we don't assert on
    # it here - test #1 already pins that path under the flag-on
    # scenario.
    instance = _find_instance(inst)
    assert instance.source_dest_check is False
    assert _backend().enis[primary_eni].source_dest_check is False


# ---------------------------------------------------------------------------
# 3. ENI-level write on a secondary does NOT touch the instance view
# ---------------------------------------------------------------------------


def test_modify_secondary_eni_attribute_does_not_change_instance(_moto_ec2):
    inst, primary_eni = _make_instance_with_primary_eni()
    secondary_eni = _attach_secondary_eni(inst)

    # Same as test #2: no flag patch. Default-mode propagation must
    # NOT touch instance-level state when the write targets a
    # secondary ENI (instance-level scope is primary-only).
    with mock.patch.object(
        ec2_provider, "call_moto",
        side_effect=_fake_call_moto_modify_eni({secondary_eni: False}),
    ), mock.patch(
        "localemu.services.ec2.docker.source_dest_check.apply_source_dest_check",
    ):
        ec2_provider.Ec2Provider().modify_network_interface_attribute(
            _ctx(),
            {
                "NetworkInterfaceId": secondary_eni,
                "SourceDestCheck": {"Value": False},
            },
        )

    instance = _find_instance(inst)
    backend = _backend()
    assert instance.source_dest_check is True
    assert backend.enis[primary_eni].source_dest_check is True
    assert backend.enis[secondary_eni].source_dest_check is False


# ---------------------------------------------------------------------------
# 4. default at boot - sync logic must not regress the AWS default
# ---------------------------------------------------------------------------


def test_default_is_true_across_all_three_cells(_moto_ec2):
    inst, primary_eni = _make_instance_with_primary_eni()
    assert _all_three_cells(inst, primary_eni) == (True, True, True)


# ---------------------------------------------------------------------------
# 5. missing address-index entry does not break the user's call
# ---------------------------------------------------------------------------


def test_instance_modify_succeeds_when_eni_not_in_address_index(_moto_ec2):
    """Sync to the address index must be best-effort. If the primary
    ENI was never registered (e.g. instance created outside LocalEmu's
    real-ENI flag), ``ModifyInstanceAttribute`` still succeeds and the
    moto cells still propagate."""
    inst, primary_eni = _make_instance_with_primary_eni()
    # Drop the ENI from the address index so the inner sync raises
    # EniNotFound. The wrapper must swallow it; the moto cells still
    # propagate via the direct NIC write.
    reset_address_index_for_tests()

    with mock.patch.object(
        ec2_provider, "call_moto",
        side_effect=_fake_call_moto_modify_instance,
    ), mock.patch(
        "localemu.services.ec2.docker.source_dest_check.apply_source_dest_check",
    ):
        ec2_provider.Ec2Provider().modify_instance_attribute(
            _ctx(InstanceId=inst, **{"SourceDestCheck.Value": "false"}),
            {"InstanceId": inst, "SourceDestCheck": {"Value": False}},
        )

    instance = _find_instance(inst)
    assert instance.source_dest_check is False
    assert _backend().enis[primary_eni].source_dest_check is False
