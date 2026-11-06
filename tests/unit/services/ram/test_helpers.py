"""Tests for RAM cross-account shared-subnet visibility helpers.

Deliberately exercises real moto backends (ram_backends/ec2_backends), not
flattened mocks - two independent reviews of the design doc caught the
same bug in an earlier draft: moto's SubnetBackend.subnets is keyed by
availability zone first, then subnet ID, not a flat {subnet_id: Subnet}
dict. A mock that skips that shape would hide exactly this bug.
"""
from __future__ import annotations

import localemu.services.ram  # noqa: F401 - triggers the patch at import
from localemu.services.ram.helpers import get_shared_subnet_arns, get_shared_subnets

ACCOUNT_A = "111111111111"  # owns the subnet
ACCOUNT_B = "222222222222"  # named principal on the share
ACCOUNT_C = "333333333333"  # NOT a principal - negative control
REGION = "us-east-1"


def _ram_backend(account_id):
    from moto.ram.models import ram_backends

    return ram_backends[account_id][REGION]


def _ec2_backend(account_id):
    from moto.ec2.models import ec2_backends

    return ec2_backends[account_id][REGION]


def _make_real_subnet(account_id):
    """A real moto Subnet, created through the real backend call (so it
    lands in the real AZ-keyed self.subnets[az][id] structure), not a
    hand-built stand-in."""
    backend = _ec2_backend(account_id)
    vpc = backend.create_vpc("10.0.0.0/16")
    subnet = backend.create_subnet(vpc.id, "10.0.1.0/24", None, "us-east-1a", None)
    return subnet


class TestGetSharedSubnetArns:
    def test_principal_account_sees_the_shared_subnet_arn(self):
        subnet = _make_real_subnet(ACCOUNT_A)
        subnet_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:subnet/{subnet.id}"
        backend = _ram_backend(ACCOUNT_A)
        backend.create_resource_share(
            name="share1", principals=[ACCOUNT_B], resourceArns=[subnet_arn],
        )

        shared = get_shared_subnet_arns(ACCOUNT_B, REGION)

        assert (subnet_arn, ACCOUNT_A) in shared

    def test_non_principal_account_sees_nothing(self):
        subnet = _make_real_subnet(ACCOUNT_A)
        subnet_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:subnet/{subnet.id}"
        backend = _ram_backend(ACCOUNT_A)
        backend.create_resource_share(
            name="share2", principals=[ACCOUNT_B], resourceArns=[subnet_arn],
        )

        shared = get_shared_subnet_arns(ACCOUNT_C, REGION)

        assert shared == []

    def test_deleted_share_grants_no_visibility(self):
        subnet = _make_real_subnet(ACCOUNT_A)
        subnet_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:subnet/{subnet.id}"
        backend = _ram_backend(ACCOUNT_A)
        share = backend.create_resource_share(
            name="share3", principals=[ACCOUNT_B], resourceArns=[subnet_arn],
        )["resourceShare"]
        backend.delete_resource_share(share["resourceShareArn"])

        shared = get_shared_subnet_arns(ACCOUNT_B, REGION)

        assert shared == []

    def test_revoke_then_reverify_principal_stops_seeing_it(self):
        """The negative-control-after-revoke case all 3 independent
        reviews flagged as the required addition, not optional polish -
        exactly where a sloppy implementation could become a real
        cross-account info-disclosure bug if it cached principal lists
        rather than re-checking share state on every call."""
        subnet = _make_real_subnet(ACCOUNT_A)
        subnet_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:subnet/{subnet.id}"
        backend = _ram_backend(ACCOUNT_A)
        share = backend.create_resource_share(
            name="share4", principals=[ACCOUNT_B], resourceArns=[subnet_arn],
        )["resourceShare"]
        arn = share["resourceShareArn"]

        assert (subnet_arn, ACCOUNT_A) in get_shared_subnet_arns(ACCOUNT_B, REGION)

        backend.disassociate_resource_share(arn, principals=[ACCOUNT_B])

        assert get_shared_subnet_arns(ACCOUNT_B, REGION) == []

    def test_non_subnet_resource_arns_are_ignored(self):
        """A share could name other RAM-shareable resource types
        (transit-gateway, prefix-list, ...) - this helper is scoped to
        subnets only and must not leak those ARNs through."""
        backend = _ram_backend(ACCOUNT_A)
        tgw_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:transit-gateway/tgw-abc123"
        backend.create_resource_share(
            name="share5", principals=[ACCOUNT_B], resourceArns=[tgw_arn],
        )

        assert get_shared_subnet_arns(ACCOUNT_B, REGION) == []


class TestGetSharedSubnets:
    def test_returns_fully_rendered_subnet_matching_describe_subnets_shape(self):
        subnet = _make_real_subnet(ACCOUNT_A)
        subnet_arn = f"arn:aws:ec2:{REGION}:{ACCOUNT_A}:subnet/{subnet.id}"
        backend = _ram_backend(ACCOUNT_A)
        backend.create_resource_share(
            name="share6", principals=[ACCOUNT_B], resourceArns=[subnet_arn],
        )

        rendered = get_shared_subnets(ACCOUNT_B, REGION)

        assert len(rendered) == 1
        entry = rendered[0]
        assert entry["SubnetId"] == subnet.id
        assert entry["VpcId"] == subnet.vpc_id
        assert entry["CidrBlock"] == "10.0.1.0/24"
        assert entry["AvailabilityZone"] == "us-east-1a"
        assert entry["OwnerId"] == ACCOUNT_A

    def test_no_shares_returns_empty_list(self):
        assert get_shared_subnets(ACCOUNT_C, REGION) == []
