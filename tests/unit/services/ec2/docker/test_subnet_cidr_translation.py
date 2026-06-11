"""Unit pins for the subnet AWS→Docker CIDR translation.

The subnet allocator carves IPs within a ``docker_cidr`` that MUST be
a sub-range of the VPC bridge's actual subnet. When the VPC bridge
takes its CIDR straight from the user's AWS request the two CIDRs
match and the translation is the identity. When the AWS CIDR collided
with another Docker network and the bridge fell back to a non-AWS
tier (e.g. AWS 10.86.0.0/16 → Docker 10.0.0.0/16), the subnet's pool
must follow the bridge or every ``connect_container_to_network --ip``
call will be rejected.

These tests pin the math so a future regression that mis-shifts the
base address would surface immediately.
"""
from __future__ import annotations

import ipaddress

import pytest

from localemu.services.ec2.docker.vpc_network import (
    translate_subnet_aws_to_docker_cidr,
)


# ---------------------------------------------------------------------------
# Happy path: AWS == Docker → identity
# ---------------------------------------------------------------------------


def test_identity_when_vpc_aws_equals_vpc_docker():
    """The no-collision path is the most common — the translation must
    return the subnet's AWS CIDR unchanged. Anything else would be a
    semantic drift even though the math could be performed."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.86.0.0/16",
        vpc_docker_cidr="10.86.0.0/16",
        subnet_aws_cidr="10.86.1.0/24",
    )
    assert out == "10.86.1.0/24"


def test_identity_for_full_vpc_subnet():
    """When the subnet IS the VPC (a single-subnet VPC), identity still
    applies. The translation is a pure function — it must not assume
    the subnet is strictly smaller than the VPC."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.99.0.0/24",
        vpc_docker_cidr="10.99.0.0/24",
        subnet_aws_cidr="10.99.0.0/24",
    )
    assert out == "10.99.0.0/24"


# ---------------------------------------------------------------------------
# Fallback path: AWS != Docker → shift
# ---------------------------------------------------------------------------


def test_shifts_subnet_when_vpc_bridge_fell_back_to_different_tier():
    """The case Tarek hit on 2026-06-07: user CreateVpc(10.86.0.0/16),
    Docker bridge already held 10.86.0.0/16 from a prior orphan, so
    the fallback picker landed the new bridge on 10.0.0.0/16. The
    subnet's AWS CIDR 10.86.1.0/24 must shift to 10.0.1.0/24 to lie
    inside the bridge."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.86.0.0/16",
        vpc_docker_cidr="10.0.0.0/16",
        subnet_aws_cidr="10.86.1.0/24",
    )
    assert out == "10.0.1.0/24"
    # Sanity: the result fits inside the bridge
    assert ipaddress.IPv4Network(out).subnet_of(
        ipaddress.IPv4Network("10.0.0.0/16"),
    )


def test_shifts_preserves_subnet_prefix_length():
    """A /28 subnet must stay /28 after translation — the bridge
    fallback only moves the base address, not the size."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.50.0.0/16",
        vpc_docker_cidr="172.20.0.0/16",
        subnet_aws_cidr="10.50.4.16/28",
    )
    assert out == "172.20.4.16/28"


def test_shifts_into_172_16_tier():
    """The 172.16/12 fallback tier slices into /16s skipping 172.17/16.
    A 10.x VPC shifted to 172.18.0.0/16 must place its subnets in the
    172.18 range, not collide with 172.17 (Docker's own default
    bridge)."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.10.0.0/16",
        vpc_docker_cidr="172.18.0.0/16",
        subnet_aws_cidr="10.10.5.0/24",
    )
    assert out == "172.18.5.0/24"


def test_shifts_into_100_64_carrier_grade_nat_tier():
    """RFC 6598 (100.64/10) is one of the fallback tiers used when 10/8
    and 172.16/12 are exhausted. The translation has no special-case
    for the CGNAT range — pure base shift, same as the others."""
    out = translate_subnet_aws_to_docker_cidr(
        vpc_aws_cidr="10.42.0.0/16",
        vpc_docker_cidr="100.64.0.0/16",
        subnet_aws_cidr="10.42.7.0/24",
    )
    assert out == "100.64.7.0/24"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_rejects_subnet_below_vpc_base():
    """A subnet whose AWS network address is BELOW the VPC's AWS base
    is internally inconsistent — moto wouldn't allow CreateSubnet for
    it. We surface the bug rather than silently shift into negative
    offsets."""
    with pytest.raises(ValueError, match="below VPC base"):
        translate_subnet_aws_to_docker_cidr(
            vpc_aws_cidr="10.86.5.0/24",
            vpc_docker_cidr="10.0.5.0/24",
            subnet_aws_cidr="10.86.4.0/24",
        )


def test_rejects_translated_subnet_outside_bridge():
    """If the VPC bridge is /20 but the subnet at its offset would
    extend past the bridge's broadcast, the translation must refuse
    rather than emit a CIDR Docker would reject at runtime. Lets the
    caller fall back to auto-IPAM with a clean log line."""
    # Bridge is 192.168.16.0/20 (192.168.16.0 - 192.168.31.255).
    # AWS subnet at offset 0x1000 (=4096) from VPC base 10.86.0.0
    # is 10.86.16.0; the translated docker base is 192.168.32.0,
    # which is OUTSIDE the bridge.
    with pytest.raises(ValueError, match="does not fit"):
        translate_subnet_aws_to_docker_cidr(
            vpc_aws_cidr="10.86.0.0/16",
            vpc_docker_cidr="192.168.16.0/20",
            subnet_aws_cidr="10.86.16.0/24",
        )
