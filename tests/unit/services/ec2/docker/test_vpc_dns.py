"""Unit tests for ``localemu.services.ec2.docker.vpc_dns``.

The resolver reads moto's ``DHCPOptionsSet`` + ``Vpc`` + ``Subnet``
structures, so the tests use real moto backends (lazy-imported) and
construct each scenario via the standard moto API - no boto, no
gateway, no Docker.
"""
from __future__ import annotations

import uuid

import pytest

from localemu.services.ec2.docker.vpc_dns import resolve_vpc_dns_servers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ec2_backend():
    """Fresh moto EC2 backend (unique account so tests can't cross-contaminate)."""
    from moto.ec2.models import ec2_backends

    region = "us-east-1"
    account_id = str(int(uuid.uuid4().int % 10_000_000_000)).zfill(12)
    return ec2_backends[account_id][region], account_id, region


def _make_subnet(ec2_backend, *, vpc_cidr="10.0.0.0/16", subnet_cidr="10.0.1.0/24"):
    vpc = ec2_backend.create_vpc(cidr_block=vpc_cidr)
    subnet = ec2_backend.create_subnet(
        vpc_id=vpc.id,
        cidr_block=subnet_cidr,
        availability_zone="us-east-1a",
    )
    return vpc, subnet


def _make_dhcp_options(ec2_backend, *, domain_name_servers):
    """Create a DHCP options set with the given DNS list (or None).

    ``EC2Backend.create_dhcp_options`` (the in-process method, NOT
    the wire-protocol entry point) takes keyword arguments - the
    ``[{"Key", "Values"}, ...]`` list-of-dicts shape only lives at
    the response layer.
    """
    return ec2_backend.create_dhcp_options(
        domain_name_servers=domain_name_servers,
    )


# ---------------------------------------------------------------------------
# No-subnet / no-VPC / no-DHCP cases
# ---------------------------------------------------------------------------


def test_no_subnet_id_returns_empty():
    assert resolve_vpc_dns_servers(
        subnet_id=None, account_id="0", region="us-east-1",
    ) == []


def test_unknown_subnet_returns_empty(ec2_backend):
    _, account_id, region = ec2_backend
    assert resolve_vpc_dns_servers(
        subnet_id="subnet-does-not-exist",
        account_id=account_id, region=region,
    ) == []


def test_unknown_account_returns_empty():
    """A garbage account_id must not crash; just return ``[]``."""
    assert resolve_vpc_dns_servers(
        subnet_id="subnet-x",
        account_id="000000000999",
        region="ap-southeast-99",
    ) == []


def test_vpc_with_no_dhcp_options_returns_empty(ec2_backend):
    backend, account_id, region = ec2_backend
    _vpc, subnet = _make_subnet(backend)
    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == []


def test_dhcp_options_with_no_dns_servers_returns_empty(ec2_backend):
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    # Build options that explicitly set domain-name but no DNS list.
    options = backend.create_dhcp_options(domain_name="example.com")
    backend.associate_dhcp_options(options, vpc)
    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == []


# ---------------------------------------------------------------------------
# Normal DNS-hijack reproduction
# ---------------------------------------------------------------------------


def test_single_dns_server_returned(ec2_backend):
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    options = _make_dhcp_options(backend, domain_name_servers=["6.6.6.6"])
    backend.associate_dhcp_options(options, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["6.6.6.6"]


def test_multiple_dns_servers_preserved_in_order(ec2_backend):
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    options = _make_dhcp_options(
        backend,
        domain_name_servers=["10.10.10.10", "8.8.8.8", "1.1.1.1"],
    )
    backend.associate_dhcp_options(options, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["10.10.10.10", "8.8.8.8", "1.1.1.1"]


def test_dns_hijack_attack_scenario(ec2_backend):
    """Reproduction of the scenario: - malicious DHCP options redirect DNS."""
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)

    # Initially: no DHCP option set associated -> Docker default DNS.
    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == []

    # Attacker creates + associates a hijack option set.
    evil = _make_dhcp_options(backend, domain_name_servers=["6.6.6.6"])
    backend.associate_dhcp_options(evil, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["6.6.6.6"]


# ---------------------------------------------------------------------------
# AmazonProvidedDNS handling
# ---------------------------------------------------------------------------


def test_amazon_provided_dns_dropped_by_default(ec2_backend):
    """``AmazonProvidedDNS`` is meaningless inside a LocalEmu container."""
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    options = _make_dhcp_options(
        backend,
        domain_name_servers=["AmazonProvidedDNS"],
    )
    backend.associate_dhcp_options(options, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == []


def test_amazon_provided_dns_kept_when_caller_asks(ec2_backend):
    """Tests can assert the raw moto contents by disabling the filter."""
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    options = _make_dhcp_options(
        backend,
        domain_name_servers=["AmazonProvidedDNS", "8.8.8.8"],
    )
    backend.associate_dhcp_options(options, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
        drop_amazon_provided_dns=False,
    ) == ["AmazonProvidedDNS", "8.8.8.8"]


def test_mixed_amazon_provided_and_real_keeps_only_real(ec2_backend):
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)
    options = _make_dhcp_options(
        backend,
        domain_name_servers=["AmazonProvidedDNS", "8.8.8.8"],
    )
    backend.associate_dhcp_options(options, vpc)

    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["8.8.8.8"]


# ---------------------------------------------------------------------------
# DHCP changed after instance launch - verify resolution is point-in-time
# ---------------------------------------------------------------------------


def test_re_association_changes_resolved_value(ec2_backend):
    """The resolver reads current moto state - re-associating a new
    option set immediately changes what the next launching instance sees."""
    backend, account_id, region = ec2_backend
    vpc, subnet = _make_subnet(backend)

    first = _make_dhcp_options(backend, domain_name_servers=["1.1.1.1"])
    backend.associate_dhcp_options(first, vpc)
    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["1.1.1.1"]

    second = _make_dhcp_options(backend, domain_name_servers=["9.9.9.9"])
    backend.associate_dhcp_options(second, vpc)
    assert resolve_vpc_dns_servers(
        subnet_id=subnet.id, account_id=account_id, region=region,
    ) == ["9.9.9.9"]
