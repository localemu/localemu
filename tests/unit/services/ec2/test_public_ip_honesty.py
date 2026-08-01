"""``DescribeInstances`` returns a truthful ``PublicIpAddress``.

Regression checks that pin the promises independently of the
running Docker daemon :

1. ``_resolve_pubport_ip_for_instance`` returns whatever the Docker
   helper says, and ``None`` when the helper says nothing / fails.
2. ``_surface_localemu_public_ip`` mutates an instance dict correctly :
   sets the pubport IP + AWS-shape DNS name when reachable ; strips
   the fields entirely otherwise. Never leaves a moto ``54.x.x.x``
   fabrication in place.
3. The AWS-shaped ``PublicDnsName`` follows the
   ``ec2-<ip-dashed>.compute-1.amazonaws.com`` convention.
"""
from __future__ import annotations

from unittest.mock import patch

from localemu.services.ec2.provider import (
    Ec2Provider,
    _resolve_pubport_ip_for_instance,
)


def test_resolve_pubport_returns_none_for_empty_instance_id():
    assert _resolve_pubport_ip_for_instance(None) is None
    assert _resolve_pubport_ip_for_instance("") is None


def test_resolve_pubport_returns_ip_from_docker_helper():
    with patch(
        "localemu.utils.docker_utils.DOCKER_CLIENT."
        "get_container_ipv4_for_network",
        return_value="172.31.255.42",
    ):
        assert (
            _resolve_pubport_ip_for_instance("i-abc") == "172.31.255.42"
        )


def test_resolve_pubport_returns_none_when_helper_yields_empty():
    with patch(
        "localemu.utils.docker_utils.DOCKER_CLIENT."
        "get_container_ipv4_for_network",
        return_value="",
    ):
        assert _resolve_pubport_ip_for_instance("i-abc") is None


def test_resolve_pubport_returns_none_when_helper_raises():
    with patch(
        "localemu.utils.docker_utils.DOCKER_CLIENT."
        "get_container_ipv4_for_network",
        side_effect=RuntimeError("docker daemon down"),
    ):
        assert _resolve_pubport_ip_for_instance("i-abc") is None


def test_surface_replaces_moto_54_fabrication_with_pubport_ip():
    """The primary contract: moto's ``54.214.x.x`` never leaks."""
    inst = {
        "InstanceId": "i-abc",
        "PublicIpAddress": "54.214.99.42",   # moto's random_public_ip
        "PublicDnsName": "ec2-54-214-99-42.compute-1.amazonaws.com",
    }
    with patch(
        "localemu.services.ec2.provider._resolve_pubport_ip_for_instance",
        return_value="172.31.255.10",
    ):
        Ec2Provider._surface_localemu_public_ip(inst)

    assert inst["PublicIpAddress"] == "172.31.255.10"
    assert (
        inst["PublicDnsName"]
        == "ec2-172-31-255-10.compute-1.amazonaws.com"
    )


def test_surface_removes_public_fields_when_no_pubport_attachment():
    """Instances with no public IP (private-only, MapPublicIpOnLaunch=false,
    no EIP) must have the fields OMITTED entirely, matching real AWS.
    """
    inst = {
        "InstanceId": "i-private",
        "PublicIpAddress": "54.214.99.99",   # moto fabrication
        "PublicDnsName": "ec2-54-214-99-99.compute-1.amazonaws.com",
    }
    with patch(
        "localemu.services.ec2.provider._resolve_pubport_ip_for_instance",
        return_value=None,
    ):
        Ec2Provider._surface_localemu_public_ip(inst)

    assert "PublicIpAddress" not in inst
    assert "PublicDnsName" not in inst


def test_surface_is_a_noop_when_instance_id_missing():
    inst = {}  # no InstanceId at all
    with patch(
        "localemu.services.ec2.provider._resolve_pubport_ip_for_instance",
        return_value=None,
    ):
        Ec2Provider._surface_localemu_public_ip(inst)
    # No crash ; no fields added.
    assert "PublicIpAddress" not in inst


def test_dns_name_uses_aws_convention_ec2_dashed_ip():
    """AWS's public DNS name has the form
    ``ec2-<ip-with-dots-as-dashes>.compute-1.amazonaws.com``. Any
    deviation confuses tools that DNS-parse the returned name.
    """
    inst = {"InstanceId": "i-xyz"}
    with patch(
        "localemu.services.ec2.provider._resolve_pubport_ip_for_instance",
        return_value="10.20.30.40",
    ):
        Ec2Provider._surface_localemu_public_ip(inst)
    assert inst["PublicDnsName"] == "ec2-10-20-30-40.compute-1.amazonaws.com"
