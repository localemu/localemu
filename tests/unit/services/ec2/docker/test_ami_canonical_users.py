"""Per-AMI canonical Linux user resolution.

Real AWS AMIs each ship a canonical Linux user. Every tutorial uses
``ssh <canonical>@<PublicIpAddress>``. This test locks the mapping so
we do not silently regress to root-only.
"""
from __future__ import annotations

from localemu.services.ec2.docker.ami_canonical_users import (
    CANONICAL_USER,
    resolve_canonical_user,
)


def test_ubuntu_amis_all_map_to_ubuntu():
    for ami in (
        "ami-ubuntu-22.04",
        "ami-ubuntu-24.04",
        "ami-ubuntu-20.04",
        "ami-localemu-ubuntu",
    ):
        assert resolve_canonical_user(ami) == "ubuntu", ami


def test_amazon_linux_maps_to_ec2_user():
    for ami in ("ami-amazon-linux-2023", "ami-amazon-linux-2", "ami-al2023"):
        assert resolve_canonical_user(ami) == "ec2-user", ami


def test_debian_maps_to_admin():
    for ami in ("ami-debian-11", "ami-debian-12"):
        assert resolve_canonical_user(ami) == "admin", ami


def test_alpine_maps_to_alpine():
    for ami in ("ami-alpine-3.18", "ami-alpine-3.20"):
        assert resolve_canonical_user(ami) == "alpine", ami


def test_centos_maps_to_cloud_user():
    assert resolve_canonical_user("ami-centos-9") == "cloud-user"


def test_unknown_ami_returns_none_so_caller_falls_back_to_root():
    """Custom / unknown AMIs must return ``None``. Callers treat that
    as "no LocalEmu-known user, root is the only entry point" - safer
    than guessing.
    """
    assert resolve_canonical_user("ami-custom-9876543210") is None
    assert resolve_canonical_user("") is None
    assert resolve_canonical_user(None) is None


def test_no_ami_maps_to_root():
    """We refuse to map any AMI to ``root``. If future maintenance
    adds a root row, this test flags it - ``_inject_ssh_key`` treats
    ``root`` as "second injection is redundant, skip it".
    """
    for ami_id, user in CANONICAL_USER.items():
        assert user != "root", (
            f"AMI {ami_id!r} maps to root ; use ``None`` (unknown) "
            f"instead if you want to skip canonical-user injection."
        )
