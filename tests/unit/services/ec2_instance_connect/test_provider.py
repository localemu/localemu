"""Unit tests for the EC2 Instance Connect provider.

Docker interactions and the AWS handler dispatch layer are mocked ;
this suite pins the pure logic : input validation, target-home
computation, and marker-block formatting.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.ec2_instance_connect.provider import (
    Ec2InstanceConnectProvider,
    _target_homes,
    _merge_payload,
)


class _FakeContext:
    account_id = "000000000000"
    region = "us-east-1"


def _make_provider():
    return Ec2InstanceConnectProvider()


# ------- pure helpers -----------------------------------------------------


def test_target_homes_for_ubuntu_returns_user_and_root():
    homes = _target_homes("ubuntu")
    assert homes == [("ubuntu", "/home/ubuntu"), ("root", "/root")]


def test_target_homes_for_ec2_user_returns_user_and_root():
    homes = _target_homes("ec2-user")
    assert homes == [("ec2-user", "/home/ec2-user"), ("root", "/root")]


def test_target_homes_for_root_returns_root_only():
    """When caller asked for root, don't inject into ``/home/root``."""
    assert _target_homes("root") == [("root", "/root")]


def test_merge_payload_prefers_expanded_kwargs():
    assert _merge_payload(None, {"a": 1}) == {"a": 1}
    assert _merge_payload({"a": 1}, {"a": 2}) == {"a": 2}
    assert _merge_payload({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}


# ------- SendSSHPublicKey validation --------------------------------------


def test_missing_instance_id_raises_validation_exception():
    p = _make_provider()
    with pytest.raises(CommonServiceException) as e:
        p.send_ssh_public_key(
            _FakeContext(),
            {"InstanceOSUser": "ubuntu", "SSHPublicKey": "ssh-ed25519 A"},
        )
    assert e.value.code == "ValidationException"


def test_missing_os_user_raises_validation_exception():
    p = _make_provider()
    with pytest.raises(CommonServiceException) as e:
        p.send_ssh_public_key(
            _FakeContext(),
            {"InstanceId": "i-abc", "SSHPublicKey": "ssh-ed25519 A"},
        )
    assert e.value.code == "ValidationException"


def test_missing_ssh_key_raises_validation_exception():
    p = _make_provider()
    with pytest.raises(CommonServiceException) as e:
        p.send_ssh_public_key(
            _FakeContext(),
            {"InstanceId": "i-abc", "InstanceOSUser": "ubuntu"},
        )
    assert e.value.code == "ValidationException"


# ------- SendSSHPublicKey behaviour ---------------------------------------


def test_unknown_instance_returns_ec2instance_not_found():
    p = _make_provider()
    with patch(
        "localemu.services.ec2_instance_connect.provider._resolve_container",
        return_value=None,
    ):
        with pytest.raises(CommonServiceException) as e:
            p.send_ssh_public_key(
                _FakeContext(),
                {
                    "InstanceId": "i-nope",
                    "InstanceOSUser": "ubuntu",
                    "SSHPublicKey": "ssh-ed25519 A",
                },
            )
    assert e.value.code == "EC2InstanceNotFoundException"


def test_send_ssh_public_key_writes_to_both_homes_and_schedules_cleanup():
    """Happy path : the base64-wrapped marker block is written to
    ``/home/ubuntu/.ssh`` AND ``/root/.ssh`` ; a cleanup Timer is
    scheduled.
    """
    p = _make_provider()
    fake_docker = MagicMock()
    with (
        patch(
            "localemu.services.ec2_instance_connect.provider._resolve_container",
            return_value="localemu-ec2-i-abc",
        ),
        patch(
            "localemu.utils.docker_utils.DOCKER_CLIENT",
            fake_docker,
        ),
        patch(
            "threading.Timer",
        ) as fake_timer,
    ):
        result = p.send_ssh_public_key(
            _FakeContext(),
            {
                "InstanceId": "i-abc",
                "InstanceOSUser": "ubuntu",
                "SSHPublicKey": "ssh-ed25519 AAAA test-key",
            },
        )

    assert result["Success"] is True
    assert result["RequestId"]  # non-empty UUID

    # Two calls to exec_in_container : one for /home/ubuntu, one for /root.
    calls = fake_docker.exec_in_container.call_args_list
    assert len(calls) == 2
    scripts = [c.args[1][2] for c in calls]
    assert any("/home/ubuntu/.ssh" in s for s in scripts)
    assert any("/root/.ssh" in s for s in scripts)

    # Cleanup Timer scheduled for 60 seconds.
    fake_timer.assert_called_once()
    ttl_arg = fake_timer.call_args.args[0]
    assert ttl_arg == 60


def test_root_os_user_only_writes_root_home():
    """``InstanceOSUser=root`` must not create a spurious ``/home/root``."""
    p = _make_provider()
    fake_docker = MagicMock()
    with (
        patch(
            "localemu.services.ec2_instance_connect.provider._resolve_container",
            return_value="localemu-ec2-i-abc",
        ),
        patch(
            "localemu.utils.docker_utils.DOCKER_CLIENT",
            fake_docker,
        ),
        patch("threading.Timer"),
    ):
        p.send_ssh_public_key(
            _FakeContext(),
            {
                "InstanceId": "i-abc",
                "InstanceOSUser": "root",
                "SSHPublicKey": "ssh-ed25519 AAAA root-key",
            },
        )

    scripts = [
        c.args[1][2]
        for c in fake_docker.exec_in_container.call_args_list
    ]
    assert len(scripts) == 1
    assert "/root/.ssh" in scripts[0]
    assert "/home/root" not in scripts[0]


def test_serial_console_returns_aws_shaped_error():
    p = _make_provider()
    with pytest.raises(CommonServiceException) as e:
        p.send_serial_console_ssh_public_key(
            _FakeContext(),
            {"InstanceId": "i-abc"},
        )
    assert e.value.code == "SerialConsoleAccessDisabledException"
