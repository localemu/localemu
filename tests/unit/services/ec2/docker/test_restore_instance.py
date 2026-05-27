"""Unit tests for EC2 restore completeness .

Previously ``restore_instance`` just ``docker start``ed the container
and rebuilt the in-memory info. Missing:

  - SG iptables were not re-applied (chains don't survive daemon restart).
  - NACL iptables were not re-applied.
  - VpcNetworkManager container tracking was not rebuilt.
  - STS credentials were not re-issued to IMDS (the code comment
    promised it; no code implemented it).

After the fix, ``restore_instance`` reads the labels we now write at
create time and drives a full reconciliation.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import vm_manager


def _inspect_for(
    instance_id: str,
    *,
    vpc_id: str | None = "vpc-abc",
    subnet_id: str | None = "subnet-1",
    sg_ids: str | None = "sg-a,sg-b",
    account_id: str = "000000000000",
    region: str = "us-east-1",
    iam_role: str | None = "TestRole",
    iam_profile_arn: str | None = "arn:aws:iam::000000000000:instance-profile/TestProfile",
    running: bool = True,
) -> dict:
    """Build a fake docker inspect dict that restore_instance will parse."""
    labels = {
        "localemu.service": "ec2",
        "localemu.instance-id": instance_id,
        "localemu.instance-type": "t2.micro",
        "localemu.ami-id": "ami-ubuntu-22.04",
        "localemu.account-id": account_id,
        "localemu.region": region,
    }
    if sg_ids is not None:
        labels["localemu.sg-ids"] = sg_ids
    if subnet_id:
        labels["localemu.subnet-id"] = subnet_id
    if iam_role:
        labels["localemu.iam-role-name"] = iam_role
    if iam_profile_arn:
        labels["localemu.iam-profile-arn"] = iam_profile_arn

    networks: dict = {"bridge": {"IPAddress": "172.17.0.2"}}
    if vpc_id:
        networks[f"localemu-vpc-{vpc_id}"] = {"IPAddress": "10.0.0.42"}

    return {
        "Id": f"fake-{instance_id}",
        "State": {"Running": running, "Status": "running" if running else "exited"},
        "Config": {"Image": "ubuntu:22.04", "Labels": labels},
        "NetworkSettings": {"Networks": networks},
        "HostConfig": {"PortBindings": {"22/tcp": [{"HostPort": "2222"}]}},
    }


@pytest.fixture
def vm_mgr():
    """A DockerVmManager with IMDS + SG proxy stubbed out."""
    mgr = vm_manager.DockerVmManager.__new__(vm_manager.DockerVmManager)
    mgr._instances = {}
    import threading as _t
    mgr._lock = _t.Lock()
    mgr._imds_server = mock.MagicMock()
    mgr._imds_server.port = 1666
    # sg_proxy was removed; iptables is the single SG enforcement point
    return mgr


class TestRestoreInstanceCompleteness:
    """The reconcile must hit every data-plane artefact that didn't
    survive the LocalEmu process death."""

    def test_reapplies_sg_iptables(self, vm_mgr):
        inspect = _inspect_for("i-r1")
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ) as _start, mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
            return_value=True,
        ) as sg_apply, mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
        ) as _vpcm, mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ) as _nacl, mock.patch(
            "localemu.services.ec2.docker.vm_manager._reissue_sts_for_restore",
        ) as _sts:
            _vpcm.return_value = mock.MagicMock()
            _sts.return_value = None
            info = vm_mgr.restore_instance(
                "i-r1", "running", "localemu-ec2-i-r1", inspect,
            )
        assert info is not None
        sg_apply.assert_called_once()
        args = sg_apply.call_args[0]
        assert args[0] == "localemu-ec2-i-r1"
        assert sorted(args[1]) == ["sg-a", "sg-b"]
        assert args[2] == "000000000000"
        assert args[3] == "us-east-1"

    def test_registers_with_vpc_network_manager(self, vm_mgr):
        inspect = _inspect_for("i-r2", vpc_id="vpc-xyz", subnet_id="subnet-42")
        fake_mgr = mock.MagicMock()
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ), mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
            return_value=True,
        ), mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=fake_mgr,
        ), mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ), mock.patch(
            "localemu.services.ec2.docker.vm_manager._reissue_sts_for_restore",
            return_value=None,
        ):
            vm_mgr.restore_instance(
                "i-r2", "running", "localemu-ec2-i-r2", inspect,
            )
        fake_mgr.register_container.assert_called_once_with(
            "vpc-xyz", "localemu-ec2-i-r2", subnet_id="subnet-42",
        )

    def test_reapplies_nacl_for_subnet(self, vm_mgr):
        inspect = _inspect_for("i-r3", subnet_id="subnet-nacl")
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ), mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
            return_value=True,
        ), mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ) as nacl_apply, mock.patch(
            "localemu.services.ec2.docker.vm_manager._reissue_sts_for_restore",
            return_value=None,
        ), mock.patch(
            "localemu.services.ec2.docker.vm_manager._resolve_nacl_for_subnet",
            return_value="acl-123",
        ):
            vm_mgr.restore_instance(
                "i-r3", "running", "localemu-ec2-i-r3", inspect,
            )
        nacl_apply.assert_called_once_with(
            "acl-123", "subnet-nacl", "000000000000", "us-east-1",
        )

    def test_reissues_sts_credentials_when_iam_role_present(self, vm_mgr):
        inspect = _inspect_for("i-r4", iam_role="MyRole")
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ), mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
            return_value=True,
        ), mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ), mock.patch(
            "localemu.services.ec2.docker.vm_manager._reissue_sts_for_restore",
        ) as sts:
            sts.return_value = {"AccessKeyId": "ASIA…", "SecretAccessKey": "secret"}
            vm_mgr.restore_instance(
                "i-r4", "running", "localemu-ec2-i-r4", inspect,
            )
        sts.assert_called_once()
        # The helper receives role name, account_id, region
        assert sts.call_args[0][0] == "MyRole"
        assert sts.call_args[0][1] == "000000000000"
        assert sts.call_args[0][2] == "us-east-1"
        # IMDS register receives the re-issued credentials
        register_call = vm_mgr._imds_server.register_instance.call_args
        assert register_call is not None
        md = register_call[0][2]
        assert md.get("iam_credentials") == {"AccessKeyId": "ASIA…", "SecretAccessKey": "secret"}

    def test_no_iam_role_skips_sts_reissue(self, vm_mgr):
        inspect = _inspect_for("i-r5", iam_role=None, iam_profile_arn=None)
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ), mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
            return_value=True,
        ), mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ), mock.patch(
            "localemu.services.ec2.docker.vm_manager._reissue_sts_for_restore",
        ) as sts:
            vm_mgr.restore_instance(
                "i-r5", "running", "localemu-ec2-i-r5", inspect,
            )
        sts.assert_not_called()

    def test_backward_compat_missing_labels_does_not_crash(self, vm_mgr):
        """Older containers (created before the account-id / region /
        sg-ids labels were added) restore without crashing — the
        label-dependent reconciliation steps must be skipped silently."""
        inspect = {
            "Id": "fake-old",
            "State": {"Running": True},
            "Config": {
                "Image": "ubuntu:22.04",
                "Labels": {
                    "localemu.service": "ec2",
                    "localemu.instance-id": "i-legacy",
                },
            },
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.9"}}},
            "HostConfig": {"PortBindings": {}},
        }
        with mock.patch.object(
            vm_manager.DOCKER_CLIENT, "start_container",
        ), mock.patch(
            "localemu.services.ec2.docker.sg_iptables.apply_sg_to_container",
        ) as sg_apply, mock.patch(
            "localemu.services.ec2.docker.vpc_network.get_vpc_network_manager",
            return_value=mock.MagicMock(),
        ), mock.patch(
            "localemu.services.ec2.docker.nacl_enforcer.apply_nacl_to_subnet_containers",
        ) as nacl_apply:
            info = vm_mgr.restore_instance(
                "i-legacy", "running", "localemu-ec2-i-legacy", inspect,
            )
        # info is still built; SG/NACL apply skipped because labels are missing
        assert info is not None
        assert info.instance_id == "i-legacy"
        sg_apply.assert_not_called()
        nacl_apply.assert_not_called()
