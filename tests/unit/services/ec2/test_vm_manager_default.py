"""EC2_VM_MANAGER defaults to ``docker``.

Historically the default was ``none`` — RunInstances returned a moto-only
record with no container, no IP, no way to SSH or curl into anything,
and every new user reported the same confused bug. Flipping the default
makes the OOTB experience match the documentation. The fallback path
(Docker daemon unreachable) stays silent so CI environments without
Docker access don't get scary warnings they didn't ask for.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def fake_provider():
    """Stand-in Ec2Provider with just enough surface for on_after_init."""
    from localemu.services.ec2.provider import Ec2Provider

    p = Ec2Provider.__new__(Ec2Provider)
    p._vm_manager = None
    return p


class TestDefaultDockerBackend:
    def test_default_no_env_starts_docker_when_available(
        self, fake_provider, monkeypatch
    ):
        monkeypatch.delenv("EC2_VM_MANAGER", raising=False)
        with (
            patch("localemu.services.ec2.provider.apply_patches"),
            patch(
                "localemu.services.ec2.docker.vm_manager.DockerVmManager"
            ) as MockVmMgr,
            patch("localemu.utils.docker_utils.DOCKER_CLIENT") as MockDocker,
            patch.object(fake_provider, "_cleanup_orphaned_docker_resources"),
            patch.object(fake_provider, "_load_key_pair_public_keys"),
        ):
            MockDocker.has_docker.return_value = True
            fake_provider.on_after_init()
            MockVmMgr.assert_called_once()
            assert fake_provider._vm_manager is MockVmMgr.return_value

    def test_default_no_env_silent_fallback_when_docker_absent(
        self, fake_provider, monkeypatch, caplog
    ):
        monkeypatch.delenv("EC2_VM_MANAGER", raising=False)
        caplog.set_level(logging.WARNING, logger="localemu.services.ec2.provider")
        with (
            patch("localemu.services.ec2.provider.apply_patches"),
            patch(
                "localemu.services.ec2.docker.vm_manager.DockerVmManager"
            ) as MockVmMgr,
            patch("localemu.utils.docker_utils.DOCKER_CLIENT") as MockDocker,
            patch.object(fake_provider, "_cleanup_orphaned_docker_resources"),
            patch.object(fake_provider, "_load_key_pair_public_keys"),
        ):
            MockDocker.has_docker.return_value = False
            fake_provider.on_after_init()

        MockVmMgr.assert_not_called()
        assert fake_provider._vm_manager is None
        # No WARNING — the user didn't ask for Docker, so a missing
        # daemon isn't a problem to flag at warning level.
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [], f"unexpected warnings on default fallback: {warnings}"

    def test_explicit_docker_warns_loudly_when_daemon_missing(
        self, fake_provider, monkeypatch, caplog
    ):
        monkeypatch.setenv("EC2_VM_MANAGER", "docker")
        caplog.set_level(logging.WARNING, logger="localemu.services.ec2.provider")
        with (
            patch("localemu.services.ec2.provider.apply_patches"),
            patch(
                "localemu.services.ec2.docker.vm_manager.DockerVmManager"
            ) as MockVmMgr,
            patch("localemu.utils.docker_utils.DOCKER_CLIENT") as MockDocker,
            patch.object(fake_provider, "_cleanup_orphaned_docker_resources"),
            patch.object(fake_provider, "_load_key_pair_public_keys"),
        ):
            MockDocker.has_docker.return_value = False
            fake_provider.on_after_init()

        MockVmMgr.assert_not_called()
        # The user explicitly asked for docker, so the daemon being absent
        # IS surprising and should surface at WARNING.
        msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("EC2_VM_MANAGER=docker" in m for m in msgs), msgs

    def test_explicit_none_skips_docker_entirely(self, fake_provider, monkeypatch):
        monkeypatch.setenv("EC2_VM_MANAGER", "none")
        with (
            patch("localemu.services.ec2.provider.apply_patches"),
            patch(
                "localemu.services.ec2.docker.vm_manager.DockerVmManager"
            ) as MockVmMgr,
            patch.object(fake_provider, "_cleanup_orphaned_docker_resources"),
            patch.object(fake_provider, "_load_key_pair_public_keys"),
        ):
            fake_provider.on_after_init()

        MockVmMgr.assert_not_called()
        assert fake_provider._vm_manager is None
