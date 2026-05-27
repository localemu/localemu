"""Tests for the two independent mechanical bug fixes:

  1. ``vpc_network._recreate_network`` previously had unreachable code
     after ``return True``, so the in-memory ``network_id`` was never
     updated after an IGW attach/detach. Fixed by moving the update
     above the return.

  2. ``nacl_enforcer._emergency_default_drop_script`` previously
     included ``-m state --state ESTABLISHED,RELATED -j ACCEPT`` —
     a stateful-on-stateless-contract violation for AWS NACLs (which
     are stateless). Fixed by removing those two lines.

Both bugs are independent of the addressing redesign and are isolated
mechanical errors with one-line fixes.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import nacl_enforcer
from localemu.services.ec2.docker import vpc_network as vpc_mod


# ---------------------------------------------------------------------------
# Fix 1: _recreate_network updates network_id after success
# ---------------------------------------------------------------------------
class TestRecreateNetworkIdRecorded:
    def test_network_id_updated_after_successful_recreate(self):
        mgr = vpc_mod.VpcNetworkManager()
        mgr._vpcs["vpc-zzz"] = {
            "network_id": "id-OLD",
            "network_name": "localemu-vpc-vpc-zzz",
            "cidr": "10.50.0.0/16",
            "docker_cidr": "10.50.0.0/16",
            "containers": set(),
            "has_igw": False,
        }
        dc = mock.MagicMock()
        # The single create_network call returns the new network's id.
        dc.create_network.return_value = "id-NEW"
        dc.inspect_network.return_value = {"Containers": {}}

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT", dc):
            ok = mgr._recreate_network(
                "vpc-zzz",
                "localemu-vpc-vpc-zzz",
                "10.50.0.0/16",
                [],  # no containers to migrate
                internal=False,
            )

        assert ok is True
        # The recorded network_id is the NEW one, not "id-OLD" -- proves
        # the tracking dict gets updated post-recreate.
        assert mgr._vpcs["vpc-zzz"]["network_id"] == "id-NEW"


# ---------------------------------------------------------------------------
# Fix 2: NACL emergency drop is genuinely stateless
# ---------------------------------------------------------------------------
class TestNaclEmergencyIsStateless:
    def test_script_has_no_conntrack_clause(self):
        """The previous code allowed ESTABLISHED,RELATED in the emergency
        fail-closed policy, which violates AWS NACL stateless contract.
        Verify the conntrack ACCEPT lines are gone."""
        script = nacl_enforcer._emergency_default_drop_script()
        # No reference to state-matching extension or conntrack module
        assert "ESTABLISHED" not in script
        assert "RELATED" not in script
        assert "--state" not in script
        assert "conntrack" not in script.lower()

    def test_script_still_allows_loopback(self):
        """Loopback stays open so init scripts (systemd, syslog, dbus)
        continue to function. This is the only exception to deny-all."""
        script = nacl_enforcer._emergency_default_drop_script()
        assert "-i lo -j ACCEPT" in script
        assert "-o lo -j ACCEPT" in script

    def test_script_ends_with_drop(self):
        """Fail-closed: every chain ends with explicit DROP."""
        script = nacl_enforcer._emergency_default_drop_script()
        assert "iptables -A NACL_IN -j DROP" in script
        assert "iptables -A NACL_OUT -j DROP" in script

    def test_script_attaches_to_input_and_output(self):
        """The NACL chains must be hooked into INPUT and OUTPUT;
        otherwise the policy is installed but never consulted."""
        script = nacl_enforcer._emergency_default_drop_script()
        assert "INPUT -j NACL_IN" in script
        assert "OUTPUT -j NACL_OUT" in script


# ---------------------------------------------------------------------------
# Fix 3: RebootInstances wires through DockerVmManager.reboot_instance
# ---------------------------------------------------------------------------
class TestRebootInstance:
    def test_reboot_instance_calls_docker_restart(self):
        from localemu.services.ec2.docker import vm_manager

        mgr = vm_manager.DockerVmManager()
        with mock.patch.object(vm_manager, "DOCKER_CLIENT") as dc:
            mgr.reboot_instance("i-abc")
            dc.restart_container.assert_called_once_with(
                "localemu-ec2-i-abc", timeout=10,
            )

    def test_reboot_instance_swallows_docker_failure(self):
        """Docker errors are logged but never raised — matches the
        pattern of stop_instance/start_instance."""
        from localemu.services.ec2.docker import vm_manager

        mgr = vm_manager.DockerVmManager()
        with mock.patch.object(vm_manager, "DOCKER_CLIENT") as dc:
            dc.restart_container.side_effect = RuntimeError("docker down")
            mgr.reboot_instance("i-abc")  # no raise
