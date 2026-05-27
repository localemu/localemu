"""Unit tests for VpcNetworkManager.cleanup_all.

Reproduces the shutdown bug seen in the wild:

    ERROR: 'docker network rm localemu-vpc-vpc-xyz': exit code 1;
    network has active endpoints (name:"localemu-imds-vpc-xyz" ...)

Root cause was that ``imds_sidecar.cleanup_all()`` ran AFTER the
per-VPC ``DOCKER_CLIENT.delete_network`` loop. The sidecar still held
a network endpoint, so the daemon refused to remove the network. The
fix is to call sidecar cleanup first.

These tests assert both the new ordering and the new accurate
``"N/M deleted"`` log shape (previously the count reported
``len(vpc_data)`` regardless of whether ``delete_network`` succeeded).
"""
from __future__ import annotations

from unittest import mock

from localemu.services.ec2.docker import vpc_network as vpc_mod


class TestCleanupAll:
    def _build_manager(self, *, with_peering: bool = False) -> vpc_mod.VpcNetworkManager:
        mgr = vpc_mod.VpcNetworkManager()
        # Seed two VPCs with one tracked container each.
        mgr._vpcs["vpc-a"] = {
            "network_name": "localemu-vpc-vpc-a",
            "subnet": "10.0.0.0/16",
            "containers": {"c-1"},
        }
        mgr._vpcs["vpc-b"] = {
            "network_name": "localemu-vpc-vpc-b",
            "subnet": "10.1.0.0/16",
            "containers": {"c-2"},
        }
        if with_peering:
            mgr._peerings["pcx-1"] = {
                "network_name": "localemu-pcx-1",
                "vpc1_id": "vpc-a",
                "vpc2_id": "vpc-b",
            }
        return mgr

    def test_imds_sidecar_cleanup_runs_before_network_rm(self):
        """The bug fix: sidecar removal must happen BEFORE delete_network,
        otherwise the daemon refuses to remove the network."""
        mgr = self._build_manager()
        call_order: list[str] = []

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT") as docker, \
             mock.patch(
                 "localemu.services.ec2.docker.imds_sidecar.cleanup_all"
             ) as imds_cleanup:
            imds_cleanup.side_effect = lambda: call_order.append("imds_cleanup_all")
            docker.delete_network.side_effect = lambda net: call_order.append(
                f"delete_network:{net}"
            )

            mgr.cleanup_all()

        # IMDS cleanup is the first thing in the order list.
        assert call_order[0] == "imds_cleanup_all"
        # And both network deletions follow.
        assert "delete_network:localemu-vpc-vpc-a" in call_order
        assert "delete_network:localemu-vpc-vpc-b" in call_order
        assert call_order.index("imds_cleanup_all") < call_order.index(
            "delete_network:localemu-vpc-vpc-a"
        )
        assert call_order.index("imds_cleanup_all") < call_order.index(
            "delete_network:localemu-vpc-vpc-b"
        )

    def test_failed_delete_network_does_not_count_as_success(self, caplog):
        """When delete_network raises, the success count must reflect it
        and a WARN must surface (we previously swallowed the error and
        still reported the count as if everything succeeded)."""
        import logging

        mgr = self._build_manager()
        caplog.set_level(logging.INFO, logger=vpc_mod.LOG.name)

        def _delete(net):
            if net == "localemu-vpc-vpc-a":
                raise RuntimeError(
                    "network localemu-vpc-vpc-a has active endpoints"
                )

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT") as docker, \
             mock.patch(
                 "localemu.services.ec2.docker.imds_sidecar.cleanup_all"
             ):
            docker.delete_network.side_effect = _delete
            mgr.cleanup_all()

        # Accurate count: 1 of 2 succeeded.
        summary_lines = [
            r.getMessage() for r in caplog.records
            if r.levelno == logging.INFO and "Cleaned up" in r.getMessage()
        ]
        assert summary_lines, f"no summary INFO line emitted; got: {caplog.records!r}"
        assert "1/2" in summary_lines[0], summary_lines

        # The failure is not silent.
        warns = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "Failed to delete VPC network" in r.getMessage()
        ]
        assert warns, "expected a WARN log for the failed delete_network"

    def test_clears_state_even_when_docker_calls_fail(self):
        """The manager's internal dicts must be reset even if Docker
        misbehaves; otherwise a subsequent restart sees stale state."""
        mgr = self._build_manager(with_peering=True)

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT") as docker, \
             mock.patch(
                 "localemu.services.ec2.docker.imds_sidecar.cleanup_all"
             ):
            docker.delete_network.side_effect = RuntimeError("boom")
            docker.disconnect_container_from_network.side_effect = RuntimeError("boom")
            mgr.cleanup_all()

        assert mgr._vpcs == {}
        assert mgr._peerings == {}
        assert mgr._container_subnets == {}

    def test_pick_free_subnet_first_tier(self):
        """Empty host: the picker returns a slot from the first tier (10/8)."""
        mgr = vpc_mod.VpcNetworkManager()
        with mock.patch.object(mgr, "_inspect_all_docker_subnets", return_value=[]):
            picked = mgr._pick_free_subnet()
        import ipaddress
        # First /16 in 10/8.
        assert picked is not None
        assert ipaddress.ip_network(picked) in ipaddress.ip_network("10.0.0.0/8").subnets(
            new_prefix=16
        )

    def test_pick_free_subnet_falls_through_to_172_16(self):
        """When all of 10/8 is consumed, the picker spills into 172.16/12."""
        import ipaddress

        mgr = vpc_mod.VpcNetworkManager()
        # Mark every /16 in 10/8 as used.
        used = list(ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=16))
        with mock.patch.object(mgr, "_inspect_all_docker_subnets", return_value=used):
            picked = mgr._pick_free_subnet()
        assert picked is not None
        picked_net = ipaddress.ip_network(picked)
        assert picked_net.subnet_of(ipaddress.ip_network("172.16.0.0/12"))
        # Must NOT collide with Docker's default bridge at 172.17.0.0/16.
        assert not picked_net.overlaps(ipaddress.ip_network("172.17.0.0/16"))

    def test_pick_free_subnet_skips_docker_default_bridge_172_17(self):
        """Even when 172.16/12 is the chosen tier, 172.17.0.0/16 is reserved."""
        import ipaddress

        mgr = vpc_mod.VpcNetworkManager()
        # Saturate 10/8 and every 172.16/12 /16 EXCEPT 172.17 to force a pick.
        used = list(ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=16))
        used += [
            n for n in ipaddress.ip_network("172.16.0.0/12").subnets(new_prefix=16)
            if n != ipaddress.ip_network("172.17.0.0/16")
        ]
        with mock.patch.object(mgr, "_inspect_all_docker_subnets", return_value=used):
            picked = mgr._pick_free_subnet()
        # Picker MUST NOT have returned 172.17 — it should fall through to
        # the next tier (100.64/10).
        if picked is not None:
            picked_net = ipaddress.ip_network(picked)
            assert picked_net != ipaddress.ip_network("172.17.0.0/16")

    def test_pick_free_subnet_reaches_100_64(self):
        """When tiers 1 and 2 are saturated, picker yields a 100.64/10 slot."""
        import ipaddress

        mgr = vpc_mod.VpcNetworkManager()
        used = list(ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=16))
        used += list(ipaddress.ip_network("172.16.0.0/12").subnets(new_prefix=16))
        with mock.patch.object(mgr, "_inspect_all_docker_subnets", return_value=used):
            picked = mgr._pick_free_subnet()
        assert picked is not None
        picked_net = ipaddress.ip_network(picked)
        assert picked_net.subnet_of(ipaddress.ip_network("100.64.0.0/10"))

    def test_pick_free_subnet_reaches_192_168_slash20(self):
        """Last-resort tier carves 192.168/16 into /20s."""
        import ipaddress

        mgr = vpc_mod.VpcNetworkManager()
        used = list(ipaddress.ip_network("10.0.0.0/8").subnets(new_prefix=16))
        used += list(ipaddress.ip_network("172.16.0.0/12").subnets(new_prefix=16))
        used += list(ipaddress.ip_network("100.64.0.0/10").subnets(new_prefix=16))
        with mock.patch.object(mgr, "_inspect_all_docker_subnets", return_value=used):
            picked = mgr._pick_free_subnet()
        assert picked is not None
        picked_net = ipaddress.ip_network(picked)
        assert picked_net.subnet_of(ipaddress.ip_network("192.168.0.0/16"))
        assert picked_net.prefixlen == 20

    def test_is_network_ready_returns_false_when_create_failed(self):
        """``is_network_ready`` discriminates between "has a name in _vpcs"
        and "has a real Docker bridge". A failed create leaves no entry
        and must therefore report not-ready."""
        mgr = vpc_mod.VpcNetworkManager()
        assert mgr.is_network_ready("vpc-missing") is False
        mgr._vpcs["vpc-pending"] = {
            "network_name": "localemu-vpc-vpc-pending",
            "network_id": None,
            "cidr": "10.0.0.0/16",
            "docker_cidr": None,
            "has_igw": False,
            "containers": set(),
        }
        assert mgr.is_network_ready("vpc-pending") is False
        mgr._vpcs["vpc-live"] = {
            "network_name": "localemu-vpc-vpc-live",
            "network_id": "net-id-123",
            "cidr": "10.0.0.0/16",
            "docker_cidr": "10.0.0.0/16",
            "has_igw": False,
            "containers": set(),
        }
        assert mgr.is_network_ready("vpc-live") is True

    def _stub_docker_network_ls(self, monkeypatch, network_names: list[str]) -> None:
        """Mirror the helper in ``test_vpc_network_adopt.py``: patch the
        ``subprocess.run`` call vpc_network.adopt makes when listing
        ``localemu-vpc-*`` networks."""
        import subprocess as _sp

        class _R:
            returncode = 0
            stdout = "\n".join(network_names)

        monkeypatch.setattr(_sp, "run", lambda *a, **kw: _R())

    def test_adopt_reclaims_orphan_with_only_localemu_imds_sidecar(
        self, monkeypatch,
    ):
        """Orphan VPC bridge whose only attached container is a LocalEmu
        IMDS sidecar gets reclaimed: stop the sidecar, remove it, then
        delete the bridge. This is the recovery path for a prior session
        that died without graceful shutdown."""
        mgr = vpc_mod.VpcNetworkManager()
        orphan_name = "localemu-vpc-vpc-ORPHAN"
        sidecar_name = "localemu-imds-vpc-ORPHAN"

        self._stub_docker_network_ls(monkeypatch, [orphan_name])

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT") as docker, \
             mock.patch.object(
                 vpc_mod.VpcNetworkManager,
                 "_lookup_vpc_cidr_in_moto",
                 staticmethod(lambda vpc_id: None),
             ):
            docker.inspect_network.return_value = {
                "Containers": {
                    "cid-1": {"Name": sidecar_name},
                },
            }
            adopted, deleted = mgr.adopt_vpc_networks_from_docker()

        assert adopted == 0
        assert deleted == 1
        docker.stop_container.assert_called_with(sidecar_name, timeout=5)
        docker.remove_container.assert_called_with(sidecar_name, force=True)
        docker.delete_network.assert_called_with(orphan_name)

    def test_adopt_leaves_orphan_with_external_container_alone(
        self, monkeypatch,
    ):
        """If any non-localemu container is attached, adoption MUST NOT
        touch the orphan bridge — something external is using it."""
        mgr = vpc_mod.VpcNetworkManager()
        orphan_name = "localemu-vpc-vpc-SHARED"

        self._stub_docker_network_ls(monkeypatch, [orphan_name])

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT") as docker, \
             mock.patch.object(
                 vpc_mod.VpcNetworkManager,
                 "_lookup_vpc_cidr_in_moto",
                 staticmethod(lambda vpc_id: None),
             ):
            docker.inspect_network.return_value = {
                "Containers": {
                    "cid-1": {"Name": "some-external-app"},
                },
            }
            adopted, deleted = mgr.adopt_vpc_networks_from_docker()

        assert adopted == 0
        assert deleted == 0
        docker.stop_container.assert_not_called()
        docker.remove_container.assert_not_called()
        docker.delete_network.assert_not_called()

    def test_peering_networks_use_their_own_count(self):
        """Peering and VPC counts are tracked independently in the
        summary line."""
        import logging

        mgr = self._build_manager(with_peering=True)
        log_cap = []

        def _log_info(fmt, *args, **kwargs):
            log_cap.append(fmt % args if args else fmt)

        with mock.patch.object(vpc_mod, "DOCKER_CLIENT"), \
             mock.patch(
                 "localemu.services.ec2.docker.imds_sidecar.cleanup_all"
             ), \
             mock.patch.object(vpc_mod.LOG, "info", side_effect=_log_info):
            mgr.cleanup_all()

        summary = next(
            (line for line in log_cap if "Cleaned up" in line),
            None,
        )
        assert summary is not None, f"summary missing in {log_cap!r}"
        # On the success path both counts equal the totals (2/2 VPCs,
        # 1/1 peerings); the format treats them independently.
        assert "2/2" in summary, summary
        assert "1/1" in summary, summary
