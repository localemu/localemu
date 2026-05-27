"""
VPC-to-Docker network manager for real network isolation.

Maps each AWS VPC to a dedicated Docker bridge network with CIDR-based
IP assignment.  Provides real networking behavior:

  - VPC isolation:     Different VPCs → different Docker networks → no cross-talk
  - Internet Gateway:  VPC created as --internal (no internet) by default.
                       AttachInternetGateway recreates the network WITHOUT --internal.
  - VPC Peering:       Containers in peered VPCs are connected to both Docker networks.
  - Container tracking: Tracks which containers are in which VPC for peering/IGW changes.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

VPC_NETWORK_PREFIX = "localemu-vpc-"
PEERING_NETWORK_PREFIX = "localemu-pcx-"

# After a failed ``docker network create``, suppress re-attempts for this
# many seconds. The dashboard polls every 3 s and the resources endpoint
# was retriggering creation on every poll; that turned a single failure
# (host pool exhausted, persisted CIDR colliding with the pubport bridge)
# into a 1-error-per-3-s storm. With the read/write split this is belt
# and braces: write callers are rare, but if one re-fires we cap the rate.
FAILED_CREATE_RETRY_TTL_SECONDS = 300

# Fallback subnet pools used when the AWS-side CIDR can't be honoured by
# Docker (overlap with another network, or the daemon's default pool is
# exhausted). We pick a free slot inside one of the tiered pools by
# scanning live ``docker network ls`` output. The AWS API still reports
# the moto CIDR to callers; only the Docker bridge uses this fallback.
#
# Tiers are walked in order. Most operators expect 10/8 first, so it stays
# at the top. 172.16/12 must skip 172.17/16 because that is Docker's own
# default ``bridge`` and reserving it would race with the daemon. 100.64/10
# is RFC 6598 carrier-grade NAT space — practically immune to collision
# with anything else on the host. 192.168/16 carved as /20s is the
# last-resort long-tail; smaller slices but still 4 094 IPs each.
#
# (cidr, prefix_len, reserved_cidrs)
FALLBACK_SUBNET_BASE = "10.0.0.0/8"  # legacy alias — referenced in log messages
FALLBACK_SUBNET_PREFIX_LEN = 16  # legacy alias
FALLBACK_SUBNET_TIERS: list[tuple[str, int, tuple[str, ...]]] = [
    ("10.0.0.0/8", 16, ()),
    ("172.16.0.0/12", 16, ("172.17.0.0/16",)),
    ("100.64.0.0/10", 16, ()),
    ("192.168.0.0/16", 20, ()),
]

# Prefixes of container names this manager considers "owned by LocalEmu".
# Used during startup adoption: if an orphan VPC bridge has only containers
# matching one of these prefixes (e.g. a leftover IMDS sidecar from a
# crashed prior session), the sidecars are stopped first and the bridge
# can then be removed. A bridge with any container outside this set is
# considered externally used and left untouched.
_LOCALEMU_CONTAINER_PREFIX = "localemu-"

# Shared bridge used exclusively for host-side port publishing
# (SSH / user ports) for EC2 containers whose VPC network is
# ``--internal=True``. Docker refuses to publish ports on internal
# networks (moby/moby#27441, #36174); we keep VPC isolation by having
# EC2 containers attached to BOTH this pubport bridge (primary, so
# ``docker -p`` works) AND their VPC bridge (secondary, for intra-VPC
# routing and SG/NACL iptables enforcement).
#
# Non-internal so Docker publishes ports, but the subnet is a
# link-local-ish 172.31.255.0/24 with no default route advertised —
# containers can't accidentally egress via this interface; the VPC
# interface (or NAT bridge when present) is the real egress path.
PUBPORT_BRIDGE_NAME = "localemu-pubport-br"
_PUBPORT_SUBNET = "172.31.255.0/24"
_pubport_lock = threading.Lock()
_pubport_ready = False


def ensure_pubport_bridge() -> str:
    """Make sure the shared port-publishing bridge exists. Idempotent.

    Returns the network name (always ``PUBPORT_BRIDGE_NAME``). Building
    it is a one-liner to Docker; the function is a no-op after the
    first successful call in-process, and the second-check-under-lock
    means concurrent ``RunInstances`` calls don't race.
    """
    global _pubport_ready
    if _pubport_ready:
        return PUBPORT_BRIDGE_NAME
    with _pubport_lock:
        if _pubport_ready:
            return PUBPORT_BRIDGE_NAME
        try:
            DOCKER_CLIENT.inspect_network(PUBPORT_BRIDGE_NAME)
            _pubport_ready = True
            return PUBPORT_BRIDGE_NAME
        except Exception:
            pass
        try:
            DOCKER_CLIENT.create_network(
                network_name=PUBPORT_BRIDGE_NAME,
                subnet=_PUBPORT_SUBNET,
                internal=False,
            )
            LOG.info(
                "Created shared port-publishing bridge %s (%s)",
                PUBPORT_BRIDGE_NAME, _PUBPORT_SUBNET,
            )
        except Exception as exc:
            # If creation fails because of a race or subnet conflict,
            # fall back to Docker-assigned subnet.
            LOG.debug(
                "pubport subnet %s conflicts (%s) — retrying without subnet",
                _PUBPORT_SUBNET, exc,
            )
            try:
                DOCKER_CLIENT.create_network(
                    network_name=PUBPORT_BRIDGE_NAME, internal=False,
                )
            except Exception:
                LOG.warning(
                    "Could not create %s — port publishing on VPC EC2s may fail",
                    PUBPORT_BRIDGE_NAME, exc_info=True,
                )
        _pubport_ready = True
    return PUBPORT_BRIDGE_NAME


class VpcNetworkManager:
    """Manages Docker networks mapped to AWS VPCs.

    Thread-safe.  Handles VPC lifecycle, Internet Gateway toggling,
    VPC peering, and container tracking.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # vpc_id → {network_name, cidr, docker_cidr, network_id, has_igw, containers: set}
        # ``cidr`` is the AWS-side CIDR (what DescribeVpcs reports);
        # ``docker_cidr`` is the actual subnet Docker assigned to the
        # bridge, which differs when the AWS CIDR collided with another
        # bridge and the fallback subnet picker kicked in.
        self._vpcs: dict[str, dict] = {}
        # peering_id → {vpc1_id, vpc2_id}
        self._peerings: dict[str, dict] = {}
        # Container_name → subnet_id mapping for per-subnet tracking
        self._container_subnets: dict[str, str] = {}
        # vpc_id → unix timestamp of last failed create_vpc_network attempt.
        # ``ensure_network_for_vpc`` consults this to skip Docker calls
        # during the cooldown window; without this the dashboard polling
        # path turned a permanent create failure into a per-poll error
        # storm.
        self._failed_creates: dict[str, float] = {}
        # Whether ``adopt_vpc_networks_from_docker`` has already run for
        # this manager instance. The adoption walks ``docker network ls``
        # and is idempotent, but doing it once per process is sufficient
        # because subsequent create/delete calls maintain ``_vpcs``
        # in lockstep with Docker.
        self._adopted = False

    # ------------------------------------------------------------------
    # VPC lifecycle
    # ------------------------------------------------------------------

    def create_vpc_network(self, vpc_id: str, cidr_block: str) -> str:
        """Create a Docker bridge network for a VPC.

        Networks are created as --internal by default (no internet).
        ``AttachInternetGateway`` flips that flag by rebuilding the
        network. If the AWS-side CIDR collides with an existing Docker
        network or the daemon's default pool is exhausted, this method
        picks a free /16 from 10.0.0.0/8 via the fallback subnet picker.
        Only if the fallback subnet also fails does the create return a
        VPC entry with ``network_id=None``: the caller still gets a
        stable ``network_name``, and the failure is recorded in
        ``_failed_creates`` so subsequent calls within the cooldown
        skip Docker entirely.

        Entire operation is atomic under the lock to prevent TOCTOU
        races.
        """
        network_name = f"{VPC_NETWORK_PREFIX}{vpc_id}"

        # Validate CIDR block before creating Docker network
        if cidr_block:
            try:
                ipaddress.ip_network(cidr_block, strict=False)
            except ValueError as e:
                LOG.warning("Invalid CIDR %s for VPC %s: %s", cidr_block, vpc_id, e)
                return network_name

        with self._lock:
            if vpc_id in self._vpcs:
                return network_name

            # Cooldown gate: a permanent failure (host pool exhausted,
            # docker daemon unreachable) must not retry on every call.
            ts = self._failed_creates.get(vpc_id)
            if ts is not None and (time.time() - ts) < FAILED_CREATE_RETRY_TTL_SECONDS:
                return network_name

            network_id, docker_cidr = self._create_docker_bridge(
                vpc_id, network_name, cidr_block, internal=True,
            )

            if network_id is None:
                # Failure recorded; create_docker_bridge already logged a
                # single WARN line with root-cause guidance. The cooldown
                # keeps the next 5 minutes silent.
                self._failed_creates[vpc_id] = time.time()
                return network_name

            self._vpcs[vpc_id] = {
                "network_name": network_name,
                "cidr": cidr_block,
                "docker_cidr": docker_cidr,
                "network_id": network_id,
                "has_igw": False,
                "containers": set(),
            }
            # Clear any cached failure for this VPC; we now have a live
            # bridge.
            self._failed_creates.pop(vpc_id, None)
            if docker_cidr and cidr_block and docker_cidr != cidr_block:
                LOG.info(
                    "Created Docker network %s for VPC %s (AWS CIDR %s, "
                    "Docker CIDR %s, internal) — AWS CIDR collided with "
                    "an existing bridge so a free slot from the fallback "
                    "pools was used; AWS API still reports %s",
                    network_name, vpc_id, cidr_block, docker_cidr,
                    cidr_block,
                )
            else:
                LOG.info(
                    "Created Docker network %s for VPC %s (CIDR %s, internal)",
                    network_name, vpc_id, cidr_block,
                )

        return network_name

    def _create_docker_bridge(
        self, vpc_id: str, network_name: str, cidr_block: str,
        internal: bool,
    ) -> tuple[str | None, str | None]:
        """Create the bridge with smart subnet fallback.

        Returns ``(network_id, docker_cidr)`` on success, ``(None, None)``
        if every attempt fails. Three-step strategy:

          1. Try the AWS-side ``cidr_block`` (matches what the user
             requested at ``CreateVpc`` time).
          2. If that collides or the pool is exhausted, pick a free /16
             from ``10.0.0.0/8`` by scanning live ``docker network ls``
             output and retry with that subnet.
          3. If even step 2 fails, log a single WARN with the actionable
             explanation and return failure. No further fallback to
             "let Docker pick a subnet": that path was the source of
             the ``all predefined address pools have been fully
             subnetted`` cascade, because the daemon's default pool is
             often the exact thing that's exhausted on a busy host.
        """
        # Step 1: AWS-side CIDR (preferred). Suppress the ``ERROR:`` stdout
        # line from the docker CLI on failure -- a collision here is an
        # expected case that we recover from in step 2. We still log the
        # debug-level note below for operators tracing the flow.
        if cidr_block:
            try:
                network_id = DOCKER_CLIENT.create_network(
                    network_name=network_name,
                    subnet=cidr_block,
                    internal=internal,
                    print_error=False,
                )
                return network_id, cidr_block
            except Exception as e:
                LOG.debug(
                    "VPC %s: docker network create with CIDR %s failed (%s); "
                    "trying fallback subnet pool",
                    vpc_id, cidr_block, e,
                )

        # Step 2: pick a free /16 from the fallback pool. Here we DO want
        # the ERROR line if it fails, because a step-2 failure is the
        # permanent error path that operators need to see.
        fallback_cidr = self._pick_free_subnet()
        if fallback_cidr is not None:
            try:
                network_id = DOCKER_CLIENT.create_network(
                    network_name=network_name,
                    subnet=fallback_cidr,
                    internal=internal,
                )
                return network_id, fallback_cidr
            except Exception as e:
                LOG.debug(
                    "VPC %s: fallback CIDR %s also failed: %s",
                    vpc_id, fallback_cidr, e,
                )

        pool_summary = ", ".join(pool for pool, _, _ in FALLBACK_SUBNET_TIERS)
        LOG.warning(
            "Failed to create Docker network for VPC %s. AWS CIDR %s "
            "collides with an existing bridge and no free slot was "
            "available across the fallback pools (%s). RunInstances into "
            "this VPC will now fail with a clear error rather than "
            "silently land on the default bridge. To recover: stop "
            "LocalEmu, run `docker network prune` (safe -- LocalEmu "
            "re-adopts or recreates its bridges on next start), then "
            "restart.",
            vpc_id, cidr_block or "(unset)", pool_summary,
        )
        return None, None

    def _pick_free_subnet(self) -> str | None:
        """Return a free slot from the fallback tier list, or None.

        Walks ``FALLBACK_SUBNET_TIERS`` in order. Each tier defines a
        pool CIDR, the prefix length to slice it at, and a set of
        reserved sub-ranges to skip (Docker's default bridge lives at
        172.17/16, so that one /16 cannot be allocated).
        """
        try:
            used_networks = self._inspect_all_docker_subnets()
        except Exception as e:
            LOG.debug("_pick_free_subnet: docker enumeration failed: %s", e)
            return None

        for pool_cidr, slice_prefix_len, reserved in FALLBACK_SUBNET_TIERS:
            reserved_nets = [
                ipaddress.ip_network(r, strict=False) for r in reserved
            ]
            pool = ipaddress.ip_network(pool_cidr, strict=False)
            try:
                candidates = pool.subnets(new_prefix=slice_prefix_len)
            except ValueError:
                continue
            for candidate in candidates:
                if any(candidate.overlaps(r) for r in reserved_nets):
                    continue
                if any(candidate.overlaps(used) for used in used_networks):
                    continue
                return str(candidate)
        return None

    @staticmethod
    def _inspect_all_docker_subnets() -> list[ipaddress._BaseNetwork]:
        """List every IPv4 subnet currently assigned to a Docker network.

        Pure read against the Docker daemon. Used by the fallback
        subnet picker to avoid overlap and by the orphan GC to know
        which networks belong to LocalEmu.
        """
        import subprocess as _sp
        try:
            ls = _sp.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            return []
        if ls.returncode != 0:
            return []
        names = [n.strip() for n in ls.stdout.splitlines() if n.strip()]
        if not names:
            return []

        subnets: list[ipaddress._BaseNetwork] = []
        for name in names:
            try:
                info = DOCKER_CLIENT.inspect_network(name) or {}
            except Exception:
                continue
            for cfg in (info.get("IPAM") or {}).get("Config") or []:
                cidr = cfg.get("Subnet")
                if not cidr:
                    continue
                try:
                    subnets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
        return subnets

    def delete_vpc_network(self, vpc_id: str) -> None:
        """Remove the Docker network for a VPC."""
        network_name = f"{VPC_NETWORK_PREFIX}{vpc_id}"

        with self._lock:
            self._vpcs.pop(vpc_id, None)
            # Clean up any peerings involving this VPC
            to_remove = [pid for pid, p in self._peerings.items()
                         if p["vpc1_id"] == vpc_id or p["vpc2_id"] == vpc_id]
            peering_nets = []
            for pid in to_remove:
                p = self._peerings.pop(pid, None)
                if p and p.get("network_name"):
                    peering_nets.append(p["network_name"])

        # Remove peering networks
        for pnet in peering_nets:
            try:
                DOCKER_CLIENT.delete_network(pnet)
            except Exception:
                pass

        # Tear down the per-VPC IMDS sidecar (if any) before deleting
        # the network — otherwise Docker refuses to delete a network
        # with attached containers.
        try:
            from localemu.services.ec2.docker.imds_sidecar import cleanup_for_vpc
            cleanup_for_vpc(vpc_id)
        except Exception:
            pass

        try:
            DOCKER_CLIENT.delete_network(network_name)
            LOG.info("Deleted Docker network for VPC %s", vpc_id)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internet Gateway — toggle network between internal and public
    # ------------------------------------------------------------------

    def attach_internet_gateway(self, vpc_id: str) -> bool:
        """Make a VPC's Docker network allow internet access.

        Recreates the Docker network without --internal flag.
        All connected containers are disconnected, the network is
        deleted and recreated, then containers are reconnected.

        Returns True on success, False if the underlying Docker
        network recreate failed (caller can decide whether to raise).
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if not vpc_info or vpc_info.get("has_igw"):
                return True
            network_name = vpc_info["network_name"]
            cidr = vpc_info["cidr"]
            containers = list(vpc_info["containers"])

        if not self._recreate_network(
            vpc_id, network_name, cidr, containers, internal=False,
        ):
            return False

        # Re-check for containers added during recreation
        new_containers = set()
        with self._lock:
            if vpc_id in self._vpcs:
                new_containers = self._vpcs[vpc_id]["containers"] - set(containers)
                self._vpcs[vpc_id]["has_igw"] = True

        for c in new_containers:
            try:
                DOCKER_CLIENT.connect_container_to_network(network_name, c)
            except Exception:
                pass

        LOG.info("Internet Gateway attached to VPC %s — network now has internet", vpc_id)
        return True

    def detach_internet_gateway(self, vpc_id: str) -> bool:
        """Block internet access for a VPC's Docker network.

        Recreates the network with --internal flag.
        Reconnects containers added during recreation.
        Returns True on success, False if the recreate failed.
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if not vpc_info or not vpc_info.get("has_igw"):
                return True
            network_name = vpc_info["network_name"]
            cidr = vpc_info["cidr"]
            containers = list(vpc_info["containers"])

        if not self._recreate_network(
            vpc_id, network_name, cidr, containers, internal=True,
        ):
            return False

        # Re-check for containers added during recreation (same pattern as attach)
        new_containers = set()
        with self._lock:
            if vpc_id in self._vpcs:
                new_containers = self._vpcs[vpc_id]["containers"] - set(containers)
                self._vpcs[vpc_id]["has_igw"] = False

        for c in new_containers:
            try:
                DOCKER_CLIENT.connect_container_to_network(network_name, c)
            except Exception:
                pass

        LOG.info("Internet Gateway detached from VPC %s — network now isolated", vpc_id)
        return True

    def _recreate_network(
        self, vpc_id: str, network_name: str, cidr: str,
        containers: list[str], internal: bool,
    ) -> bool:
        """Recreate a Docker network with a flipped ``--internal`` flag.

        Docker can't toggle the internal flag in place and refuses to
        let two bridge networks share a CIDR pool. So the only correct
        sequence is: disconnect every endpoint from the old network,
        delete it (freeing the CIDR), create a new one with the same
        name + same CIDR + the new flag, reconnect every endpoint.

        Returns True on success, False if any irrecoverable step
        failed. On False the caller must NOT mark ``has_igw`` as
        changed -- callers (``attach_internet_gateway`` /
        ``detach_internet_gateway``) gate the flag flip on this
        return value.
        """
        # 1. Discover every endpoint on the old network (tracked EC2s
        #    plus service-owned attachments like the per-VPC IMDS
        #    sidecar). All must be disconnected before
        #    ``docker network rm`` will accept the delete.
        try:
            net_info = DOCKER_CLIENT.inspect_network(network_name) or {}
            endpoint_names = [
                info.get("Name", "")
                for info in (net_info.get("Containers") or {}).values()
                if info.get("Name")
            ]
        except Exception:
            endpoint_names = list(containers)
        # Merge tracked containers in case ``inspect_network`` missed
        # them (race with a just-connected container).
        all_endpoints = list({*endpoint_names, *containers})

        # 2. Disconnect every endpoint.
        for c in all_endpoints:
            try:
                DOCKER_CLIENT.disconnect_container_from_network(
                    network_name, c,
                )
            except Exception as e:
                LOG.warning(
                    "vpc_network: disconnect %s from %s failed: %s",
                    c, network_name, e,
                )

        # 3. Delete the old network. This frees the CIDR pool so the
        #    create in step 4 can claim the same CIDR.
        try:
            DOCKER_CLIENT.delete_network(network_name)
        except Exception as e:
            LOG.error(
                "vpc_network: delete_network %s failed: %s -- IGW flag "
                "change cannot proceed (still attached endpoints?).",
                network_name, e,
            )
            # Try to put endpoints back so the VPC stays usable.
            for c in all_endpoints:
                try:
                    DOCKER_CLIENT.connect_container_to_network(
                        network_name, c,
                    )
                except Exception:
                    pass
            return False

        # 4. Create the replacement under the same name + same CIDR +
        #    new internal flag. Only the flag changed; everything else
        #    must round-trip exactly.
        try:
            new_network_id = DOCKER_CLIENT.create_network(
                network_name=network_name,
                subnet=cidr,
                internal=internal,
            )
        except Exception as e:
            LOG.error(
                "vpc_network: create_network %s (cidr=%s, internal=%s) "
                "failed: %s -- VPC %s now has no Docker network. Run "
                "``docker network prune`` or check the bridge IPAM "
                "pool; the next ``RunInstances`` will fail until this "
                "is resolved.",
                network_name, cidr, internal, e, vpc_id,
            )
            return False

        # 5. Reconnect every endpoint to the new network.
        for c in all_endpoints:
            try:
                DOCKER_CLIENT.connect_container_to_network(
                    network_name, c,
                )
            except Exception as e:
                LOG.warning(
                    "vpc_network: reconnect %s to %s failed: %s",
                    c, network_name, e,
                )

        with self._lock:
            if vpc_id in self._vpcs:
                self._vpcs[vpc_id]["network_id"] = new_network_id
        return True

    # ------------------------------------------------------------------
    # VPC Peering — connect containers to both VPC networks
    # ------------------------------------------------------------------

    def create_peering(self, peering_id: str, vpc1_id: str, vpc2_id: str) -> None:
        """Establish VPC peering via a dedicated Docker bridge network.

        Self-peering is rejected ().
        Creates a separate Docker network for this peering connection and
        connects all containers from both VPCs to it.  This avoids
        transitive peering: if A<->B and A<->C are peered, B and C each
        get their own peering network with A, so B and C cannot
        communicate through A.
        """
        if vpc1_id == vpc2_id:
            LOG.warning("Cannot peer VPC %s with itself", vpc1_id)
            return

        peering_net_name = f"{PEERING_NETWORK_PREFIX}{peering_id}"

        with self._lock:
            vpc1_info = self._vpcs.get(vpc1_id, {})
            vpc2_info = self._vpcs.get(vpc2_id, {})
            vpc1_containers = list(vpc1_info.get("containers", set()))
            vpc2_containers = list(vpc2_info.get("containers", set()))

        # Create a dedicated bridge network for this peering (no subnet
        # needed — Docker assigns IPs automatically on the bridge).
        # Labels let the startup reconciler (rebuild_peerings_from_docker)
        # recognise orphan networks across a LocalEmu restart when moto
        # state has been reset but Docker hasn't.
        try:
            network_id = DOCKER_CLIENT.create_network(
                network_name=peering_net_name,
                internal=True,
                labels={
                    "localemu.kind": "vpc-peering",
                    "localemu.pcx-id": peering_id,
                    "localemu.vpc1": vpc1_id,
                    "localemu.vpc2": vpc2_id,
                },
            )
        except Exception as e:
            LOG.warning("Failed to create peering network %s: %s", peering_net_name, e)
            return

        with self._lock:
            self._peerings[peering_id] = {
                "vpc1_id": vpc1_id,
                "vpc2_id": vpc2_id,
                "network_name": peering_net_name,
                "network_id": network_id,
            }

        # Connect all containers from both VPCs to the peering network
        for container in vpc1_containers + vpc2_containers:
            try:
                DOCKER_CLIENT.connect_container_to_network(peering_net_name, container)
            except Exception:
                pass

        # Program in-container routes so real VPC IPs route across the
        # peering — without this, only the Docker-assigned pcx-bridge
        # IP works and the peer's own VPC IP (the one a user actually
        # writes into Terraform) is unreachable. Fix design:
        # DockerEmulation/vpc_peering_tgw_design/01_peering_routing.md.
        self._program_peering_routes_for_pair(
            peering_net_name, vpc1_containers, vpc2_id, vpc1_id,
        )
        self._program_peering_routes_for_pair(
            peering_net_name, vpc2_containers, vpc1_id, vpc2_id,
        )

        LOG.info("VPC peering %s established: %s <-> %s (network %s)", peering_id, vpc1_id, vpc2_id, peering_net_name)

    def _peer_instances_for(
        self, peering_net_name: str, peer_vpc_id: str,
    ) -> list[tuple[str, str]]:
        """Return ``[(peer_vpc_ip, peer_pcx_ip), …]`` for every container
        in ``peer_vpc_id`` that is attached to ``peering_net_name``."""
        peer_vpc_net = f"{VPC_NETWORK_PREFIX}{peer_vpc_id}"
        peer_containers = list(
            (self._vpcs.get(peer_vpc_id) or {}).get("containers", set())
        )
        out: list[tuple[str, str]] = []
        for peer_c in peer_containers:
            try:
                peer_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                    peer_c, peer_vpc_net,
                )
                peer_pcx_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                    peer_c, peering_net_name,
                )
            except Exception:
                continue
            if peer_vpc_ip and peer_pcx_ip:
                out.append((peer_vpc_ip, peer_pcx_ip))
        return out

    def _program_peering_routes_for_pair(
        self, peering_net_name: str, containers: list, peer_vpc_id: str, own_vpc_id: str,
    ) -> None:
        """For each container in ``own_vpc_id``, program full peering
        routing — alias, /32 peer DNAT+route, blanket SNAT on pcx."""
        from localemu.services.ec2.docker.container_routing import (
            program_peering_routes, resolve_pcx_iface,
        )
        own_vpc_net = f"{VPC_NETWORK_PREFIX}{own_vpc_id}"
        peer_instances = self._peer_instances_for(peering_net_name, peer_vpc_id)
        for container in containers:
            try:
                own_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                    container, own_vpc_net,
                )
                own_pcx_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                    container, peering_net_name,
                )
            except Exception:
                own_vpc_ip = own_pcx_ip = None
            if not (own_vpc_ip and own_pcx_ip):
                continue
            pcx_iface = resolve_pcx_iface(container, peering_net_name)
            if not pcx_iface:
                continue
            program_peering_routes(
                container, pcx_iface, own_vpc_ip, own_pcx_ip, peer_instances,
            )

    def delete_peering(self, peering_id: str) -> None:
        """Remove VPC peering by destroying the dedicated peering network."""
        with self._lock:
            peering = self._peerings.pop(peering_id, None)
            if not peering:
                return
            vpc1_id = peering["vpc1_id"]
            vpc2_id = peering["vpc2_id"]
            peering_net = peering.get("network_name")
            vpc1_info = self._vpcs.get(vpc1_id, {})
            vpc2_info = self._vpcs.get(vpc2_id, {})
            vpc1_containers = list(vpc1_info.get("containers", set()))
            vpc2_containers = list(vpc2_info.get("containers", set()))

        if peering_net:
            # Disconnect all containers first, then remove the network
            for container in vpc1_containers + vpc2_containers:
                try:
                    DOCKER_CLIENT.disconnect_container_from_network(peering_net, container)
                except Exception:
                    pass
            try:
                DOCKER_CLIENT.delete_network(peering_net)
            except Exception:
                pass

        LOG.info("VPC peering %s removed: %s <-> %s", peering_id, vpc1_id, vpc2_id)

    def get_peered_networks(self, vpc_id: str) -> list[str]:
        """Return dedicated peering network names for all peerings involving this VPC."""
        networks = []
        with self._lock:
            for peering in self._peerings.values():
                if peering["vpc1_id"] == vpc_id or peering["vpc2_id"] == vpc_id:
                    net = peering.get("network_name")
                    if net:
                        networks.append(net)
        return networks

    # ------------------------------------------------------------------
    # Container tracking
    # ------------------------------------------------------------------

    def register_container(
        self, vpc_id: str, container_name: str, subnet_id: str | None = None,
    ) -> None:
        """Track a container as belonging to a VPC (for IGW/peering operations).

        Also records subnet_id for per-subnet operations (NACLs).
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if vpc_info:
                vpc_info["containers"].add(container_name)
            if subnet_id:
                self._container_subnets[container_name] = subnet_id

        # If this VPC has active peerings, connect container to peer networks
        # AND program in-container routes so the peer's VPC IP is reachable.
        peer_networks = self.get_peered_networks(vpc_id)
        for peer_net in peer_networks:
            try:
                DOCKER_CLIENT.connect_container_to_network(peer_net, container_name)
            except Exception:
                pass

        # Late-join: program routes for every peering this VPC participates in.
        if peer_networks:
            self._program_peering_routes_for_new_container(
                vpc_id, container_name,
            )

    def _program_peering_routes_for_new_container(
        self, own_vpc_id: str, container_name: str,
    ) -> None:
        """Late-join: a new container joined an already-peered VPC. Wire
        it into every active peering AND update every existing peer
        container with a /32 route back to the newcomer."""
        from localemu.services.ec2.docker.container_routing import (
            add_peer_host_route, program_peering_routes, resolve_pcx_iface,
        )
        with self._lock:
            peerings = list(self._peerings.values())
        own_vpc_net = f"{VPC_NETWORK_PREFIX}{own_vpc_id}"
        try:
            own_vpc_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                container_name, own_vpc_net,
            )
        except Exception:
            own_vpc_ip = None
        if not own_vpc_ip:
            return
        for peering in peerings:
            if peering.get("vpc1_id") == own_vpc_id:
                peer_vpc_id = peering.get("vpc2_id")
            elif peering.get("vpc2_id") == own_vpc_id:
                peer_vpc_id = peering.get("vpc1_id")
            else:
                continue
            peer_net = peering.get("network_name") or ""
            if not peer_net:
                continue
            new_pcx_iface = resolve_pcx_iface(container_name, peer_net)
            if not new_pcx_iface:
                continue
            try:
                new_pcx_ip = DOCKER_CLIENT.get_container_ipv4_for_network(
                    container_name, peer_net,
                )
            except Exception:
                new_pcx_ip = None
            if not new_pcx_ip:
                continue
            peer_instances = self._peer_instances_for(peer_net, peer_vpc_id)
            # (1) Full programming on the newcomer.
            program_peering_routes(
                container_name, new_pcx_iface, own_vpc_ip, new_pcx_ip,
                peer_instances,
            )
            # (2) Install /32 route on every existing peer container
            # pointing at the newcomer's VPC IP via the newcomer's
            # pcx IP (peers' SNAT rules already cover their own
            # outbound direction; they just need the host route).
            peer_containers = list(
                (self._vpcs.get(peer_vpc_id) or {}).get("containers", set())
            )
            for peer_c in peer_containers:
                peer_iface = resolve_pcx_iface(peer_c, peer_net)
                if not peer_iface:
                    continue
                add_peer_host_route(
                    peer_c, peer_iface, own_vpc_ip, new_pcx_ip,
                )

    def deregister_container(self, vpc_id: str, container_name: str) -> None:
        """Remove a container from VPC tracking and disconnect from peering networks."""
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if vpc_info:
                vpc_info["containers"].discard(container_name)
            # Clean up subnet tracking
            self._container_subnets.pop(container_name, None)
            # Get peering networks to disconnect from ()
            peer_networks = [
                p.get("network_name") for p in self._peerings.values()
                if (p["vpc1_id"] == vpc_id or p["vpc2_id"] == vpc_id) and p.get("network_name")
            ]

        for peer_net in peer_networks:
            try:
                DOCKER_CLIENT.disconnect_container_from_network(peer_net, container_name)
            except Exception:
                pass

    def get_containers_in_subnet(self, vpc_id: str, subnet_id: str) -> list[str]:
        """Return container names that belong to a specific subnet.

        Enables per-subnet operations like NACL enforcement.
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if not vpc_info:
                return []
            return [
                c for c in vpc_info["containers"]
                if self._container_subnets.get(c) == subnet_id
            ]

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def is_network_ready(self, vpc_id: str) -> bool:
        """Whether a real Docker bridge exists and is tracked for ``vpc_id``.

        Returns ``True`` only when the manager has both a name and a
        non-empty ``network_id`` for the VPC. Callers in the
        ``RunInstances`` path use this to detect the
        "create_vpc_network failed but returned a name" case and surface
        an actionable error instead of silently landing the instance on
        Docker's default bridge.
        """
        with self._lock:
            entry = self._vpcs.get(vpc_id)
        return bool(entry and entry.get("network_id"))

    def get_network_for_vpc(self, vpc_id: str) -> str | None:
        """Return the Docker network name for a VPC if one exists.

        Pure read. Does NOT call Docker, does NOT create. Returns the
        tracked ``network_name`` or ``None`` if the VPC has no live
        bridge.

        Read callers (dashboard, status pages, validation of optional
        side-effects) should use this. Write callers that need a real
        bridge to exist before continuing (``RunInstances``,
        ``AttachInternetGateway``) should call
        ``ensure_network_for_vpc`` instead. Previously this method
        lazily created the bridge on miss, which let the dashboard's
        3-second polling fire a ``docker network create`` per poll;
        failures were not cached and the daemon ended up logging the
        same WARN line several hundred times per session.
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if vpc_info:
                return vpc_info["network_name"]
        return None

    def ensure_network_for_vpc(self, vpc_id: str) -> str | None:
        """Return the Docker network for a VPC, creating it if missing.

        Write path. Looks the VPC up in moto across all
        accounts/regions, calls ``create_vpc_network`` with the
        AWS-side CIDR. Subject to the failure-cooldown gate, so a
        permanent failure (host pool exhausted, daemon unreachable)
        does not loop. Returns ``None`` only when the VPC truly does
        not exist in moto or the create failed and is in cooldown.
        """
        with self._lock:
            vpc_info = self._vpcs.get(vpc_id)
            if vpc_info and vpc_info.get("network_id"):
                return vpc_info["network_name"]
            ts = self._failed_creates.get(vpc_id)
            in_cooldown = ts is not None and (
                time.time() - ts
            ) < FAILED_CREATE_RETRY_TTL_SECONDS

        if in_cooldown:
            return None

        cidr = self._lookup_vpc_cidr_in_moto(vpc_id)
        if not cidr:
            return None

        return self.create_vpc_network(vpc_id, cidr)

    @staticmethod
    def _lookup_vpc_cidr_in_moto(vpc_id: str) -> str | None:
        """Find a VPC's CIDR in the moto metadata store across all regions.

        Returns the CIDR string or ``None`` if the VPC ID is not known
        to moto. moto stores the AWS-side metadata; the real bridge
        is a separate concern handled by this module.
        """
        try:
            from moto.ec2.models import ec2_backends
        except Exception:
            return None
        for _acct, region_map in ec2_backends.items():
            if not isinstance(region_map, dict):
                continue
            for _region, backend in region_map.items():
                vpc = getattr(backend, "vpcs", {}).get(vpc_id)
                if vpc is not None:
                    cidr = getattr(vpc, "cidr_block", "")
                    if cidr:
                        return cidr
        return None

    def adopt_vpc_networks_from_docker(self) -> tuple[int, int]:
        """Reconcile ``self._vpcs`` against live Docker + moto state.

        Walks every ``localemu-vpc-*`` network the daemon knows about,
        cross-references the embedded VPC ID against moto, and either:

          * **Adopts** the bridge into ``self._vpcs`` so subsequent
            ``get_network_for_vpc`` calls return it without ever
            triggering a Docker create (this is the fix for the
            persisted-default-VPC retry storm), OR
          * **Deletes** the bridge as an orphan if its VPC ID is not
            present in any moto backend AND no containers are
            currently attached.

        Idempotent: subsequent calls are no-ops as long as the
        daemon and moto stay in sync. Returns ``(adopted, deleted)``
        counts for logging.
        """
        with self._lock:
            if self._adopted:
                return 0, 0

        adopted = 0
        deleted = 0
        try:
            import subprocess as _sp
            ls = _sp.run(
                [
                    "docker", "network", "ls", "--format", "{{.Name}}",
                    "--filter", f"name={VPC_NETWORK_PREFIX}",
                ],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as e:
            LOG.debug("adopt_vpc_networks_from_docker: docker network ls failed: %s", e)
            return 0, 0
        if ls.returncode != 0:
            return 0, 0

        names = [n.strip() for n in ls.stdout.splitlines() if n.strip()]
        for name in names:
            if not name.startswith(VPC_NETWORK_PREFIX):
                continue
            vpc_id = name.removeprefix(VPC_NETWORK_PREFIX)
            # Old peering networks share the localemu- prefix family but
            # not this exact one; still, defend against odd names.
            if not vpc_id.startswith("vpc-"):
                continue

            try:
                info = DOCKER_CLIENT.inspect_network(name) or {}
            except Exception:
                continue

            cidr_in_moto = self._lookup_vpc_cidr_in_moto(vpc_id)
            if cidr_in_moto is None:
                attached_map = info.get("Containers") or {}
                attached_names = [
                    (entry.get("Name") or "").lstrip("/")
                    for entry in attached_map.values()
                ]
                attached_names = [n for n in attached_names if n]

                if not attached_names:
                    # The simple orphan case: no endpoints, just delete.
                    try:
                        DOCKER_CLIENT.delete_network(name)
                        deleted += 1
                        LOG.info(
                            "adopt: deleted orphan VPC bridge %s "
                            "(vpc-id not in moto, no containers attached)",
                            name,
                        )
                    except Exception as e:
                        LOG.debug(
                            "adopt: could not delete orphan %s: %s", name, e,
                        )
                    continue

                # Endpoints attached. If every endpoint is one of LocalEmu's
                # own containers (IMDS sidecar from a crashed prior session,
                # an EC2 we lost track of, etc.) we own the cleanup: stop
                # and remove each, then delete the bridge. This is the path
                # that recovers from ``docker kill`` on the LocalEmu
                # container — without it, a single leftover sidecar keeps
                # an entire /16 reserved forever and exhausts the fallback
                # pools.
                external = [
                    n for n in attached_names
                    if not n.startswith(_LOCALEMU_CONTAINER_PREFIX)
                ]
                if external:
                    LOG.debug(
                        "adopt: leaving orphan VPC bridge %s alone — "
                        "%d non-localemu container(s) attached (%s)",
                        name, len(external), ", ".join(external[:3]),
                    )
                    continue

                reclaimed_any = False
                for owned in attached_names:
                    try:
                        DOCKER_CLIENT.stop_container(owned, timeout=5)
                    except Exception:
                        pass
                    try:
                        DOCKER_CLIENT.remove_container(owned, force=True)
                        reclaimed_any = True
                    except Exception as e:
                        LOG.debug(
                            "adopt: could not remove leftover container "
                            "%s on orphan bridge %s: %s",
                            owned, name, e,
                        )
                try:
                    DOCKER_CLIENT.delete_network(name)
                    deleted += 1
                    LOG.info(
                        "adopt: reclaimed orphan VPC bridge %s "
                        "(removed %d leftover localemu container(s) "
                        "blocking it)",
                        name, sum(1 for _ in attached_names) if reclaimed_any else 0,
                    )
                except Exception as e:
                    LOG.debug(
                        "adopt: could not delete reclaimed bridge %s "
                        "even after removing %d leftover container(s): %s",
                        name, len(attached_names), e,
                    )
                continue

            docker_cidr = ""
            for cfg in (info.get("IPAM") or {}).get("Config") or []:
                if cfg.get("Subnet"):
                    docker_cidr = cfg["Subnet"]
                    break
            is_internal = bool(info.get("Internal"))

            with self._lock:
                if vpc_id in self._vpcs:
                    continue
                self._vpcs[vpc_id] = {
                    "network_name": name,
                    "cidr": cidr_in_moto,
                    "docker_cidr": docker_cidr,
                    "network_id": info.get("Id"),
                    "has_igw": not is_internal,
                    "containers": set(),
                }
                self._failed_creates.pop(vpc_id, None)
            adopted += 1

        with self._lock:
            self._adopted = True

        if adopted or deleted:
            LOG.info(
                "VpcNetworkManager: adopted %d existing VPC bridge(s), "
                "deleted %d orphan(s)",
                adopted, deleted,
            )
        return adopted, deleted

    def get_vpc_id_for_subnet(self, subnet_id: str, account_id: str, region: str) -> str | None:
        """Resolve a subnet ID to its VPC ID via Moto."""
        try:
            import moto.backends as moto_backends

            ec2_backend = moto_backends.get_backend("ec2")[account_id][region]
            for _az, subnets in ec2_backend.subnets.items():
                if isinstance(subnets, dict):
                    for sub in subnets.values():
                        if hasattr(sub, "id") and sub.id == subnet_id:
                            return sub.vpc_id
                elif hasattr(subnets, "id") and subnets.id == subnet_id:
                    return subnets.vpc_id
        except Exception as e:
            LOG.debug("Failed to resolve subnet %s: %s", subnet_id, e)
        return None

    def get_network_for_subnet(self, subnet_id: str, account_id: str, region: str) -> str | None:
        """Resolve a subnet ID to the VPC's Docker network name.

        Mutating: this is the resolver used by RunInstances and other
        write paths. If the underlying VPC has no Docker bridge yet,
        ``ensure_network_for_vpc`` creates one (subject to the failure
        cooldown). Returns the bridge name on success, ``None`` when
        the VPC cannot be resolved or the create is in cooldown.
        """
        vpc_id = self.get_vpc_id_for_subnet(subnet_id, account_id, region)
        return self.ensure_network_for_vpc(vpc_id) if vpc_id else None

    def get_network_for_instance(
        self, instance_data: dict, account_id: str, region: str
    ) -> str | None:
        """Resolve an EC2 instance to its VPC Docker network.

        Mutating: called from the RunInstances handler in
        ``services/ec2/provider.py`` to determine which bridge to
        attach the new container to. The first VPC ID found (instance
        ``VpcId`` field, then subnet lookup, then ENI list) is passed
        through ``ensure_network_for_vpc`` so the bridge exists by the
        time the container start call runs.
        """
        vpc_id = instance_data.get("VpcId")
        if vpc_id:
            network = self.ensure_network_for_vpc(vpc_id)
            if network:
                return network

        subnet_id = instance_data.get("SubnetId")
        if subnet_id:
            return self.get_network_for_subnet(subnet_id, account_id, region)

        for nic in instance_data.get("NetworkInterfaces", []):
            vpc_id = nic.get("VpcId")
            if vpc_id:
                return self.ensure_network_for_vpc(vpc_id)

        return None

    # ------------------------------------------------------------------
    # Persistence restore 
    # ------------------------------------------------------------------

    def rebuild_from_docker(self) -> None:
        """Reconstruct ``_vpcs[*].containers`` and ``_container_subnets``
        from live Docker state.

        After LocalEmu restart the in-memory tracking is empty while
        ``PERSISTENCE=1`` has preserved the containers and their VPC
        network attachments. This method walks every container that
        carries a ``localemu.service`` label, inspects it for
        ``localemu-vpc-*`` network attachments, and rebuilds the
        tracking so subsequent IGW / peering / NACL operations see the
        restored containers.

        Idempotent: calling it twice has the same effect as once.
        Safe in the presence of inspect failures for individual
        containers — a single broken container doesn't abort the
        whole rebuild.
        """
        try:
            containers = DOCKER_CLIENT.list_containers(
                filter=["label=localemu.service"], all=True,
            )
        except Exception:
            LOG.debug("rebuild_from_docker: list_containers failed", exc_info=True)
            return

        rebuilt = 0
        for c in containers:
            name = c.get("name") or c.get("id") or ""
            if not name:
                continue
            try:
                inspect = DOCKER_CLIENT.inspect_container(name)
            except Exception:
                LOG.debug(
                    "rebuild_from_docker: inspect(%s) failed — skipping",
                    name, exc_info=True,
                )
                continue

            labels = (inspect.get("Config") or {}).get("Labels") or {}
            networks = (inspect.get("NetworkSettings") or {}).get("Networks") or {}

            vpc_ids: list[str] = []
            for net_name in networks:
                if net_name.startswith(VPC_NETWORK_PREFIX):
                    vpc_ids.append(net_name.removeprefix(VPC_NETWORK_PREFIX))

            if not vpc_ids:
                continue  # container not on any VPC network

            subnet_id = labels.get("localemu.subnet-id") or None

            with self._lock:
                for vpc_id in vpc_ids:
                    if vpc_id not in self._vpcs:
                        # Container is on a VPC network we don't track
                        # yet — create a minimal record so future ops
                        # (IGW toggle, peering) can find the container.
                        self._vpcs[vpc_id] = {
                            "network_name": f"{VPC_NETWORK_PREFIX}{vpc_id}",
                            "cidr": "",
                            "network_id": None,
                            "has_igw": False,
                            "containers": set(),
                        }
                    self._vpcs[vpc_id]["containers"].add(name)
                if subnet_id:
                    self._container_subnets[name] = subnet_id

            rebuilt += 1

        if rebuilt:
            LOG.info(
                "VpcNetworkManager: rebuilt tracking for %d container(s) from Docker state",
                rebuilt,
            )

    def reconcile_peerings_from_docker(self) -> int:
        """Sweep orphan / drifted ``localemu-pcx-*`` Docker networks.

        Called from ``Ec2Provider.on_after_state_load`` after
        ``rebuild_from_docker``. Fixes two classes of leak:

          1. LocalEmu restart with PERSISTENCE=0 resets moto state but
             Docker state survives → orphan ``localemu-pcx-*`` networks.
             We delete them (recognisable by the ``localemu.kind=vpc-peering``
             label).
          2. Active moto peering where the Docker network was deleted
             out-of-band (e.g. manual ``docker network prune``) — we
             recreate it and re-attach containers.

        Returns the number of orphan networks deleted.
        """
        from moto.ec2.models import ec2_backends

        # Enumerate ``localemu-pcx-*`` Docker networks AND our tracked
        # peerings, then reconcile. ``DOCKER_CLIENT.get_networks`` takes
        # a container name so it doesn't help — shell out to
        # ``docker network ls`` and parse names.
        pcx_nets: set[str] = set()
        try:
            import subprocess as _sp
            out = _sp.run(
                ["docker", "network", "ls", "--format", "{{.Name}}",
                 "--filter", f"name={PEERING_NETWORK_PREFIX}"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                for line in out.stdout.splitlines():
                    name = line.strip()
                    if name.startswith(PEERING_NETWORK_PREFIX):
                        pcx_nets.add(name)
        except Exception:
            LOG.debug("reconciler: docker network ls failed", exc_info=True)
        # Active peerings across every account/region backend.
        active_pcx: dict[str, tuple[str, str]] = {}
        try:
            for _acct, region_map in ec2_backends.items():
                for _region, be in region_map.items():
                    for pcx in getattr(be, "vpc_pcxs", {}).values():
                        status = (getattr(pcx, "_status", None)
                                  or getattr(pcx, "status", None))
                        code = getattr(status, "code", None)
                        if code is None and isinstance(status, dict):
                            code = status.get("Code") or status.get("code")
                        if code != "active":
                            continue
                        active_pcx[pcx.id] = (
                            getattr(getattr(pcx, "vpc", None), "id", "") or "",
                            getattr(getattr(pcx, "peer_vpc", None), "id", "") or "",
                        )
        except Exception:
            LOG.debug("reconcile_peerings_from_docker: moto enumeration failed",
                      exc_info=True)

        deleted = 0
        # 1. Orphan Docker networks (pcx name doesn't map to any active moto pcx).
        for net_name in pcx_nets:
            pcx_id = net_name.removeprefix(PEERING_NETWORK_PREFIX)
            if pcx_id in active_pcx:
                continue
            try:
                # Disconnect every attached container before removing.
                info = DOCKER_CLIENT.inspect_network(net_name) or {}
                for c in (info.get("Containers") or {}).values():
                    cname = c.get("Name")
                    if cname:
                        try:
                            DOCKER_CLIENT.disconnect_container_from_network(
                                net_name, cname,
                            )
                        except Exception:
                            pass
                DOCKER_CLIENT.delete_network(net_name)
                deleted += 1
                LOG.info("reconciler: deleted orphan peering network %s", net_name)
            except Exception as e:
                LOG.debug("reconciler: cannot delete %s: %s", net_name, e)

        # 2. Active moto pcx with no Docker network → recreate.
        for pcx_id, (v1, v2) in active_pcx.items():
            expected = f"{PEERING_NETWORK_PREFIX}{pcx_id}"
            if expected in pcx_nets:
                continue
            if not (v1 and v2):
                continue
            try:
                self.create_peering(pcx_id, v1, v2)
                LOG.info("reconciler: re-created peering network for %s", pcx_id)
            except Exception as e:
                LOG.debug("reconciler: cannot recreate %s: %s", expected, e)

        return deleted

    def cleanup_all(self) -> None:
        """Remove all VPC and peering Docker networks. Called on shutdown.

        IMDS sidecars are removed first because they hold network
        endpoints that would otherwise block ``docker network rm``.
        """
        with self._lock:
            vpc_data = {vid: dict(info) for vid, info in self._vpcs.items()}
            peering_data = list(self._peerings.values())
            self._vpcs.clear()
            self._peerings.clear()
            self._container_subnets.clear()

        # Tear down all per-VPC IMDS sidecars FIRST: each sidecar holds
        # an endpoint on its VPC network, and ``docker network rm`` below
        # would fail with "has active endpoints" if we left them attached.
        try:
            from localemu.services.ec2.docker.imds_sidecar import cleanup_all as _imds_cleanup_all
            _imds_cleanup_all()
        except Exception:
            LOG.debug("IMDS sidecar cleanup failed during shutdown", exc_info=True)

        # Disconnect containers from peering networks, then delete
        peering_deleted = 0
        for peering in peering_data:
            pnet = peering.get("network_name")
            if not pnet:
                continue
            for vid in (peering.get("vpc1_id"), peering.get("vpc2_id")):
                for c in vpc_data.get(vid, {}).get("containers", set()):
                    try:
                        DOCKER_CLIENT.disconnect_container_from_network(pnet, c)
                    except Exception:
                        pass
            try:
                DOCKER_CLIENT.delete_network(pnet)
                peering_deleted += 1
            except Exception:
                LOG.warning(
                    "Failed to delete peering network %s", pnet,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        # Disconnect containers from VPC networks, then delete
        vpc_deleted = 0
        for vpc_id, info in vpc_data.items():
            network_name = info.get("network_name", f"{VPC_NETWORK_PREFIX}{vpc_id}")
            for c in info.get("containers", set()):
                try:
                    DOCKER_CLIENT.disconnect_container_from_network(network_name, c)
                except Exception:
                    pass
            try:
                DOCKER_CLIENT.delete_network(network_name)
                vpc_deleted += 1
            except Exception:
                LOG.warning(
                    "Failed to delete VPC network %s", network_name,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        LOG.info(
            "Cleaned up %d/%d VPC Docker networks and %d/%d peering networks",
            vpc_deleted, len(vpc_data), peering_deleted, len(peering_data),
        )


# Module-level singleton
_vpc_network_manager: VpcNetworkManager | None = None
_manager_lock = threading.Lock()


def get_vpc_network_manager() -> VpcNetworkManager:
    """Return the global VPC network manager singleton.

    First call also runs ``adopt_vpc_networks_from_docker`` so any
    bridges that survived a previous LocalEmu session reattach into
    ``_vpcs`` instead of triggering lazy-create attempts. The adoption
    is also called explicitly from ``Ec2Provider.on_after_init`` and
    ``Ec2Provider.on_after_state_load`` (the latter, before
    ``rebuild_from_docker``); this accessor-level call is the
    belt-and-braces path that covers any code path that touches the
    manager before either lifecycle hook fires.
    """
    global _vpc_network_manager
    if _vpc_network_manager is None:
        with _manager_lock:
            if _vpc_network_manager is None:
                _vpc_network_manager = VpcNetworkManager()
    if not _vpc_network_manager._adopted:
        try:
            _vpc_network_manager.adopt_vpc_networks_from_docker()
        except Exception:
            LOG.debug(
                "VPC adoption on singleton access raised; "
                "will retry on the next call",
                exc_info=True,
            )
    return _vpc_network_manager
