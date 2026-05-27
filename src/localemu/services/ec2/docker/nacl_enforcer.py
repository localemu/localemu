"""
Network ACL enforcement via iptables inside Docker containers.

Translates AWS NACL rules to iptables custom chains and applies them
via ``docker exec``.  NACLs are stateless firewall rules at the subnet
level — each container in the subnet gets the same iptables rules.

Works on Mac, Linux, and Windows (Docker Desktop).
Requires NET_ADMIN capability on containers.

Architecture
------------

  CreateNetworkAclEntry → translate to iptables → docker exec per container
  Chain structure:
    INPUT  → NACL_IN  (inbound rules, ordered by rule number)
    OUTPUT → NACL_OUT (outbound rules, ordered by rule number)

Fail-closed contract 
-------------------------------
``apply_nacl_to_container`` returns ``True`` only on full success. On
any failure (``iptables`` missing, exec step errors), it returns
``False`` and installs a fail-closed default-DROP policy on
NACL_IN/NACL_OUT — never leaves the container at Docker's default
ACCEPT while pretending NACLs are enforced.
"""

from __future__ import annotations

import logging

from localemu.services.ec2.docker.sg_iptables import _probe_iptables
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# Protocol number to iptables protocol name
_PROTO_MAP = {
    "-1": "all",
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
}


def _build_iptables_rules(entries: list, egress: bool) -> list[str]:
    """Convert NACL entries to ordered iptables rule commands.

    Entries are sorted by rule number (lowest first = highest priority).
    Rule 32767 is the default deny-all (implicit in iptables as final DROP).
    """
    chain = "NACL_OUT" if egress else "NACL_IN"

    filtered = [
        e for e in entries
        if getattr(e, "egress", False) == egress
        and getattr(e, "rule_number", 0) < 32767
    ]
    filtered.sort(key=lambda e: getattr(e, "rule_number", 0))

    rules = []
    for entry in filtered:
        action = "ACCEPT" if getattr(entry, "rule_action", "") == "allow" else "DROP"
        proto = _PROTO_MAP.get(str(getattr(entry, "protocol", "-1")), "all")
        cidr = getattr(entry, "cidr_block", "0.0.0.0/0") or "0.0.0.0/0"

        port_flags = ""
        if proto in ("tcp", "udp"):
            from_port = getattr(entry, "port_range_from", None)
            to_port = getattr(entry, "port_range_to", None)
            if from_port is None or to_port is None:
                port_range = getattr(entry, "port_range", None)
                if isinstance(port_range, dict):
                    from_port = (
                        port_range.get("from_port")
                        or port_range.get("from")
                        or from_port
                    )
                    to_port = (
                        port_range.get("to_port")
                        or port_range.get("to")
                        or to_port
                    )
                elif port_range is not None:
                    from_port = getattr(port_range, "from_port", from_port)
                    to_port = getattr(port_range, "to_port", to_port)
            if from_port is not None and to_port is not None:
                if from_port == to_port:
                    port_flags = f"--dport {from_port}"
                else:
                    port_flags = f"--dport {from_port}:{to_port}"

        direction = "-d" if egress else "-s"
        if proto == "all":
            rule = f"-A {chain} {direction} {cidr} -j {action}"
        elif port_flags:
            rule = f"-A {chain} -p {proto} {direction} {cidr} {port_flags} -j {action}"
        else:
            rule = f"-A {chain} -p {proto} {direction} {cidr} -j {action}"

        rules.append(rule)

    # Default deny at the end
    rules.append(f"-A {chain} -j DROP")

    return rules


def _build_apply_script(in_rules: list[str], out_rules: list[str]) -> str:
    """Atomic apply script. ``set -e`` makes any step-failure abort so
    the caller will install the emergency default-DROP policy.
    """
    commands = [
        "set -e",
        "iptables -N NACL_IN 2>/dev/null || true",
        "iptables -N NACL_OUT 2>/dev/null || true",
        "iptables -F NACL_IN",
        "iptables -F NACL_OUT",
    ]
    commands.extend(f"iptables {r}" for r in in_rules)
    commands.extend(f"iptables {r}" for r in out_rules)
    commands.append("iptables -C INPUT -j NACL_IN 2>/dev/null || iptables -I INPUT -j NACL_IN")
    commands.append("iptables -C OUTPUT -j NACL_OUT 2>/dev/null || iptables -I OUTPUT -j NACL_OUT")
    return "; ".join(commands)


def _emergency_default_drop_script() -> str:
    """Fail-closed NACL: loopback only, final DROP.

    AWS NACLs are STATELESS: return traffic needs an explicit allow
    rule, conntrack does not auto-permit it. Including
    ``-m state --state ESTABLISHED,RELATED -j ACCEPT`` here would make
    the emergency policy MORE permissive than a strict AWS NACL would
    be — a stateful-on-stateless-contract violation. Loopback stays
    open because every distro's init scripts rely on it.

    When this script fires the operator should notice: it means the
    normal NACL apply path failed, the container is in deny-everything
    mode, and external traffic (including return packets for
    previously-allowed flows) is dropped. That is correct fail-closed
    behavior.
    """
    commands = [
        "iptables -N NACL_IN 2>/dev/null || true",
        "iptables -N NACL_OUT 2>/dev/null || true",
        "iptables -F NACL_IN",
        "iptables -F NACL_OUT",
        "iptables -A NACL_IN -i lo -j ACCEPT",
        "iptables -A NACL_IN -j DROP",
        "iptables -A NACL_OUT -o lo -j ACCEPT",
        "iptables -A NACL_OUT -j DROP",
        "iptables -C INPUT -j NACL_IN 2>/dev/null || iptables -I INPUT -j NACL_IN",
        "iptables -C OUTPUT -j NACL_OUT 2>/dev/null || iptables -I OUTPUT -j NACL_OUT",
    ]
    return "; ".join(commands)


def _try_emergency_default_drop(container_name: str) -> None:
    """Best-effort fail-closed install."""
    try:
        DOCKER_CLIENT.exec_in_container(
            container_name, ["sh", "-c", _emergency_default_drop_script()],
        )
        LOG.warning(
            "Container %s: installed fail-closed default-DROP NACL policy",
            container_name,
        )
    except Exception as exc:
        LOG.error(
            "Container %s: could not install fail-closed NACL (%s). "
            "Container may have Docker's default ACCEPT policy — SECURITY RISK.",
            container_name, exc,
        )


def apply_nacl_to_container(container_name: str, nacl_entries: list) -> bool:
    """Apply NACL rules to a container via iptables.

    Returns
    -------
    bool
        ``True`` on full success. ``False`` on any failure; a
        fail-closed default-DROP policy is installed in that case.
    """
    if not _probe_iptables(container_name):
        LOG.error(
            "Container %s: iptables not available — NACL cannot be applied. "
            "Installing fail-closed default-DROP policy.",
            container_name,
        )
        _try_emergency_default_drop(container_name)
        return False

    in_rules = _build_iptables_rules(nacl_entries, egress=False)
    out_rules = _build_iptables_rules(nacl_entries, egress=True)
    script = _build_apply_script(in_rules, out_rules)

    try:
        DOCKER_CLIENT.exec_in_container(container_name, ["sh", "-c", script])
    except Exception:
        LOG.exception(
            "Container %s: NACL apply script failed. "
            "Installing fail-closed default-DROP policy.",
            container_name,
        )
        _try_emergency_default_drop(container_name)
        return False

    LOG.debug(
        "Container %s: applied NACL rules (%d in, %d out)",
        container_name, len(in_rules), len(out_rules),
    )
    return True


def apply_nacl_to_subnet_containers(
    nacl_id: str, subnet_id: str, account_id: str, region: str,
) -> None:
    """Apply NACL rules to all running containers in a subnet.

    Looks up the NACL in Moto's EC2 backend, resolves the subnet's
    Docker network, finds all containers, and applies iptables rules.
    """
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("ec2")[account_id][region]

        nacl = backend.network_acls.get(nacl_id)
        if not nacl:
            return

        entries = getattr(nacl, "network_acl_entries", [])

        from localemu.services.ec2.docker.vpc_network import get_vpc_network_manager
        mgr = get_vpc_network_manager()

        vpc_id = mgr.get_vpc_id_for_subnet(subnet_id, account_id, region)
        if not vpc_id:
            return

        containers = mgr.get_containers_in_subnet(vpc_id, subnet_id)

        # Fallback: no per-subnet tracking data (older containers created
        # before per-subnet membership was tracked).
        if not containers:
            vpc_info = mgr._vpcs.get(vpc_id, {})
            containers = list(vpc_info.get("containers", set()))

        applied = failed = 0
        for container_name in containers:
            if apply_nacl_to_container(container_name, entries):
                applied += 1
            else:
                failed += 1

        LOG.info(
            "NACL %s → subnet %s: applied=%d, failed=%d (of %d containers)",
            nacl_id, subnet_id, applied, failed, len(containers),
        )

    except Exception as e:
        LOG.warning("Failed to apply NACL %s: %s", nacl_id, e)
