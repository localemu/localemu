"""Security group rule evaluator for EC2 Docker instances.

Reads security group rules from Moto's EC2 backend and evaluates whether
a TCP connection (source_ip, protocol, dest_port) is permitted by the
instance's attached security groups.

AWS security groups are permissive-OR: if ANY rule in ANY attached SG
allows the traffic, it passes. There are no deny rules.
"""

import ipaddress
import logging
from dataclasses import dataclass

LOG = logging.getLogger(__name__)


@dataclass
class ConnectionAttempt:
    """Represents an incoming connection to evaluate."""
    source_ip: str
    protocol: str  # "tcp", "udp", "icmp", "-1" (all)
    dest_port: int


class SecurityGroupEvaluator:
    """Evaluates security group rules against connection attempts.

    Reads rules from Moto at evaluation time (not cached), so
    AuthorizeSecurityGroupIngress/RevokeSecurityGroupIngress
    take effect immediately without proxy restart.
    """

    def __init__(self, account_id: str, region: str):
        self.account_id = account_id
        self.region = region

    def is_ingress_allowed(
        self,
        security_group_ids: list[str],
        conn: ConnectionAttempt,
    ) -> bool:
        """Check if an inbound connection is allowed by any attached security group.

        Args:
            security_group_ids: List of SG IDs attached to the instance
            conn: The connection attempt to evaluate

        Returns:
            True if any rule in any SG allows this connection
        """
        if not security_group_ids:
            # In AWS, instances always have at least the default SG.
            # Deny by default when no SGs are attached (audit fix #1).
            return False

        try:
            from moto.ec2.models import ec2_backends

            backend = ec2_backends[self.account_id][self.region]

            for sg_id in security_group_ids:
                sgs = list(backend.describe_security_groups(group_ids=[sg_id]))
                if not sgs:
                    continue

                sg = sgs[0]
                for rule in sg.ingress_rules:
                    if self._rule_matches(rule, conn, security_group_ids):
                        LOG.debug(
                            "SG %s allows %s:%d from %s (rule: %s %s-%s)",
                            sg_id, conn.protocol, conn.dest_port, conn.source_ip,
                            rule.ip_protocol, rule.from_port, rule.to_port,
                        )
                        return True

        except Exception as e:
            LOG.warning("SG evaluation error, defaulting to deny: %s", e)
            return False

        LOG.debug(
            "SG DENY: no rule allows %s:%d from %s (checked %d SGs)",
            conn.protocol, conn.dest_port, conn.source_ip, len(security_group_ids),
        )
        return False

    def _rule_matches(self, rule, conn: ConnectionAttempt, instance_sg_ids: list[str]) -> bool:
        """Check if a single ingress rule matches the connection attempt."""
        # Check protocol
        rule_protocol = str(rule.ip_protocol)
        if rule_protocol != "-1" and rule_protocol != conn.protocol:
            return False

        # Check port range (skip for ICMP and "all" protocol)
        if rule_protocol not in ("-1", "icmp"):
            from_port = int(rule.from_port) if rule.from_port is not None else 0
            to_port = int(rule.to_port) if rule.to_port is not None else 65535
            if not (from_port <= conn.dest_port <= to_port):
                return False

        # Moto's SecurityGroupRule stores one CIDR per row (``ip_range``,
        # singular dict like ``{"CidrIp": "0.0.0.0/0"}``) plus an
        # optional single source-group ref (``source_group``). Earlier
        # versions used plural ``ip_ranges`` lists — handle both shapes
        # so we work across moto versions.
        cidr_candidates: list[str] = []
        ip_range = getattr(rule, "ip_range", None)
        if isinstance(ip_range, dict) and ip_range.get("CidrIp"):
            cidr_candidates.append(ip_range["CidrIp"])
        elif isinstance(ip_range, str):
            cidr_candidates.append(ip_range)
        for legacy in (getattr(rule, "ip_ranges", None) or []):
            if isinstance(legacy, str):
                cidr_candidates.append(legacy)
            elif isinstance(legacy, dict) and legacy.get("CidrIp"):
                cidr_candidates.append(legacy["CidrIp"])
        for cidr in cidr_candidates:
            if cidr and self._ip_in_cidr(conn.source_ip, cidr):
                return True

        # IPv6 CIDRs (singular ``ipv6_range``/legacy ``ip_ranges_ipv6``)
        ipv6 = getattr(rule, "ipv6_range", None)
        if isinstance(ipv6, dict) and ipv6.get("CidrIpv6"):
            if self._ip_in_cidr(conn.source_ip, ipv6["CidrIpv6"]):
                return True
        for legacy_v6 in (getattr(rule, "ip_ranges_ipv6", None) or []):
            cidr = legacy_v6 if isinstance(legacy_v6, str) else legacy_v6.get("CidrIpv6", "")
            if cidr and self._ip_in_cidr(conn.source_ip, cidr):
                return True

        # Source-SG refs: moto's new model stores a single ``source_group``
        # dict per rule; older moto used the plural ``source_groups``.
        sg_refs: list = []
        sg_single = getattr(rule, "source_group", None)
        if isinstance(sg_single, dict) and sg_single.get("GroupId"):
            sg_refs.append(sg_single)
        sg_refs.extend(getattr(rule, "source_groups", None) or [])
        for sg_ref in sg_refs:
            ref_sg_id = sg_ref if isinstance(sg_ref, str) else sg_ref.get("GroupId", "")
            if not ref_sg_id:
                continue

            # Self-referencing SG: if the referenced SG is one of the
            # instance's own SGs, allow from localhost (loopback proxy case)
            if ref_sg_id in instance_sg_ids and conn.source_ip in ("127.0.0.1", "::1"):
                return True

            # Look up which SGs are attached to the source IP's instance
            source_sg_ids = self._get_sg_ids_for_ip(conn.source_ip)
            if ref_sg_id in source_sg_ids:
                return True

        return False

    def _get_sg_ids_for_ip(self, ip: str) -> list[str]:
        """Return the security group IDs attached to the instance with this private IP.

        Checks both Moto's tracked private_ip_address and Docker container IPs
        for container-to-container communication within VPC Docker networks.
        """
        try:
            from moto.ec2.models import ec2_backends

            backend = ec2_backends[self.account_id][self.region]
            for instance in backend.all_instances():
                if getattr(instance, "private_ip_address", None) == ip:
                    return [sg.id for sg in getattr(instance, "security_groups", [])]
                # Also check additional private IPs (network interfaces)
                for nic in getattr(instance, "nics", {}).values():
                    for priv_ip in getattr(nic, "private_ip_addresses", []):
                        addr = priv_ip if isinstance(priv_ip, str) else priv_ip.get("PrivateIpAddress", "")
                        if addr == ip:
                            return [sg.id for sg in getattr(instance, "security_groups", [])]
        except Exception:
            pass
        return []

    @staticmethod
    def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
        """Check if an IP address is within a CIDR range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(cidr_str, strict=False)
            return ip in network
        except ValueError:
            return False
