"""Resolve a VPC's DHCP-driven DNS server list for a launching instance.

When an EC2 instance container starts, real AWS expects the instance's
``/etc/resolv.conf`` to point at whatever ``domain-name-servers`` the
VPC's currently-associated DHCP option set advertises. Without honouring
that, the "VPC DNS Hijack" attack — set a malicious ``domain-name-servers``
on the option set, associate it, watch every new instance resolve
through it — is undetectable from inside the instance.

This module reads moto's DHCP option set + VPC tables and returns the
list of DNS server IPs the container should be created with (passed as
``--dns`` to Docker). The resolution honours the AWS-documented order:

1. The DHCP option set explicitly associated with the VPC.
2. The default option set the VPC fell back to (moto creates one for
   every account on first VPC creation).
3. Nothing — return empty; the caller leaves Docker's default DNS in
   place (the Docker daemon's resolver, which is what the LocalEmu
   non-VPC instance path uses today).

The special value ``"AmazonProvidedDNS"`` — AWS's "use the default
VPC-internal resolver at ``<VPC CIDR>.2``" — is **kept** in the list
even though LocalEmu has no Route53 reachable at that address. The
caller decides how to handle it (replace with a fallback, or drop);
this module's job is faithful translation only.
"""
from __future__ import annotations

import logging
from typing import Iterable

LOG = logging.getLogger(__name__)


_AMAZON_PROVIDED_DNS = "AmazonProvidedDNS"


def resolve_vpc_dns_servers(
    *,
    subnet_id: str | None,
    account_id: str,
    region: str,
    drop_amazon_provided_dns: bool = True,
) -> list[str]:
    """Return the DNS server list configured on a subnet's VPC's DHCP option set.

    Args:
        subnet_id: The subnet the launching instance will attach to. May be
            ``None`` for the legacy non-VPC code path; in that case the
            function returns ``[]`` since no DHCP option set is meaningful.
        account_id: The account owning the subnet.
        region: The region the subnet lives in.
        drop_amazon_provided_dns: When ``True`` (default), the special
            ``"AmazonProvidedDNS"`` token is filtered out before the
            caller hands the list to Docker. The token is a Route53
            indirection that LocalEmu has no resolver for; leaving it
            in would point the container at a non-existent DNS server
            and break resolution entirely. Tests can set this to
            ``False`` to assert the raw moto contents.

    Returns:
        A list of DNS server IPs/hostnames suitable for Docker
        ``--dns``. Empty when there's no subnet, no VPC, no DHCP
        option set, or the option set has no
        ``domain-name-servers`` entry.
    """
    if not subnet_id:
        return []

    try:
        import moto.backends as moto_backends
    except Exception:
        # moto not importable for some reason — keep RunInstances working
        # rather than fail loud here. The caller will see the empty list
        # as "no override, use Docker default".
        return []

    try:
        ec2_backend = moto_backends.get_backend("ec2")[account_id][region]
    except Exception:
        LOG.debug(
            "vpc_dns: no ec2 backend for account=%s region=%s; skipping DHCP "
            "DNS resolution", account_id, region,
        )
        return []

    subnet = _get_subnet(ec2_backend, subnet_id)
    if subnet is None:
        LOG.debug("vpc_dns: subnet %s not in moto state; skipping", subnet_id)
        return []

    vpc_id = getattr(subnet, "vpc_id", None) or getattr(subnet, "vpc", None)
    if hasattr(vpc_id, "id"):
        # moto sometimes hands back the Vpc object instead of the id string.
        vpc_id = vpc_id.id

    vpc = _get_vpc(ec2_backend, vpc_id)
    if vpc is None:
        LOG.debug("vpc_dns: vpc %s not in moto state; skipping", vpc_id)
        return []

    raw = _read_dhcp_dns_servers(vpc)
    return _filter_servers(raw, drop_amazon_provided_dns=drop_amazon_provided_dns)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _get_subnet(ec2_backend, subnet_id: str):
    """Return moto's Subnet object for ``subnet_id`` or ``None``."""
    # moto's subnet store is namespaced by AZ in some versions and a flat
    # dict in others. Try the flat-dict path first, then walk subnets.
    subnets = getattr(ec2_backend, "subnets", None)
    if isinstance(subnets, dict):
        direct = subnets.get(subnet_id)
        if direct is not None:
            return direct
        # AZ-namespaced shape: {az: {subnet_id: Subnet}}
        for entry in subnets.values():
            if isinstance(entry, dict):
                candidate = entry.get(subnet_id)
                if candidate is not None:
                    return candidate
    get_subnet = getattr(ec2_backend, "get_subnet", None)
    if callable(get_subnet):
        try:
            return get_subnet(subnet_id)
        except Exception:
            return None
    return None


def _get_vpc(ec2_backend, vpc_id: str | None):
    if not vpc_id:
        return None
    vpcs = getattr(ec2_backend, "vpcs", None)
    if isinstance(vpcs, dict):
        direct = vpcs.get(vpc_id)
        if direct is not None:
            return direct
    get_vpc = getattr(ec2_backend, "get_vpc", None)
    if callable(get_vpc):
        try:
            return get_vpc(vpc_id)
        except Exception:
            return None
    return None


def _read_dhcp_dns_servers(vpc) -> list[str]:
    """Pull ``domain-name-servers`` off the VPC's DHCP option set.

    moto's ``DHCPOptionsSet`` exposes the configuration as a private
    ``_options`` dict keyed by the AWS-canonical option names
    (``domain-name-servers``, ``domain-name``, ``ntp-servers``,
    ``netbios-name-servers``, ``netbios-node-type``). We read the
    private attribute directly because moto offers no public accessor;
    the structure is stable across the moto 4.x and 5.x lines we
    pin against.
    """
    options = getattr(vpc, "dhcp_options", None)
    if options is None:
        return []
    raw = None
    if hasattr(options, "_options") and isinstance(options._options, dict):
        raw = options._options.get("domain-name-servers")
    if raw is None:
        return []
    if isinstance(raw, str):
        # moto sometimes stores the value as a comma-string.
        return [item.strip() for item in raw.split(",") if item.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw if item]
    LOG.debug(
        "vpc_dns: unexpected domain-name-servers shape %s; treating as empty",
        type(raw).__name__,
    )
    return []


def _filter_servers(
    raw: Iterable[str], *, drop_amazon_provided_dns: bool,
) -> list[str]:
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        if drop_amazon_provided_dns and entry == _AMAZON_PROVIDED_DNS:
            # AWS's pseudo-name for "use the VPC-internal Route53". We
            # have no Route53 reachable from inside a LocalEmu instance,
            # so passing the literal string to Docker would either be
            # silently ignored or cause name resolution to fail.
            continue
        out.append(entry)
    return out
