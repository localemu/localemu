"""Elastic IP pool allocator using RFC 5737 TEST-NET-2 (198.51.100.0/24).

Upstream moto's ``ElasticAddress.__init__`` calls ``random_ip()`` which
generates a ``127.x.y.z`` address. That overlaps with the host's
loopback range, doesn't look like an AWS public IP, and confuses
users who copy a "public IP" from DescribeAddresses expecting to
hand it to ``curl`` or ssh from another host.

This module owns a per-(account_id, region) allocator carved from
``198.51.100.0/24`` (RFC 5737 TEST-NET-2, the range AWS uses in its
own documentation examples). Addresses are issued sequentially with
collision-free reuse: each allocation walks the pool, skips any IP
that is already held by an existing ``ElasticAddress`` in the same
backend, and returns the first free one. With 254 usable IPs per
account-region, a linear scan is fine; no need for separate tracking.

Why not patch ``moto.ec2.utils.random_ip``: that helper is used by
several other moto code paths (private IP synthesis, ENI auto-IP)
that legitimately want 127/8. The EIP-specific patch is in
``eip_patches.apply_eip_patches`` and only touches the ElasticAddress
constructor.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

LOG = logging.getLogger(__name__)

# RFC 5737 TEST-NET-2 — reserved for documentation examples; safe to use
# without colliding with any real public IP allocation.
EIP_POOL_CIDR = "198.51.100.0/24"

# Skip network (.0) and broadcast (.255); .1 through .254 are usable.
_USABLE_RANGE = (1, 254)

_lock = threading.Lock()


def usable_pool() -> list[ipaddress.IPv4Address]:
    """Return the full list of usable IPs in the EIP pool (254 entries)."""
    base = ipaddress.IPv4Network(EIP_POOL_CIDR)
    return [
        base.network_address + i
        for i in range(_USABLE_RANGE[0], _USABLE_RANGE[1] + 1)
    ]


def next_free_ip(used_ips: set[str]) -> str | None:
    """Return the lowest usable IP in the pool not in ``used_ips``.

    Returns None if the pool is exhausted. Caller is responsible for
    re-checking after a release; we do not track state here.
    """
    with _lock:
        for ip in usable_pool():
            if str(ip) not in used_ips:
                return str(ip)
    return None
