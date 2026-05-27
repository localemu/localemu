"""moto EIP patch: allocate from a real-looking pool, not 127/8.

See ``eip_pool.py`` for the why. This module wires the patch.
"""
from __future__ import annotations

import logging

from moto.ec2.models.elastic_ip_addresses import ElasticAddress

from localemu.services.ec2.eip_pool import next_free_ip
from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)


@patch(target=ElasticAddress.__init__, pass_target=True)
def _elastic_address_init_with_real_pool(
    fn, self, ec2_backend, domain, address=None, tags=None,
):
    """When no explicit address is given, allocate from 198.51.100.0/24.

    Falls back to the upstream random_ip() path if the pool is
    exhausted (unlikely — 254 IPs per account-region) or if the
    backend has somehow no addresses attribute yet.
    """
    if address is None:
        try:
            used = {a.public_ip for a in getattr(ec2_backend, "addresses", [])}
            chosen = next_free_ip(used)
            if chosen is not None:
                address = chosen
        except Exception:
            LOG.debug(
                "eip_patches: pool allocation failed; falling back to "
                "upstream random_ip",
                exc_info=True,
            )
    return fn(self, ec2_backend, domain, address=address, tags=tags)


def apply_eip_patches() -> None:
    """No-op; importing this module triggers the @patch decorators."""
    LOG.debug("ec2: applied moto ElasticAddress pool patch")
