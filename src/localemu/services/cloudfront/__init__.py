"""CloudFront service provider for LocalEmu.

Control plane delegates to moto for storage and schema validation. On top we
add:

  - A deployment scheduler that simulates AWS's "InProgress -> Deployed"
    status transition (configurable delay).
  - An invalidation queue that simulates an invalidation lifecycle
    independent of any cache purging (cache layer lives in the data plane
    and is introduced in a later phase).
  - Registration hooks for Origin Access Controls, Origin Access Identities,
    and Lambda@Edge associations that higher-level data-plane code consumes.

Operations not overridden by :class:`provider.CloudFrontProvider` fall
through to moto via :class:`localemu.services.moto.MotoFallbackDispatcher`.

Moto patches for gaps (``_moto_patches.py``) are applied at import time
so the first provider construction inherits them.
"""

from localemu.services.cloudfront import _moto_patches as _moto_patches
from localemu.services.cloudfront.auth import oac_guard as _oac_guard

_moto_patches.apply()
_oac_guard.apply()
