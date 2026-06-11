"""moto-side patches for the Kinesis service.

moto's ``Stream.init_shards`` crashes with ``TypeError: unsupported
operand type(s) for //: 'int' and 'NoneType'`` when ``CreateStream`` is
called without ``ShardCount`` and without ``StreamModeDetails`` :
``shard_count`` propagates as ``None`` and the very first line of
``init_shards`` tries to compute ``2**128 // None``.

Real AWS rejects that call with ``InvalidArgumentException``: the
``CreateStream`` request must specify either ``ShardCount`` (for
``PROVISIONED`` mode) or ``StreamModeDetails={"StreamMode":"ON_DEMAND"}``.
The 2023+ SDKs default to ``ON_DEMAND`` with no explicit shard count,
which is what callers expect.

We wrap ``init_shards`` so that, when ``shard_count`` is missing, we
fall back to ``ON_DEMAND`` with 4 shards (matching moto's own
ON_DEMAND default) instead of crashing. The stream's ``stream_mode``
is also flipped to ``ON_DEMAND`` so downstream reads stay consistent.

The patch is idempotent and applied lazily on the first request via
the provider factory in :mod:`localemu.services.providers`.
"""

from __future__ import annotations

import logging

LOG = logging.getLogger(__name__)

_APPLIED = False


def apply_patches() -> None:
    """Install the Kinesis patches. Idempotent."""
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    from moto.kinesis import models as _m

    _original_init_shards = _m.Stream.init_shards
    if getattr(_original_init_shards, "_localemu_wrapped", False):
        return

    def _wrapped_init_shards(self, shard_count):
        if shard_count is None or shard_count == 0:
            # AWS rejects ``CreateStream`` without ShardCount or
            # StreamModeDetails; the modern SDK / CLI convention is to
            # default to ON_DEMAND with 4 shards. Match that rather than
            # crashing inside the integer division.
            shard_count = 4
            stream_mode = getattr(self, "stream_mode", None) or {}
            if stream_mode.get("StreamMode") != "ON_DEMAND":
                self.stream_mode = {"StreamMode": "ON_DEMAND"}
        _original_init_shards(self, shard_count)

    _wrapped_init_shards._localemu_wrapped = True
    _m.Stream.init_shards = _wrapped_init_shards
    LOG.info("LocalEmu Kinesis patches applied")
