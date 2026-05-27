"""In-memory LRU + TTL cache for CloudFront data-plane responses.

One :class:`DistributionCache` per process. Entries are keyed by
``(distribution_id, cache_key_tuple)`` where ``cache_key_tuple`` is built
from the parts of the request the cache-behavior's cache-key policy deems
significant (URI, included query-string names, included headers). The
cache-key construction is the caller's responsibility; the cache only
stores whatever tuple it receives.

Eviction rules:

  - LRU per distribution, capped by byte-size
    (``CLOUDFRONT_CACHE_SIZE_MB``, default 100 MB per distribution).
  - Expired entries on read return ``None`` and are lazily removed.
  - Invalidation patterns (``/*``, ``/images/*``, literal paths) are
    evaluated with ``fnmatch`` against every stored path for the target
    distribution. O(n) in cache entries; matches AWS's own "invalidate
    walks the cache" behaviour.

This cache is intentionally NOT persisted across process restart. Real
CloudFront's cache is also cold on every distribution redeploy; hiding
cold-start behaviour would mask a real class of prod bugs.

Thread-safety: all mutating operations take a per-distribution lock. The
per-distribution granularity keeps a slow invalidation sweep from
blocking reads on other distributions.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

LOG = logging.getLogger(__name__)


def _default_cache_size_bytes() -> int:
    raw = os.environ.get("CLOUDFRONT_CACHE_SIZE_MB", "").strip()
    mb = 100
    if raw:
        try:
            mb = max(1, int(raw))
        except ValueError:
            LOG.warning("CLOUDFRONT_CACHE_SIZE_MB=%r not an int; using 100", raw)
    return mb * 1024 * 1024


CacheKey = tuple  # opaque — built by the router from (uri, query, headers)


@dataclass
class CacheEntry:
    """A cached response + metadata for eviction and invalidation."""

    body: bytes
    headers: dict[str, str]
    status: int
    # Absolute epoch seconds after which the entry is stale.
    expires_at: float
    # Raw request URI path — used by invalidation pattern matching.
    uri_path: str
    # Byte cost charged against the per-distribution LRU budget.
    size_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        self.size_bytes = len(self.body) + sum(
            len(k) + len(v) for k, v in self.headers.items()
        )


class _Shard:
    """Per-distribution cache shard. LRU + TTL + byte cap."""

    def __init__(self, byte_cap: int) -> None:
        self._entries: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._byte_cap = byte_cap
        self._bytes_used = 0
        self._lock = threading.Lock()
        # Stats exposed via ``get_stats`` for the dashboard.
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: CacheKey, now: float) -> CacheEntry | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            if entry.expires_at <= now:
                # Lazy eviction of expired entries.
                self._bytes_used -= entry.size_bytes
                self._entries.pop(key, None)
                self.misses += 1
                return None
            # LRU update: move to the end (most-recently-used).
            self._entries.move_to_end(key)
            self.hits += 1
            return entry

    def put(self, key: CacheKey, entry: CacheEntry) -> None:
        with self._lock:
            # Replace if present (release its bytes first).
            existing = self._entries.pop(key, None)
            if existing is not None:
                self._bytes_used -= existing.size_bytes
            self._entries[key] = entry
            self._bytes_used += entry.size_bytes
            self._evict_over_budget()

    def purge(self, path_patterns: list[str]) -> int:
        """Remove every entry whose ``uri_path`` matches any pattern.

        Returns the count of evicted entries. Patterns follow CloudFront's
        documented invalidation syntax: ``*`` and ``?`` wildcards and
        literal paths. Leading ``/`` is optional in user input; we accept
        both forms.
        """
        if not path_patterns:
            return 0
        normalized = [p if p.startswith("/") else "/" + p for p in path_patterns]
        removed = 0
        with self._lock:
            to_remove = []
            for key, entry in self._entries.items():
                for pat in normalized:
                    # fnmatch on the stored URI path. ``/*`` matches
                    # ``/foo``, ``/foo/bar``, etc. — correct for CloudFront.
                    if fnmatch.fnmatch(entry.uri_path, pat):
                        to_remove.append((key, entry))
                        break
            for key, entry in to_remove:
                self._entries.pop(key, None)
                self._bytes_used -= entry.size_bytes
                removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._bytes_used = 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "entries": len(self._entries),
                "bytes_used": self._bytes_used,
                "bytes_cap": self._byte_cap,
            }

    def _evict_over_budget(self) -> None:
        """Evict LRU entries until ``_bytes_used <= _byte_cap``.

        Called with ``self._lock`` held.
        """
        while self._bytes_used > self._byte_cap and self._entries:
            _, entry = self._entries.popitem(last=False)
            self._bytes_used -= entry.size_bytes
            self.evictions += 1


class DistributionCache:
    """Process-wide cache with per-distribution shards."""

    def __init__(self, *, byte_cap_per_dist: int | None = None,
                 clock: callable = time.time) -> None:
        self._shards: dict[str, _Shard] = {}
        self._shards_lock = threading.Lock()
        self._byte_cap = byte_cap_per_dist or _default_cache_size_bytes()
        self._clock = clock

    def get(self, distribution_id: str, key: CacheKey) -> CacheEntry | None:
        shard = self._shards.get(distribution_id)
        if shard is None:
            return None
        return shard.get(key, now=self._clock())

    def put(self, distribution_id: str, key: CacheKey, entry: CacheEntry) -> None:
        shard = self._get_or_create_shard(distribution_id)
        shard.put(key, entry)

    def purge(self, distribution_id: str, path_patterns: list[str]) -> int:
        shard = self._shards.get(distribution_id)
        if shard is None:
            return 0
        return shard.purge(path_patterns)

    def drop_distribution(self, distribution_id: str) -> None:
        """Called when a distribution is deleted — wipe its shard entirely."""
        with self._shards_lock:
            self._shards.pop(distribution_id, None)

    def stats(self, distribution_id: str) -> dict[str, Any] | None:
        shard = self._shards.get(distribution_id)
        if shard is None:
            return None
        return shard.stats()

    def all_stats(self) -> dict[str, dict[str, Any]]:
        with self._shards_lock:
            return {dist_id: shard.stats() for dist_id, shard in self._shards.items()}

    def _get_or_create_shard(self, distribution_id: str) -> _Shard:
        shard = self._shards.get(distribution_id)
        if shard is not None:
            return shard
        with self._shards_lock:
            shard = self._shards.get(distribution_id)
            if shard is None:
                shard = _Shard(byte_cap=self._byte_cap)
                self._shards[distribution_id] = shard
            return shard


# ---------------------------------------------------------------------------
# Singleton — lazy-initialized on first use
# ---------------------------------------------------------------------------

_singleton: DistributionCache | None = None
_singleton_lock = threading.Lock()


def get_cache() -> DistributionCache:
    """Return the process-wide cache, constructing it if needed."""
    global _singleton
    if _singleton is not None:
        return _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = DistributionCache()
    return _singleton


def reset_cache_for_tests() -> None:
    """Test-only hook to wipe the singleton between cases."""
    global _singleton
    with _singleton_lock:
        _singleton = None
