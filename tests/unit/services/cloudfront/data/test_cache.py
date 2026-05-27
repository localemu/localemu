"""Unit tests for the data-plane cache."""

from __future__ import annotations

import pytest

from localemu.services.cloudfront.data.cache import (
    CacheEntry,
    DistributionCache,
    reset_cache_for_tests,
    get_cache,
)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


def _entry(body: bytes = b"x", uri: str = "/a", ttl_from_now: float = 60.0,
           now: float = 1000.0, headers=None) -> CacheEntry:
    return CacheEntry(
        body=body,
        headers=headers or {},
        status=200,
        expires_at=now + ttl_from_now,
        uri_path=uri,
    )


class TestBasicGetPut:
    def test_miss_then_hit(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        key = ("/a", ())
        assert cache.get("E1", key) is None

        cache.put("E1", key, _entry(now=clock.now))
        got = cache.get("E1", key)
        assert got is not None
        assert got.body == b"x"

    def test_different_distributions_are_isolated(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        key = ("/a", ())
        cache.put("E1", key, _entry(body=b"e1-body", now=clock.now))
        cache.put("E2", key, _entry(body=b"e2-body", now=clock.now))
        assert cache.get("E1", key).body == b"e1-body"
        assert cache.get("E2", key).body == b"e2-body"

    def test_put_replaces_existing(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        key = ("/a", ())
        cache.put("E1", key, _entry(body=b"first", now=clock.now))
        cache.put("E1", key, _entry(body=b"second", now=clock.now))
        assert cache.get("E1", key).body == b"second"


class TestTtlExpiry:
    def test_entry_expires_at_ttl(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        key = ("/a", ())
        cache.put("E1", key, _entry(ttl_from_now=5.0, now=clock.now))
        clock.advance(4.999)
        assert cache.get("E1", key) is not None
        clock.advance(0.002)  # total 5.001
        assert cache.get("E1", key) is None

    def test_expired_entry_is_lazily_purged(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        key = ("/a", ())
        cache.put("E1", key, _entry(body=b"big" * 100, ttl_from_now=1.0, now=clock.now))
        stats_before = cache.stats("E1")
        assert stats_before["entries"] == 1
        assert stats_before["bytes_used"] > 0
        clock.advance(2.0)
        cache.get("E1", key)  # triggers lazy purge
        stats_after = cache.stats("E1")
        assert stats_after["entries"] == 0
        assert stats_after["bytes_used"] == 0


class TestLruEviction:
    def test_byte_cap_triggers_lru_eviction(self):
        """Fill cache past cap — oldest entry evicts first."""
        clock = FakeClock()
        # 300 bytes per entry (body size dominates), cap = 650 bytes
        cache = DistributionCache(byte_cap_per_dist=650, clock=clock)
        for i in range(3):
            cache.put("E1", (f"/key-{i}", ()), _entry(
                body=b"x" * 300, uri=f"/key-{i}", now=clock.now,
            ))
        # 3 entries × 300 bytes = 900 > cap 650 → oldest evicted
        assert cache.get("E1", ("/key-0", ())) is None
        assert cache.get("E1", ("/key-1", ())) is not None
        assert cache.get("E1", ("/key-2", ())) is not None
        stats = cache.stats("E1")
        assert stats["evictions"] == 1

    def test_recently_accessed_entry_survives_lru(self):
        """LRU-correct: touching /a before adding big /c evicts /b, not /a."""
        clock = FakeClock()
        cache = DistributionCache(byte_cap_per_dist=650, clock=clock)
        cache.put("E1", ("/a", ()), _entry(body=b"x" * 300, uri="/a", now=clock.now))
        cache.put("E1", ("/b", ()), _entry(body=b"y" * 300, uri="/b", now=clock.now))
        # Touch /a to promote it to MRU
        cache.get("E1", ("/a", ()))
        cache.put("E1", ("/c", ()), _entry(body=b"z" * 300, uri="/c", now=clock.now))
        assert cache.get("E1", ("/a", ())) is not None
        assert cache.get("E1", ("/b", ())) is None  # LRU victim
        assert cache.get("E1", ("/c", ())) is not None


class TestPurge:
    def test_purge_wildcard_all(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/a", ()), _entry(uri="/a", now=clock.now))
        cache.put("E1", ("/b", ()), _entry(uri="/b", now=clock.now))
        assert cache.purge("E1", ["/*"]) == 2
        assert cache.get("E1", ("/a", ())) is None
        assert cache.get("E1", ("/b", ())) is None

    def test_purge_prefix(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/images/a.jpg", ()), _entry(uri="/images/a.jpg", now=clock.now))
        cache.put("E1", ("/images/b.png", ()), _entry(uri="/images/b.png", now=clock.now))
        cache.put("E1", ("/css/site.css", ()), _entry(uri="/css/site.css", now=clock.now))
        assert cache.purge("E1", ["/images/*"]) == 2
        assert cache.get("E1", ("/images/a.jpg", ())) is None
        assert cache.get("E1", ("/css/site.css", ())) is not None

    def test_purge_literal_path(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/robots.txt", ()), _entry(uri="/robots.txt", now=clock.now))
        cache.put("E1", ("/sitemap.xml", ()), _entry(uri="/sitemap.xml", now=clock.now))
        assert cache.purge("E1", ["/robots.txt"]) == 1
        assert cache.get("E1", ("/robots.txt", ())) is None
        assert cache.get("E1", ("/sitemap.xml", ())) is not None

    def test_purge_leading_slash_optional(self):
        """CloudFront accepts ``/images/*`` and ``images/*``; treat equivalently."""
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/images/a.jpg", ()), _entry(uri="/images/a.jpg", now=clock.now))
        assert cache.purge("E1", ["images/*"]) == 1

    def test_purge_empty_pattern_list_is_noop(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/a", ()), _entry(uri="/a", now=clock.now))
        assert cache.purge("E1", []) == 0
        assert cache.get("E1", ("/a", ())) is not None

    def test_purge_unknown_distribution_is_zero(self):
        cache = DistributionCache()
        assert cache.purge("E-NONE", ["/*"]) == 0


class TestStats:
    def test_hits_and_misses_are_counted(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.get("E1", ("/a", ()))  # miss (no shard yet — returns None silently)
        cache.put("E1", ("/a", ()), _entry(now=clock.now))
        cache.get("E1", ("/a", ()))  # hit
        cache.get("E1", ("/a", ()))  # hit
        cache.get("E1", ("/b", ()))  # miss (same shard)
        stats = cache.stats("E1")
        assert stats["hits"] == 2
        assert stats["misses"] == 1  # the first get returned None before shard existed

    def test_drop_distribution_removes_shard(self):
        clock = FakeClock()
        cache = DistributionCache(clock=clock)
        cache.put("E1", ("/a", ()), _entry(now=clock.now))
        cache.drop_distribution("E1")
        assert cache.stats("E1") is None
        assert cache.get("E1", ("/a", ())) is None


class TestSingleton:
    def test_get_cache_is_idempotent(self):
        reset_cache_for_tests()
        c1 = get_cache()
        c2 = get_cache()
        assert c1 is c2

    def test_reset_creates_fresh_instance(self):
        reset_cache_for_tests()
        c1 = get_cache()
        reset_cache_for_tests()
        c2 = get_cache()
        assert c1 is not c2
