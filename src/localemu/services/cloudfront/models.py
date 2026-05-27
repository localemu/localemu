"""Native CloudFront state.

Moto owns the canonical distribution / invalidation / OAC records. LocalEmu
keeps a thin sidecar here only for things moto doesn't track:

  - ``oac_bucket_bindings`` — mapping of bucket-arn -> set of OAC identifiers
    (populated when :class:`.provider.CloudFrontProvider` sees a
    ``CreateOriginAccessControl`` and the distribution pins an S3 origin).
    The data-plane S3 guard (Phase 2) reads this to decide whether a direct
    S3 request from outside the CloudFront router should be denied.
  - ``cache_stats`` — per-distribution hit / miss counters populated by the
    Phase 2 router. Persisted so the dashboard survives restarts.

Scheduler + invalidation-queue pending-state is intentionally NOT persisted:
on load we treat any non-``Deployed`` distribution as ``Deployed`` rather
than resume a timer across a process restart (deterministic restore).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute

# CloudFront is a global service, following the same store convention as
# ``route53`` (see ``services/route53/models.py``): a single
# ``AccountRegionBundle`` with ``validate=False`` and ``"global"`` as the
# sole region key. botocore's endpoint spec doesn't list ``us-east-1`` (or
# any commercial region) for these services, and there is no real per-
# region state to distinguish, so region-key validation would add friction
# without adding safety.
CLOUDFRONT_REGION = "global"


@dataclass
class CacheStats:
    """Per-distribution counters populated by the data-plane router (Phase 2)."""

    hits: int = 0
    misses: int = 0
    bytes_served: int = 0


class CloudFrontStore(BaseStore):
    # Keyed by S3 bucket ARN. Value is the set of OAC identifiers that
    # reference this bucket via a distribution origin. Phase 2 S3 guard
    # rejects direct bucket access when this set is non-empty and the
    # request didn't originate from our CloudFront router.
    oac_bucket_bindings: dict[str, set[str]] = LocalAttribute(default=dict)

    # Legacy OAI equivalent — same shape, different principal form.
    oai_bucket_bindings: dict[str, set[str]] = LocalAttribute(default=dict)

    # Per-distribution cache hit/miss/byte counters (Phase 2).
    cache_stats: dict[str, CacheStats] = LocalAttribute(default=dict)


cloudfront_stores = AccountRegionBundle("cloudfront", CloudFrontStore, validate=False)


def get_cloudfront_store(account_id: str) -> CloudFrontStore:
    """Shortcut for ``cloudfront_stores[account_id][CLOUDFRONT_REGION]`` —
    callers should use this rather than reaching into the bundle directly so
    the global-service convention is localized to one place.
    """
    return cloudfront_stores[account_id][CLOUDFRONT_REGION]
