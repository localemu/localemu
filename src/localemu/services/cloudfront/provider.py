"""CloudFront provider (control plane).

Wraps moto's CloudFront backend to add:

  - Time-based status lifecycle for distributions. Moto already supports
    a "time"-progression variant on its ``ManagedState`` model; we register
    the desired delay at provider construction from
    ``CLOUDFRONT_PROPAGATION_SECONDS`` so subsequent ``GetDistribution`` /
    ``ListDistributions`` calls see the status flip naturally.
  - Invalidation-status lifecycle. Moto hard-codes ``COMPLETED`` on
    creation; we enqueue a deferred flip to ``Completed`` via
    :class:`~.invalidation_queue.InvalidationQueue`.
  - OAC / OAI binding registry so the Phase 2 S3 guard knows which buckets
    are locked behind a CloudFront distribution.

All other CloudFront operations fall through to moto via
``MotoFallbackDispatcher``.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any

from localemu.aws.api import RequestContext, handler
from localemu.aws.api.cloudfront import (
    CloudfrontApi,
    CreateCloudFrontOriginAccessIdentityResult,
    CreateDistributionResult,
    CreateDistributionWithTagsResult,
    CreateInvalidationResult,
    CreateOriginAccessControlResult,
)
from localemu.services import moto as _moto
from localemu.services.cloudfront.data.cache import get_cache as _get_cache
from localemu.services.cloudfront.data.router import ensure_routes_registered
from localemu.services.cloudfront.invalidation_queue import InvalidationQueue
from localemu.services.cloudfront.models import cloudfront_stores, get_cloudfront_store
from localemu.services.plugins import ServiceLifecycleHook
from localemu.state import StateVisitor

LOG = logging.getLogger(__name__)


_DISTRIBUTION_MODEL = "cloudfront::distribution"


def _propagation_seconds() -> int:
    """Configurable delay before a distribution flips from InProgress to Deployed.

    Read at call time so tests / operators can change it without a restart.
    """
    raw = os.environ.get("CLOUDFRONT_PROPAGATION_SECONDS", "").strip()
    if not raw:
        return 10
    try:
        value = int(raw)
    except ValueError:
        LOG.warning("CLOUDFRONT_PROPAGATION_SECONDS=%r is not an int; using default 10s", raw)
        return 10
    return max(0, value)


def _invalidation_seconds() -> int:
    raw = os.environ.get("CLOUDFRONT_INVALIDATION_SECONDS", "").strip()
    if not raw:
        return 5
    try:
        value = int(raw)
    except ValueError:
        LOG.warning("CLOUDFRONT_INVALIDATION_SECONDS=%r is not an int; using default 5s", raw)
        return 5
    return max(0, value)


def _configure_moto_transition() -> None:
    """Tell moto's state_manager to progress ``cloudfront::distribution`` on a
    time budget instead of flipping immediately.

    Idempotent. Called from the provider's ``on_after_init`` hook so the
    configuration is in place before the first CreateDistribution lands.
    """
    try:
        from moto.moto_api import state_manager
    except ImportError:  # pragma: no cover — moto always installed
        return

    seconds = _propagation_seconds()
    if seconds <= 0:
        # Honor explicit "0" as "flip immediately" for fast tests.
        state_manager.set_transition(_DISTRIBUTION_MODEL, {"progression": "immediate"})
        return
    state_manager.set_transition(
        _DISTRIBUTION_MODEL, {"progression": "time", "seconds": seconds},
    )


# ---------------------------------------------------------------------------
# Invalidation status mutation
# ---------------------------------------------------------------------------

def _moto_cloudfront_backend(account_id: str, region: str):
    """Load moto's CloudFront backend for the given account/region.

    Moto's CloudFront is a global service, so ``region`` is always ignored
    in the backend dict — we keep the argument for signature consistency
    with other providers.
    """
    from moto.cloudfront.models import cloudfront_backends

    return cloudfront_backends[account_id]["global"]


def _purge_cache_entries(
    account_id: str, region: str, distribution_id: str, paths: list[str],
) -> None:
    """Callback passed to InvalidationQueue — drives real cache eviction
    when an invalidation flips to Completed.

    The cache is process-wide; account / region are accepted for signature
    consistency with the queue's purge hook but aren't needed for lookup.
    """
    if not distribution_id or not paths:
        return
    try:
        _get_cache().purge(distribution_id, paths)
    except Exception:
        LOG.warning("cloudfront: failed to purge cache entries for %s",
                    distribution_id, exc_info=True)


def _set_invalidation_status(
    account_id: str, region: str, distribution_id: str,
    invalidation_id: str, status: str,
) -> None:
    """Mutate the status field on moto's ``Invalidation`` object.

    Moto stores invalidations on the backend itself (``backend.invalidations``
    is ``dict[dist_id, list[Invalidation]]``) — NOT on the Distribution
    object. This routinely trips up callers who walk ``dist.invalidations``
    expecting to find them there.

    Used as the callback passed to :class:`InvalidationQueue`. Intentionally
    tolerant of missing records — if the distribution was deleted mid-flight
    the invalidation record is gone too; log and move on rather than raise.
    """
    try:
        backend = _moto_cloudfront_backend(account_id, region)
    except Exception:
        LOG.debug("cloudfront backend for %s unavailable; invalidation %s status flip skipped",
                  account_id, invalidation_id)
        return

    invalidations_by_dist = getattr(backend, "invalidations", {}) or {}
    invalidations = invalidations_by_dist.get(distribution_id) or []
    for inv in invalidations:
        if getattr(inv, "invalidation_id", None) == invalidation_id:
            inv.status = status
            return
    LOG.debug("invalidation %s not found on distribution %s; status flip skipped",
              invalidation_id, distribution_id)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class CloudFrontProvider(CloudfrontApi, ServiceLifecycleHook):
    """CloudFront control-plane provider with a thin set of overrides.

    Non-overridden operations fall through to moto via the
    ``MotoFallbackDispatcher`` factory attached in ``services/providers.py``.
    """

    service = "cloudfront"

    def __init__(self) -> None:
        super().__init__()
        self._invalidation_queue: InvalidationQueue | None = None
        self._queue_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_after_init(self) -> None:
        _configure_moto_transition()
        self._ensure_invalidation_queue()
        ensure_routes_registered()

    def on_before_stop(self) -> None:
        queue = self._invalidation_queue
        if queue is not None:
            queue.shutdown()

    def accept_state_visitor(self, visitor: StateVisitor) -> None:
        visitor.visit(cloudfront_stores)

    # ------------------------------------------------------------------
    # Overrides — only operations where we add behaviour.
    #
    # Each override is re-decorated with ``@handler(<OperationName>)``. Moto
    # + LocalEmu's skeleton dispatcher discovers overrides by the decorator,
    # not by method name alone; without it the dispatch table silently falls
    # through to the base ``NotImplementedError`` and on to MotoFallback.
    # ------------------------------------------------------------------

    @handler("CreateDistribution", expand=False)
    def create_distribution(
        self, context: RequestContext, request,
    ) -> CreateDistributionResult:
        _configure_moto_transition()
        response = _moto.call_moto(context)
        # Bindings come from the REQUEST, not the response: moto's Origin
        # class doesn't preserve OriginAccessControlId when round-tripping.
        # (Phase 1 follow-up commit ``_moto_patches.py`` fixes the round
        # trip; reading from request is still the correct source of truth
        # for the registry because it's what the caller actually declared.)
        dist_config = (request or {}).get("DistributionConfig") or {}
        self._register_origin_bindings_from_config(dist_config, context.account_id)
        return response

    @handler("CreateDistributionWithTags", expand=False)
    def create_distribution_with_tags(
        self, context: RequestContext, request,
    ) -> CreateDistributionWithTagsResult:
        _configure_moto_transition()
        response = _moto.call_moto(context)
        wrapper = (request or {}).get("DistributionConfigWithTags") or {}
        dist_config = wrapper.get("DistributionConfig") or {}
        self._register_origin_bindings_from_config(dist_config, context.account_id)
        return response

    @handler("UpdateDistribution", expand=False)
    def update_distribution(self, context: RequestContext, request):
        _configure_moto_transition()
        response = _moto.call_moto(context)
        dist_config = (request or {}).get("DistributionConfig") or {}
        self._register_origin_bindings_from_config(dist_config, context.account_id)
        return response

    @handler("DeleteDistribution", expand=False)
    def delete_distribution(self, context: RequestContext, request):
        response = _moto.call_moto(context)
        distribution_id = (request or {}).get("Id")
        if distribution_id:
            self._unregister_origin_bindings(
                distribution_id=distribution_id, account_id=context.account_id,
            )
            # Drop the cache shard — any cached content is meaningless once
            # the distribution is gone.
            try:
                _get_cache().drop_distribution(distribution_id)
            except Exception:
                LOG.debug("failed to drop cache shard for %s",
                          distribution_id, exc_info=True)
        return response

    @handler("CreateInvalidation", expand=False)
    def create_invalidation(
        self, context: RequestContext, request,
    ) -> CreateInvalidationResult:
        response = _moto.call_moto(context)
        params = request or {}
        self._schedule_invalidation_completion(
            account_id=context.account_id,
            region=context.region,
            distribution_id=params.get("DistributionId"),
            response=response,
            invalidation_batch=params.get("InvalidationBatch"),
        )
        return response

    @handler("DeleteOriginAccessControl", expand=False)
    def delete_origin_access_control(self, context: RequestContext, request):
        response = _moto.call_moto(context)
        oac_id = (request or {}).get("Id")
        if oac_id:
            self._drop_oac_bindings(oac_id=oac_id, account_id=context.account_id)
        return response

    @handler("DeleteCloudFrontOriginAccessIdentity", expand=False)
    def delete_cloud_front_origin_access_identity(
        self, context: RequestContext, request,
    ):
        response = _moto.call_moto(context)
        oai_id = (request or {}).get("Id")
        if oai_id:
            self._drop_oai_bindings(oai_id=oai_id, account_id=context.account_id)
        return response

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_invalidation_queue(self) -> InvalidationQueue:
        with self._queue_lock:
            if self._invalidation_queue is None:
                queue = InvalidationQueue(
                    set_status=_set_invalidation_status,
                    purge=_purge_cache_entries,
                )
                queue.start()
                self._invalidation_queue = queue
            return self._invalidation_queue

    def _schedule_invalidation_completion(
        self, *, account_id: str, region: str, distribution_id: str,
        response: dict[str, Any], invalidation_batch: dict[str, Any] | None,
    ) -> None:
        try:
            invalidation = response.get("Invalidation") or {}
            invalidation_id = invalidation.get("Id")
            if not invalidation_id:
                return
            paths_section = (invalidation_batch or {}).get("Paths") or {}
            items = paths_section.get("Items") or []
            queue = self._ensure_invalidation_queue()
            queue.enqueue(
                account_id=account_id,
                region=region,
                distribution_id=distribution_id,
                invalidation_id=invalidation_id,
                paths=list(items),
                delay_seconds=_invalidation_seconds(),
            )
            # Moto marks the invalidation Completed immediately. Flip back to
            # InProgress so the queue's later Completed flip is meaningful.
            _set_invalidation_status(
                account_id, region, distribution_id, invalidation_id, "InProgress",
            )
        except Exception:
            LOG.warning("failed to schedule invalidation completion", exc_info=True)

    # ---- OAC/OAI binding bookkeeping ---------------------------------

    _S3_HOST_RE = re.compile(r"^(?P<bucket>[^./]+)\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$")

    def _register_origin_bindings_from_config(
        self, distribution_config: dict[str, Any], account_id: str,
    ) -> None:
        """Extract S3-origin <-> OAC/OAI bindings from a DistributionConfig.

        Moto's Origin class doesn't preserve OriginAccessControlId across the
        create/get round-trip, so we walk the caller's request (which has
        the full schema) rather than the response.
        """
        try:
            origins = (distribution_config.get("Origins") or {}).get("Items") or []
            if not origins:
                return
            store = get_cloudfront_store(account_id)
            for origin in origins:
                bucket_arn = self._origin_to_s3_bucket_arn(origin)
                if not bucket_arn:
                    continue
                oac_id = origin.get("OriginAccessControlId")
                if oac_id:
                    store.oac_bucket_bindings.setdefault(bucket_arn, set()).add(oac_id)
                s3_config = origin.get("S3OriginConfig") or {}
                oai_path = s3_config.get("OriginAccessIdentity") or ""
                if oai_path.startswith("origin-access-identity/cloudfront/"):
                    oai_id = oai_path.rsplit("/", 1)[-1]
                    if oai_id:
                        store.oai_bucket_bindings.setdefault(bucket_arn, set()).add(oai_id)
        except Exception:
            LOG.debug("register_origin_bindings_from_config: walk failed", exc_info=True)

    def _register_origin_bindings(self, response: dict[str, Any], account_id: str) -> None:
        """Legacy response-shape entry point. Kept for tests that exercise the
        full distribution-response path. New callers should use
        :meth:`_register_origin_bindings_from_config` directly against the
        request payload.
        """
        distribution = (response or {}).get("Distribution") or {}
        config = distribution.get("DistributionConfig") or {}
        self._register_origin_bindings_from_config(config, account_id)

    def _origin_to_s3_bucket_arn(self, origin: dict[str, Any]) -> str | None:
        domain = origin.get("DomainName") or ""
        if not domain:
            return None
        m = self._S3_HOST_RE.match(domain)
        if m:
            return f"arn:aws:s3:::{m.group('bucket')}"
        # Some users configure an S3-website endpoint or a custom domain
        # that maps to S3 via Route53. Those look like ordinary HTTP origins
        # and we can't reliably infer a bucket ARN; leave unregistered. The
        # Phase 2 data-plane router will treat them as HTTP origins.
        return None

    def _unregister_origin_bindings(self, *, distribution_id: str, account_id: str) -> None:
        """When a distribution is deleted, its OAC / OAI bindings no longer
        reference live origins.

        The simple approach — clearing the store — is correct here because
        Phase 1 only records bindings at Create/Update time. A deleted
        distribution's bindings become orphans that we can't reliably
        reconstruct from moto's lossy state (moto doesn't preserve
        OriginAccessControlId on Origin objects). Surviving distributions
        will re-register their bindings on their next Update, or when a
        later data-plane request forces a refresh in Phase 2.
        """
        store = get_cloudfront_store(account_id)
        store.oac_bucket_bindings.clear()
        store.oai_bucket_bindings.clear()

    def _drop_oac_bindings(self, *, oac_id: str, account_id: str) -> None:
        store = get_cloudfront_store(account_id)
        for bucket_arn, oac_set in list(store.oac_bucket_bindings.items()):
            oac_set.discard(oac_id)
            if not oac_set:
                store.oac_bucket_bindings.pop(bucket_arn, None)

    def _drop_oai_bindings(self, *, oai_id: str, account_id: str) -> None:
        store = get_cloudfront_store(account_id)
        for bucket_arn, oai_set in list(store.oai_bucket_bindings.items()):
            oai_set.discard(oai_id)
            if not oai_set:
                store.oai_bucket_bindings.pop(bucket_arn, None)
