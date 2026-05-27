"""CloudFront native-store round-trip across a persistence save/load cycle.

The CloudFront distribution / OAC / OAI records live in the moto
backend (which the save engine already serializes). The OAC bucket
bindings and per-distribution cache stats live in a LocalEmu-side
``AccountRegionBundle`` — without it being registered in the
persistence registry those bindings vanish on restart, and the S3
data-plane guard silently lets direct bucket access through on every
restored OAC-protected distribution.
"""

from __future__ import annotations

import pytest


ACCOUNT = "000000000000"


@pytest.fixture
def data_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _register_pickle_fixes():
    from localemu.state.persistence import _register_pickle_fixes

    _register_pickle_fixes()


class TestCloudFrontNativeStore:
    def test_cloudfront_is_in_native_stores_registry(self):
        from localemu.state.registry import NATIVE_STORES

        assert "cloudfront" in NATIVE_STORES, (
            "CloudFront native sidecar store must be persisted — the OAC "
            "bindings drive the S3 guard, and losing them silently allows "
            "direct bucket access on restored OAC-protected distributions."
        )

    def test_cloudfront_oac_bindings_survive_round_trip(self, data_dir):
        from localemu.services.cloudfront.models import (
            CLOUDFRONT_REGION,
            cloudfront_stores,
        )
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        bucket_arn = "arn:aws:s3:::cf-guarded-bucket"
        oac_id = "E1ABCDEFGHIJK"

        store = cloudfront_stores[ACCOUNT][CLOUDFRONT_REGION]
        store.oac_bucket_bindings[bucket_arn] = {oac_id}
        store.oai_bucket_bindings["arn:aws:s3:::legacy-bucket"] = {"oai-deadbeef"}
        from localemu.services.cloudfront.models import CacheStats

        store.cache_stats["E1XYZ"] = CacheStats(hits=42, misses=7, bytes_served=1_234_567)

        manifest = SaveOrchestrator().save(data_dir)
        assert "cloudfront" in manifest["services"], manifest

        cloudfront_stores[ACCOUNT][CLOUDFRONT_REGION].oac_bucket_bindings.clear()
        cloudfront_stores[ACCOUNT][CLOUDFRONT_REGION].oai_bucket_bindings.clear()
        cloudfront_stores[ACCOUNT][CLOUDFRONT_REGION].cache_stats.clear()

        assert LoadOrchestrator().load(data_dir, trigger_post_load_hooks=False) is True

        restored = cloudfront_stores[ACCOUNT][CLOUDFRONT_REGION]
        assert restored.oac_bucket_bindings.get(bucket_arn) == {oac_id}
        assert restored.oai_bucket_bindings.get("arn:aws:s3:::legacy-bucket") == {
            "oai-deadbeef"
        }
        assert restored.cache_stats["E1XYZ"].hits == 42
        assert restored.cache_stats["E1XYZ"].misses == 7
        assert restored.cache_stats["E1XYZ"].bytes_served == 1_234_567

    def test_cloudfront_appears_in_load_order_tiers(self):
        from localemu.state.registry import LOAD_ORDER

        flat = [svc for tier in LOAD_ORDER for svc in tier]
        assert "cloudfront" in flat, (
            "CloudFront must appear in some LOAD_ORDER tier or the loader "
            "will skip it during restart even though the snapshot was saved."
        )
