"""Regression tests for the systemic moto<->LocalEmu S3 bridge.

LocalEmu's S3 is native; moto's S3 backend is a separate store. A
number of moto consumers resolve bucket identity through
``moto.s3.models.s3_backends`` and therefore see LocalEmu-created
buckets as missing.

``localemu.services.s3.moto_bridge`` patches
``moto.s3.models.S3Backend.get_bucket``/``head_bucket`` to consult
LocalEmu's native store as a fallback and surface the bucket as a
``FakeBucket`` shim registered in moto's backend dict. The patch is
idempotent (guarded by ``_le_moto_bridge_patched``) and never removes
functionality — moto-native buckets still resolve via moto's own fast
path first.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _install_bridge_and_isolate():
    from localemu.services.s3.moto_bridge import install_moto_s3_bridge
    install_moto_s3_bridge()

    # Snapshot LocalEmu + moto state so tests are independent.
    from localemu.services.s3.models import s3_stores as le_stores
    from moto.s3.models import s3_backends

    le_snapshot = dict(le_stores)
    le_stores.clear()
    try:
        yield
    finally:
        le_stores.clear()
        le_stores.update(le_snapshot)
        # Best-effort cleanup of moto's synthesised buckets.
        try:
            for account in list(s3_backends):
                for partition in list(s3_backends[account]):
                    backend = s3_backends[account][partition]
                    backend.buckets.clear()
        except Exception:
            pass


class TestBridgeInstallation:
    def test_patch_is_idempotent(self):
        from moto.s3.models import S3Backend
        from localemu.services.s3.moto_bridge import install_moto_s3_bridge

        install_moto_s3_bridge()
        first = S3Backend.get_bucket
        install_moto_s3_bridge()
        install_moto_s3_bridge()
        assert S3Backend.get_bucket is first
        assert getattr(S3Backend.get_bucket, "_le_moto_bridge_patched", False)
        assert getattr(S3Backend.head_bucket, "_le_moto_bridge_patched", False)


class TestLocalEmuBucketVisibleToMoto:
    def test_native_bucket_visible_through_moto_backend_get_bucket(self):
        """A bucket created in LocalEmu's native store must be
        resolvable via ``moto.s3.models.s3_backends[account][partition]
        .get_bucket(name)`` — the code path used by 11 moto services."""
        from moto.s3.models import s3_backends
        from localemu.services.s3.models import s3_stores

        account = "000000000000"
        region_store = s3_stores[account]["us-east-1"]
        region_store.buckets["flagship-bucket"] = object()

        moto_backend = s3_backends[account]["aws"]
        bucket = moto_backend.get_bucket("flagship-bucket")
        assert bucket is not None
        assert bucket.name == "flagship-bucket"

    def test_head_bucket_also_resolves(self):
        from moto.s3.models import s3_backends
        from localemu.services.s3.models import s3_stores

        account = "000000000000"
        s3_stores[account]["us-east-1"].buckets["head-me"] = object()

        bucket = s3_backends[account]["aws"].head_bucket("head-me")
        assert bucket.name == "head-me"

    def test_unknown_bucket_still_raises_missingbucket(self):
        from moto.s3.exceptions import MissingBucket
        from moto.s3.models import s3_backends

        with pytest.raises(MissingBucket):
            s3_backends["000000000000"]["aws"].get_bucket("nope-never-existed")

    def test_synthesised_bucket_is_cached_for_subsequent_calls(self):
        from moto.s3.models import s3_backends
        from localemu.services.s3.models import s3_stores

        account = "000000000000"
        s3_stores[account]["us-east-1"].buckets["cache-me"] = object()
        backend = s3_backends[account]["aws"]

        first = backend.get_bucket("cache-me")
        second = backend.get_bucket("cache-me")
        assert first is second, (
            "Bridge should register synthesised bucket in moto's backend "
            "so repeated lookups return the same object"
        )


class TestBidirectionalSafety:
    def test_moto_created_bucket_still_resolves(self):
        """Regression: the bridge must not break buckets created
        directly through moto. The moto fast-path must run first."""
        from moto.s3.models import FakeBucket, s3_backends

        backend = s3_backends["000000000000"]["aws"]
        backend.buckets["moto-native"] = FakeBucket(
            name="moto-native",
            account_id="000000000000",
            region_name="us-east-1",
        )
        bucket = backend.get_bucket("moto-native")
        assert bucket.name == "moto-native"

    def test_bridge_does_not_overwrite_moto_bucket_with_localemu(self):
        """If a bucket name exists in BOTH stores, moto's wins (fast path)."""
        from moto.s3.models import FakeBucket, s3_backends
        from localemu.services.s3.models import s3_stores

        account = "000000000000"
        moto_bucket = FakeBucket(
            name="both-stores", account_id=account, region_name="us-east-1",
        )
        s3_backends[account]["aws"].buckets["both-stores"] = moto_bucket
        s3_stores[account]["us-east-1"].buckets["both-stores"] = object()

        resolved = s3_backends[account]["aws"].get_bucket("both-stores")
        assert resolved is moto_bucket
