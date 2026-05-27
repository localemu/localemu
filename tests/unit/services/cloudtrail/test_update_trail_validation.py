"""Regression test for B4 — UpdateTrail must re-validate bucket/topic/KMS
before applying the mutation. Moto's ``update_trail`` does not call
``check_bucket_exists`` / ``check_topic_exists`` itself, so without our
intercept a trail could be silently repointed at a bucket/topic that
does not exist.
"""

from __future__ import annotations

import pytest

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.services.cloudtrail.provider import (
    _handle_update_trail,
    _patch_moto_bucket_check,
    _patch_moto_topic_check,
)


@pytest.fixture(autouse=True)
def _patches_installed():
    _patch_moto_bucket_check()
    _patch_moto_topic_check()


@pytest.fixture(autouse=True)
def _isolate_stores():
    from localemu.services.s3.models import s3_stores
    from localemu.services.sns.models import sns_stores
    from localemu.services.kms.models import kms_stores

    bundles = [s3_stores, sns_stores, kms_stores]
    snapshots = [dict(b) for b in bundles]
    for b in bundles:
        b.clear()
    yield
    for b, snap in zip(bundles, snapshots):
        b.clear()
        b.update(snap)


def _ctx(account="000000000000", region="us-east-1") -> RequestContext:
    from localemu.http.request import Request
    c = RequestContext(Request(method="POST", path="/", body=b""))
    c.account_id = account
    c.region = region
    return c


class TestUpdateTrailValidation:
    def test_rejects_bogus_bucket(self):
        from moto.cloudtrail.models import S3BucketDoesNotExistException

        with pytest.raises(S3BucketDoesNotExistException):
            _handle_update_trail(
                _ctx(),
                {
                    "Name": "my-trail",
                    "S3BucketName": "le-never-existed-bucket",
                },
            )

    def test_rejects_bogus_sns_topic(self):
        from moto.cloudtrail.models import InsufficientSnsTopicPolicyException
        from localemu.services.s3.models import s3_stores

        # Seed a valid S3 bucket so bucket check passes when the request
        # includes a bucket too.
        s3_stores["000000000000"]["us-east-1"].buckets["ok-bucket"] = object()

        with pytest.raises(InsufficientSnsTopicPolicyException):
            _handle_update_trail(
                _ctx(),
                {
                    "Name": "my-trail",
                    "SnsTopicName": "le-never-existed-topic",
                },
            )

    def test_rejects_bogus_kms_key_id(self):
        with pytest.raises(CommonServiceException) as ei:
            _handle_update_trail(
                _ctx(),
                {
                    "Name": "my-trail",
                    "KmsKeyId": "00000000-0000-0000-0000-000000000000",
                },
            )
        assert ei.value.code == "KmsKeyNotFoundException"
