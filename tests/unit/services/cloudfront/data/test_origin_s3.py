"""Unit tests for the S3 origin helpers.

``fetch()`` is exercised via the Phase 2 E2E — it requires a running
boto3 client plus S3 service and can't be meaningfully stubbed. These
tests cover the pure-logic helpers.
"""

import pytest

from localemu.services.cloudfront.data.origin_s3 import (
    bucket_from_origin,
    is_s3_origin,
)


class TestIsS3Origin:
    @pytest.mark.parametrize(
        "domain, expected",
        [
            ("my-bucket.s3.amazonaws.com", True),
            ("my-bucket.s3.us-west-2.amazonaws.com", True),
            ("my-bucket.s3-us-west-2.amazonaws.com", True),
            ("origin.example.com", False),
            ("", False),
            ("s3.amazonaws.com", False),  # no bucket part before s3
            ("bucket.s3.website-us-east-1.amazonaws.com", True),
        ],
    )
    def test_detects_s3_origin(self, domain, expected):
        assert is_s3_origin(domain) is expected


class TestBucketFromOrigin:
    @pytest.mark.parametrize(
        "domain, expected",
        [
            ("my-bucket.s3.amazonaws.com", "my-bucket"),
            ("bucket-regional.s3.us-west-2.amazonaws.com", "bucket-regional"),
            ("origin.example.com", None),
            ("", None),
        ],
    )
    def test_extracts_bucket(self, domain, expected):
        assert bucket_from_origin(domain) == expected
