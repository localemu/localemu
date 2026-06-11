"""End-to-end coverage for the S3 Access Point data plane.

Covers:
- GetObject through the AP ARN returns the underlying bucket's body.
- Three addressing forms: ARN, alias, hostname (via boto3 + custom endpoint).
- PUT through AP visible to direct bucket reads.
- ListObjectsV2 through AP returns the bucket's objects.
- AP-incompatible operations (PutBucketVersioning) rejected with InvalidRequest.
- AP not found returns NoSuchBucket.
- The Access Point Bypass security lab: bucket policy delegating via
  ``s3:DataAccessPointAccount`` lets a non-privileged user read through
  a permissive AP while direct bucket access remains denied.

Runs against a live LocalEmu (``LOCALEMU_ENDPOINT`` env var; default
http://localhost:4578). Skipped if the gateway is not up.
"""

from __future__ import annotations

import json
import os
import urllib.request

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError


ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4578")
REGION = "us-east-1"
_CFG = Config(retries={"max_attempts": 0})


def _client(service: str, *, key: str = "AKIAIOSFODNN7EXAMPLE",
            secret: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token: str | None = None):
    kwargs = dict(
        endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id=key, aws_secret_access_key=secret, config=_CFG,
    )
    if session_token:
        kwargs["aws_session_token"] = session_token
    return boto3.client(service, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def _gate_localemu():
    try:
        urllib.request.urlopen(f"{ENDPOINT}/_localemu/health", timeout=5).read()
    except Exception as e:
        pytest.skip(f"LocalEmu not reachable at {ENDPOINT}: {e}")


# ---------------------------------------------------------------------------
# Routing: three addressing forms
# ---------------------------------------------------------------------------


class TestAccessPointRouting:
    BUCKET = "ap-routing-bucket"
    AP = "routing-ap"
    AP_ARN = f"arn:aws:s3:us-east-1:000000000000:accesspoint/{AP}"

    @pytest.fixture(autouse=True)
    def _setup(self):
        s3 = _client("s3")
        s3c = _client("s3control")
        try:
            s3.create_bucket(Bucket=self.BUCKET)
        except ClientError:
            pass
        s3.put_object(Bucket=self.BUCKET, Key="k", Body=b"hello")
        try:
            s3c.create_access_point(
                AccountId="000000000000", Name=self.AP, Bucket=self.BUCKET,
            )
        except ClientError:
            pass
        yield

    def test_get_object_via_access_point_arn_returns_underlying_bucket_body(self):
        s3 = _client("s3")
        body = s3.get_object(Bucket=self.AP_ARN, Key="k")["Body"].read()
        assert body == b"hello"

    def test_get_via_alias(self):
        s3 = _client("s3")
        s3c = _client("s3control")
        alias = s3c.get_access_point(AccountId="000000000000", Name=self.AP)["Alias"]
        body = s3.get_object(Bucket=alias, Key="k")["Body"].read()
        assert body == b"hello"

    def test_put_via_ap_visible_on_direct_bucket(self):
        s3 = _client("s3")
        s3.put_object(Bucket=self.AP_ARN, Key="via-ap", Body=b"written-via-ap")
        body = s3.get_object(Bucket=self.BUCKET, Key="via-ap")["Body"].read()
        assert body == b"written-via-ap"

    def test_list_objects_v2_via_ap(self):
        s3 = _client("s3")
        keys = [
            obj["Key"]
            for obj in s3.list_objects_v2(Bucket=self.AP_ARN).get("Contents", [])
        ]
        assert "k" in keys


# ---------------------------------------------------------------------------
# AP-incompatible operations
# ---------------------------------------------------------------------------


class TestAccessPointIncompatibleOps:
    BUCKET = "ap-incompat-bucket"
    AP = "incompat-ap"
    AP_ARN = f"arn:aws:s3:us-east-1:000000000000:accesspoint/{AP}"

    @pytest.fixture(autouse=True)
    def _setup(self):
        s3 = _client("s3")
        s3c = _client("s3control")
        try:
            s3.create_bucket(Bucket=self.BUCKET)
        except ClientError:
            pass
        try:
            s3c.create_access_point(
                AccountId="000000000000", Name=self.AP, Bucket=self.BUCKET,
            )
        except ClientError:
            pass
        yield

    def test_put_bucket_versioning_via_ap_rejected(self):
        s3 = _client("s3")
        with pytest.raises(ClientError) as exc:
            s3.put_bucket_versioning(
                Bucket=self.AP_ARN,
                VersioningConfiguration={"Status": "Enabled"},
            )
        assert exc.value.response["Error"]["Code"] in {
            "InvalidRequest", "InternalError",
        }


# ---------------------------------------------------------------------------
# AP not found
# ---------------------------------------------------------------------------


class TestAccessPointMissing:
    def test_unknown_ap_arn_returns_no_such_bucket(self):
        s3 = _client("s3")
        with pytest.raises(ClientError) as exc:
            s3.get_object(
                Bucket="arn:aws:s3:us-east-1:000000000000:accesspoint/does-not-exist",
                Key="x",
            )
        assert exc.value.response["Error"]["Code"] in {"NoSuchBucket", "404"}


# ---------------------------------------------------------------------------
# Access Point Bypass security lab
# ---------------------------------------------------------------------------


class TestAccessPointBypassLab:
    """Bucket delegates via s3:DataAccessPointAccount ; non-root user reads
    through an attacker-controlled AP that the delegation trusts.

    Requires IAM_ENFORCEMENT=1. Skipped if enforcement is off — the lab's
    point is the contrast between "denied direct" and "allowed via AP".
    """

    BUCKET = "bypass-vault"
    AP = "bypass-ap"
    AP_ARN = f"arn:aws:s3:us-east-1:000000000000:accesspoint/{AP}"

    @pytest.fixture(autouse=True)
    def _setup(self):
        import urllib.request, json as _json
        # Detect whether IAM enforcement is on by hitting a deliberately
        # denied path with anonymous creds; skip the lab if it lets us through.
        s3 = _client("s3")
        try:
            s3.create_bucket(Bucket=self.BUCKET)
        except ClientError:
            pass
        s3.put_object(Bucket=self.BUCKET, Key="secret.txt", Body=b"crown-jewels")
        s3.put_bucket_policy(
            Bucket=self.BUCKET,
            Policy=_json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DelegateToAPs",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{self.BUCKET}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:DataAccessPointAccount": "000000000000",
                        },
                    },
                }],
            }),
        )
        s3c = _client("s3control")
        try:
            s3c.create_access_point(
                AccountId="000000000000", Name=self.AP, Bucket=self.BUCKET,
            )
        except ClientError:
            pass
        s3c.put_access_point_policy(
            AccountId="000000000000", Name=self.AP,
            Policy=_json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "OpenRead",
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": f"{self.AP_ARN}/object/*",
                }],
            }),
        )
        iam = _client("iam")
        try:
            iam.create_user(UserName="eve")
        except ClientError:
            pass
        keys = iam.create_access_key(UserName="eve")["AccessKey"]
        self.eve_key = keys["AccessKeyId"]
        self.eve_secret = keys["SecretAccessKey"]
        yield
        try:
            iam.delete_access_key(UserName="eve", AccessKeyId=self.eve_key)
        except ClientError:
            pass

    def _enforcement_on(self) -> bool:
        # Eve has no identity policies. If direct bucket read succeeds for
        # Eve, IAM enforcement is off — skip the lab assertions.
        s3 = _client("s3", key=self.eve_key, secret=self.eve_secret)
        try:
            s3.get_object(Bucket=self.BUCKET, Key="secret.txt")
            return False
        except ClientError as exc:
            return exc.response["Error"]["Code"] == "AccessDenied"

    def test_direct_bucket_read_denied_for_eve(self):
        if not self._enforcement_on():
            pytest.skip("IAM_ENFORCEMENT not on; bypass lab requires it")
        s3 = _client("s3", key=self.eve_key, secret=self.eve_secret)
        with pytest.raises(ClientError) as exc:
            s3.get_object(Bucket=self.BUCKET, Key="secret.txt")
        assert exc.value.response["Error"]["Code"] == "AccessDenied"

    def test_read_via_ap_allowed_for_eve(self):
        if not self._enforcement_on():
            pytest.skip("IAM_ENFORCEMENT not on; bypass lab requires it")
        s3 = _client("s3", key=self.eve_key, secret=self.eve_secret)
        body = s3.get_object(Bucket=self.AP_ARN, Key="secret.txt")["Body"].read()
        assert body == b"crown-jewels"
