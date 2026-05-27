"""E2E: S3 access-control enforcement under IAM_ENFORCEMENT=1.

Requires LocalEmu running with IAM_ENFORCEMENT=1. Run with:
    pytest tests/e2e/test_s3_iam_enforcement_e2e.py -v

Proves LocalEmu actually DENIES S3 calls that IAM identity policies or S3
bucket policies forbid : the differentiator neither moto nor ministack provide:
  * an IAM user whose policy allows only s3:GetObject can read but not delete
  * an explicit Deny in a bucket policy blocks even an allowed identity

Setup runs as the account root key (implicit allow); the enforced calls run as
a real IAM user whose access key is evaluated against its attached policy. The
tests skip themselves if enforcement is not active (so the suite stays green
when LocalEmu runs in its default, non-enforcing mode).
"""

import json
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
CFG = Config(retries={"max_attempts": 0})
ROOT_KEY = "AKIAIOSFODNN7EXAMPLE"


def _client(service, access_key, secret="x"):
    return boto3.client(
        service, endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id=access_key, aws_secret_access_key=secret, config=CFG,
    )


@pytest.fixture(scope="module")
def root():
    return {"s3": _client("s3", ROOT_KEY), "iam": _client("iam", ROOT_KEY)}


@pytest.fixture(scope="module", autouse=True)
def _require_enforcement(root):
    """Skip unless IAM_ENFORCEMENT is active: a no-policy user must be denied."""
    iam = root["iam"]
    uname = f"probe-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=uname)
    key = iam.create_access_key(UserName=uname)["AccessKey"]
    s3 = _client("s3", key["AccessKeyId"], key["SecretAccessKey"])
    try:
        s3.list_buckets()
        enforced = False  # a policy-less user was allowed -> enforcement off
    except ClientError as e:
        enforced = e.response["Error"]["Code"] == "AccessDenied"
    finally:
        try:
            iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
            iam.delete_user(UserName=uname)
        except Exception:
            pass
    if not enforced:
        pytest.skip("IAM_ENFORCEMENT not active; start LocalEmu with IAM_ENFORCEMENT=1")


def _user_with_policy(iam, policy_doc):
    uname = f"u-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=uname)
    iam.put_user_policy(UserName=uname, PolicyName="p", PolicyDocument=json.dumps(policy_doc))
    key = iam.create_access_key(UserName=uname)["AccessKey"]
    return uname, key["AccessKeyId"], key["SecretAccessKey"]


class TestS3IamEnforcement:
    def test_identity_policy_allows_get_denies_delete(self, root):
        bucket = f"enf-{uuid.uuid4().hex[:8]}"
        root["s3"].create_bucket(Bucket=bucket)
        root["s3"].put_object(Bucket=bucket, Key="k", Body=b"data")
        allow_get = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }],
        }
        _, akid, secret = _user_with_policy(root["iam"], allow_get)
        s3 = _client("s3", akid, secret)

        # allowed by the identity policy
        assert s3.get_object(Bucket=bucket, Key="k")["Body"].read() == b"data"

        # not granted -> implicit deny -> AccessDenied
        with pytest.raises(ClientError) as exc:
            s3.delete_object(Bucket=bucket, Key="k")
        assert exc.value.response["Error"]["Code"] == "AccessDenied"

        root["s3"].delete_object(Bucket=bucket, Key="k")
        root["s3"].delete_bucket(Bucket=bucket)

    def test_bucket_policy_deny_overrides_identity_allow(self, root):
        bucket = f"enf-{uuid.uuid4().hex[:8]}"
        root["s3"].create_bucket(Bucket=bucket)
        root["s3"].put_object(Bucket=bucket, Key="k", Body=b"data")
        allow_get = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }],
        }
        _, akid, secret = _user_with_policy(root["iam"], allow_get)
        s3 = _client("s3", akid, secret)

        # works before the bucket policy is applied
        assert s3.get_object(Bucket=bucket, Key="k")["Body"].read() == b"data"

        # explicit Deny in the bucket policy must override the identity Allow
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
            }],
        }
        root["s3"].put_bucket_policy(Bucket=bucket, Policy=json.dumps(deny_policy))
        with pytest.raises(ClientError) as exc:
            s3.get_object(Bucket=bucket, Key="k")
        assert exc.value.response["Error"]["Code"] == "AccessDenied"

        root["s3"].delete_bucket_policy(Bucket=bucket)
        root["s3"].delete_object(Bucket=bucket, Key="k")
        root["s3"].delete_bucket(Bucket=bucket)
