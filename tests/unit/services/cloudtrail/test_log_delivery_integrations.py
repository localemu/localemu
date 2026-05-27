"""Regression tests for CloudTrail trail log-file delivery integrations.

Covers the two cross-service parity gaps closed on 2026-04-15:

* **C2** — when a trail has ``sns_topic_name`` set, every delivered log
  file must trigger an SNS ``Publish`` to the trail's topic with the AWS
  documented body ``{"s3Bucket": <bucket>, "s3ObjectKey": [<key>]}``.
* **C3** — when a trail has ``kms_key_id`` set, the log file's
  ``put_object`` call must use SSE-KMS (``ServerSideEncryption=aws:kms``
  and ``SSEKMSKeyId=<key id>``).

We exercise ``_deliver_log_file`` directly with mock S3/SNS clients
rather than running the full polling loop.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu.services.cloudtrail.provider import _deliver_log_file


ACCOUNT_ID = "000000000000"
REGION = "us-east-1"
BUCKET = "audit-bucket"
KEY = (
    "AWSLogs/000000000000/CloudTrail/us-east-1/2026/04/15/"
    "000000000000_CloudTrail_us-east-1_20260415T120000Z.json.gz"
)
BODY = b"\x1f\x8b\x08\x00\x00"  # any gzip-ish bytes; opaque here


def _trail(*, sns_topic_name=None, kms_key_id=None, partition="aws"):
    """Build a minimal Trail-shaped object exposing only the attributes
    ``_deliver_log_file`` reads."""
    topic_arn = None
    if sns_topic_name:
        topic_arn = (
            f"arn:{partition}:sns:{REGION}:{ACCOUNT_ID}:{sns_topic_name}"
        )
    return SimpleNamespace(
        sns_topic_name=sns_topic_name,
        kms_key_id=kms_key_id,
        partition=partition,
        topic_arn=topic_arn,
    )


def _call(trail, s3_client=None, sns_client=None):
    s3_client = s3_client or MagicMock()
    sns_client = sns_client or MagicMock()
    _deliver_log_file(
        trail=trail,
        s3_client=s3_client,
        sns_client=sns_client,
        account_id=ACCOUNT_ID,
        region=REGION,
        bucket_name=BUCKET,
        s3_key=KEY,
        body=BODY,
    )
    return s3_client, sns_client


# ---------------------------------------------------------------------------
# C2 — SNS publish behavior
# ---------------------------------------------------------------------------
class TestSnsNotification:
    def test_publish_happens_when_trail_has_sns_topic(self):
        trail = _trail(sns_topic_name="ct-topic")
        s3, sns = _call(trail)

        assert s3.put_object.call_count == 1
        assert sns.publish.call_count == 1
        kwargs = sns.publish.call_args.kwargs
        assert kwargs["TopicArn"] == (
            f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:ct-topic"
        )

    def test_no_publish_when_trail_has_no_sns_topic(self):
        trail = _trail(sns_topic_name=None)
        s3, sns = _call(trail)

        assert s3.put_object.call_count == 1
        sns.publish.assert_not_called()

    def test_sns_publish_failure_does_not_unwind_s3_put(self):
        """The S3 write is the source of truth — a failing SNS publish
        must not raise out of ``_deliver_log_file``."""
        trail = _trail(sns_topic_name="ct-topic")
        sns = MagicMock()
        sns.publish.side_effect = RuntimeError("SNS is on fire")
        s3 = MagicMock()

        # Must not raise.
        _deliver_log_file(
            trail=trail,
            s3_client=s3,
            sns_client=sns,
            account_id=ACCOUNT_ID,
            region=REGION,
            bucket_name=BUCKET,
            s3_key=KEY,
            body=BODY,
        )
        assert s3.put_object.call_count == 1
        assert sns.publish.call_count == 1

    def test_payload_shape_matches_aws_documentation(self):
        """Real CloudTrail sends the JSON body
        ``{"s3Bucket": <bucket>, "s3ObjectKey": [<key>]}`` as the
        ``Message`` string (not MessageAttributes)."""
        trail = _trail(sns_topic_name="ct-topic")
        _, sns = _call(trail)

        kwargs = sns.publish.call_args.kwargs
        assert "MessageAttributes" not in kwargs
        body = json.loads(kwargs["Message"])
        assert body == {
            "s3Bucket": BUCKET,
            "s3ObjectKey": [KEY],
        }


# ---------------------------------------------------------------------------
# C3 — SSE-KMS on put_object
# ---------------------------------------------------------------------------
class TestKmsEncryption:
    def test_put_object_uses_sse_kms_when_kms_key_id_set(self):
        trail = _trail(kms_key_id="alias/cloudtrail")
        s3, _ = _call(trail)

        kwargs = s3.put_object.call_args.kwargs
        assert kwargs["Bucket"] == BUCKET
        assert kwargs["Key"] == KEY
        assert kwargs["ServerSideEncryption"] == "aws:kms"
        assert kwargs["SSEKMSKeyId"] == "alias/cloudtrail"

    def test_put_object_has_no_sse_params_when_kms_absent(self):
        trail = _trail(kms_key_id=None)
        s3, _ = _call(trail)

        kwargs = s3.put_object.call_args.kwargs
        assert "ServerSideEncryption" not in kwargs
        assert "SSEKMSKeyId" not in kwargs

    def test_put_object_carries_body_and_content_type(self):
        """Backwards-compatible default behavior must still send the
        gzipped log body with the CloudTrail content type."""
        trail = _trail()
        s3, _ = _call(trail)

        kwargs = s3.put_object.call_args.kwargs
        assert kwargs["Body"] == BODY
        assert kwargs["ContentType"] == "application/x-gzip"


# ---------------------------------------------------------------------------
# Combined — C2 + C3 together
# ---------------------------------------------------------------------------
class TestCombined:
    def test_sns_and_kms_together(self):
        trail = _trail(sns_topic_name="ct-topic", kms_key_id="alias/ct")
        s3, sns = _call(trail)

        s3_kwargs = s3.put_object.call_args.kwargs
        assert s3_kwargs["ServerSideEncryption"] == "aws:kms"
        assert s3_kwargs["SSEKMSKeyId"] == "alias/ct"

        sns_kwargs = sns.publish.call_args.kwargs
        assert sns_kwargs["TopicArn"].endswith(":ct-topic")
        assert json.loads(sns_kwargs["Message"]) == {
            "s3Bucket": BUCKET,
            "s3ObjectKey": [KEY],
        }

    def test_neither_configured_is_vanilla_put(self):
        """A bare trail yields exactly one un-encrypted put and no SNS."""
        trail = _trail()
        s3, sns = _call(trail)

        sns.publish.assert_not_called()
        s3_kwargs = s3.put_object.call_args.kwargs
        assert set(s3_kwargs.keys()) == {"Bucket", "Key", "Body", "ContentType"}


# ---------------------------------------------------------------------------
# Topic ARN derivation fallback
# ---------------------------------------------------------------------------
def test_topic_arn_derived_when_not_exposed_by_trail():
    """If the trail object exposes ``sns_topic_name`` but no ``topic_arn``
    attribute (e.g., a simple stand-in), we derive the ARN from
    account/region/partition."""
    trail = SimpleNamespace(
        sns_topic_name="ct-topic",
        kms_key_id=None,
        partition="aws",
        # Intentionally no topic_arn attribute at all.
    )
    # Remove topic_arn so getattr returns None.
    assert not hasattr(trail, "topic_arn")

    s3 = MagicMock()
    sns = MagicMock()
    _deliver_log_file(
        trail=trail,
        s3_client=s3,
        sns_client=sns,
        account_id=ACCOUNT_ID,
        region=REGION,
        bucket_name=BUCKET,
        s3_key=KEY,
        body=BODY,
    )
    kwargs = sns.publish.call_args.kwargs
    assert kwargs["TopicArn"] == f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:ct-topic"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
