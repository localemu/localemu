"""Regression tests for AWS CloudTrail requestParameters key-casing parity.

Real AWS CloudTrail events publish ``detail.requestParameters`` with
lowerCamelCase keys (derived from the service's API model PascalCase) plus
a handful of per-service renames. EventBridge rules like
``{"detail":{"requestParameters":{"bucketName":[...]}}}`` will silently fail
if LocalEmu publishes PascalCase ``Bucket`` instead.

Before this fix, boto3's PascalCase ``service_request`` (e.g. ``{"Bucket":
"foo"}``) flowed through to the stored event unchanged. Consumers reading
``detail.requestParameters.bucketName`` got ``None``.

The fix normalises keys in ``_sanitize_params``:
  * first-char-lowercase on every key (``Bucket`` → ``bucket``,
    ``CreateBucketConfiguration`` → ``createBucketConfiguration``)
  * leading ALL-CAPS acronyms preserved (``ACL`` → ``ACL``)
  * per-service renames (S3: ``bucket`` → ``bucketName``) applied after the
    lowercase pass.
"""

from __future__ import annotations

from localemu.services.cloudtrail.event_store import (
    _lowercase_first_char,
    _normalize_keys,
    _sanitize_params,
    create_event_from_context,
)


class TestLowercaseFirstChar:
    def test_single_word_pascal(self):
        assert _lowercase_first_char("Bucket") == "bucket"

    def test_multi_word_camel(self):
        assert _lowercase_first_char("CreateBucketConfiguration") == "createBucketConfiguration"

    def test_leading_acronym_preserved(self):
        assert _lowercase_first_char("ACL") == "ACL"
        assert _lowercase_first_char("ARN") == "ARN"
        assert _lowercase_first_char("KMSKeyId") == "KMSKeyId"

    def test_already_lower_is_noop(self):
        assert _lowercase_first_char("bucket") == "bucket"

    def test_empty_string(self):
        assert _lowercase_first_char("") == ""

    def test_single_uppercase_char_preserved(self):
        """Single-char uppercase keys are type-tag discriminators (DynamoDB
        uses S/N/B/BOOL/NULL/L/M/SS/NS/BS). Real AWS CloudTrail preserves
        them, and so do we."""
        assert _lowercase_first_char("A") == "A"
        assert _lowercase_first_char("S") == "S"
        assert _lowercase_first_char("N") == "N"

    def test_single_lowercase_char_is_noop(self):
        assert _lowercase_first_char("a") == "a"


class TestNormalizeKeys:
    def test_flat_dict(self):
        got = _normalize_keys({"Bucket": "x", "Key": "y"})
        assert got == {"bucket": "x", "key": "y"}

    def test_nested_dict(self):
        got = _normalize_keys({"CreateBucketConfiguration": {"LocationConstraint": "us-west-2"}})
        assert got == {
            "createBucketConfiguration": {"locationConstraint": "us-west-2"}
        }

    def test_list_of_dicts(self):
        got = _normalize_keys({"Grants": [{"Grantee": {"Type": "Group"}}]})
        assert got == {"grants": [{"grantee": {"type": "Group"}}]}

    def test_acl_preserved(self):
        assert _normalize_keys({"ACL": "public-read"}) == {"ACL": "public-read"}

    def test_s3_bucket_renamed_to_bucketname(self):
        """S3 is the one service where AWS CloudTrail renames ``Bucket`` to
        ``bucketName`` (not just lowercasing)."""
        got = _normalize_keys({"Bucket": "my-bucket"}, service_name="s3")
        assert got == {"bucketName": "my-bucket"}

    def test_s3_bucket_rename_does_not_affect_other_services(self):
        got = _normalize_keys({"Bucket": "my-bucket"}, service_name="dynamodb")
        assert got == {"bucket": "my-bucket"}

    def test_s3_rename_applies_in_nested_dicts_too(self):
        """CloudTrail's bucket rename is applied at every nesting level."""
        got = _normalize_keys({"Outer": {"Bucket": "b"}}, service_name="s3")
        assert got == {"outer": {"bucketName": "b"}}

    def test_non_string_keys_preserved(self):
        got = _normalize_keys({123: "x", "Foo": "y"})
        assert got == {123: "x", "foo": "y"}

    def test_depth_guard_returns_original(self):
        # Construct something 13 levels deep; function should bail out safely.
        deep = {"Level0": {}}
        cur = deep["Level0"]
        for i in range(15):
            cur[f"Level{i+1}"] = {}
            cur = cur[f"Level{i+1}"]
        cur["Leaf"] = 1
        # Doesn't raise.
        got = _normalize_keys(deep)
        assert "level0" in got

    def test_primitive_passthrough(self):
        assert _normalize_keys("string") == "string"
        assert _normalize_keys(42) == 42
        assert _normalize_keys(None) is None


class TestSanitizeParamsIntegration:
    def test_s3_create_bucket_shape_matches_aws(self):
        got = _sanitize_params(
            {
                "Bucket": "my-bucket",
                "ACL": "public-read",
                "CreateBucketConfiguration": {"LocationConstraint": "us-west-2"},
            },
            service_name="s3",
        )
        assert got == {
            "bucketName": "my-bucket",
            "ACL": "public-read",
            "createBucketConfiguration": {"locationConstraint": "us-west-2"},
        }

    def test_sns_publish_shape(self):
        got = _sanitize_params(
            {"TopicArn": "arn:...:topic", "Message": "hi", "Subject": "x"},
            service_name="sns",
        )
        assert got == {"topicArn": "arn:...:topic", "message": "hi", "subject": "x"}

    def test_dynamodb_put_item_shape(self):
        got = _sanitize_params(
            {"TableName": "t", "Item": {"id": {"S": "1"}}},
            service_name="dynamodb",
        )
        assert got == {"tableName": "t", "item": {"id": {"S": "1"}}}

    def test_empty_params_returns_none(self):
        assert _sanitize_params(None, service_name="s3") is None
        assert _sanitize_params({}, service_name="s3") is None

    def test_large_value_still_truncated_after_normalization(self):
        huge = "x" * 5000
        got = _sanitize_params({"LongValue": huge}, service_name="s3")
        assert "longValue" in got
        assert got["longValue"].endswith("chars>")

    def test_small_utf8_bytes_decoded_to_string(self):
        # Lambda Invoke payloads land here as bytes. Showing the JSON in
        # the drill-down beats a useless ``<binary, N bytes>`` placeholder.
        got = _sanitize_params(
            {"Payload": b'{"k":"v"}'}, service_name="lambda"
        )
        assert got["payload"] == '{"k":"v"}'

    def test_large_binary_bytes_kept_as_placeholder(self):
        big = b"\x00" * 16_000  # over 8KB inline threshold AND not UTF-8
        got = _sanitize_params({"Payload": big}, service_name="lambda")
        assert got["payload"].startswith("<binary, ")
        assert "16000 bytes" in got["payload"]

    def test_non_serializable_object_replaced_with_type_placeholder(self):
        # Twisted streams and other opaque objects used to leak through
        # ``json.dumps(default=str)`` as an unreadable repr.
        class _DummyStream:
            pass

        got = _sanitize_params(
            {"Payload": _DummyStream()}, service_name="lambda"
        )
        assert got["payload"] == "<_DummyStream>"


class TestCreateEventFromContextPropagatesServiceName:
    """End-to-end: create_event_from_context → CloudTrailEvent has normalised
    request_parameters."""

    def test_s3_create_bucket_event_has_bucketName(self):
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            account_id="000000000000",
            region="us-east-1",
            service_request={"Bucket": "probe", "ACL": "private"},
        )
        assert evt.request_parameters == {"bucketName": "probe", "ACL": "private"}

    def test_dynamodb_put_item_event_uses_lowercamel(self):
        evt = create_event_from_context(
            service_name="dynamodb",
            operation_name="PutItem",
            service_request={"TableName": "t", "Item": {}},
        )
        assert evt.request_parameters == {"tableName": "t", "item": {}}

    def test_response_elements_also_normalised(self):
        evt = create_event_from_context(
            service_name="s3",
            operation_name="CreateBucket",
            service_request=None,
            response_elements={"Location": "/probe", "BucketArn": "arn:aws:s3:::probe"},
        )
        assert evt.response_elements == {
            "location": "/probe",
            "bucketArn": "arn:aws:s3:::probe",
        }
