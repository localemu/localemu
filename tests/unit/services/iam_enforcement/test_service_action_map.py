"""Unit tests for operation -> IAM-action mapping (BUG-002).

Before the fix, ``map_action`` had no Lambda entries, so the engine asked
for ``lambda:Invoke`` (the wire operation name) instead of the AWS-correct
IAM action ``lambda:InvokeFunction``. A policy granting the correct action
got a 403; the workaround was to grant the non-AWS-standard ``lambda:Invoke``
spelling that would never work in real AWS.

These tests cover every row of ``ACTION_MAP`` that we care about plus the
default 1:1 fallback.
"""

from __future__ import annotations

import pytest

from localemu.services.iam_enforcement.service_action_map import ACTION_MAP, map_action


@pytest.mark.parametrize(
    "service, operation, expected",
    [
        # ---- BUG-002: Lambda Invoke family ----
        ("lambda", "Invoke", ["lambda:InvokeFunction"]),
        ("lambda", "InvokeWithResponseStream", ["lambda:InvokeFunction"]),
        ("lambda", "InvokeAsync", ["lambda:InvokeFunction"]),
        ("lambda", "GetLayerVersionByArn", ["lambda:GetLayerVersion"]),
        # ---- S3 (pre-existing entries kept working) ----
        ("s3", "ListBuckets", ["s3:ListAllMyBuckets"]),
        ("s3", "ListObjects", ["s3:ListBucket"]),
        ("s3", "ListObjectsV2", ["s3:ListBucket"]),
        ("s3", "HeadBucket", ["s3:ListBucket"]),
        ("s3", "HeadObject", ["s3:GetObject"]),
        ("s3", "CopyObject", ["s3:GetObject", "s3:PutObject"]),
        # ---- S3 multipart (new) ----
        ("s3", "CreateMultipartUpload", ["s3:PutObject"]),
        ("s3", "UploadPart", ["s3:PutObject"]),
        ("s3", "UploadPartCopy", ["s3:PutObject", "s3:GetObject"]),
        ("s3", "CompleteMultipartUpload", ["s3:PutObject"]),
        ("s3", "ListMultipartUploads", ["s3:ListBucketMultipartUploads"]),
        ("s3", "ListParts", ["s3:ListMultipartUploadParts"]),
        # ---- S3 object query / batch delete (new) ----
        ("s3", "SelectObjectContent", ["s3:GetObject"]),
        ("s3", "DeleteObjects", ["s3:DeleteObject"]),
        # ---- S3 bucket-config name rewrites (new) ----
        ("s3", "GetBucketEncryption", ["s3:GetEncryptionConfiguration"]),
        ("s3", "PutBucketEncryption", ["s3:PutEncryptionConfiguration"]),
        ("s3", "DeleteBucketEncryption", ["s3:PutEncryptionConfiguration"]),
        ("s3", "GetBucketCors", ["s3:GetBucketCORS"]),
        ("s3", "PutBucketCors", ["s3:PutBucketCORS"]),
        ("s3", "DeleteBucketCors", ["s3:PutBucketCORS"]),
        ("s3", "GetBucketReplication", ["s3:GetReplicationConfiguration"]),
        ("s3", "GetBucketLifecycle", ["s3:GetLifecycleConfiguration"]),
        ("s3", "GetBucketLifecycleConfiguration", ["s3:GetLifecycleConfiguration"]),
        ("s3", "PutBucketLifecycleConfiguration", ["s3:PutLifecycleConfiguration"]),
        ("s3", "GetPublicAccessBlock", ["s3:GetBucketPublicAccessBlock"]),
        ("s3", "PutPublicAccessBlock", ["s3:PutBucketPublicAccessBlock"]),
        ("s3", "DeletePublicAccessBlock", ["s3:PutBucketPublicAccessBlock"]),
        # ---- SQS batch ops collapse (new) ----
        ("sqs", "SendMessageBatch", ["sqs:SendMessage"]),
        ("sqs", "DeleteMessageBatch", ["sqs:DeleteMessage"]),
        ("sqs", "ChangeMessageVisibilityBatch", ["sqs:ChangeMessageVisibility"]),
        # ---- SNS batch (new) ----
        ("sns", "PublishBatch", ["sns:Publish"]),
        # ---- KMS ReEncrypt requires BOTH halves (new) ----
        ("kms", "ReEncrypt", ["kms:ReEncryptFrom", "kms:ReEncryptTo"]),
        # ---- DynamoDB transactions (new) ----
        (
            "dynamodb",
            "TransactWriteItems",
            [
                "dynamodb:ConditionCheckItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
            ],
        ),
        ("dynamodb", "TransactGetItems", ["dynamodb:GetItem"]),
        # ---- Default fallback: unknown service/operation maps 1:1 ----
        ("foobar", "DoSomething", ["foobar:DoSomething"]),
        ("ec2", "DescribeInstances", ["ec2:DescribeInstances"]),
        ("dynamodb", "PutItem", ["dynamodb:PutItem"]),
        ("iam", "CreateUser", ["iam:CreateUser"]),
        ("sts", "AssumeRole", ["sts:AssumeRole"]),
    ],
)
def test_map_action(service: str, operation: str, expected: list[str]) -> None:
    assert map_action(service, operation) == expected


def test_bug_002_lambda_invoke_returns_invoke_function_not_invoke() -> None:
    """The BUG-002 regression assertion: lambda:Invoke (wire op) MUST map to
    lambda:InvokeFunction (the real AWS IAM action), NOT to lambda:Invoke
    (which is not a real IAM action and would never work in real AWS)."""
    actions = map_action("lambda", "Invoke")
    assert actions == ["lambda:InvokeFunction"]
    assert "lambda:Invoke" not in actions


def test_action_map_has_minimum_expected_rows() -> None:
    """Sanity baseline: if someone trims ACTION_MAP, this trips so we notice."""
    assert len(ACTION_MAP) >= 30, (
        f"ACTION_MAP has {len(ACTION_MAP)} entries, expected at least 30"
    )


def test_map_action_returns_a_copy_not_the_stored_list() -> None:
    """Callers must be free to mutate the returned list without poisoning
    the shared ACTION_MAP."""
    a = map_action("lambda", "Invoke")
    a.append("attacker:sneak")
    b = map_action("lambda", "Invoke")
    assert b == ["lambda:InvokeFunction"]
    assert "attacker:sneak" not in b
