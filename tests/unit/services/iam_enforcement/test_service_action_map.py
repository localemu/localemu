"""Unit tests for the operation -> IAM-action translation map.

AWS deliberately uses non-1:1 mappings between API operations and IAM
actions: ``lambda:Invoke`` (the wire op) is authorized as
``lambda:InvokeFunction`` ; S3's multipart suite collapses to
``s3:PutObject`` ; SQS / SNS batch ops drop the ``Batch`` suffix ;
S3Control access-point ops live in the ``s3:`` namespace. Without the
translation map, a policy granting the AWS-correct IAM action gets a
403 because the enforcer is checking against a non-existent permission
like ``lambda:Invoke`` or ``s3control:CreateAccessPoint``.

These tests cover every row of ``ACTION_MAP`` we care about plus the
default 1:1 fallback.
"""

from __future__ import annotations

import pytest

from localemu.services.iam_enforcement.service_action_map import ACTION_MAP, map_action


@pytest.mark.parametrize(
    "service, operation, expected",
    [
        # ---- Lambda Invoke family (wire op vs IAM action) ----
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
        # ---- S3Control AP ops use the s3: namespace ----
        ("s3control", "CreateAccessPoint",       ["s3:CreateAccessPoint"]),
        ("s3control", "GetAccessPoint",          ["s3:GetAccessPoint"]),
        ("s3control", "ListAccessPoints",        ["s3:ListAccessPoints"]),
        ("s3control", "DeleteAccessPoint",       ["s3:DeleteAccessPoint"]),
        ("s3control", "PutAccessPointPolicy",    ["s3:PutAccessPointPolicy"]),
        ("s3control", "GetAccessPointPolicy",    ["s3:GetAccessPointPolicy"]),
        ("s3control", "DeleteAccessPointPolicy", ["s3:DeleteAccessPointPolicy"]),
        ("s3control", "GetAccessPointPolicyStatus",
            ["s3:GetAccessPointPolicyStatus"]),
        # MRAP
        ("s3control", "CreateMultiRegionAccessPoint",
            ["s3:CreateMultiRegionAccessPoint"]),
        ("s3control", "GetMultiRegionAccessPoint",
            ["s3:GetMultiRegionAccessPoint"]),
        ("s3control", "ListMultiRegionAccessPoints",
            ["s3:ListMultiRegionAccessPoints"]),
        # Object Lambda APs
        ("s3control", "CreateAccessPointForObjectLambda",
            ["s3:CreateAccessPointForObjectLambda"]),
        ("s3control", "GetAccessPointForObjectLambda",
            ["s3:GetAccessPointForObjectLambda"]),
        # Account-level PAB
        ("s3control", "GetPublicAccessBlock",   ["s3:GetAccountPublicAccessBlock"]),
        ("s3control", "PutPublicAccessBlock",   ["s3:PutAccountPublicAccessBlock"]),
        ("s3control", "DeletePublicAccessBlock", ["s3:PutAccountPublicAccessBlock"]),
        # Storage Lens
        ("s3control", "PutStorageLensConfiguration",
            ["s3:PutStorageLensConfiguration"]),
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


def test_lambda_invoke_wire_op_maps_to_invoke_function_iam_action() -> None:
    """``lambda:Invoke`` is the wire-protocol operation name ; the real
    AWS IAM action is ``lambda:InvokeFunction``. The translator must
    return the IAM action, never the wire op (which is not a real
    permission and would never authorize on real AWS).
    """
    actions = map_action("lambda", "Invoke")
    assert actions == ["lambda:InvokeFunction"]
    assert "lambda:Invoke" not in actions


def test_s3control_create_access_point_uses_s3_namespace_iam_action() -> None:
    """The s3control service uses the ``s3:`` namespace for its IAM
    actions per AWS docs. ``CreateAccessPoint`` must authorize against
    ``s3:CreateAccessPoint``, never ``s3control:CreateAccessPoint``
    (which is not a real permission and would never authorize on real
    AWS).
    """
    actions = map_action("s3control", "CreateAccessPoint")
    assert actions == ["s3:CreateAccessPoint"]
    assert "s3control:CreateAccessPoint" not in actions


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
