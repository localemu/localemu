"""Map boto3 operation names to AWS IAM action names.

AWS deliberately uses non-1:1 mappings between API operations and IAM
actions. The most surprising offenders:

* ``lambda:Invoke``                           -> ``lambda:InvokeFunction``
* ``s3:ListObjects`` / ``s3:ListObjectsV2``   -> ``s3:ListBucket``
* ``s3:ListBuckets``                          -> ``s3:ListAllMyBuckets``
* ``s3:HeadBucket``                           -> ``s3:ListBucket``
* ``s3:HeadObject``                           -> ``s3:GetObject``
* ``kms:ReEncrypt`` requires BOTH ``kms:ReEncryptFrom`` AND ``kms:ReEncryptTo``
* All S3 multipart upload ops collapse to ``s3:PutObject``
* All SQS/SNS ``*Batch`` ops collapse to their non-batch action

Without this translator, a user with a policy granting the correct
IAM action gets a 403 because the enforcer is checking against a
non-existent permission like ``lambda:Invoke`` or ``s3:ListObjects``.

This map is intentionally narrow: the default ``service:OperationName``
mapping is correct for the vast majority of AWS actions, so we only
list the cases where AWS diverges. Pulled from the AWS Service
Authorization Reference (``s3``, ``lambda``, ``sqs``, ``sns``, ``kms``,
``dynamodb`` chapters):
https://docs.aws.amazon.com/service-authorization/latest/reference/
"""

from __future__ import annotations

# (service, operation_name) -> list of IAM action names that must all be allowed.
# When the right-hand list has multiple entries, the call requires ALL of them
# (e.g. CopyObject needs both GetObject on the source and PutObject on the dest).
ACTION_MAP: dict[tuple[str, str], list[str]] = {
    # ---- S3 ----
    ("s3", "ListBuckets"):        ["s3:ListAllMyBuckets"],
    ("s3", "ListObjects"):        ["s3:ListBucket"],
    ("s3", "ListObjectsV2"):      ["s3:ListBucket"],
    ("s3", "ListObjectVersions"): ["s3:ListBucketVersions"],
    ("s3", "HeadBucket"):         ["s3:ListBucket"],
    ("s3", "HeadObject"):         ["s3:GetObject"],
    ("s3", "CopyObject"):         ["s3:GetObject", "s3:PutObject"],
    ("s3", "GetBucketTagging"):   ["s3:GetBucketTagging"],
    ("s3", "PutBucketTagging"):   ["s3:PutBucketTagging"],
    ("s3", "GetBucketLocation"):  ["s3:GetBucketLocation"],
    # ---- S3 multipart upload (all gate on PutObject in real AWS) ----
    ("s3", "CreateMultipartUpload"):   ["s3:PutObject"],
    ("s3", "UploadPart"):              ["s3:PutObject"],
    ("s3", "UploadPartCopy"):          ["s3:PutObject", "s3:GetObject"],
    ("s3", "CompleteMultipartUpload"): ["s3:PutObject"],
    ("s3", "ListMultipartUploads"):    ["s3:ListBucketMultipartUploads"],
    ("s3", "ListParts"):               ["s3:ListMultipartUploadParts"],
    # ---- S3 object query / batch delete ----
    ("s3", "SelectObjectContent"):     ["s3:GetObject"],
    ("s3", "DeleteObjects"):           ["s3:DeleteObject"],
    # ---- S3 bucket-config name rewrites ----
    ("s3", "GetBucketEncryption"):     ["s3:GetEncryptionConfiguration"],
    ("s3", "PutBucketEncryption"):     ["s3:PutEncryptionConfiguration"],
    ("s3", "DeleteBucketEncryption"):  ["s3:PutEncryptionConfiguration"],
    ("s3", "GetBucketCors"):           ["s3:GetBucketCORS"],
    ("s3", "PutBucketCors"):           ["s3:PutBucketCORS"],
    ("s3", "DeleteBucketCors"):        ["s3:PutBucketCORS"],
    ("s3", "GetBucketReplication"):    ["s3:GetReplicationConfiguration"],
    ("s3", "PutBucketReplication"):    ["s3:PutReplicationConfiguration"],
    ("s3", "DeleteBucketReplication"): ["s3:PutReplicationConfiguration"],
    ("s3", "GetBucketLifecycle"):              ["s3:GetLifecycleConfiguration"],
    ("s3", "GetBucketLifecycleConfiguration"): ["s3:GetLifecycleConfiguration"],
    ("s3", "PutBucketLifecycle"):              ["s3:PutLifecycleConfiguration"],
    ("s3", "PutBucketLifecycleConfiguration"): ["s3:PutLifecycleConfiguration"],
    ("s3", "DeleteBucketLifecycle"):           ["s3:PutLifecycleConfiguration"],
    ("s3", "GetPublicAccessBlock"):    ["s3:GetBucketPublicAccessBlock"],
    ("s3", "PutPublicAccessBlock"):    ["s3:PutBucketPublicAccessBlock"],
    ("s3", "DeletePublicAccessBlock"): ["s3:PutBucketPublicAccessBlock"],
    # ---- Lambda (closes BUG-002: Invoke is the wire op, IAM action is InvokeFunction) ----
    ("lambda", "Invoke"):                   ["lambda:InvokeFunction"],
    ("lambda", "InvokeWithResponseStream"): ["lambda:InvokeFunction"],
    ("lambda", "InvokeAsync"):              ["lambda:InvokeFunction"],
    ("lambda", "GetLayerVersionByArn"):     ["lambda:GetLayerVersion"],
    # ---- SQS batch ops collapse to the non-batch action ----
    ("sqs", "SendMessageBatch"):             ["sqs:SendMessage"],
    ("sqs", "DeleteMessageBatch"):           ["sqs:DeleteMessage"],
    ("sqs", "ChangeMessageVisibilityBatch"): ["sqs:ChangeMessageVisibility"],
    # ---- SNS batch op ----
    ("sns", "PublishBatch"): ["sns:Publish"],
    # ---- KMS ReEncrypt requires BOTH halves ----
    ("kms", "ReEncrypt"): ["kms:ReEncryptFrom", "kms:ReEncryptTo"],
    # ---- DynamoDB transactions (safe-by-default: require all four; refining by
    # body inspection is future work).
    ("dynamodb", "TransactWriteItems"): [
        "dynamodb:ConditionCheckItem", "dynamodb:PutItem",
        "dynamodb:UpdateItem", "dynamodb:DeleteItem",
    ],
    ("dynamodb", "TransactGetItems"): ["dynamodb:GetItem"],
    # ---- EC2 ----
    # EC2 mostly matches 1:1, but Describe* is universal and Run* maps to RunInstances.
    # No overrides needed today; placeholder for future.
    # ---- IAM ----
    # IAM operations match 1:1 (CreateUser -> iam:CreateUser, etc.). No overrides.
    # ---- STS ----
    # STS operations match 1:1 (AssumeRole -> sts:AssumeRole, etc.).
}


def map_action(service: str, operation_name: str) -> list[str]:
    """Translate an API operation to its IAM action name(s).

    Returns ``["{service}:{operation_name}"]`` (default 1:1) unless the
    pair is in ``ACTION_MAP``, in which case the mapped names are
    returned. The caller should treat the response as a list of actions
    that ALL must be authorised — for actions with multi-permission
    requirements (like CopyObject), enforcement is by intersection.
    """
    mapped = ACTION_MAP.get((service, operation_name))
    if mapped:
        return list(mapped)
    return [f"{service}:{operation_name}"]
