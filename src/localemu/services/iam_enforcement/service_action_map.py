"""Map boto3 operation names to AWS IAM action names.

AWS deliberately uses non-1:1 mappings between API operations and IAM
actions. The most surprising offenders:

* ``s3:ListObjects`` / ``s3:ListObjectsV2``  → ``s3:ListBucket``
* ``s3:ListBuckets``                          → ``s3:ListAllMyBuckets``
* ``s3:HeadBucket``                           → ``s3:ListBucket``
* ``s3:HeadObject``                           → ``s3:GetObject``

Without this translator, a user with a policy granting the correct
IAM action gets a 403 because the enforcer is checking against a
non-existent permission like ``s3:ListObjects``.

This map is intentionally narrow: the default ``service:OperationName``
mapping is correct for the vast majority of AWS actions, so we only
list the cases where AWS diverges. Pulled from the AWS Service
Authorization Reference (``s3``, ``ec2``, ``dynamodb`` chapters):
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
    # ---- EC2 ----
    # EC2 mostly matches 1:1, but Describe* is universal and Run* maps to RunInstances.
    # No overrides needed today; placeholder for future.
    # ---- IAM ----
    # IAM operations match 1:1 (CreateUser → iam:CreateUser, etc.). No overrides.
    # ---- STS ----
    # STS operations match 1:1 (AssumeRole → sts:AssumeRole, etc.).
    # ---- DynamoDB ----
    # DynamoDB operations match 1:1 (PutItem → dynamodb:PutItem, etc.).
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
