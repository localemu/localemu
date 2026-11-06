import json
import logging
import os
import re
import threading

from moto.iam.models import (
    AccessKey,
    AWSManagedPolicy,
    IAMBackend,
    InlinePolicy,
    ManagedPolicy,
    Policy,
    User,
)
from moto.iam.models import Role as MotoRole
from moto.iam.policy_validation import VALID_STATEMENT_ELEMENTS

from localemu import config
from localemu.constants import TAG_KEY_CUSTOM_ID
from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)

ADDITIONAL_MANAGED_POLICIES = {
    "AWSLambdaExecute": {
        "Arn": "arn:aws:iam::aws:policy/AWSLambdaExecute",
        "Path": "/",
        "CreateDate": "2017-10-20T17:23:10+00:00",
        "DefaultVersionId": "v4",
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:*"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::*",
                },
            ],
        },
        "UpdateDate": "2019-05-20T18:22:18+00:00",
    }
}

_IAM_PRINCIPAL_ARN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):(user|role)/(?:.*/)?([^/]+)$")


def _validate_trust_principals(backend, document: str) -> None:
    """Reject a trust policy that names an IAM user or role that does not exist.

    AWS resolves every ``Principal: {"AWS": "arn:...:user|role/<name>"}`` when the policy is
    saved and answers ``MalformedPolicyDocument: Invalid principal in policy`` for a missing one.
    That answer is what lets an outsider test whether a role exists in somebody else's account,
    so it is only enforced in enforcement mode, where LocalEmu behaves like a hardened account.
    """
    if os.environ.get("IAM_ENFORCEMENT", "").strip().lower() not in ("1", "soft"):
        return
    from moto.iam.exceptions import MalformedPolicyDocument
    from moto.iam.models import iam_backends

    try:
        statements = json.loads(document).get("Statement") or []
    except (ValueError, AttributeError):
        return
    for statement in [statements] if isinstance(statements, dict) else statements:
        principal = statement.get("Principal") if isinstance(statement, dict) else None
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        for arn in [aws] if isinstance(aws, str) else (aws or []):
            match = _IAM_PRINCIPAL_ARN.match(str(arn))
            if not match:
                continue
            account_id, kind, name = match.groups()
            other = iam_backends[account_id]["global"]
            exists = name in (other.users if kind == "user" else {r.name: r for r in other.roles.values()})
            if not exists:
                raise MalformedPolicyDocument(f'Invalid principal in policy: "AWS":"{arn}"')


IAM_PATCHED = False
IAM_PATCH_LOCK = threading.RLock()


def apply_iam_patches():
    global IAM_PATCHED

    # prevent patching multiple times, as this is called from both STS and IAM (for now)
    # Do ALL patching inside the lock to prevent race conditions
    with IAM_PATCH_LOCK:
        if IAM_PATCHED:
            return

        try:
            _do_iam_patches()
            IAM_PATCHED = True
        except Exception:
            # L-07: Reset flag on failure so patching can be retried
            IAM_PATCHED = False
            raise


def _do_iam_patches():
    # support service linked roles
    moto_role_og_arn_prop = MotoRole.arn

    @property
    def moto_role_arn(self):
        return getattr(self, "service_linked_role_arn", None) or moto_role_og_arn_prop.__get__(self)

    MotoRole.arn = moto_role_arn

    # Add missing managed polices
    # TODO this might not be necessary
    @patch(IAMBackend._init_aws_policies)
    def _init_aws_policies_extended(_init_aws_policies, self):
        loaded_policies = _init_aws_policies(self)
        loaded_policies.extend(
            [
                AWSManagedPolicy.from_data(name, self.account_id, self.region_name, d)
                for name, d in ADDITIONAL_MANAGED_POLICIES.items()
            ]
        )
        return loaded_policies

    if "Principal" not in VALID_STATEMENT_ELEMENTS:
        VALID_STATEMENT_ELEMENTS.append("Principal")

    # patch policy __init__ to set document as attribute

    @patch(Policy.__init__)
    def policy__init__(
        fn,
        self,
        name,
        account_id,
        region,
        default_version_id=None,
        description=None,
        document=None,
        **kwargs,
    ):
        fn(self, name, account_id, region, default_version_id, description, document, **kwargs)
        self.document = document
        if "tags" in kwargs and TAG_KEY_CUSTOM_ID in kwargs["tags"]:
            self.id = kwargs["tags"][TAG_KEY_CUSTOM_ID]["Value"]

    # moto's own ``update_default_version`` clears ``is_default`` when
    # called with the version that is *already* the default: it loops over
    # ``self.versions`` once, and for the matching version both the "set
    # new default" and the "clear old default" branches fire in the same
    # iteration (old == new), with the clear running last. Real AWS is a
    # no-op in that case - the version stays the default. Without this fix,
    # calling SetDefaultPolicyVersion on the current default leaves every
    # version with IsDefaultVersion=False and DeletePolicyVersion then
    # refuses to delete it ("Cannot delete the default version").
    @patch(ManagedPolicy.update_default_version)
    def managed_policy_update_default_version(fn, self, new_default_version_id: str):
        if new_default_version_id == self.default_version_id:
            return
        fn(self, new_default_version_id)

    @patch(IAMBackend.create_role)
    def iam_backend_create_role(
        fn,
        self,
        role_name: str,
        assume_role_policy_document: str,
        path: str,
        permissions_boundary: str | None,
        description: str,
        tags: list[dict[str, str]],
        max_session_duration: str | None,
        linked_service: str | None = None,
    ):
        _validate_trust_principals(self, assume_role_policy_document)
        role = fn(
            self,
            role_name,
            assume_role_policy_document,
            path,
            permissions_boundary,
            description,
            tags,
            max_session_duration,
            linked_service,
        )
        new_id_tag = [tag for tag in (tags or []) if tag["Key"] == TAG_KEY_CUSTOM_ID]
        if new_id_tag:
            new_id = new_id_tag[0]["Value"]
            old_id = role.id
            role.id = new_id
            self.roles[new_id] = self.roles.pop(old_id)
        return role

    @patch(IAMBackend.update_assume_role_policy)
    def iam_backend_update_assume_role_policy(fn, self, role_name: str, policy_document: str):
        _validate_trust_principals(self, policy_document)
        return fn(self, role_name, policy_document)

    @patch(InlinePolicy.unapply_policy)
    def inline_policy_unapply_policy(fn, self, backend):
        try:
            fn(self, backend)
        except Exception:
            # Log the exception instead of silently swallowing
            # Role can be deleted before policy being deleted in cloudformation
            LOG.debug(
                "Failed to unapply inline policy %s (role may already be deleted): %s",
                getattr(self, "name", "unknown"),
                exc_info=True,
            )

    @patch(AccessKey.__init__)
    def access_key__init__(
        fn,
        self,
        user_name: str | None,
        prefix: str,
        account_id: str,
        status: str = "Active",
        **kwargs,
    ):
        if not config.PARITY_AWS_ACCESS_KEY_ID:
            prefix = "L" + prefix[1:]
        fn(self, user_name, prefix, account_id, status, **kwargs)

    @patch(User.__init__)
    def user__init__(
        fn,
        self,
        *args,
        **kwargs,
    ):
        fn(self, *args, **kwargs)
        self.service_specific_credentials = []
