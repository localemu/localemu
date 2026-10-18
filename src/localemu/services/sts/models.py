import threading
from datetime import datetime
from typing import Any, TypedDict

from localemu.aws.api.sts import Tag
from localemu.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


class _SessionConfigBase(TypedDict):
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag]
    # list of lowercase transitive tag keys
    transitive_tags: list[str]
    # other stored context variables
    iam_context: dict[str, Any]
    # source_identity propagated through role chains (EMU-06)
    source_identity: str
    # session expiration time (EMU-05)
    expiration: datetime | None
    # when this session's credentials were minted. Drives aws:TokenIssueTime
    # in the request context - the condition key AWS's own incident-response
    # runbooks use to deny every action for sessions issued before a
    # containment timestamp, without touching the role's permissions going
    # forward for sessions minted after remediation.
    issued_at: datetime | None
    # session policies for role chaining intersection (EMU-04)
    session_policies: list[dict]
    # True when the STS call that minted this session supplied a SerialNumber
    # (i.e. AssumeRole/GetSessionToken with --serial-number --token-code). Drives
    # aws:MultiFactorAuthPresent in the request context. Per AWS, MFA does NOT
    # propagate through AssumeRole chains; only GetSessionToken preserves MFA in
    # downstream API calls made with the returned credentials.
    mfa_authenticated: bool


class SessionConfig(_SessionConfigBase, total=False):
    # Set only for credentials minted by GetSessionToken / GetFederationToken,
    # which belong to an IAM user rather than to a role. "session-token" =>
    # the credentials act as that user; "federated" => a federated user whose
    # permissions are the user's policies intersected with the session policy.
    session_kind: str
    # IAM user (name) that called GetSessionToken / GetFederationToken.
    base_username: str
    # Name passed to GetFederationToken (the ``federated-user/<name>`` ARN).
    federated_name: str


class STSStore(BaseStore):
    # maps access key ids to tagging config for the session they belong to
    sessions: dict[str, SessionConfig] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)

# Thread lock to prevent race conditions on session store access
sts_store_lock = threading.Lock()
