"""IAM Enforcement Handler for the LocalEmu handler chain.

Evaluates IAM policies on every API request. Activated by IAM_ENFORCEMENT=1.
Runs AFTER request parsing, BEFORE service dispatch.

Modes:
  IAM_ENFORCEMENT=1    - Enforce: deny unauthorized requests
  IAM_ENFORCEMENT=soft - Audit: log denials but allow all requests

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from localemu import config as _lemu_config
from localemu import constants as _lemu_constants
from localemu.aws.api import CommonServiceException, RequestContext
from localemu.aws.chain import Handler, HandlerChain
from localemu.http import Response

from .arn_builder import build_resource_arn
from .evaluator import Decision, PolicyEvaluator
from .identity import resolve_caller

LOG = logging.getLogger(__name__)

# Only sts:GetCallerIdentity is exempt (needed for identity bootstrap).
# LocalEmu-internal endpoints under /_localemu/* short-circuit BEFORE this
# handler via ``serve_localemu_resources`` in ``aws/app.py``, so they don't
# need to be listed here. AWS itself allows sts:GetCallerIdentity without an
# authenticated context — every API client uses it to discover who they are.
# Actions that authenticate via mechanisms OTHER than SigV4 IAM creds and
# must not be denied just because the caller has no IAM identity:
#   * ``sts:GetCallerIdentity`` — used by every SDK to discover identity;
#     denying it would break SDK clients before any other call.
#   * ``sts:AssumeRoleWithWebIdentity`` / ``sts:AssumeRoleWithSAML`` —
#     authenticate via a JWT / SAML assertion, not via signed creds. The
#     trust-policy evaluator in ``services/sts/provider.py`` validates the
#     federated principal independently.
#   * Cognito User Pools' end-user APIs — these are explicitly designed
#     to be callable by unauthenticated users (SignUp, ConfirmSignUp,
#     ForgotPassword) or by users whose only credential is the JWT they
#     just obtained (GetUser, ChangePassword, UpdateUserAttributes,
#     etc.). Cognito's own provider handles the AccessToken validation;
#     blocking these at the SigV4 layer breaks every UI sign-in flow.
_EXEMPT_ACTIONS = {
    "sts:GetCallerIdentity",
    "sts:AssumeRoleWithWebIdentity",
    "sts:AssumeRoleWithSAML",
    "cognito-idp:SignUp",
    "cognito-idp:ConfirmSignUp",
    "cognito-idp:ResendConfirmationCode",
    "cognito-idp:InitiateAuth",
    "cognito-idp:RespondToAuthChallenge",
    "cognito-idp:ForgotPassword",
    "cognito-idp:ConfirmForgotPassword",
    "cognito-idp:GetUser",
    "cognito-idp:ChangePassword",
    "cognito-idp:UpdateUserAttributes",
    "cognito-idp:DeleteUser",
    "cognito-idp:VerifyUserAttribute",
    "cognito-idp:GetUserAttributeVerificationCode",
    "cognito-idp:AssociateSoftwareToken",
    "cognito-idp:VerifySoftwareToken",
    "cognito-idp:SetUserMFAPreference",
    "cognito-idp:GlobalSignOut",
    "cognito-idp:RevokeToken",
}


class IAMEnforcementHandler(Handler):
    """Handler chain component that evaluates IAM policies on every API call.

    Injected into the handler chain after request parsing and before service dispatch.
    """

    def __init__(self):
        self.evaluator = PolicyEvaluator()

    def _read_mode(self):
        """Read enforcement mode from env var at call time (not import time)."""
        mode = os.environ.get("IAM_ENFORCEMENT", "").strip().lower()
        return mode == "1", mode == "soft", (mode == "1" or mode == "soft")

    @staticmethod
    def _is_internal_call(context: RequestContext, access_key: str | None) -> bool:
        """Whether this request is a LocalEmu service-to-service hop that
        must bypass user-IAM evaluation.

        Two independent signals, either sufficient:

        1. ``context.internal_request_params`` is populated. Set by
           :class:`InternalRequestParamsEnricher` whenever the incoming
           request carries the ``x-localemu-data`` header. Every client
           built by :class:`InternalClientFactory` (i.e. any hop through
           ``connect_to(...)``) emits that header unconditionally via the
           ``before-call.*.*`` event hook — see ``aws/connect.py:463-473``.
           ``RequestContext.is_internal_call`` already codifies this exact
           check; we reuse it here so the meaning stays synchronized with
           the rest of the codebase.

        2. The access key matches one of LocalEmu's internal sentinels:
           ``INTERNAL_AWS_ACCESS_KEY_ID`` (``constants.py``) or
           ``INTERNAL_RESOURCE_ACCOUNT`` (``config.py``). This covers the
           one call site that signs requests without going through
           :class:`InternalClientFactory` — Lambda code presigned-URL
           signing at ``lambda_models.py:245`` — where the sentinel ends
           up in the URL's query string and no header can ride along.
           The identical idiom is already used downstream at
           ``services/s3/presigned_url.py:255``.

        Trust model: ``x-localemu-data`` and the sentinel keys are
        LocalEmu-internal primitives. LocalEmu already extends implicit
        trust to this header for account/region overrides in
        ``aws/handlers/internal_requests.py`` and elsewhere — the
        enforcement boundary is "simulate AWS IAM for regular test
        traffic", not "defend against a hostile local caller". See the
        commit message for the full threat-model rationale.
        """
        if context.is_internal_call:
            return True
        if access_key and access_key in (
            _lemu_constants.INTERNAL_AWS_ACCESS_KEY_ID,
            _lemu_config.INTERNAL_RESOURCE_ACCOUNT,
        ):
            return True
        return False

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        enforce, audit, enabled = self._read_mode()
        if not enabled:
            return

        # Skip if service/operation not yet parsed
        if not context.service or not context.operation:
            return

        service_name = context.service.service_name
        # AWS uses non-1:1 mappings between API operations and IAM actions in
        # a handful of services. ``service_action_map`` returns the IAM
        # action(s) for this operation; the vast majority of ops map 1:1
        # via the default ``service:OperationName``, but e.g.
        # ``s3:ListObjects`` actually requires the ``s3:ListBucket`` IAM
        # permission, and ``s3:ListBuckets`` requires
        # ``s3:ListAllMyBuckets``. Without this translation, a correctly
        # written policy gets denied on the wire.
        from localemu.services.iam_enforcement.service_action_map import map_action

        iam_actions = map_action(service_name, context.operation.name)
        # For exempt/log purposes, surface the *first* mapped action (this
        # is what users see in the AccessDenied message). The evaluator
        # below loops over every entry and only allows the call when
        # *every* IAM action it implies is permitted (matches AWS's
        # multi-permission semantics for CopyObject etc.).
        action = iam_actions[0]

        # Only exempt sts:GetCallerIdentity
        if action in _EXEMPT_ACTIONS:
            return

        # Extract access key from Authorization header or query string
        access_key = _extract_access_key(context)

        # Service-to-service short-circuit. Runs before the "no access key"
        # branch so presigned-URL requests — whose credentials live in the
        # query string, not the Authorization header — are recognized via
        # the sentinel-key fallback in ``_is_internal_call``. This is the
        # fix for LocalEmu_Bugs_2.md: every internal hop through
        # ``connect_to(...)`` was previously denied because the internal
        # access key ``__internal_call__`` is not a known IAM caller.
        if self._is_internal_call(context, access_key):
            return

        if not access_key:
            # No credentials with enforcement enabled = deny
            LOG.info("IAM: no access key found in request, denying (enforcement enabled)")
            if audit:
                LOG.warning("IAM AUDIT DENY: unauthenticated request for %s", action)
                return
            raise CommonServiceException(
                code="AccessDenied",
                message="Request is missing Authentication Token",
                status_code=403,
            )

        # Resolve caller identity
        account_id = context.account_id or "000000000000"
        caller = resolve_caller(access_key, account_id, context.region)
        if not caller:
            # The wire response must mirror AWS for SDK-level parity. The
            # operator-facing log carries the actionable hint so first-time
            # IAM_ENFORCEMENT=1 users see why boto3 defaults (access_key=
            # 'test') get denied and what to do about it.
            LOG.warning(
                "IAM: unknown caller for %s — key=%s (account=%s) is not a known "
                "IAM user, role session, or root key. Either create the IAM "
                "user via `aws iam create-user` + `create-access-key`, or set "
                "ROOT_ACCESS_KEYS='<your-key>' to bypass enforcement for that key.",
                action, access_key[:8] if access_key else "<none>", account_id,
            )
            if audit:
                return  # soft mode: already logged, allow through
            raise CommonServiceException(
                code="AccessDenied",
                message="The security token included in the request is invalid",
                status_code=403,
            )

        # Root bypasses all
        if caller.principal_type == "Root":
            return

        # Build resource ARN
        resource_arn = build_resource_arn(
            service=service_name,
            operation=context.operation.name,
            request_params=context.service_request,
            region=context.region or "us-east-1",
            account_id=context.account_id or "000000000000",
        )

        # Stash the resource ARN on the context so ``_build_conditions``
        # can pass it to the resource-tag loader for aws:ResourceTag/*.
        try:
            context._iam_resource_arn = resource_arn  # type: ignore[attr-defined]
        except Exception:
            pass

        # Build condition context
        conditions = _build_conditions(context, caller)

        # Get resource-based policy (if applicable)
        resource_policy = _get_resource_policy(
            service_name, resource_arn, context.account_id, context.region
        )

        # Evaluate every IAM action implied by this API call. ``map_action``
        # returns multiple entries only for the rare ops where AWS demands
        # several permissions at once (e.g. CopyObject needs both
        # s3:GetObject and s3:PutObject). The call is allowed only when
        # all of them resolve to ALLOW; the first denial short-circuits.
        decision = Decision.ALLOW
        for iam_action in iam_actions:
            decision = self.evaluator.evaluate(
                caller=caller,
                action=iam_action,
                resource=resource_arn,
                conditions=conditions,
                resource_policy=resource_policy,
            )
            if decision != Decision.ALLOW:
                action = iam_action  # surface the failing action in the error
                break

        if decision != Decision.ALLOW:
            reason = "explicit deny" if decision == Decision.EXPLICIT_DENY else "no allowing policy"
            if caller.principal_type == "Anonymous":
                # Unsigned request with no public grant. AWS returns a bare
                # "Access Denied" (no principal ARN) for anonymous callers.
                log_message = (
                    f"anonymous (unsigned) request not authorized to perform: "
                    f"{action} on resource: {resource_arn} because {reason}"
                )
                wire_message = "Access Denied"
            else:
                log_message = (
                    f"User: {caller.arn} is not authorized to perform: "
                    f"{action} on resource: {resource_arn} because {reason}"
                )
                wire_message = (
                    f"User: {caller.arn} is not authorized to perform: "
                    f"{action} on resource: {resource_arn}"
                )

            if audit:
                LOG.warning("IAM AUDIT DENY: %s", log_message)
                return  # Soft mode: log but allow

            LOG.info("IAM DENY: %s", log_message)
            raise CommonServiceException(
                code="AccessDenied",
                message=wire_message,
                status_code=403,
            )


def _extract_access_key(context: RequestContext) -> str:
    """Extract the access key ID from the Authorization header or query string."""
    # Check Authorization header first
    auth = context.request.headers.get("Authorization", "")
    if "Credential=" in auth:
        cred_part = auth.split("Credential=")[1].split(",")[0]
        return cred_part.split("/")[0]
    # Check query string auth (presigned URLs use X-Amz-Credential)
    try:
        qs = parse_qs(urlparse(context.request.url).query)
        amz_cred = qs.get("X-Amz-Credential", [None])[0]
        if amz_cred:
            return amz_cred.split("/")[0]
    except Exception:
        LOG.debug("Failed to parse query string for X-Amz-Credential")
    return ""


def _get_user_id(caller) -> str | None:
    """Resolve the AWS unique user ID for a caller.

    For Users: the IAM unique ID from Moto (AIDA...).
    For AssumedRoles: ROLEID:session-name.
    For Root: account_id.
    """
    if caller.principal_type == "Root":
        return caller.account_id
    try:
        from moto.iam.models import iam_backends

        backend = iam_backends[caller.account_id]["global"]
        if caller.principal_type == "User" and caller.username:
            user = backend.users.get(caller.username)
            if user and hasattr(user, "id"):
                return user.id
        elif caller.principal_type == "AssumedRole" and caller.role_name:
            for role in backend.roles.values():
                if role.name == caller.role_name:
                    role_id = getattr(role, "id", None) or getattr(role, "role_id", None)
                    session = caller.session_name or ""
                    return f"{role_id}:{session}" if role_id else None
    except Exception:
        pass
    return None


def _build_conditions(context: RequestContext, caller) -> dict:
    """Build the condition context for policy evaluation.

    Includes all standard AWS global condition context keys.
    Caller tags are stored in caller.tags and merged in evaluator.evaluate(),
    so they are NOT merged here to avoid duplication.
    """
    now = datetime.now(timezone.utc)
    # aws:SecureTransport is always-present per AWS, "true" iff the request
    # came over TLS. Falls back to a URL-prefix sniff if is_secure isn't
    # available on the request object (e.g. a synthetic context).
    is_secure = False
    try:
        is_secure = bool(context.request.is_secure)
    except Exception:
        try:
            is_secure = str(getattr(context.request, "url", "")).lower().startswith("https://")
        except Exception:
            is_secure = False
    conditions = {
        "aws:PrincipalArn": caller.arn,
        "aws:PrincipalAccount": caller.account_id,
        "aws:PrincipalType": caller.principal_type,
        "aws:SourceIp": context.request.remote_addr or "127.0.0.1",
        "aws:CurrentTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "aws:EpochTime": str(int(now.timestamp())),
        "aws:SecureTransport": "true" if is_secure else "false",
        "aws:UserAgent": context.request.headers.get("User-Agent", ""),
        "aws:RequestedRegion": context.region or "us-east-1",
    }
    # aws:MultiFactorAuthPresent is ABSENT when the credentials weren't minted
    # via MFA, and "true" only for sessions from AssumeRole/GetSessionToken with
    # --serial-number. Per AWS: BoolIfExists conditions rely on absence to tell
    # MFA-backed from non-MFA requests. Hard-coding "false" would make every
    # long-term IAM-user call appear as "not MFA" while still being a present
    # key, which breaks BoolIfExists: {aws:MultiFactorAuthPresent: false} Deny
    # rules commonly used to gate sensitive actions.
    if caller.principal_type == "AssumedRole" and caller.access_key_id:
        try:
            from localemu.services.sts.models import sts_stores, sts_store_lock
            _store = sts_stores[caller.account_id]["us-east-1"]
            with sts_store_lock:
                _session_cfg = _store.sessions.get(caller.access_key_id)
            if _session_cfg and _session_cfg.get("mfa_authenticated"):
                conditions["aws:MultiFactorAuthPresent"] = "true"
        except Exception as mfa_err:
            LOG.debug("Failed to resolve MFA status for %s: %s",
                      caller.access_key_id[:8], mfa_err)
    # aws:username and aws:userid - only for IAM users / assumed roles
    if caller.username:
        conditions["aws:username"] = caller.username
    # aws:userid: unique ID for the caller
    # For Users: the IAM unique ID (e.g. AIDAEXAMPLE)
    # For AssumedRoles: ROLEID:session-name
    _userid = _get_user_id(caller)
    if _userid:
        conditions["aws:userid"] = _userid

    # aws:RequestTag/* and aws:TagKeys from the request params (tag-on-create)
    params = context.service_request or {}
    tags = params.get("Tags") or params.get("tags") or params.get("TagSet") or []
    if isinstance(tags, list):
        tag_keys = []
        for tag in tags:
            if isinstance(tag, dict):
                key = tag.get("Key", tag.get("key", ""))
                value = tag.get("Value", tag.get("value", ""))
                if key:
                    conditions[f"aws:RequestTag/{key}"] = value
                    tag_keys.append(key)
        if tag_keys:
            conditions["aws:TagKeys"] = tag_keys
    elif isinstance(tags, dict):
        tag_keys = list(tags.keys())
        for key, value in tags.items():
            conditions[f"aws:RequestTag/{key}"] = value
        if tag_keys:
            conditions["aws:TagKeys"] = tag_keys

    # aws:ResourceTag/<key> — pull tags for the target resource via the
    # per-service loader. Best-effort: when the service / backend shape is
    # unknown we return {} and any ResourceTag condition silently becomes
    # absent (matching AWS's behaviour for an untagged resource).
    try:
        from localemu.services.iam_enforcement.resource_tag_loader import load_resource_tags

        resource_arn = getattr(context, "_iam_resource_arn", None) or ""
        if resource_arn:
            for key, value in load_resource_tags(
                resource_arn,
                context.account_id or "000000000000",
                context.region or "us-east-1",
            ).items():
                conditions[f"aws:ResourceTag/{key}"] = value
    except Exception:
        LOG.debug("ResourceTag load failed", exc_info=True)

    return conditions


def _resolve_kms_key_id(backend, resource_arn: str) -> str | None:
    """Turn any KMS ARN / alias / bare id into the UUID key_id used by moto.

    KMS accepts four reference forms:
      - ``arn:aws:kms:region:acct:key/<uuid>``
      - ``arn:aws:kms:region:acct:alias/<alias-name>``
      - ``alias/<alias-name>``
      - bare ``<uuid>``

    ``backend.key_to_aliases`` has flipped direction between moto versions
    (some store ``{alias: {key_id}}`` and some ``{key_id: {alias, ...}}``); we
    handle both shapes rather than rely on moto's own
    ``get_key_id_from_alias`` which is broken for the inverted form.
    """
    if not resource_arn:
        return None
    tail = resource_arn.rsplit(":", 1)[-1] if resource_arn.startswith("arn:") else resource_arn

    if tail.startswith("alias/"):
        alias_name = tail
    elif tail.startswith("key/"):
        return tail.split("/", 1)[1]
    elif "/" not in tail:
        # Bare UUID (or a key_id that happens not to have a prefix)
        return tail
    else:
        # Unknown shape — last-segment fallback matches the old best-effort
        return tail.rsplit("/", 1)[-1]

    alias_map = getattr(backend, "key_to_aliases", None) or {}
    for k, v in alias_map.items():
        if k == alias_name and v:
            # {alias: {key_id, ...}} form
            return next(iter(v))
        if isinstance(v, (set, list, tuple)) and alias_name in v:
            # {key_id: {alias, ...}} form
            return k
    return None


def _get_resource_policy(service: str, resource_arn: str, account_id: str, region: str) -> dict | None:
    """Retrieve resource-based policy from Moto backend."""
    try:
        if service == "s3":
            # LocalEmu S3 is the ASF provider with its own store; moto's
            # s3_backends is not the data path, so the bucket policy lives in
            # localemu.services.s3.models.s3_stores. Buckets are cross-region
            # within an account; global_bucket_map resolves the owner account
            # for the (rare) cross-account case.
            from localemu.constants import AWS_REGION_US_EAST_1
            from localemu.services.s3.models import s3_stores

            bucket_name = resource_arn.split(":::")[-1].split("/")[0]
            store = s3_stores[account_id][AWS_REGION_US_EAST_1]
            s3_bucket = store.buckets.get(bucket_name)
            if s3_bucket is None:
                owner = store.global_bucket_map.get(bucket_name)
                if owner:
                    s3_bucket = s3_stores[owner][AWS_REGION_US_EAST_1].buckets.get(bucket_name)
            if s3_bucket is not None and getattr(s3_bucket, "policy", None):
                return json.loads(s3_bucket.policy)

        elif service == "sqs":
            # LocalEmu SQS is native (not moto): the queue Policy lives in
            # localemu.services.sqs.models.sqs_stores (queue.attributes["Policy"]).
            from localemu.services.sqs.models import sqs_stores

            store = sqs_stores[account_id][region]
            for queue in store.queues.values():
                if queue.arn == resource_arn:
                    policy = queue.attributes.get("Policy")
                    if policy:
                        return json.loads(policy)
                    break

        elif service == "sns":
            # LocalEmu SNS is native (not moto): the topic Policy lives in
            # localemu.services.sns.models.sns_stores (topic["attributes"]["Policy"]).
            from localemu.services.sns.models import sns_stores

            store = sns_stores[account_id][region]
            topic = store.topics.get(resource_arn)
            if topic:
                policy = (topic.get("attributes") or {}).get("Policy")
                if policy:
                    return json.loads(policy)

        elif service == "kms":
            from moto.kms.models import kms_backends
            backend = kms_backends[account_id][region]
            key_id = _resolve_kms_key_id(backend, resource_arn)
            if key_id:
                key = backend.keys.get(key_id)
                if key and getattr(key, "policy", None):
                    return json.loads(key.policy)

    except Exception as e:
        LOG.debug("Failed to get resource policy for %s: %s", resource_arn, e)

    return None


# Singleton handler instance (env var is read at call time, not import time)
iam_enforcement_handler = IAMEnforcementHandler()
