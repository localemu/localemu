import json
import os
import logging
import re
from datetime import datetime, timezone

from localemu.aws.api import CommonServiceException, RequestContext, ServiceException
from localemu.aws.api.sts import (
    AssumeRoleResponse,
    AssumeRoleWithWebIdentityResponse,
    DecodeAuthorizationMessageResponse,
    GetCallerIdentityResponse,
    GetFederationTokenResponse,
    GetSessionTokenResponse,
    ProvidedContextsListType,
    StsApi,
    accessKeyIdType,
    arnType,
    clientTokenType,
    durationSecondsType,
    encodedMessageType,
    externalIdType,
    policyDescriptorListType,
    roleDurationSecondsType,
    roleSessionNameType,
    serialNumberType,
    sessionPolicyDocumentType,
    sourceIdentityType,
    tagKeyListType,
    tagListType,
    tokenCodeType,
    unrestrictedSessionPolicyDocumentType,
    urlType,
    userNameType,
    GetAccessKeyInfoResponse,
)
from localemu.aws.accounts import get_account_id_from_access_key_id
from localemu.services.iam.iam_patches import apply_iam_patches
from localemu.services.moto import call_moto
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.sts.models import SessionConfig, sts_stores, sts_store_lock
from localemu.state import StateVisitor
from localemu.utils.aws.arns import extract_account_id_from_arn
from localemu.utils.aws.request_context import extract_access_key_id_from_auth_header

LOG = logging.getLogger(__name__)


class InvalidParameterValueError(ServiceException):
    code = "InvalidParameterValue"
    status_code = 400
    sender_fault = True


# Stricter regex - must be iam service and role/ resource type
ROLE_ARN_REGEX = re.compile(
    r"^arn:[^:]+:iam:[^:]*:[^:]*:role/[a-zA-Z0-9+=,.@_/-]+$"
)
# Session name regex as specified in the error response from AWS
SESSION_NAME_REGEX = re.compile(r"^[\w+=,.@-]*$")


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class MalformedPolicyDocumentError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("MalformedPolicyDocument", message, 400, True)


# Duration limits per operation
_ASSUME_ROLE_MIN_DURATION = 900
_ASSUME_ROLE_MAX_DURATION = 43200
_ASSUME_ROLE_DEFAULT_DURATION = 3600

_SESSION_TOKEN_MIN_DURATION = 900
_SESSION_TOKEN_MAX_DURATION = 129600
_SESSION_TOKEN_DEFAULT_DURATION = 43200

_FEDERATION_TOKEN_MIN_DURATION = 900
_FEDERATION_TOKEN_MAX_DURATION = 129600
_FEDERATION_TOKEN_DEFAULT_DURATION = 43200

_WEB_IDENTITY_MIN_DURATION = 900
_WEB_IDENTITY_MAX_DURATION = 43200
_WEB_IDENTITY_DEFAULT_DURATION = 3600


def _validate_duration(value, min_val, max_val, operation_name):
    """Validate session duration within AWS-specified range."""
    if value is not None:
        if value < min_val or value > max_val:
            raise ValidationError(
                f"1 validation error detected: Value '{value}' at 'durationSeconds' "
                f"failed to satisfy constraint: Member must have value between "
                f"{min_val} and {max_val} for {operation_name}"
            )


def _get_root_access_keys() -> set[str]:
    """Build the set of root access keys (mirrors identity.py)."""
    import os
    env_val = os.environ.get("ROOT_ACCESS_KEYS", "").strip()
    if env_val:
        return {k.strip() for k in env_val.split(",") if k.strip()}
    return {"AKIAIOSFODNN7EXAMPLE", "000000000000"}


def _decode_jwt_claims_unverified(token: str) -> dict:
    """Decode every claim of a JWT without verifying its signature.

    Used only to drive trust-policy Condition matching when no registered
    OIDC provider could verify the token (no ``iss`` claim, or an issuer
    nobody registered) - the structural-match fallback
    ``_trust_policy_allows_web_identity`` already documents. A trust
    policy's wildcard ``sub``/``aud`` condition is only a real control if
    it's actually evaluated against *something*; skipping evaluation just
    because nothing verified the token's signature would make a wildcard
    condition and a tightly-scoped one behave identically here, which is
    the opposite of what this condition exists to test. Returns ``{}`` on
    any decode failure.
    """
    if not token or "." not in token:
        return {}
    try:
        import base64 as _b64
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = _b64.urlsafe_b64decode(payload_b64 + padding)
        decoded = json.loads(payload)
        return decoded if isinstance(decoded, dict) else {}
    except Exception:
        return {}


def _extract_jwt_issuer(token: str) -> str:
    """Pull the ``iss`` claim out of a JWT without verifying the signature.

    Used only to drive trust-policy matching - the signature trust is
    established separately by the IdP-specific endpoint. Returns ""
    on any decode failure; the caller then falls back to the wildcard
    Federated principals.
    """
    return str(_decode_jwt_claims_unverified(token).get("iss") or "")


# Well-known federated provider strings AWS recognises in
# ``Principal: {Federated: …}``. Cognito user-pool tokens (LocalEmu's
# OIDC issuer = ``http://localhost:4566/<region>_<pool-id>``) match
# ``cognito-idp.amazonaws.com`` per AWS's standard mapping. Cognito
# Identity (federated-identity service) maps to
# ``cognito-identity.amazonaws.com``.
_FEDERATED_PROVIDER_ALIASES = {
    "cognito-idp.amazonaws.com",
    "cognito-identity.amazonaws.com",
    "accounts.google.com",
    "graph.facebook.com",
    "api.twitter.com",
    "www.amazon.com",
}


def _find_registered_oidc_provider(account_id: str, issuer: str):
    """Return the IAM OIDC provider registered for this issuer, or None.

    A provider only counts as "registered" if its URL matches the token's
    ``iss`` claim - an issuer nobody registered has nothing to verify
    against, so callers fall back to the existing structural check (this
    preserves LocalEmu's own Cognito-via-WebIdentity flow, which never goes
    through ``iam:CreateOpenIDConnectProvider`` at all).
    """
    if not issuer:
        return None
    issuer_host = issuer.split("://", 1)[-1].rstrip("/")
    try:
        from moto.iam.models import iam_backends

        backend = iam_backends[account_id]["global"]
        for provider in backend.open_id_providers.values():
            if provider.url.rstrip("/") == issuer_host:
                return provider
    except Exception:
        LOG.debug("OIDC provider lookup failed for issuer %s", issuer, exc_info=True)
    return None


def _trust_policy_allows_web_identity(
    role, issuer: str, claims: dict | None = None, provider_arn: str | None = None,
) -> bool:
    """True if the role's trust policy authorises this JWT-issuer to
    call ``sts:AssumeRoleWithWebIdentity``.

    Matches any of:
      * ``Principal: "*"`` - anonymous federated trust.
      * ``Principal: {Federated: "*"}`` - same effect, dict form.
      * ``Principal: {Federated: <provider_arn>}`` - the ARN of a
        registered ``iam:CreateOpenIDConnectProvider`` provider, exactly
        matching the resolved provider's own ARN. This is what AWS
        actually documents for a real OIDC provider's trust policy; a
        real IAM-registered provider's trust policy names the ARN
        (``arn:aws:iam::<acct>:oidc-provider/<url>``), never the bare
        issuer URL, so comparing it against ``issuer`` (which is the
        ``https://<url>`` form) by substring could never match either
        direction - the ARN has no "https://" and the URL has no
        "arn:aws:iam::...:oidc-provider/".
      * ``Principal: {Federated: <provider>}`` where provider is a
        well-known alias (``cognito-idp.amazonaws.com`` etc.) OR a
        substring of the JWT's ``iss`` claim (catches the local
        ``http://localhost:4566/...`` issuer, and providers referenced
        by bare URL instead of ARN).
    """
    from localemu.services.iam_enforcement.condition_evaluator import matches_conditions

    trust_doc_str = getattr(role, "assume_role_policy_document", None)
    if not trust_doc_str:
        return False
    try:
        trust_doc = (
            json.loads(trust_doc_str) if isinstance(trust_doc_str, str)
            else trust_doc_str
        )
    except Exception:
        return False
    statements = trust_doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if not isinstance(st, dict):
            continue
        if (st.get("Effect") or "").lower() != "allow":
            continue
        action = st.get("Action") or []
        if isinstance(action, str):
            action = [action]
        if not any(
            a in ("sts:AssumeRoleWithWebIdentity", "sts:*", "*") for a in action
        ):
            continue
        principal = st.get("Principal")
        if principal == "*":
            return True
        if not isinstance(principal, dict):
            continue
        fed = principal.get("Federated") or []
        if isinstance(fed, str):
            fed = [fed]
        for f in fed:
            idp_host_override = None
            if f == "*":
                matched = True
            elif provider_arn and f == provider_arn:
                matched = True
            elif f in _FEDERATED_PROVIDER_ALIASES:
                matched = True
            # Match by issuer substring - handles LocalEmu's
            # ``http://localhost:4566/...`` and full Cognito issuer URLs
            # like ``https://cognito-idp.us-east-1.amazonaws.com/...``.
            elif issuer and (f in issuer or issuer in f):
                matched = True
            # The trust policy names a specific registered-provider ARN
            # directly - the normal, AWS-documented shape. Match
            # structurally even when the token's issuer couldn't be
            # resolved (no ``iss`` claim, or an unverified/forged token -
            # see _decode_jwt_claims_unverified), and derive the
            # condition-key hostname from the ARN itself rather than from
            # ``issuer`` (which is empty here) or ``f`` as a whole (which
            # would build an unmatchable ``arn:...:sub`` condition key -
            # this is the bug the comment below used to warn about without
            # actually preventing it).
            elif provider_arn is None and f.startswith("arn:") and ":oidc-provider/" in f:
                # Only when NOTHING could be resolved/verified for this
                # token at all (provider_arn is None) - if a specific,
                # different provider WAS resolved, a statement naming some
                # other provider ARN must still not match just because it
                # happens to be ARN-shaped.
                matched = True
                idp_host_override = f.split(":oidc-provider/", 1)[-1]
            else:
                continue

            # Evaluate the statement's Condition (e.g.
            # ``token.actions.githubusercontent.com:sub``/``:aud``) with the
            # same engine used for identity/resource policies - this used to
            # be skipped entirely, so e.g. a ``repo:myorg/*`` sub condition
            # never actually restricted anything.
            #
            # The condition-key prefix is always the IdP's bare hostname
            # (AWS's documented convention: ``<idp-host>:<claim>``), never
            # ``f`` - ``f`` matched here via the provider's ARN, an alias,
            # or an issuer substring, and using it directly as the prefix
            # would silently build keys like
            # ``arn:aws:iam::...:oidc-provider/host:sub`` that can never
            # match a real trust policy's ``host:sub`` condition -
            # ``idp_host_override`` (set above for the ARN-shaped match)
            # takes precedence over that for exactly this reason.
            #
            # ``claims is not None`` (not truthy) deliberately still runs
            # condition matching against an empty ``{}`` - a wildcard
            # ``sub: repo:*`` condition and a scoped ``sub: repo:org/*``
            # one must not behave identically just because the token had
            # no claims to check; an empty context correctly fails a
            # scoped condition while a true wildcard still passes.
            if claims is not None:
                idp_host = idp_host_override or (issuer or "").split("://", 1)[-1].rstrip("/") or f
                condition_context = {f"{idp_host}:{k}": v for k, v in claims.items()}
                if not matches_conditions(st, condition_context):
                    continue
            return True
    return False


def _build_trust_policy_conditions(
    caller_arn: str,
    caller_account_id: str,
    region: str,
    access_key_id: str | None,
    external_id: str | None,
    serial_number: str | None,
    session_tags: list | None,
    source_identity: str | None,
) -> dict:
    """Build the condition context for trust-policy evaluation.

    Mirrors ``iam_enforcement.enforcer._build_conditions`` but for the
    *trust* side of AssumeRole: the "principal" being checked is the caller
    attempting to assume the role, not the role itself.
    """
    context: dict = {}
    if external_id:
        context["sts:ExternalId"] = external_id
    # Present only when MFA was actually supplied - BoolIfExists conditions
    # rely on absence, same rationale as iam_enforcement.enforcer.
    if serial_number:
        context["aws:MultiFactorAuthPresent"] = "true"
    if source_identity:
        context["sts:SourceIdentity"] = source_identity

    # aws:PrincipalTag/<key> - the CALLER's own existing tags (the entity
    # trying to assume the role), e.g. an IAM user tagged Department=Eng.
    if access_key_id:
        try:
            from localemu.services.iam_enforcement.identity import resolve_caller

            caller = resolve_caller(access_key_id, caller_account_id, region)
            if caller and caller.tags:
                context.update(caller.tags)
        except Exception:
            LOG.debug("Failed to resolve caller tags for trust policy evaluation", exc_info=True)

    # aws:RequestTag/<key> and aws:TagKeys - the session tags being
    # requested BY this AssumeRole call (the ``Tags`` parameter), not the
    # role's own tags.
    if session_tags:
        tag_keys = []
        for tag in session_tags:
            key = (tag or {}).get("Key")
            value = (tag or {}).get("Value", "")
            if key:
                context[f"aws:RequestTag/{key}"] = value
                tag_keys.append(key)
        if tag_keys:
            context["aws:TagKeys"] = tag_keys

    return context


def _evaluate_trust_policy(role, caller_arn: str, caller_account_id: str,
                           external_id: str | None = None,
                           serial_number: str | None = None,
                           service_principal: str | None = None,
                           region: str = "us-east-1",
                           access_key_id: str | None = None,
                           session_tags: list | None = None,
                           source_identity: str | None = None) -> bool:
    """Evaluate the role's trust policy (AssumeRolePolicyDocument).

    Returns True if the caller is allowed to assume the role.

    ``service_principal``, when provided, identifies an internal AWS service
    (e.g. ``"lambda"``) acting on its own behalf. Trust statements with a
    ``Principal: {Service: ...}`` clause are matched against this value
    (suffix ``.amazonaws.com`` form), mirroring how AWS authorizes service
    role assumption (e.g. Lambda assuming the function execution role).

    Trust-policy ``Condition`` blocks are evaluated with the same IAM
    condition engine used for identity/resource policies (see
    ``iam_enforcement.condition_evaluator``), covering any operator -
    ``StringEquals``/``StringLike``/``Bool``/etc - not just the
    ``sts:ExternalId``/``aws:MultiFactorAuthPresent`` special cases this
    function used to hand-check. Context keys currently NOT populated here
    (not yet plumbed through the call sites that would need to supply them):
    ``aws:SourceAccount``/``aws:SourceArn`` (only meaningful for a handful of
    service-principal assumptions that pass a source resource) and
    ``aws:PrincipalOrgID`` (would duplicate the Organizations lookup that
    already lives in ``enforcer.py``).
    """
    from localemu.services.iam_enforcement.condition_evaluator import matches_conditions

    trust_conditions = _build_trust_policy_conditions(
        caller_arn, caller_account_id, region, access_key_id,
        external_id, serial_number, session_tags, source_identity,
    )
    trust_doc_str = getattr(role, "assume_role_policy_document", None)
    if not trust_doc_str:
        # No trust policy = deny
        return False

    try:
        if isinstance(trust_doc_str, str):
            trust_doc = json.loads(trust_doc_str)
        else:
            trust_doc = trust_doc_str
    except (json.JSONDecodeError, TypeError):
        LOG.debug("Failed to parse trust policy for role %s", getattr(role, "name", "unknown"))
        return False

    # AWS IAM policy grammar: ``Statement`` may be a single statement object
    # OR a list of statement objects. ``for statement in trust_doc["Statement"]``
    # on the single-dict form would iterate over the dict's *keys* (the strings
    # ``"Effect"``, ``"Principal"`` ...) and ``.get`` would fail on each.
    # Normalise before iterating.
    statements = trust_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        LOG.debug(
            "Trust policy for role %s has malformed Statement (type=%s); denying",
            getattr(role, "name", "unknown"),
            type(statements).__name__,
        )
        return False

    for statement in statements:
        if not isinstance(statement, dict):
            LOG.debug(
                "Trust policy for role %s contains non-dict statement; denying",
                getattr(role, "name", "unknown"),
            )
            return False
        effect = statement.get("Effect", "")
        if (effect or "").lower() != "allow":
            continue

        # Check principal
        principal = statement.get("Principal")
        if not principal:
            continue

        if not _trust_principal_matches(principal, caller_arn, caller_account_id,
                                        service_principal=service_principal):
            continue

        if not matches_conditions(statement, trust_conditions):
            continue

        return True

    return False


def _trust_principal_matches(principal, caller_arn: str, caller_account_id: str,
                             service_principal: str | None = None) -> bool:
    """Check if a trust policy principal matches the caller.

    ``service_principal`` (e.g. ``"lambda"``) lets internal AWS services
    (Lambda, Events, etc.) successfully match ``Service: lambda.amazonaws.com``
    trust statements when assuming a service role. The internal request
    parameter ``_ServicePrincipal`` is the carrier - see
    :mod:`localemu.aws.connect`.
    """
    if principal == "*":
        return True

    if isinstance(principal, str):
        return _trust_value_matches(principal, caller_arn, caller_account_id)

    if isinstance(principal, dict):
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for p in aws_principals:
            if _trust_value_matches(p, caller_arn, caller_account_id):
                return True

        service_principals = principal.get("Service", [])
        if isinstance(service_principals, str):
            service_principals = [service_principals]
        if service_principal:
            sp_lower = service_principal.lower()
            for sp in service_principals:
                if not isinstance(sp, str):
                    continue
                sp_norm = sp.lower()
                # Accept both "lambda" and "lambda.amazonaws.com" (and any
                # AWS partition variant such as "lambda.amazonaws.com.cn").
                if sp_norm == sp_lower:
                    return True
                # "<svc>.amazonaws.com" or "<svc>.amazonaws.com.<suffix>"
                head = sp_norm.split(".", 1)[0]
                if head == sp_lower:
                    return True

        federated = principal.get("Federated", [])
        if isinstance(federated, str):
            federated = [federated]
        for fp in federated:
            if fp == "*":
                return True

    return False


def _trust_value_matches(value: str, caller_arn: str, caller_account_id: str) -> bool:
    """Match a single trust policy principal value."""
    if value == "*":
        return True
    if value == caller_account_id:
        return True
    if value == caller_arn:
        return True
    # Root principal matches all in the account
    if value.endswith(":root"):
        parts = value.split(":")
        if len(parts) >= 5 and parts[4] == caller_account_id:
            return True
    return False


def _resolve_role(account_id: str, role_arn: str):
    """Look up a Moto IAM role object by ARN."""
    try:
        from moto.iam.models import iam_backends
        backend = iam_backends[account_id]["global"]
        role_name = role_arn.split("/")[-1] if "/" in role_arn else ""
        for r in backend.roles.values():
            if r.name == role_name:
                return r
    except Exception as e:
        LOG.debug("Failed to resolve role %s: %s", role_arn, e)
    return None


def _resolve_caller_arn(access_key_id: str, account_id: str) -> str:
    """Resolve caller ARN from access key for trust policy evaluation."""
    if access_key_id in _get_root_access_keys():
        return f"arn:aws:iam::{account_id}:root"
    try:
        from moto.iam.models import iam_backends
        backend = iam_backends[account_id]["global"]
        for user in backend.users.values():
            for key in user.access_keys:
                if key.access_key_id == access_key_id and key.status == "Active":
                    return user.arn
        # Check assumed roles
        from moto.sts.models import sts_backends
        sts_backend = sts_backends[account_id]["global"]
        for assumed_role in getattr(sts_backend, "assumed_roles", []):
            if getattr(assumed_role, "access_key_id", None) == access_key_id:
                role_arn = getattr(assumed_role, "role_arn", "")
                return role_arn
    except Exception as e:
        LOG.debug("Failed to resolve caller ARN for key %s: %s", access_key_id[:8], e)
    return f"arn:aws:iam::{account_id}:root"


def _caller_session_fields(
    context, caller_access_key_id: str | None, kind: str, federated_name: str | None = None,
) -> dict:
    """Session fields recording which IAM user a GetSessionToken /
    GetFederationToken credential belongs to, so IAM enforcement can resolve
    it. Empty when the caller is not the root account or an IAM user."""
    if not caller_access_key_id:
        return {}
    try:
        from localemu.services.iam_enforcement.identity import resolve_caller

        caller = resolve_caller(caller_access_key_id, context.account_id, context.region)
    except Exception:
        return {}
    if caller is not None and caller.principal_type == "Root" and kind == "session-token":
        # The root account's session credentials act as root.
        return {"session_kind": "root"}
    if caller is None or caller.principal_type != "User" or not caller.username:
        return {}
    fields: dict = {"session_kind": kind, "base_username": caller.username}
    if federated_name:
        fields["federated_name"] = federated_name
    return fields


def _store_session(target_account_id: str, access_key_id: str, config: SessionConfig):
    """Thread-safe session store write."""
    store = sts_stores[target_account_id]["us-east-1"]
    with sts_store_lock:
        store.sessions[access_key_id] = config


def _get_session(account_id: str, access_key_id: str) -> SessionConfig | None:
    """Thread-safe session store read."""
    store = sts_stores[account_id]["us-east-1"]
    with sts_store_lock:
        return store.sessions.get(access_key_id)


class StsProvider(StsApi, ServiceLifecycleHook):
    def __init__(self):
        apply_iam_patches()

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.sts.models import sts_backends

        visitor.visit(sts_backends)
        visitor.visit(sts_stores)

    def get_caller_identity(self, context: RequestContext, **kwargs) -> GetCallerIdentityResponse:
        # Check access key against root keys instead of a fragile Moto ARN heuristic
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        response = call_moto(context)

        if access_key_id and access_key_id in _get_root_access_keys():
            response["Arn"] = f"arn:{context.partition}:iam::{response['Account']}:root"

        # EMU-06: Include source_identity if this is a session with one
        if access_key_id:
            session = _get_session(response.get("Account", context.account_id), access_key_id)
            if session and session.get("source_identity"):
                response["SourceIdentity"] = session["source_identity"]
            if session and session.get("session_kind"):
                # GetSessionToken / GetFederationToken credentials: report the
                # IAM user (or federated user) they belong to, not moto's stub.
                from localemu.services.iam_enforcement.identity import resolve_caller

                identity = resolve_caller(access_key_id, context.account_id, context.region)
                if identity is not None:
                    response["Arn"] = identity.arn
                    if identity.principal_type == "FederatedUser":
                        response["UserId"] = f"{identity.account_id}:{session.get('federated_name', '')}"

        return response

    def assume_role(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        policy_arns: policyDescriptorListType = None,
        policy: unrestrictedSessionPolicyDocumentType = None,
        duration_seconds: roleDurationSecondsType = None,
        tags: tagListType = None,
        transitive_tag_keys: tagKeyListType = None,
        external_id: externalIdType = None,
        serial_number: serialNumberType = None,
        token_code: tokenCodeType = None,
        source_identity: sourceIdentityType = None,
        provided_contexts: ProvidedContextsListType = None,
        **kwargs,
    ) -> AssumeRoleResponse:
        # Validate ARN is iam service and role/ resource type
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        # Validate duration range
        _validate_duration(
            duration_seconds, _ASSUME_ROLE_MIN_DURATION, _ASSUME_ROLE_MAX_DURATION, "AssumeRole"
        )

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)

        # / Trust policy evaluation
        role = _resolve_role(target_account_id, role_arn)
        if not role and os.environ.get("IAM_ENFORCEMENT", "").strip().lower() in ("1", "soft"):
            internal_params = getattr(context, "internal_request_params", None) or {}
            if not internal_params.get("service_principal"):
                # AWS answers AssumeRole on a role that does not exist exactly like a refusal by the
                # trust policy, so callers cannot tell the two cases apart.
                caller_arn = _resolve_caller_arn(access_key_id, context.account_id)
                raise CommonServiceException(
                    code="AccessDenied",
                    message=(
                        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on "
                        f"resource: {role_arn}"
                    ),
                    status_code=403,
                )
        if role:
            caller_arn = _resolve_caller_arn(access_key_id, context.account_id)
            # Internal services (Lambda, Events, ...) propagate
            # ``service_principal`` via the ``_ServicePrincipal`` internal
            # request param so trust policies of the form
            # ``Principal: {Service: lambda.amazonaws.com}`` resolve to
            # Allow rather than the default Deny.
            internal_params = getattr(context, "internal_request_params", None) or {}
            caller_service_principal = internal_params.get("service_principal")
            if not _evaluate_trust_policy(role, caller_arn, context.account_id,
                                          external_id=external_id,
                                          serial_number=serial_number,
                                          service_principal=caller_service_principal,
                                          region=context.region or "us-east-1",
                                          access_key_id=access_key_id,
                                          session_tags=tags,
                                          source_identity=source_identity):
                raise CommonServiceException(
                    code="AccessDenied",
                    message=(
                        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on "
                        f"resource: {role_arn}"
                    ),
                    status_code=403,
                )

        # Thread-safe session read
        existing_session_config = _get_session(target_account_id, access_key_id) if access_key_id else None

        if tags:
            tag_keys = {tag["Key"].lower() for tag in tags}
            # if the lower-cased set is smaller than the number of keys, there have to be some duplicates.
            if len(tag_keys) < len(tags):
                raise InvalidParameterValueError(
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                )

            # prevent transitive tags from being overridden
            if existing_session_config:
                if set(existing_session_config.get("transitive_tags", [])).intersection(tag_keys):
                    raise InvalidParameterValueError(
                        "One of the specified transitive tag keys can't be set because it "
                        "conflicts with a transitive tag key from the calling session."
                    )
            if transitive_tag_keys:
                transitive_tag_key_set = {key.lower() for key in transitive_tag_keys}
                if not transitive_tag_key_set <= tag_keys:
                    raise InvalidParameterValueError(
                        "The specified transitive tag key must be included in the requested tags."
                    )

        response: AssumeRoleResponse = call_moto(context)

        transitive_tag_keys = transitive_tag_keys or []
        tags = tags or []
        transformed_tags = {tag["Key"].lower(): tag for tag in tags}

        # propagate transitive tags from parent session
        if existing_session_config:
            for tag in existing_session_config.get("transitive_tags", []):
                transformed_tags[tag] = existing_session_config.get("tags", {})[tag]
            transitive_tag_keys += existing_session_config.get("transitive_tags", [])

        # EMU-06: Propagate source_identity from parent session or set from parameter
        resolved_source_identity = source_identity or ""
        if existing_session_config and existing_session_config.get("source_identity"):
            # source_identity is sticky: once set, it propagates and cannot be changed
            resolved_source_identity = existing_session_config["source_identity"]

        # EMU-04: Collect session policies for role chaining intersection
        session_policies = []
        if policy:
            try:
                session_policies.append(json.loads(policy) if isinstance(policy, str) else policy)
            except (json.JSONDecodeError, TypeError):
                raise MalformedPolicyDocumentError("The policy is not in valid JSON format.")
        # Inherit chained session policies from parent
        if existing_session_config:
            session_policies.extend(existing_session_config.get("session_policies", []))

        # Compute expiration
        effective_duration = duration_seconds or _ASSUME_ROLE_DEFAULT_DURATION
        expiration = datetime.now(timezone.utc).timestamp() + effective_duration

        # Thread-safe session store write
        new_access_key_id = response["Credentials"]["AccessKeyId"]
        _store_session(target_account_id, new_access_key_id, SessionConfig(
            tags=transformed_tags,
            transitive_tags=[key.lower() for key in transitive_tag_keys],
            iam_context={},
            source_identity=resolved_source_identity,
            expiration=datetime.fromtimestamp(expiration, tz=timezone.utc),
            issued_at=datetime.now(timezone.utc),
            session_policies=session_policies,
            mfa_authenticated=bool(serial_number),
        ))

        # EMU-06: Include source_identity in response
        if resolved_source_identity:
            response["SourceIdentity"] = resolved_source_identity

        return response

    def assume_role_with_web_identity(
        self,
        context: RequestContext,
        role_arn: arnType,
        role_session_name: roleSessionNameType,
        web_identity_token: clientTokenType,
        provider_id: urlType | None = None,
        policy_arns: policyDescriptorListType | None = None,
        policy: sessionPolicyDocumentType | None = None,
        duration_seconds: roleDurationSecondsType | None = None,
        **kwargs,
    ) -> AssumeRoleWithWebIdentityResponse:
        """Custom AssumeRoleWithWebIdentity with session tag storage."""
        # Validate role ARN
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        # EMU-08: Basic web identity token validation
        if not web_identity_token or len(web_identity_token) < 4:
            raise CommonServiceException(
                code="InvalidIdentityToken",
                message="Token must be a non-empty string",
                status_code=400,
            )

        # Duration validation
        _validate_duration(
            duration_seconds, _WEB_IDENTITY_MIN_DURATION, _WEB_IDENTITY_MAX_DURATION,
            "AssumeRoleWithWebIdentity"
        )

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id

        # Trust policy evaluation for federated AssumeRole.
        # AWS requires at least one ``Effect: Allow`` statement whose
        # ``Principal: {Federated: <provider>}`` matches the JWT issuer
        # AND whose ``Action`` contains ``sts:AssumeRoleWithWebIdentity``
        # (or a wildcard). Before this change the check only verified
        # the trust policy was non-empty - so a role with
        # ``Principal: {AWS: alice}`` accepted ANY web-identity token.
        role = _resolve_role(target_account_id, role_arn)
        if role:
            issuer = _extract_jwt_issuer(web_identity_token)
            claims = None

            # If an OIDC provider is actually registered for this issuer,
            # real AWS requires the token's signature to verify against
            # that provider's JWKS - a structural match on the issuer
            # string alone (the previous behaviour) let ANY token through,
            # forged signature and all, as long as the Principal matched.
            # An issuer nobody registered (e.g. LocalEmu's own Cognito
            # issuer) keeps the pre-existing structural-only check.
            provider = _find_registered_oidc_provider(target_account_id, issuer)
            if provider is not None:
                from localemu.services.sts.oidc_local import verify_web_identity_token

                claims = verify_web_identity_token(web_identity_token, provider)
                if claims is None:
                    raise CommonServiceException(
                        code="InvalidIdentityToken",
                        message="Signature verification failed",
                        status_code=400,
                    )
            else:
                # No issuer claim (or no provider registered for it) means
                # nothing CAN verify this token's signature - fall back to
                # decoding its claims unverified, purely to drive the trust
                # policy's own Condition matching (e.g. sub/aud). This is
                # a deliberate structural-only check, not a security
                # control: a forged/unsigned token with a resolvable
                # provider ARN named directly in the trust policy still
                # only gets through if that policy's own conditions (like
                # an overly-broad wildcard sub) allow it - exactly the
                # misconfiguration this is meant to let a lab demonstrate.
                claims = _decode_jwt_claims_unverified(web_identity_token)

            if not _trust_policy_allows_web_identity(
                role, issuer, claims=claims, provider_arn=getattr(provider, "arn", None)
            ):
                raise CommonServiceException(
                    code="AccessDenied",
                    message=f"Not authorized to perform sts:AssumeRoleWithWebIdentity on resource: {role_arn}",
                    status_code=403,
                )

        response: AssumeRoleWithWebIdentityResponse = call_moto(context)

        # Store session config
        session_policies = []
        if policy:
            try:
                session_policies.append(json.loads(policy) if isinstance(policy, str) else policy)
            except (json.JSONDecodeError, TypeError):
                raise MalformedPolicyDocumentError("The policy is not in valid JSON format.")

        effective_duration = duration_seconds or _WEB_IDENTITY_DEFAULT_DURATION
        expiration = datetime.now(timezone.utc).timestamp() + effective_duration

        new_access_key_id = response["Credentials"]["AccessKeyId"]
        _store_session(target_account_id, new_access_key_id, SessionConfig(
            tags={},
            transitive_tags=[],
            iam_context={},
            source_identity="",
            expiration=datetime.fromtimestamp(expiration, tz=timezone.utc),
            issued_at=datetime.now(timezone.utc),
            session_policies=session_policies,
            # AssumeRoleWithSAML/WebIdentity: MFA assertions live in the upstream
            # IdP, not in STS. AWS does not reflect them via aws:MultiFactorAuthPresent.
            mfa_authenticated=False,
        ))

        return response

    def get_session_token(
        self,
        context: RequestContext,
        duration_seconds: durationSecondsType | None = None,
        serial_number: serialNumberType | None = None,
        token_code: tokenCodeType | None = None,
        **kwargs,
    ) -> GetSessionTokenResponse:
        """Custom GetSessionToken with duration validation and expiration tracking."""
        # Duration validation
        _validate_duration(
            duration_seconds, _SESSION_TOKEN_MIN_DURATION, _SESSION_TOKEN_MAX_DURATION,
            "GetSessionToken"
        )

        # MFA validation - if serial_number provided, token_code must also be provided
        if serial_number and not token_code:
            raise ValidationError(
                "Also provide a value for tokenCode when providing serialNumber."
            )

        response: GetSessionTokenResponse = call_moto(context)

        # Track expiration for the returned credentials (EMU-05)
        effective_duration = duration_seconds or _SESSION_TOKEN_DEFAULT_DURATION
        expiration = datetime.now(timezone.utc).timestamp() + effective_duration

        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        new_access_key_id = response["Credentials"]["AccessKeyId"]
        source_account_id = context.account_id

        # Inherit tags from calling session if any
        existing_session = _get_session(source_account_id, access_key_id) if access_key_id else None

        _store_session(source_account_id, new_access_key_id, SessionConfig(
            tags=existing_session.get("tags", {}) if existing_session else {},
            transitive_tags=existing_session.get("transitive_tags", []) if existing_session else [],
            iam_context={},
            source_identity=existing_session.get("source_identity", "") if existing_session else "",
            expiration=datetime.fromtimestamp(expiration, tz=timezone.utc),
            issued_at=datetime.now(timezone.utc),
            session_policies=existing_session.get("session_policies", []) if existing_session else [],
            mfa_authenticated=bool(serial_number),
            **_caller_session_fields(context, access_key_id, "session-token"),
        ))

        return response

    def get_federation_token(
        self,
        context: RequestContext,
        name: userNameType,
        policy: sessionPolicyDocumentType | None = None,
        policy_arns: policyDescriptorListType | None = None,
        duration_seconds: durationSecondsType | None = None,
        tags: tagListType | None = None,
        **kwargs,
    ) -> GetFederationTokenResponse:
        """/ Custom GetFederationToken with session tag storage."""
        # Duration validation
        _validate_duration(
            duration_seconds, _FEDERATION_TOKEN_MIN_DURATION, _FEDERATION_TOKEN_MAX_DURATION,
            "GetFederationToken"
        )

        if tags:
            tag_keys = {tag["Key"].lower() for tag in tags}
            if len(tag_keys) < len(tags):
                raise InvalidParameterValueError(
                    "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                )

        response: GetFederationTokenResponse = call_moto(context)

        tags = tags or []
        transformed_tags = {tag["Key"].lower(): tag for tag in tags}

        session_policies = []
        if policy:
            try:
                session_policies.append(json.loads(policy) if isinstance(policy, str) else policy)
            except (json.JSONDecodeError, TypeError):
                raise MalformedPolicyDocumentError("The policy is not in valid JSON format.")
        if not session_policies and not policy_arns:
            # AWS: a federated user passed no policy has no permissions of its
            # own (only resource-based policies can grant it access). An empty
            # session policy makes the intersection with the user's policies empty.
            session_policies.append({"Version": "2012-10-17", "Statement": []})

        effective_duration = duration_seconds or _FEDERATION_TOKEN_DEFAULT_DURATION
        expiration = datetime.now(timezone.utc).timestamp() + effective_duration

        new_access_key_id = response["Credentials"]["AccessKeyId"]
        source_account_id = context.account_id

        _store_session(source_account_id, new_access_key_id, SessionConfig(
            tags=transformed_tags,
            transitive_tags=[],
            iam_context={},
            source_identity="",
            expiration=datetime.fromtimestamp(expiration, tz=timezone.utc),
            issued_at=datetime.now(timezone.utc),
            session_policies=session_policies,
            # GetFederationToken does not accept MFA and produces no MFA context.
            mfa_authenticated=False,
            **_caller_session_fields(
                context,
                extract_access_key_id_from_auth_header(context.request.headers),
                "federated",
                federated_name=name,
            ),
        ))

        return response

    def decode_authorization_message(
        self, context: RequestContext, encoded_message: encodedMessageType, **kwargs
    ) -> DecodeAuthorizationMessageResponse:
        """Return a more useful decoded message instead of Moto stub."""
        # In AWS, this decodes an encoded authorization failure message.
        # We return a synthetic decoded message that includes the encoded input,
        # since LocalEmu doesn't produce real encoded auth messages.
        decoded = json.dumps({
            "allowed": False,
            "explicitDeny": False,
            "matchedStatements": {"items": []},
            "failures": {"items": []},
            "context": {
                "principal": {"id": "UNKNOWN", "arn": "UNKNOWN"},
                "action": "UNKNOWN",
                "resource": "UNKNOWN",
                "conditions": {"items": []},
            },
        })
        return DecodeAuthorizationMessageResponse(DecodedMessage=decoded)

    def get_access_key_info(
        self, context: RequestContext, access_key_id: accessKeyIdType, **kwargs
    ) -> GetAccessKeyInfoResponse:
        """Return the account ID for the given access key."""
        account_id = get_account_id_from_access_key_id(access_key_id)
        return GetAccessKeyInfoResponse(Account=account_id)
