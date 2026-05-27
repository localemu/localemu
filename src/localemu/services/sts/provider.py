import json
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


# BUG-05: Stricter regex — must be iam service and role/ resource type
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


# Duration limits per operation (PARITY-04)
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
    """PARITY-04: Validate session duration within AWS-specified range."""
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


def _extract_jwt_issuer(token: str) -> str:
    """Pull the ``iss`` claim out of a JWT without verifying the signature.

    Used only to drive trust-policy matching — the signature trust is
    established separately by the IdP-specific endpoint. Returns ""
    on any decode failure; the caller then falls back to the wildcard
    Federated principals.
    """
    if not token or "." not in token:
        return ""
    try:
        import base64 as _b64
        parts = token.split(".")
        if len(parts) < 2:
            return ""
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = _b64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(payload)
        return str(claims.get("iss") or "")
    except Exception:
        return ""


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


def _trust_policy_allows_web_identity(role, issuer: str) -> bool:
    """True if the role's trust policy authorises this JWT-issuer to
    call ``sts:AssumeRoleWithWebIdentity``.

    Matches any of:
      * ``Principal: "*"`` — anonymous federated trust.
      * ``Principal: {Federated: "*"}`` — same effect, dict form.
      * ``Principal: {Federated: <provider>}`` where provider is a
        well-known alias (``cognito-idp.amazonaws.com`` etc.) OR a
        substring of the JWT's ``iss`` claim (catches the local
        ``http://localhost:4566/...`` issuer).
    """
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
            if f == "*":
                return True
            if f in _FEDERATED_PROVIDER_ALIASES:
                return True
            # Match by issuer substring — handles LocalEmu's
            # ``http://localhost:4566/...`` and full Cognito issuer URLs
            # like ``https://cognito-idp.us-east-1.amazonaws.com/...``.
            if issuer and (f in issuer or issuer in f):
                return True
    return False


def _evaluate_trust_policy(role, caller_arn: str, caller_account_id: str,
                           external_id: str | None = None,
                           serial_number: str | None = None,
                           service_principal: str | None = None) -> bool:
    """PARITY-02: Evaluate the role's trust policy (AssumeRolePolicyDocument).

    Returns True if the caller is allowed to assume the role.

    ``service_principal``, when provided, identifies an internal AWS service
    (e.g. ``"lambda"``) acting on its own behalf. Trust statements with a
    ``Principal: {Service: ...}`` clause are matched against this value
    (suffix ``.amazonaws.com`` form), mirroring how AWS authorizes service
    role assumption (e.g. Lambda assuming the function execution role).
    """
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

    for statement in trust_doc.get("Statement", []):
        effect = statement.get("Effect", "")
        if effect != "Allow":
            continue

        # Check principal
        principal = statement.get("Principal")
        if not principal:
            continue

        if not _trust_principal_matches(principal, caller_arn, caller_account_id,
                                        service_principal=service_principal):
            continue

        # Check conditions
        conditions = statement.get("Condition", {})

        # PARITY-02: ExternalId check
        external_id_condition = (
            conditions.get("StringEquals", {}).get("sts:ExternalId")
            or conditions.get("StringEquals", {}).get("sts:externalId")
        )
        if external_id_condition:
            if isinstance(external_id_condition, list):
                if external_id not in external_id_condition:
                    continue
            elif external_id != external_id_condition:
                continue

        # PARITY-05: MFA check
        mfa_required = conditions.get("Bool", {}).get("aws:MultiFactorAuthPresent")
        if mfa_required == "true" and not serial_number:
            continue

        return True

    return False


def _trust_principal_matches(principal, caller_arn: str, caller_account_id: str,
                             service_principal: str | None = None) -> bool:
    """Check if a trust policy principal matches the caller.

    ``service_principal`` (e.g. ``"lambda"``) lets internal AWS services
    (Lambda, Events, etc.) successfully match ``Service: lambda.amazonaws.com``
    trust statements when assuming a service role. The internal request
    parameter ``_ServicePrincipal`` is the carrier — see
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


def _store_session(target_account_id: str, access_key_id: str, config: SessionConfig):
    """BUG-02: Thread-safe session store write."""
    store = sts_stores[target_account_id]["us-east-1"]
    with sts_store_lock:
        store.sessions[access_key_id] = config


def _get_session(account_id: str, access_key_id: str) -> SessionConfig | None:
    """BUG-02: Thread-safe session store read."""
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
        # BUG-01: Check access key against root keys instead of fragile Moto ARN heuristic
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        response = call_moto(context)

        if access_key_id and access_key_id in _get_root_access_keys():
            response["Arn"] = f"arn:{context.partition}:iam::{response['Account']}:root"

        # EMU-06: Include source_identity if this is a session with one
        if access_key_id:
            session = _get_session(response.get("Account", context.account_id), access_key_id)
            if session and session.get("source_identity"):
                response["SourceIdentity"] = session["source_identity"]

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
        # BUG-05: Validate ARN is iam service and role/ resource type
        if not ROLE_ARN_REGEX.match(role_arn):
            raise ValidationError(f"{role_arn} is invalid")

        if not SESSION_NAME_REGEX.match(role_session_name):
            raise ValidationError(
                f"1 validation error detected: Value '{role_session_name}' at 'roleSessionName' "
                f"failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]*"
            )

        # BUG-06 / PARITY-04: Validate duration range
        _validate_duration(
            duration_seconds, _ASSUME_ROLE_MIN_DURATION, _ASSUME_ROLE_MAX_DURATION, "AssumeRole"
        )

        target_account_id = extract_account_id_from_arn(role_arn) or context.account_id
        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)

        # PARITY-02 / PARITY-06: Trust policy evaluation
        role = _resolve_role(target_account_id, role_arn)
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
                                          service_principal=caller_service_principal):
                raise CommonServiceException(
                    code="AccessDenied",
                    message=(
                        f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on "
                        f"resource: {role_arn}"
                    ),
                    status_code=403,
                )

        # BUG-02: Thread-safe session read
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

        # BUG-02: Thread-safe session store write
        new_access_key_id = response["Credentials"]["AccessKeyId"]
        _store_session(target_account_id, new_access_key_id, SessionConfig(
            tags=transformed_tags,
            transitive_tags=[key.lower() for key in transitive_tag_keys],
            iam_context={},
            source_identity=resolved_source_identity,
            expiration=datetime.fromtimestamp(expiration, tz=timezone.utc),
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
        """PARITY-01: Custom AssumeRoleWithWebIdentity with session tag storage."""
        # BUG-05: Validate role ARN
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

        # PARITY-04: Duration validation
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
        # the trust policy was non-empty — so a role with
        # ``Principal: {AWS: alice}`` accepted ANY web-identity token.
        role = _resolve_role(target_account_id, role_arn)
        if role:
            issuer = _extract_jwt_issuer(web_identity_token)
            if not _trust_policy_allows_web_identity(role, issuer):
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
        """PARITY-01: Custom GetSessionToken with duration validation and expiration tracking."""
        # PARITY-04: Duration validation
        _validate_duration(
            duration_seconds, _SESSION_TOKEN_MIN_DURATION, _SESSION_TOKEN_MAX_DURATION,
            "GetSessionToken"
        )

        # PARITY-05: MFA validation — if serial_number provided, token_code must also be provided
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
            session_policies=existing_session.get("session_policies", []) if existing_session else [],
            mfa_authenticated=bool(serial_number),
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
        """PARITY-01 / PARITY-03: Custom GetFederationToken with session tag storage."""
        # PARITY-04: Duration validation
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
            session_policies=session_policies,
            # GetFederationToken does not accept MFA and produces no MFA context.
            mfa_authenticated=False,
        ))

        return response

    def decode_authorization_message(
        self, context: RequestContext, encoded_message: encodedMessageType, **kwargs
    ) -> DecodeAuthorizationMessageResponse:
        """PARITY-08: Return a more useful decoded message instead of Moto stub."""
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
