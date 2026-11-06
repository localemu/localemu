"""Cognito Identity pools: role attachment and role credentials.

Moto's backend creates pools and identities but has no role attachment and returns
fixed fake credentials. This provider keeps Moto for pool and identity management and
implements the part that matters for security: ``SetIdentityPoolRoles``,
``GetIdentityPoolRoles`` and ``GetCredentialsForIdentity``, which hands out the
credentials of the pool's IAM role.

The role is chosen the way AWS chooses it: unauthenticated callers get the
``unauthenticated`` role (only if the pool allows them), callers with a login get the
``authenticated`` role unless a role mapping (token claim or rules) picks another one.
The role's trust policy must trust ``cognito-identity.amazonaws.com`` for
``sts:AssumeRoleWithWebIdentity`` and its conditions on ``cognito-identity.amazonaws.com:aud``
and ``:amr`` are evaluated, so a role that is not meant for the pool is refused.
Logins issued by LocalEmu's own user pools are verified cryptographically.
"""

import logging
from datetime import datetime, timezone

from localemu.aws.api import CommonServiceException, RequestContext, ServiceRequest
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service

LOG = logging.getLogger(__name__)

_FEDERATED = "cognito-identity.amazonaws.com"
_CREDENTIAL_LIFETIME_SECONDS = 3600


def _error(code: str, message: str, status: int = 400) -> CommonServiceException:
    return CommonServiceException(code=code, message=message, status_code=status)


def _required(request: ServiceRequest, field: str) -> str:
    """Fetch a required request field, or raise the AWS-shaped error real
    Cognito Identity returns for a missing one, instead of letting a bare
    dict-indexing ``KeyError`` escape uncaught (``Skeleton.invoke`` only
    catches ``ServiceException``/``NotImplementedError``, so an uncaught
    ``KeyError`` surfaces as a raw InternalFailure, not a real AWS error)."""
    value = request.get(field)
    if not value:
        raise _error("InvalidParameterException", f"{field} is required.")
    return value


def _backend(context: RequestContext, pool_or_identity_id: str | None = None):
    from moto.cognitoidentity.models import cognitoidentity_backends

    region = (pool_or_identity_id or context.region).split(":")[0]
    try:
        return cognitoidentity_backends[context.account_id][region]
    except KeyError:
        # A well-formed-but-unknown IdentityId/IdentityPoolId (e.g. a real
        # region with a made-up UUID) is handled by the ResourceNotFound
        # checks further down each handler. This is the OTHER case: an ID
        # with no valid "<region>:..." prefix at all (missing colon, or a
        # region string moto doesn't recognize) - not a crash, a bad request.
        raise _error(
            "InvalidParameterException",
            f"'{pool_or_identity_id}' is not a valid Cognito Identity Pool/Identity ID.",
        ) from None


def _state(backend) -> dict:
    """Role attachments and the pool each identity belongs to, kept on the Moto backend object so
    they follow its state (reset, snapshot)."""
    if not hasattr(backend, "localemu_state"):
        backend.localemu_state = {"roles": {}, "identities": {}}
    return backend.localemu_state


def _pool(backend, pool_id: str):
    pool = backend.identity_pools.get(pool_id)
    if pool is None:
        raise _error("ResourceNotFoundException", f"IdentityPool '{pool_id}' not found.")
    return pool


def _handle_get_id(context: RequestContext, request: ServiceRequest):
    pool_id = _required(request, "IdentityPoolId")
    response = call_moto(context)
    backend = _backend(context, pool_id)
    _state(backend)["identities"][response["IdentityId"]] = {
        "pool": pool_id,
        "logins": sorted((request.get("Logins") or {}).keys()),
    }
    return response


def _handle_set_roles(context: RequestContext, request: ServiceRequest):
    pool_id = _required(request, "IdentityPoolId")
    backend = _backend(context, pool_id)
    _pool(backend, pool_id)
    roles = request.get("Roles") or {}
    if not roles:
        raise _error("InvalidParameterException", "Roles is required.")
    _state(backend)["roles"][pool_id] = {
        "Roles": dict(roles),
        "RoleMappings": dict(request.get("RoleMappings") or {}),
    }
    return {}


def _handle_get_roles(context: RequestContext, request: ServiceRequest):
    pool_id = _required(request, "IdentityPoolId")
    backend = _backend(context, pool_id)
    _pool(backend, pool_id)
    attached = _state(backend)["roles"].get(pool_id)
    if not attached:
        raise _error("ResourceNotFoundException", f"IdentityPool '{pool_id}' has no roles.")
    return {
        "IdentityPoolId": pool_id,
        "Roles": attached["Roles"],
        "RoleMappings": attached["RoleMappings"],
    }


def _verify_logins(pool, logins: dict) -> list[dict]:
    """Return the claims of every login after checking it belongs to the pool."""
    from localemu.services.cognito_idp.verify import TokenVerificationError, verify_cognito_token

    allowed = {p.get("ProviderName") for p in pool.cognito_identity_providers or []}
    claims_list = []
    for provider, token in logins.items():
        if provider.startswith("cognito-idp."):
            if provider not in allowed:
                raise _error("NotAuthorizedException", "Invalid login token. Not a valid provider for this pool.", 400)
            pool_id = provider.split("/", 1)[1]
            try:
                claims_list.append(
                    {"_provider": provider, **verify_cognito_token(token, allowed_pool_ids=[pool_id])}
                )
            except TokenVerificationError as exc:
                raise _error("NotAuthorizedException", f"Invalid login token. {exc}", 400) from exc
        else:
            known = set((pool.supported_login_providers or {}).keys()) | set(pool.open_id_connect_provider_arns or [])
            if provider not in known and not any(provider in arn for arn in known):
                raise _error("NotAuthorizedException", "Invalid login token. Not a valid provider for this pool.", 400)
            # External identity providers cannot be verified locally; the login is taken as given.
            claims_list.append({"_provider": provider})
    return claims_list


def _rule_matches(rule: dict, claims: dict) -> bool:
    value = claims.get(rule.get("Claim"))
    if value is None:
        return False
    if isinstance(value, list):
        value = ",".join(str(v) for v in value)
    value, expected = str(value), rule.get("Value", "")
    kind = rule.get("MatchType")
    return {
        "Equals": value == expected,
        "NotEqual": value != expected,
        "Contains": expected in value,
        "StartsWith": value.startswith(expected),
    }.get(kind, False)


def _role_from_mapping(attached: dict, claims_list: list[dict], custom_role_arn: str | None) -> str | None:
    """The role a role mapping selects for these logins, or None to fall back to the authenticated role."""
    for claims in claims_list:
        # A user pool mapping is keyed "<provider>:<app client id>", the client being the token's audience.
        mapping = attached["RoleMappings"].get(f"{claims['_provider']}:{claims.get('aud')}") or attached[
            "RoleMappings"
        ].get(claims["_provider"])
        if not mapping:
            continue
        chosen = None
        if mapping.get("Type") == "Token":
            preferred = claims.get("cognito:preferred_role")
            roles = claims.get("cognito:roles") or []
            if custom_role_arn:
                chosen = custom_role_arn if custom_role_arn in roles or custom_role_arn == preferred else None
            else:
                chosen = preferred or (roles[0] if len(roles) == 1 else None)
        elif mapping.get("Type") == "Rules":
            for rule in (mapping.get("RulesConfiguration") or {}).get("Rules", []):
                if _rule_matches(rule, claims):
                    chosen = rule.get("RoleARN")
                    break
        if chosen:
            return chosen
        if mapping.get("AmbiguousRoleResolution") == "Deny":
            raise _error("NotAuthorizedException", "Role mapping did not select a role and resolution is Deny.", 403)
    return None


def _trust_allows(role, pool_id: str, amr: str) -> bool:
    import json

    from localemu.services.iam_enforcement.condition_evaluator import matches_conditions

    doc = role.assume_role_policy_document
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            # Malformed trust-policy JSON fails safe: treated as "this role
            # does not trust the pool", which the caller turns into the same
            # InvalidIdentityPoolConfigurationException a real trust-policy
            # mismatch produces - not an uncaught JSONDecodeError.
            LOG.warning("Role %s has a malformed assume-role policy document", getattr(role, "name", "?"))
            return False
    statements = doc.get("Statement") or []
    statements = [statements] if isinstance(statements, dict) else statements
    context = {f"{_FEDERATED}:aud": pool_id, f"{_FEDERATED}:amr": [amr]}
    for st in statements:
        if (st.get("Effect") or "").lower() != "allow":
            continue
        actions = st.get("Action") or []
        actions = [actions] if isinstance(actions, str) else actions
        if not any(a in ("sts:AssumeRoleWithWebIdentity", "sts:*", "*") for a in actions):
            continue
        principal = st.get("Principal")
        federated = principal.get("Federated") if isinstance(principal, dict) else None
        federated = [federated] if isinstance(federated, str) else (federated or [])
        if principal != "*" and _FEDERATED not in federated and "*" not in federated:
            continue
        if matches_conditions(st, context):
            return True
    return False


def _handle_get_credentials(context: RequestContext, request: ServiceRequest):
    from moto.iam.models import iam_backends
    from moto.sts.models import sts_backends

    from localemu.services.sts.models import SessionConfig
    from localemu.services.sts.provider import _store_session

    identity_id = _required(request, "IdentityId")
    backend = _backend(context, identity_id)
    identity = _state(backend)["identities"].get(identity_id)
    if not identity:
        raise _error("ResourceNotFoundException", f"Identity '{identity_id}' not found.")
    pool_id = identity["pool"]
    pool = _pool(backend, pool_id)
    attached = _state(backend)["roles"].get(pool_id)
    logins = request.get("Logins") or {}

    claims_list = _verify_logins(pool, logins) if logins else []
    if not logins and not pool.allow_unauthenticated_identities:
        raise _error("NotAuthorizedException", "Unauthenticated access is not supported for this identity pool.")
    if not attached:
        raise _error(
            "InvalidIdentityPoolConfigurationException",
            "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
        )

    amr = "authenticated" if logins else "unauthenticated"
    role_arn = _role_from_mapping(attached, claims_list, request.get("CustomRoleArn")) if logins else None
    role_arn = role_arn or attached["Roles"].get(amr)
    if not role_arn:
        raise _error(
            "InvalidIdentityPoolConfigurationException",
            "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
        )

    role_name = role_arn.split("/")[-1]
    role = next((r for r in iam_backends[context.account_id]["global"].roles.values() if r.name == role_name), None)
    if role is None or not _trust_allows(role, pool_id, amr):
        raise _error(
            "InvalidIdentityPoolConfigurationException",
            "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
        )

    assumed = sts_backends[context.account_id]["global"].assume_role(
        region_name=context.region,
        role_session_name="CognitoIdentityCredentials",
        role_arn=role_arn,
        policy=None,
        duration=_CREDENTIAL_LIFETIME_SECONDS,
        external_id=None,
    )
    now = datetime.now(timezone.utc)
    expiration = datetime.fromtimestamp(now.timestamp() + _CREDENTIAL_LIFETIME_SECONDS, tz=timezone.utc)
    _store_session(
        context.account_id,
        assumed.access_key_id,
        SessionConfig(
            tags={},
            transitive_tags=[],
            # Known limitation: aws:FederatedProvider and
            # cognito-identity.amazonaws.com:aud/:amr are NOT propagated into
            # downstream IAM condition evaluation (enforcer.py::_build_conditions)
            # for this session - a role policy that conditions on these keys
            # will never match. This fails safe (denies access real AWS would
            # grant), not open, and is a systemic gap shared with the
            # sts:AssumeRoleWithWebIdentity path, not unique to this feature.
            iam_context={},
            source_identity="",
            expiration=expiration,
            issued_at=now,
            session_policies=[],
            mfa_authenticated=False,
        ),
    )
    return {
        "IdentityId": identity_id,
        "Credentials": {
            "AccessKeyId": assumed.access_key_id,
            "SecretKey": assumed.secret_access_key,
            "SessionToken": assumed.session_token,
            "Expiration": expiration,
        },
    }


_INTERCEPTED_OPS = {
    "GetId": _handle_get_id,
    "SetIdentityPoolRoles": _handle_set_roles,
    "GetIdentityPoolRoles": _handle_get_roles,
    "GetCredentialsForIdentity": _handle_get_credentials,
}


def CognitoIdentityDispatcher(service_model) -> DispatchTable:
    return {op: _INTERCEPTED_OPS.get(op, _proxy_moto) for op in service_model.operation_names}


class CognitoIdentityState:
    service = "cognito-identity"

    def accept_state_visitor(self, visitor):
        from localemu.state.inspect import ReflectionStateLocator

        ReflectionStateLocator(service=self.service).accept_state_visitor(visitor)


def create_cognito_identity_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("cognito-identity")
    service = Service(name="cognito-identity", skeleton=Skeleton(service_model, CognitoIdentityDispatcher(service_model)))
    service._provider = CognitoIdentityState()
    return service
