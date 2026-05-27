"""IAM caller identity resolution.

Resolves an AWS access key to a CallerIdentity by looking up Moto's IAM
backend for users, roles, and assumed role sessions.
"""

import json
import logging
import os
from dataclasses import dataclass, field

from localemu.constants import ANONYMOUS_ACCESS_KEY_ID

LOG = logging.getLogger(__name__)


def _get_root_access_keys() -> set[str]:
    """Build the set of root access keys, configurable via ROOT_ACCESS_KEYS env var.

    The env var is a comma-separated list of access key IDs.
    Default includes the AWS example key and the default account ID.
    """
    env_val = os.environ.get("ROOT_ACCESS_KEYS", "").strip()
    if env_val:
        return {k.strip() for k in env_val.split(",") if k.strip()}
    return {"AKIAIOSFODNN7EXAMPLE", "000000000000"}


@dataclass
class CallerIdentity:
    """Represents the entity making an API call."""

    principal_type: str  # "Root", "User", "AssumedRole", "FederatedUser", "Anonymous"
    account_id: str
    arn: str
    username: str | None = None
    role_name: str | None = None
    session_name: str | None = None
    access_key_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    source_identity: str | None = None  # EMU-06: propagated source identity
    # Service principals this caller is acting AS, derived from the role's
    # AssumeRolePolicyDocument. A bucket policy / KMS policy granting
    # ``Principal: {Service: lambda.amazonaws.com}`` matches a caller
    # whose role's trust policy lets ``lambda.amazonaws.com`` assume it.
    # Only populated for AssumedRole callers.
    acting_services: list[str] = field(default_factory=list)


def resolve_caller(
    access_key_id: str,
    account_id: str,
    region: str,
) -> CallerIdentity | None:
    """Resolve an access key to a caller identity via Moto's IAM backend.

    Checks the anonymous sentinel first, then IAM user access keys, then root
    credentials, then assumed-role sessions. Returns None if the key cannot be
    resolved (a genuinely unknown caller).
    """
    if not access_key_id:
        return None

    # Unauthenticated requests carry the anonymous sentinel (stamped by
    # MissingAuthHeaderInjector). They resolve to the anonymous principal:
    # the evaluator has no identity policies to consider, so access is granted
    # only by a resource policy that names Principal "*" — exactly AWS's
    # behaviour for unsigned requests.
    if access_key_id == ANONYMOUS_ACCESS_KEY_ID:
        return CallerIdentity(
            principal_type="Anonymous",
            account_id=account_id,
            arn="*",
            access_key_id=access_key_id,
        )

    # Root account keys bypass all checks
    if access_key_id in _get_root_access_keys():
        return CallerIdentity(
            principal_type="Root",
            account_id=account_id,
            arn=f"arn:aws:iam::{account_id}:root",
            access_key_id=access_key_id,
        )

    try:
        from moto.iam.models import iam_backends

        backend = iam_backends[account_id]["global"]

        # Check IAM user access keys — use Moto's access_keys index if available (O(1)),
        # fall back to linear scan (O(n*m)) for older Moto versions.
        user = None
        key_match = None
        if hasattr(backend, "access_keys") and isinstance(backend.access_keys, dict):
            key_match = backend.access_keys.get(access_key_id)
            if key_match and getattr(key_match, "status", "") == "Active":
                user_name = getattr(key_match, "user_name", "")
                user = backend.users.get(user_name)
        if not user:
            for user_name, _user in backend.users.items():
                for key in _user.access_keys:
                    if key.access_key_id == access_key_id and key.status == "Active":
                        user = _user
                        key_match = key
                        break
                if user:
                    break
        if user and key_match:
            # Alias for backward compat with code below
            user_name = getattr(user, "name", user_name)
            key = key_match
            if key.access_key_id == access_key_id and key.status == "Active":
                    tags = {}
                    user_tags = getattr(user, "tags", None) or {}
                    if isinstance(user_tags, dict):
                        for tag in user_tags.values():
                            if isinstance(tag, dict):
                                tags[f"aws:PrincipalTag/{tag.get('Key', '')}"] = tag.get("Value", "")
                    return CallerIdentity(
                        principal_type="User",
                        account_id=account_id,
                        arn=user.arn,
                        username=user_name,
                        access_key_id=access_key_id,
                        tags=tags,
                    )

        # Check assumed role temporary credentials (STS)
        # Moto stores assumed roles in sts_backend.assumed_roles (a list of
        # AssumedRole objects, each wrapping an AccessKey with role metadata).
        try:
            from moto.sts.models import sts_backends

            sts_backend = sts_backends[account_id]["global"]
            for assumed_role in getattr(sts_backend, "assumed_roles", []):
                if getattr(assumed_role, "access_key_id", None) == access_key_id:
                    role_arn = getattr(assumed_role, "role_arn", "")
                    role_name = role_arn.split("/")[-1] if "/" in role_arn else ""
                    session_name = getattr(assumed_role, "session_name", "") or getattr(assumed_role, "role_session_name", "")

                    # EMU-05: Check credential expiration
                    try:
                        from localemu.services.sts.models import sts_stores, sts_store_lock
                        from datetime import datetime, timezone
                        store = sts_stores[account_id]["us-east-1"]
                        with sts_store_lock:
                            session_cfg = store.sessions.get(access_key_id)
                        if session_cfg and session_cfg.get("expiration"):
                            exp = session_cfg["expiration"]
                            if isinstance(exp, datetime) and exp < datetime.now(timezone.utc):
                                LOG.info(
                                    "IAM: expired temporary credentials for key %s (expired %s)",
                                    access_key_id[:8], exp.isoformat(),
                                )
                                return None  # Expired credentials = unresolvable
                    except Exception as exp_err:
                        LOG.debug("Failed to check expiration for %s: %s", access_key_id[:8], exp_err)

                    # Load session tags: first from sts_stores (BUG-03 fix),
                    # then from Moto's assumed_role object, then from IAM role tags
                    tags = {}

                    # Priority 1: Tags stored by our custom STS provider (sts_stores)
                    try:
                        from localemu.services.sts.models import sts_stores as _sts_stores, sts_store_lock as _lock
                        _store = _sts_stores[account_id]["us-east-1"]
                        with _lock:
                            _session_cfg = _store.sessions.get(access_key_id)
                        if _session_cfg:
                            for _tag_key, _tag in _session_cfg.get("tags", {}).items():
                                if isinstance(_tag, dict):
                                    key = _tag.get("Key", _tag.get("key", ""))
                                    value = _tag.get("Value", _tag.get("value", ""))
                                    if key:
                                        tags[f"aws:PrincipalTag/{key}"] = value
                    except Exception as sts_store_err:
                        LOG.debug("Failed to load sts_stores tags for %s: %s", access_key_id[:8], sts_store_err)

                    # Priority 2: Tags from Moto's assumed role object (fallback)
                    if not tags:
                        for tag in getattr(assumed_role, "tags", []) or []:
                            if isinstance(tag, dict):
                                key = tag.get("Key", tag.get("key", ""))
                                value = tag.get("Value", tag.get("value", ""))
                                if key:
                                    tags[f"aws:PrincipalTag/{key}"] = value

                    # Priority 3: Tags from the underlying IAM role (lowest priority)
                    try:
                        from moto.iam.models import iam_backends as _iam_backends
                        _iam_backend = _iam_backends[account_id]["global"]
                        for r in _iam_backend.roles.values():
                            if r.name == role_name:
                                role_tags = getattr(r, "tags", None) or {}
                                if isinstance(role_tags, dict):
                                    for rt in role_tags.values():
                                        if isinstance(rt, dict):
                                            rk = rt.get("Key", "")
                                            rv = rt.get("Value", "")
                                            if rk:
                                                # Session tags override role tags
                                                tags.setdefault(f"aws:PrincipalTag/{rk}", rv)
                                break
                    except Exception as tag_err:
                        LOG.debug("Failed to load role tags for %s: %s", role_name, tag_err)

                    # EMU-06: Load source_identity
                    resolved_source_identity = None
                    try:
                        from localemu.services.sts.models import sts_stores as _si_stores, sts_store_lock as _si_lock
                        _si_store = _si_stores[account_id]["us-east-1"]
                        with _si_lock:
                            _si_cfg = _si_store.sessions.get(access_key_id)
                        if _si_cfg:
                            resolved_source_identity = _si_cfg.get("source_identity") or None
                    except Exception as si_err:
                        LOG.debug("Failed to load source_identity for %s: %s", access_key_id[:8], si_err)

                    # Pull the service principals the role's trust policy
                    # accepts. Used by resource-policy ``Principal: {Service:
                    # X}`` matching so e.g. a Lambda execution role with
                    # ``Service: lambda.amazonaws.com`` in its trust policy
                    # matches an S3 bucket policy granting Lambda.
                    acting_services = _trust_policy_services(
                        backend, role_name,
                    )

                    return CallerIdentity(
                        principal_type="AssumedRole",
                        account_id=account_id,
                        arn=f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}",
                        role_name=role_name,
                        session_name=session_name,
                        access_key_id=access_key_id,
                        tags=tags,
                        source_identity=resolved_source_identity,
                        acting_services=acting_services,
                    )
        except Exception as e:
            LOG.debug("Failed to check STS assumed roles for key %s: %s", access_key_id[:8], e)

    except Exception as e:
        LOG.debug("Failed to resolve caller identity for key %s: %s", access_key_id[:8], e)

    return None


def get_identity_policies(caller: CallerIdentity) -> list[dict]:
    """Gather all identity-based policies for a caller.

    For Users: inline policies + attached managed policies + group policies
    For Roles: inline policies + attached managed policies
    """
    try:
        from moto.iam.models import iam_backends

        backend = iam_backends[caller.account_id]["global"]
    except Exception:
        return []

    policies = []

    if caller.principal_type == "User" and caller.username:
        user = backend.users.get(caller.username)
        if user:
            # Inline policies
            for policy_doc in user.policies.values():
                policies.append(_parse_policy(policy_doc))

            # Attached managed policies (dict: arn -> policy object)
            for policy_arn, policy in (user.managed_policies or {}).items():
                doc = _get_managed_policy_doc(backend, policy_arn)
                if doc:
                    policies.append(doc)

            # Group policies (user.group_list is a list of group names in moto)
            for group_name in getattr(user, "group_list", []):
                group = backend.groups.get(group_name)
                if group:
                    for policy_doc in group.policies.values():
                        policies.append(_parse_policy(policy_doc))
                    for policy_arn in (group.managed_policies or {}):
                        doc = _get_managed_policy_doc(backend, policy_arn)
                        if doc:
                            policies.append(doc)

    elif caller.principal_type == "AssumedRole" and caller.role_name:
        # Moto indexes backend.roles by role ID, not name. Measured cost:
        # ~10 us per scan for 1000 roles (~0.2% CPU at 100 RPS), which is
        # negligible for LocalEmu's dev workloads. A name→role cache would
        # speed this 250x but requires invalidation on create/update/delete/
        # attach/detach across multiple Moto call sites; until the scan
        # shows up in a real profile, the linear approach stays.
        role = None
        for r in backend.roles.values():
            if r.name == caller.role_name:
                role = r
                break
        if role:
            for policy_doc in role.policies.values():
                policies.append(_parse_policy(policy_doc))
            for policy_arn in (role.managed_policies or {}):
                doc = _get_managed_policy_doc(backend, policy_arn)
                if doc:
                    policies.append(doc)

    return [p for p in policies if p]  # Filter out None


def get_permission_boundary(caller: CallerIdentity) -> dict | None:
    """Get the permission boundary policy for a caller (if any)."""
    try:
        from moto.iam.models import iam_backends

        backend = iam_backends[caller.account_id]["global"]

        if caller.principal_type == "User" and caller.username:
            user = backend.users.get(caller.username)
            boundary = getattr(user, "permissions_boundary", None) if user else None
            if boundary:
                return _get_managed_policy_doc(backend, boundary)

        elif caller.principal_type == "AssumedRole" and caller.role_name:
            role = None
            for r in backend.roles.values():
                if r.name == caller.role_name:
                    role = r
                    break
            boundary = getattr(role, "permissions_boundary", None) if role else None
            if boundary:
                return _get_managed_policy_doc(backend, boundary)
    except Exception as e:
        LOG.debug("Failed to get permission boundary for %s: %s", caller.arn, e)

    return None


def get_session_policies(caller: CallerIdentity) -> list[dict]:
    """Get inline session policies passed during AssumeRole (if any).

    These are the Policy parameter(s) provided in the AssumeRole call.
    They further restrict what the assumed role session can do.
    EMU-04: Also includes chained session policies from role chaining.
    """
    if caller.principal_type != "AssumedRole":
        return []

    policies = []

    # First: check sts_stores for session policies (EMU-04: includes chained policies)
    try:
        from localemu.services.sts.models import sts_stores, sts_store_lock
        store = sts_stores[caller.account_id]["us-east-1"]
        with sts_store_lock:
            session_cfg = store.sessions.get(caller.access_key_id)
        if session_cfg:
            stored_policies = session_cfg.get("session_policies", [])
            if stored_policies:
                return stored_policies
    except Exception as e:
        LOG.debug("Failed to load session policies from sts_stores: %s", e)

    # Fallback: check Moto's assumed role objects
    try:
        from moto.sts.models import sts_backends

        sts_backend = sts_backends[caller.account_id]["global"]
        for assumed_role in getattr(sts_backend, "assumed_roles", []):
            if getattr(assumed_role, "access_key_id", None) == caller.access_key_id:
                # Moto stores the inline session policy as 'policy'
                session_policy = getattr(assumed_role, "policy", None)
                if session_policy:
                    doc = _parse_policy(session_policy)
                    if doc:
                        policies.append(doc)
                # Moto may also store policy_arns for managed session policies
                policy_arns = getattr(assumed_role, "policy_arns", None) or []
                if policy_arns:
                    try:
                        from moto.iam.models import iam_backends
                        backend = iam_backends[caller.account_id]["global"]
                        for pa in policy_arns:
                            arn = pa if isinstance(pa, str) else getattr(pa, "arn", str(pa))
                            doc = _get_managed_policy_doc(backend, arn)
                            if doc:
                                policies.append(doc)
                    except Exception as e:
                        LOG.debug("Failed to load managed session policies: %s", e)
                return policies
    except Exception as e:
        LOG.debug("Failed to get session policies for %s: %s", caller.arn, e)

    return policies


def _get_managed_policy_doc(backend, policy_arn: str) -> dict | None:
    """Retrieve the document of a managed policy from Moto."""
    try:
        policy = backend.managed_policies.get(policy_arn)
        if policy and policy.default_version:
            return _parse_policy(policy.default_version.document)
    except Exception as e:
        LOG.debug("Failed to get managed policy doc for %s: %s", policy_arn, e)
    return None


def _parse_policy(doc) -> dict | None:
    """Parse a policy document (may be str or dict)."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except json.JSONDecodeError:
            return None
    return None


def _trust_policy_services(backend, role_name: str) -> list[str]:
    """Service principals named in a role's AssumeRolePolicyDocument.

    Returns the service principals (e.g. ``["lambda.amazonaws.com"]``) the
    role is willing to be assumed by. A resource policy granting
    ``Principal: {Service: lambda.amazonaws.com}`` matches a caller whose
    role's trust policy accepts that same service principal — that's the
    common Lambda-execution-role / SNS-topic-policy / S3-bucket-policy
    pattern.

    Best-effort: a malformed trust policy or a moto shape change returns
    [] and the caller simply doesn't match Service principals (same as
    AWS when the role has no service principal in its trust policy).
    """
    try:
        role = backend.get_role(role_name) if hasattr(backend, "get_role") else None
    except Exception:
        return []
    if role is None:
        return []
    doc = (
        getattr(role, "assume_role_policy_document", None)
        or getattr(role, "AssumeRolePolicyDocument", None)
        or ""
    )
    if isinstance(doc, str):
        import json as _json
        try:
            doc = _json.loads(doc)
        except Exception:
            return []
    if not isinstance(doc, dict):
        return []
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    services: set[str] = set()
    for st in statements:
        if not isinstance(st, dict):
            continue
        if (st.get("Effect") or "").lower() != "allow":
            continue
        action = st.get("Action") or []
        if isinstance(action, str):
            action = [action]
        if not any(
            a == "sts:AssumeRole" or a == "*" or a == "sts:*" for a in action
        ):
            continue
        principal = st.get("Principal") or {}
        if not isinstance(principal, dict):
            continue
        svc = principal.get("Service") or []
        if isinstance(svc, str):
            svc = [svc]
        for s in svc:
            if isinstance(s, str) and s:
                services.add(s)
    return sorted(services)
