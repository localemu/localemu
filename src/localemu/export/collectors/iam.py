"""IAM collector: enumerate roles / users / managed policies / groups.

IAM is a *global* service. LocalEmu (via moto) still keys backends by
region, but there is exactly one canonical backend per account. We only
emit resources when ``region == "global"``; the orchestrator is
responsible for calling the IAM collector once per account with this
magic region. Emitting under both ``global`` and ``us-east-1`` would
double-count every IAM resource.

Policy documents come out of moto URL-encoded (``%7B%22Version%22...``)
so that they survive round-trips through AWS's validation layer. We
decode them into plain dicts in the IR — writers always want structured
JSON, not escaped strings.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)

# Magic region value used by the orchestrator for IAM. Anything else is
# ignored.
_GLOBAL = "global"


@register_collector("iam")
class IamCollector(BaseCollector):
    """Collect IAM resources for a single account (global only)."""

    service = "iam"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        if region != _GLOBAL:
            return []

        try:
            import moto.backends as moto_backends
        except Exception:  # pragma: no cover
            LOG.warning("moto is unavailable; skipping IAM", exc_info=True)
            return []

        try:
            backend = moto_backends.get_backend("iam")[account_id]["global"]
        except Exception:
            LOG.warning(
                "No IAM backend for account=%s", account_id, exc_info=True
            )
            return []

        # Pre-compute user→[group] membership by scanning groups, since
        # moto stores the relation on the group side only and our user
        # resources need ``groups`` populated for the writer to emit
        # ``aws_iam_user_group_membership`` resources.
        user_to_groups: dict[str, list[str]] = {}
        for grp in (getattr(backend, "groups", {}) or {}).values():
            gname = getattr(grp, "name", None)
            if not gname:
                continue
            for member in getattr(grp, "users", []) or []:
                uname = (
                    getattr(member, "name", None)
                    if not isinstance(member, str)
                    else member
                )
                if uname:
                    user_to_groups.setdefault(uname, []).append(gname)

        resources: list[Resource] = []
        resources.extend(self._collect_roles(backend, account_id))
        resources.extend(
            self._collect_users(backend, account_id, user_to_groups)
        )
        resources.extend(self._collect_groups(backend, account_id))
        resources.extend(self._collect_managed_policies(backend, account_id))
        resources.extend(self._collect_instance_profiles(backend, account_id))
        resources.extend(self._collect_oidc_providers(backend, account_id))
        resources.extend(self._collect_saml_providers(backend, account_id))
        return resources

    # ------------------------------------------------------------------
    # Instance profiles
    # ------------------------------------------------------------------

    def _collect_instance_profiles(
        self, backend: Any, account_id: str
    ) -> list[Resource]:
        out: list[Resource] = []
        profiles = getattr(backend, "instance_profiles", {}) or {}
        for ip in dict(profiles).values():
            try:
                role_names = [
                    getattr(r, "name", None)
                    for r in (getattr(ip, "roles", []) or [])
                ]
                role_names = [r for r in role_names if r]
                role_ref: Any = None
                if role_names:
                    # CFN AWS::IAM::InstanceProfile takes a list of role NAMES;
                    # TF aws_iam_instance_profile takes a single role NAME.
                    # Carry the first role as a Ref so writers can resolve it.
                    role_ref = Ref(
                        service="iam",
                        resource_type="role",
                        resource_id=role_names[0],
                        attribute="name",
                    )
                attrs: dict[str, Any] = {
                    "name": getattr(ip, "name", None)
                    or getattr(ip, "instance_profile_name", None),
                    "path": getattr(ip, "path", "/"),
                    "arn": getattr(ip, "arn", None),
                    "role": role_ref,
                    "roles": role_names,
                }
                tags = _iam_tags_to_dict(getattr(ip, "tags", None))
                created_at = _iso(getattr(ip, "create_date", None))
                out.append(
                    Resource(
                        service="iam",
                        resource_type="instance_profile",
                        resource_id=attrs["name"],
                        account_id=account_id,
                        region=_GLOBAL,
                        attributes=attrs,
                        tags=tags,
                        created_at=created_at,
                    )
                )
            except Exception:
                LOG.warning(
                    "Failed to serialize instance profile %r; skipping",
                    getattr(ip, "name", "?"),
                    exc_info=True,
                )
        return out

    # ------------------------------------------------------------------
    # OIDC / SAML providers
    # ------------------------------------------------------------------

    def _collect_oidc_providers(
        self, backend: Any, account_id: str
    ) -> list[Resource]:
        out: list[Resource] = []
        providers = getattr(backend, "open_id_providers", {}) or {}
        for arn, p in dict(providers).items():
            try:
                url = getattr(p, "url", None) or arn.split("/", 1)[-1]
                attrs: dict[str, Any] = {
                    "url": url if url and url.startswith("http") else f"https://{url}",
                    "arn": getattr(p, "arn", None) or arn,
                    "client_id_list": list(getattr(p, "client_id_list", []) or []),
                    "thumbprint_list": list(getattr(p, "thumbprint_list", []) or []),
                }
                # Resource id is the URL host+path (without scheme), to
                # match how AWS uniquely identifies OIDC providers.
                rid = attrs["url"].split("://", 1)[-1]
                tags = _iam_tags_to_dict(getattr(p, "tags", None))
                out.append(
                    Resource(
                        service="iam",
                        resource_type="oidc_provider",
                        resource_id=rid,
                        account_id=account_id,
                        region=_GLOBAL,
                        attributes=attrs,
                        tags=tags,
                    )
                )
            except Exception:
                LOG.warning(
                    "Failed to serialize OIDC provider %r; skipping",
                    arn, exc_info=True,
                )
        return out

    def _collect_saml_providers(
        self, backend: Any, account_id: str
    ) -> list[Resource]:
        out: list[Resource] = []
        providers = getattr(backend, "saml_providers", {}) or {}
        for arn, p in dict(providers).items():
            try:
                name = getattr(p, "name", None) or arn.rsplit("/", 1)[-1]
                attrs: dict[str, Any] = {
                    "name": name,
                    "arn": getattr(p, "arn", None) or arn,
                    "saml_metadata_document": getattr(
                        p, "saml_metadata_document", None
                    ),
                }
                tags = _iam_tags_to_dict(getattr(p, "tags", None))
                out.append(
                    Resource(
                        service="iam",
                        resource_type="saml_provider",
                        resource_id=name,
                        account_id=account_id,
                        region=_GLOBAL,
                        attributes=attrs,
                        tags=tags,
                    )
                )
            except Exception:
                LOG.warning(
                    "Failed to serialize SAML provider %r; skipping",
                    arn, exc_info=True,
                )
        return out

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def _collect_roles(self, backend: Any, account_id: str) -> list[Resource]:
        out: list[Resource] = []
        roles = getattr(backend, "roles", {}) or {}
        for role in dict(roles).values():
            try:
                out.append(self._role_resource(role, account_id))
            except Exception:
                LOG.warning(
                    "Failed to serialize IAM role %r; skipping",
                    getattr(role, "name", "?"),
                    exc_info=True,
                )
        return out

    def _role_resource(self, role: Any, account_id: str) -> Resource:
        assume = _decode_policy_document(
            getattr(role, "assume_role_policy_document", None)
        )

        attached_managed: list[Any] = []
        for policy in (getattr(role, "managed_policies", {}) or {}).values():
            attached_managed.append(
                _managed_policy_ref_or_arn(policy, account_id)
            )

        inline: dict[str, Any] = {}
        for pname, pdoc in (getattr(role, "policies", {}) or {}).items():
            inline[str(pname)] = _decode_policy_document(pdoc)

        instance_profiles = [
            getattr(ip, "name", None) or getattr(ip, "instance_profile_name", None)
            for ip in getattr(role, "instance_profile_list", []) or []
        ]
        instance_profiles = [ip for ip in instance_profiles if ip]

        attrs: dict[str, Any] = {
            "name": getattr(role, "name", None),
            "path": getattr(role, "path", "/"),
            "role_id": getattr(role, "id", None),
            "arn": getattr(role, "arn", None),
            "assume_role_policy_document": assume,
            "attached_managed_policies": attached_managed,
            "inline_policies": inline,
            "instance_profile_list": instance_profiles,
            "description": getattr(role, "description", None),
            "max_session_duration": getattr(role, "max_session_duration", None),
            "permissions_boundary": getattr(role, "permissions_boundary_arn", None),
        }

        tags = _iam_tags_to_dict(getattr(role, "tags", None))
        created_at = _iso(getattr(role, "create_date", None))

        return Resource(
            service="iam",
            resource_type="role",
            resource_id=attrs["name"],
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def _collect_users(
        self,
        backend: Any,
        account_id: str,
        user_to_groups: dict[str, list[str]],
    ) -> list[Resource]:
        out: list[Resource] = []
        users = getattr(backend, "users", {}) or {}
        for user in dict(users).values():
            try:
                out.append(
                    self._user_resource(user, account_id, user_to_groups)
                )
            except Exception:
                LOG.warning(
                    "Failed to serialize IAM user %r; skipping",
                    getattr(user, "name", "?"),
                    exc_info=True,
                )
        return out

    def _user_resource(
        self,
        user: Any,
        account_id: str,
        user_to_groups: dict[str, list[str]],
    ) -> Resource:
        attached_managed = [
            _managed_policy_ref_or_arn(p, account_id)
            for p in (getattr(user, "managed_policies", {}) or {}).values()
        ]
        inline: dict[str, Any] = {}
        for pname, pdoc in (getattr(user, "policies", {}) or {}).items():
            inline[str(pname)] = _decode_policy_document(pdoc)

        # moto stores group membership only on the group side, not the
        # user; we backfilled an inverse map at the top of collect().
        uname = getattr(user, "name", None)
        groups: list[str] = list(user_to_groups.get(uname, []))

        # Access key *metadata* only; the secret key is deliberately
        # omitted. AccessKeyId is non-secret and useful for mapping.
        access_keys_meta: list[dict[str, Any]] = []
        for ak in _safe_list(user, ("access_keys", "get_all_access_keys")):
            access_keys_meta.append(
                {
                    "access_key_id": getattr(ak, "access_key_id", None),
                    "status": getattr(ak, "status", None),
                    "create_date": _iso(getattr(ak, "create_date", None)),
                }
            )

        attrs: dict[str, Any] = {
            "name": getattr(user, "name", None),
            "path": getattr(user, "path", "/"),
            "user_id": getattr(user, "id", None),
            "arn": getattr(user, "arn", None),
            "attached_managed_policies": attached_managed,
            "inline_policies": inline,
            "groups": groups,
            "access_keys": access_keys_meta,
        }
        tags = _iam_tags_to_dict(getattr(user, "tags", None))
        created_at = _iso(getattr(user, "create_date", None))
        return Resource(
            service="iam",
            resource_type="user",
            resource_id=attrs["name"],
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def _collect_groups(self, backend: Any, account_id: str) -> list[Resource]:
        out: list[Resource] = []
        groups = getattr(backend, "groups", {}) or {}
        for group in dict(groups).values():
            try:
                out.append(self._group_resource(group, account_id))
            except Exception:
                LOG.warning(
                    "Failed to serialize IAM group %r; skipping",
                    getattr(group, "name", "?"),
                    exc_info=True,
                )
        return out

    def _group_resource(self, group: Any, account_id: str) -> Resource:
        attached_managed = [
            _managed_policy_ref_or_arn(p, account_id)
            for p in (getattr(group, "managed_policies", {}) or {}).values()
        ]
        inline: dict[str, Any] = {}
        for pname, pdoc in (getattr(group, "policies", {}) or {}).items():
            inline[str(pname)] = _decode_policy_document(pdoc)

        users: list[str] = []
        for u in getattr(group, "users", []) or []:
            uname = getattr(u, "name", None) if not isinstance(u, str) else u
            if uname:
                users.append(uname)

        attrs: dict[str, Any] = {
            "name": getattr(group, "name", None),
            "path": getattr(group, "path", "/"),
            "arn": getattr(group, "arn", None),
            "attached_managed_policies": attached_managed,
            "inline_policies": inline,
            "users": users,
        }
        created_at = _iso(getattr(group, "create_date", None))
        return Resource(
            service="iam",
            resource_type="group",
            resource_id=attrs["name"],
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags={},
            created_at=created_at,
        )

    # ------------------------------------------------------------------
    # Managed policies
    # ------------------------------------------------------------------

    def _collect_managed_policies(
        self, backend: Any, account_id: str
    ) -> list[Resource]:
        out: list[Resource] = []
        # ``managed_policies`` holds customer-managed; ``aws_managed_policies``
        # holds AWS-managed. We only export customer-managed — AWS-managed
        # are identical across every account and would pollute the
        # snapshot with thousands of read-only entries.
        managed = getattr(backend, "managed_policies", {}) or {}
        for policy in dict(managed).values():
            arn = getattr(policy, "arn", "") or ""
            # Skip anything in the aws-managed namespace defensively.
            if ":iam::aws:policy/" in arn:
                continue
            try:
                out.append(self._managed_policy_resource(policy, account_id))
            except Exception:
                LOG.warning(
                    "Failed to serialize IAM managed policy %r; skipping",
                    getattr(policy, "name", "?"),
                    exc_info=True,
                )
        return out

    def _managed_policy_resource(
        self, policy: Any, account_id: str
    ) -> Resource:
        document = _policy_default_document(policy)
        attrs: dict[str, Any] = {
            "name": getattr(policy, "name", None),
            "path": getattr(policy, "path", "/"),
            "arn": getattr(policy, "arn", None),
            "description": getattr(policy, "description", None),
            "policy_document": document,
            "default_version_id": getattr(policy, "default_version_id", None),
        }
        tags = _iam_tags_to_dict(getattr(policy, "tags", None))
        created_at = _iso(getattr(policy, "create_date", None))
        return Resource(
            service="iam",
            resource_type="policy",
            resource_id=attrs["name"],
            account_id=account_id,
            region=_GLOBAL,
            attributes=attrs,
            tags=tags,
            created_at=created_at,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_policy_document(doc: Any) -> Any:
    """Return a policy document as a dict.

    Moto persists documents as URL-encoded JSON strings. We unquote + parse
    so writers receive a structured value, not opaque text.
    """
    if doc is None:
        return None
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, (bytes, bytearray)):
        doc = doc.decode("utf-8", errors="replace")
    if not isinstance(doc, str):
        return None
    # Policy docs may be URL-encoded once. ``unquote`` on an already-plain
    # string is a no-op so this is safe.
    candidate = urllib.parse.unquote(doc)
    try:
        return json.loads(candidate)
    except Exception:
        # Some paths store the document as raw JSON without URL encoding.
        try:
            return json.loads(doc)
        except Exception:
            LOG.warning("IAM policy document is not valid JSON; dropping", exc_info=True)
            return None


def _policy_default_document(policy: Any) -> Any:
    """Extract the *default* policy version document as a dict."""
    versions = getattr(policy, "versions", None) or []
    default_id = getattr(policy, "default_version_id", None)
    target = None
    for v in versions:
        if getattr(v, "version_id", None) == default_id or getattr(
            v, "is_default", False
        ):
            target = v
            break
    if target is None and versions:
        target = versions[0]
    if target is None:
        return None
    doc = getattr(target, "document", None)
    return _decode_policy_document(doc)


def _managed_policy_ref_or_arn(policy: Any, account_id: str) -> Any:
    arn = getattr(policy, "arn", None)
    if not arn:
        return None
    # aws-managed policies live in the aws account — keep as raw ARN.
    if ":iam::aws:policy/" in arn:
        return arn
    # customer-managed in *this* account — ref by name.
    parts = arn.split(":")
    if len(parts) >= 5 and parts[4] == account_id:
        name = getattr(policy, "name", None)
        if name:
            return Ref(service="iam", resource_type="policy", resource_id=name)
    return arn


def _iam_tags_to_dict(tags: Any) -> dict[str, str]:
    if not tags:
        return {}
    if isinstance(tags, dict):
        # Some moto versions use {key: {"Key": k, "Value": v}} shape.
        out: dict[str, str] = {}
        for k, v in tags.items():
            if isinstance(v, dict) and "Value" in v:
                out[str(k)] = str(v.get("Value", ""))
            else:
                out[str(k)] = str(v)
        return out
    if isinstance(tags, list):
        out = {}
        for entry in tags:
            if isinstance(entry, dict) and "Key" in entry and "Value" in entry:
                out[str(entry["Key"])] = str(entry["Value"])
        return out
    return {}


def _iso(dt: Any) -> str | None:
    if dt is None:
        return None
    iso = getattr(dt, "isoformat", None)
    if callable(iso):
        try:
            return iso()
        except Exception:
            return None
    return str(dt)


def _safe_list(obj: Any, candidates: tuple[str, ...]) -> list[Any]:
    for name in candidates:
        value = getattr(obj, name, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        if value is None:
            continue
        if isinstance(value, dict):
            return list(value.values())
        if isinstance(value, (list, tuple, set)):
            return list(value)
    return []
