"""moto-side patches for the Organizations service.

Adds the three behaviours documented in the package docstring:

1. ``OrganizationsBackend.describe_effective_policy`` returns a
   well-formed empty effective-policy document instead of raising
   ``InternalFailure``.
2. ``OrganizationsBackend.create_account`` is wrapped to attach the
   ``AdministratorAccess`` managed policy to the auto-created
   ``OrganizationAccountAccessRole``.
3. The same wrap pushes the new account into the LocalEmu
   :class:`AccountRegistry`.

All three patches are idempotent. ``apply_patches`` is called by the
provider factory in :mod:`localemu.services.providers`.
"""

from __future__ import annotations

import json
import logging
import time

LOG = logging.getLogger(__name__)

_APPLIED = False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


_ADMIN_ACCESS_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_ADMIN_ACCESS_POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def _attach_admin_to_role(account_id: str, role_name: str) -> None:
    """Give the freshly-created role full administrator permissions.

    AWS's real ``OrganizationAccountAccessRole`` carries the AWS-managed
    ``AdministratorAccess`` policy. LocalEmu's IAM backend does not ship
    the AWS-managed catalog by default, so attaching by the canonical
    ARN would fail. We side-step the catalog entirely and write an
    equivalent inline policy on the role: the effect is identical from
    the IAM-enforcement perspective, and the role's ``GetRole``/
    ``ListRolePolicies`` shape mirrors what a real member account looks
    like after `Organizations.CreateAccount` plus the standard manual
    attach.
    """
    try:
        from moto.iam import iam_backends

        iam = iam_backends[account_id]["global"]
        iam.put_role_policy(
            role_name=role_name,
            policy_name="AdministratorAccess",
            policy_json=json.dumps(_ADMIN_ACCESS_POLICY_DOC),
        )
    except Exception as e:
        LOG.debug("Admin attach to %s/%s skipped: %s", account_id, role_name, e)


def _sync_account_to_registry(account_id: str, name: str, email: str,
                              org_id: str | None = None) -> None:
    """Mirror moto's CreateAccount into the LocalEmu account registry."""
    try:
        from localemu.accounts import get_registry

        get_registry().ensure(
            account_id, email=email, name=name,
            joined_method="CREATED", org_id=org_id,
        )
        if org_id:
            get_registry().update_arn(account_id, org_id)
    except Exception as e:
        LOG.debug("Registry sync for account %s skipped: %s", account_id, e)


# --------------------------------------------------------------------------
# Patch entry point
# --------------------------------------------------------------------------


def apply_patches() -> None:
    """Install the Organizations patches. Idempotent."""
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    from moto.organizations import models as _m
    from moto.organizations import responses as _r

    # ---- Patch 1: DescribeEffectivePolicy returns a well-formed empty doc.
    # Add the backend method AND the response-class dispatcher (moto's
    # request routing reads the snake_case action name as an attribute
    # on the response class, NOT the backend, so both sides need wiring).
    if not hasattr(_m.OrganizationsBackend, "describe_effective_policy"):
        def describe_effective_policy(self, **kwargs):
            if self.org is None:
                target = kwargs.get("TargetId") or "r-empty"
            else:
                target = kwargs.get("TargetId") or self.org.master_account_id
            policy_type = kwargs.get("PolicyType") or "TAG_POLICY"
            # Empty effective policy doc, AWS-shape. Real AWS merges SCPs
            # along the OU chain; we acknowledge SCP storage but don't
            # enforce, so the effective merge is empty by design.
            return {
                "EffectivePolicy": {
                    "PolicyContent": json.dumps({"tags": {}}),
                    "LastUpdatedTimestamp": time.time(),
                    "Target": target,
                    "PolicyType": policy_type,
                }
            }
        _m.OrganizationsBackend.describe_effective_policy = describe_effective_policy

    if not hasattr(_r.OrganizationsResponse, "describe_effective_policy"):
        def _response_describe_effective_policy(self):
            return json.dumps(
                self.organizations_backend.describe_effective_policy(
                    **self.request_params
                )
            )
        _r.OrganizationsResponse.describe_effective_policy = (
            _response_describe_effective_policy
        )

    # ---- Patch 2 + 3: wrap FakeAccount.__init__ to attach admin policy and
    # ---- sync to the LocalEmu registry. We wrap rather than subclass so
    # ---- any code path that instantiates FakeAccount picks the behaviour
    # ---- up regardless of how it was reached. We wrap the PUBLIC
    # ---- create_account entrypoint rather than FakeAccount.__init__ on
    # ---- purpose: moto's own create_organization() also builds a
    # ---- FakeAccount for the implicit master account, then overwrites
    # ---- master_account.id = org.master_account_id right after
    # ---- construction (FakeAccount.__init__ always assigns a fresh random
    # ---- id first; create_organization replaces it for the master-account
    # ---- case only). Reading self.id inside __init__ raced that overwrite
    # ---- and synced the wrong, immediately-discarded random id into the
    # ---- registry - a real bug that showed up as a phantom extra
    # ---- "master" account (with an id nothing else in the system ever
    # ---- references) every time Organizations.CreateOrganization ran.
    # ---- create_account() never overwrites the id it generates, so
    # ---- reading it after the call returns is always correct.
    _original_create_account = _m.OrganizationsBackend.create_account

    def _wrapped_create_account(self, **kwargs):
        result = _original_create_account(self, **kwargs)
        account_id = self.accounts[-1].id
        role_name = kwargs.get("RoleName", "OrganizationAccountAccessRole")
        _attach_admin_to_role(account_id, role_name)
        _sync_account_to_registry(
            account_id=account_id,
            name=kwargs.get("AccountName") or f"account-{account_id}",
            email=kwargs.get("Email") or f"{account_id}@localemu.local",
            org_id=self.org.id if self.org is not None else None,
        )
        return result

    # Idempotency: don't wrap twice across hot reloads.
    if getattr(_m.OrganizationsBackend.create_account, "_localemu_wrapped", False):
        return
    _wrapped_create_account._localemu_wrapped = True
    _m.OrganizationsBackend.create_account = _wrapped_create_account

    # ---- Patch 4: also sync the master/management account when an
    # ---- organization is created (moto allocates it implicitly).
    _original_create_org = _m.OrganizationsBackend.create_organization

    def _wrapped_create_org(self, region, **kwargs):
        result = _original_create_org(self, region=region, **kwargs)
        try:
            org = self.org
            if org is not None:
                _sync_account_to_registry(
                    account_id=org.master_account_id,
                    name="master",
                    email=getattr(org, "master_account_email", None)
                          or "master@example.com",
                    org_id=org.id,
                )
        except Exception as e:
            LOG.debug("Registry sync for master account skipped: %s", e)
        return result

    if not getattr(_m.OrganizationsBackend.create_organization, "_localemu_wrapped", False):
        _wrapped_create_org._localemu_wrapped = True
        _m.OrganizationsBackend.create_organization = _wrapped_create_org

    LOG.info("LocalEmu Organizations patches applied")
