"""Moto WAFv2 overlay: enforce "at most one Web ACL per resource".

Moto's own ``WAFV2Backend.associate_web_acl`` (moto/wafv2/models.py) just
appends the resource ARN onto the target Web ACL's ``associated_resources``
list, with no check for an existing association. Real AWS WAFv2 only ever
lets one Web ACL protect a given resource at a time - associating a new
one implicitly replaces any previous association.

Without this fix, re-associating a different Web ACL to the same ALB
(a very plausible "swap in the stricter ACL" lab scenario) without an
explicit DisassociateWebACL first leaves BOTH Web ACLs' associated-
resources lists containing that ALB's ARN. ``get_web_acl_for_resource``
would then return whichever Web ACL happens to be first in dict
insertion order - not necessarily the one most recently associated -
making "which Web ACL actually applies" undefined. Found during
independent design review; fixed here at the backend-method level (not
just the HTTP response layer) so every caller, not only the REST API
path, gets the corrected invariant.

Idempotent: ``apply_patches`` checks a module-level flag and is safe to
call from multiple plugin entry points.
"""

from __future__ import annotations

_APPLIED = False


def apply_patches() -> None:
    global _APPLIED
    if _APPLIED:
        return
    _APPLIED = True

    from moto.wafv2.models import WAFV2Backend

    _original_associate = WAFV2Backend.associate_web_acl

    def associate_web_acl(self, web_acl_arn: str, resource_arn: str) -> None:
        # Disassociate first so at most one Web ACL ever claims this
        # resource - mirrors real WAFv2's "associating replaces" contract.
        self.disassociate_web_acl(resource_arn)
        _original_associate(self, web_acl_arn, resource_arn)

    WAFV2Backend.associate_web_acl = associate_web_acl
