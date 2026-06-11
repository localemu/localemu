"""LocalEmu Organizations service overlay.

moto's ``organizations`` backend implements 38/39 ops natively (verified
against moto 5.x). LocalEmu's overlay adds:

* ``DescribeEffectivePolicy`` (unimplemented in moto, raised
  ``InternalFailure`` before this patch).
* Auto-attach the ``AdministratorAccess`` managed policy to the
  ``OrganizationAccountAccessRole`` that moto auto-creates on
  ``CreateAccount`` (moto creates the role with a correct trust policy
  but no permission, which makes cross-account assume from the
  management account land in a member with zero capabilities).
* Sync every ``CreateAccount`` to the central
  :class:`localemu.accounts.AccountRegistry` so the admin endpoint
  and the dashboard see the new member immediately.

The overlay applies on first request via :func:`apply_patches`, mirroring
the Backup overlay pattern (:mod:`localemu.services.backup.patches`).
"""

from .patches import apply_patches

__all__ = ["apply_patches"]
