"""moto SSM patches applied at provider import time.

Patch 1: Command._get_instance_ids_from_targets

  Upstream moto's Command.__init__ unconditionally calls
  ``self._get_instance_ids_from_targets()`` and unions the result
  into ``self.instance_ids``. That method translates each
  ``{Key, Values}`` entry of ``self.targets`` into an
  ``ec2_backend.all_reservations(filters=...)`` filter dict. When
  the user did NOT pass Targets and only passed InstanceIds,
  ``self.targets`` is ``[]``, so the filter dict is ``{}``.

  An empty filter on ``all_reservations`` matches EVERY reservation
  in the account/region — so every existing EC2 instance gets
  unioned into the Command's InstanceIds, regardless of what the
  user actually targeted. The SendCommand response and every
  subsequent invocation enumeration then carries that whole list.

  This breaks any caller that relies on Command.InstanceIds /
  TargetCount to reflect what was actually requested — and it
  produces flaky E2E tests where SSM probes to one instance leak
  results from every other instance in the session.

  The fix: skip the targets→instances expansion entirely when
  ``self.targets`` is empty. Real AWS only resolves targets to
  instance IDs when targets were actually specified.
"""
from __future__ import annotations

import logging

from moto.ssm.models import Command

from localemu.utils.patch import patch

LOG = logging.getLogger(__name__)


@patch(target=Command._get_instance_ids_from_targets, pass_target=True)
def _get_instance_ids_from_targets_only_when_targets_set(fn, self):
    """Return [] when no targets were specified; otherwise call upstream."""
    if not self.targets:
        return []
    return fn(self)


def apply_ssm_patches() -> None:
    """No-op; importing this module triggers the @patch decorators."""
    LOG.debug("ssm: applied moto Command target-expansion patch")
