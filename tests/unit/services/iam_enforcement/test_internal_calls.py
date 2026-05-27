"""Unit tests for :meth:`IAMEnforcementHandler._is_internal_call`.

The method decides whether a request that reached the enforcer came from
another LocalEmu service (and must therefore bypass user-IAM evaluation)
or from an external caller. Two independent signals are recognized:

    1. ``RequestContext.is_internal_call`` == True, i.e. the inbound
       request carried the ``x-localemu-data`` header that every
       :class:`InternalClientFactory`-built client emits.
    2. The request's access key is one of the two LocalEmu-internal
       sentinels: ``INTERNAL_AWS_ACCESS_KEY_ID`` or
       ``INTERNAL_RESOURCE_ACCOUNT``.

The fix for LocalEmu_Bugs_2.md hinges on this helper; if either branch
regresses, every cross-service hop that runs under ``IAM_ENFORCEMENT=1``
breaks again.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu import config as _lemu_config
from localemu import constants as _lemu_constants
from localemu.services.iam_enforcement.enforcer import IAMEnforcementHandler


def _ctx(*, is_internal: bool) -> SimpleNamespace:
    """Minimal RequestContext stand-in; only ``is_internal_call`` is read
    by the helper, so the rest of the request-context surface is moot."""
    return SimpleNamespace(is_internal_call=is_internal)


class TestInternalDtoBranch:
    def test_internal_request_params_alone_is_sufficient(self):
        # connect_to(...) clients always emit x-localemu-data, even when the
        # DTO is empty — that's what the InternalClientFactory before-call
        # hook does. An empty DTO still flips is_internal_call to True.
        assert IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=True), access_key=None,
        )

    def test_internal_request_params_with_real_user_key_still_allows(self):
        # A real operator key (unlikely to carry the DTO in practice, but
        # exercised here for completeness) must not override the trust
        # signal from the header. The header's presence is the edict.
        assert IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=True), access_key="AKIAIOSFODNN7EXAMPLE",
        )


class TestSentinelKeyBranch:
    def test_internal_call_sentinel_access_key(self):
        # The connect_to default ("__internal_call__"). Covers every
        # hop that doesn't explicitly override aws_access_key_id.
        assert IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False),
            access_key=_lemu_constants.INTERNAL_AWS_ACCESS_KEY_ID,
        )

    def test_internal_resource_account_access_key(self):
        # The second sentinel (currently "949334387222"). Covers Lambda
        # code storage (lambda_models.py:213/248/321,
        # lambda_service.py:725) and the S3 presigned-URL path where the
        # key arrives as a query-string parameter rather than a header.
        assert IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False),
            access_key=_lemu_config.INTERNAL_RESOURCE_ACCOUNT,
        )


class TestNegativeCases:
    def test_external_request_with_normal_key_is_not_internal(self):
        # The control case: no DTO header, ordinary access key. Must
        # return False so the enforcer falls through to its usual
        # resolve_caller -> evaluate path.
        assert not IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False), access_key="AKIAIOSFODNN7EXAMPLE",
        )

    def test_unauthenticated_external_request_is_not_internal(self):
        # No DTO, no access key — must still fall through so the existing
        # "missing authentication token" deny fires.
        assert not IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False), access_key=None,
        )

    def test_empty_access_key_treated_as_no_key(self):
        # Defensive: an empty string should not hit the sentinel branch.
        assert not IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False), access_key="",
        )

    def test_sentinel_substring_is_not_enough(self):
        # The sentinel check is exact-match only. A key that merely
        # contains the sentinel substring must not bypass — otherwise an
        # attacker could append the sentinel to any key string.
        assert not IAMEnforcementHandler._is_internal_call(
            _ctx(is_internal=False),
            access_key="AKIA" + _lemu_constants.INTERNAL_AWS_ACCESS_KEY_ID,
        )


class TestConstantsDidNotDrift:
    """Guard against someone silently renaming a sentinel. The fix is
    pinned to these two strings; if either one is renamed without
    updating the enforcer, the bypass would silently stop firing and
    every S2S hop would regress."""

    def test_internal_aws_access_key_id_value(self):
        # Locked to the value the codebase ships with today. A rename is
        # fine, but the rename has to update the enforcer's check too.
        assert _lemu_constants.INTERNAL_AWS_ACCESS_KEY_ID == "__internal_call__"

    def test_internal_resource_account_value(self):
        assert _lemu_config.INTERNAL_RESOURCE_ACCOUNT == "949334387222"
