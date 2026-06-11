"""Unit tests for the SSM Patch Manager read stubs.

``DescribeInstancePatchStates`` and ``DescribeInstancePatchStatesForPatchGroup``
return an empty list (matching real AWS on a clean account). ``GetPatchBaseline``
raises a typed ``DoesNotExistException`` for any unknown baseline ID so a
caller scanning for patch state gets an AWS-shaped error instead of
``InternalFailure``.
"""

from __future__ import annotations

from unittest import mock

import pytest

from localemu.aws.api import CommonServiceException
from localemu.services.ssm import provider as ssm_provider_module


def _ctx(account="000000000000", region="us-east-1"):
    ctx = mock.MagicMock()
    ctx.account_id = account
    ctx.region = region
    return ctx


def _provider():
    return ssm_provider_module.SsmProvider()


def test_describe_instance_patch_states_empty_default():
    p = _provider()
    out = p.describe_instance_patch_states(_ctx(), {"InstanceIds": ["i-unknown"]})
    assert out == {"InstancePatchStates": [], "NextToken": None}


def test_describe_instance_patch_states_for_patch_group_empty_default():
    p = _provider()
    out = p.describe_instance_patch_states_for_patch_group(
        _ctx(), {"PatchGroup": "production"}
    )
    assert out == {"InstancePatchStates": [], "NextToken": None}


def test_get_patch_baseline_unknown_raises_typed_error():
    """The whole point of these stubs is to surface a typed
    ``DoesNotExistException`` instead of moto's ``InternalFailure``."""
    p = _provider()
    with pytest.raises(CommonServiceException) as exc:
        p.get_patch_baseline(_ctx(), {"BaselineId": "pb-doesnotexist"})
    assert exc.value.code == "DoesNotExistException"
