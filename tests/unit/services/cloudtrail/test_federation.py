"""Regression tests for EnableFederation / DisableFederation.

These APIs toggle a flag on a (conceptual) event data store. LocalEmu
does not implement the federation query path — we only track the flag
state so that callers' Describe/Enable/Disable loops see consistent
values.
"""

from __future__ import annotations

import pytest

from localemu.aws.api.core import CommonServiceException
from localemu.services.cloudtrail import native


EDS_ARN = "arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/eds1"
ROLE_ARN = "arn:aws:iam::000000000000:role/federation"


def test_enable_federation_returns_enabled(ctx):
    resp = native.enable_federation(
        ctx, {"EventDataStore": EDS_ARN, "FederationRoleArn": ROLE_ARN}
    )
    assert resp == {
        "EventDataStoreArn": EDS_ARN,
        "FederationStatus": "ENABLED",
        "FederationRoleArn": ROLE_ARN,
    }


def test_disable_federation_returns_disabled(ctx):
    native.enable_federation(ctx, {"EventDataStore": EDS_ARN, "FederationRoleArn": ROLE_ARN})
    resp = native.disable_federation(ctx, {"EventDataStore": EDS_ARN})
    assert resp == {"EventDataStoreArn": EDS_ARN, "FederationStatus": "DISABLED"}


def test_enable_then_disable_then_enable_cycle(ctx):
    native.enable_federation(ctx, {"EventDataStore": EDS_ARN, "FederationRoleArn": ROLE_ARN})
    native.disable_federation(ctx, {"EventDataStore": EDS_ARN})
    resp = native.enable_federation(ctx, {"EventDataStore": EDS_ARN, "FederationRoleArn": ROLE_ARN})
    assert resp["FederationStatus"] == "ENABLED"


def test_disable_federation_on_never_enabled_is_idempotent(ctx):
    resp = native.disable_federation(ctx, {"EventDataStore": EDS_ARN})
    assert resp["FederationStatus"] == "DISABLED"


def test_enable_requires_role_arn(ctx):
    with pytest.raises(CommonServiceException):
        native.enable_federation(ctx, {"EventDataStore": EDS_ARN})
