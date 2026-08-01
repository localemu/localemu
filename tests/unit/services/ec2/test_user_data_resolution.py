"""Pin the user-data resolution that feeds the boot-time executor.

The boot-time executor (vm_manager.create_instance) needs the
**resolved** user-data: whatever moto's ``add_instances`` decided to
stamp onto ``Instance.user_data`` after merging the LaunchTemplate (if
any) with the direct request parameter. Reading the raw request
parameter alone would silently drop every LaunchTemplate-only launch
and the Launch-Template-Poisoning attack lab would produce instances
with the backdoor user-data attached but never executed.

These tests run moto in-process (no Docker required) to pin both
flows: direct ``UserData=...`` and ``LaunchTemplate=...``-only.
"""
from __future__ import annotations

import base64

import boto3
import pytest
from moto import mock_aws

from localemu.services.ec2.provider import _resolved_user_data_from_moto


# Use AWS-published example credentials (the same canonical values
# referenced inside src/localemu/cli/awsemu.py:_LOCALEMU_DEFAULT_AK).
# These map to account 000000000000 in moto's default backend.
_AK = "AKIAIOSFODNN7EXAMPLE"
_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_REGION = "us-east-1"


def _client():
    return boto3.client(
        "ec2", aws_access_key_id=_AK, aws_secret_access_key=_SK,
        region_name=_REGION,
    )


def _moto_account_id() -> str:
    """moto's default account when access keys aren't mapped is
    ``123456789012``. We resolve it dynamically rather than hard-code,
    so a future moto bump that changes the placeholder doesn't break
    the test."""
    from moto.core.models import DEFAULT_ACCOUNT_ID
    return DEFAULT_ACCOUNT_ID


# ---------------------------------------------------------------------------
# Direct UserData path - the previous behaviour, must keep working
# ---------------------------------------------------------------------------


@mock_aws
def test_direct_user_data_lands_on_moto_instance():
    """This case already worked before the fix (provider read the raw
    request param). The helper must agree with the raw request - moto
    must hold the same value the fix would surface."""
    ec2 = _client()
    script = b"#!/bin/bash\necho RAN > /tmp/m\n"
    payload_b64 = base64.b64encode(script).decode()

    r = ec2.run_instances(
        ImageId="ami-12c6146b", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, UserData=script.decode(),
    )
    iid = r["Instances"][0]["InstanceId"]

    resolved = _resolved_user_data_from_moto(
        _moto_account_id(), _REGION, iid,
    )
    assert resolved == payload_b64, (
        f"direct UserData must land in moto Instance verbatim; "
        f"got {resolved!r}, expected {payload_b64!r}"
    )


# ---------------------------------------------------------------------------
# Launch-template UserData - the fix
# ---------------------------------------------------------------------------


@mock_aws
def test_launch_template_user_data_resolves_through_moto():
    """The literal reproduction: CreateLaunchTemplate
    with UserData, RunInstances via the template (no direct UserData).
    The helper must return the template's UserData, otherwise the
    boot-time executor never runs and Launch-Template Poisoning (E1)
    is unprovable."""
    ec2 = _client()
    script = b"#!/bin/bash\necho RAN > /tmp/m\n"
    payload_b64 = base64.b64encode(script).decode()

    ec2.create_launch_template(
        LaunchTemplateName="t-pr007",
        LaunchTemplateData={
            "ImageId": "ami-12c6146b",
            "InstanceType": "t2.micro",
            "UserData": payload_b64,
        },
    )
    r = ec2.run_instances(
        LaunchTemplate={"LaunchTemplateName": "t-pr007"},
        MinCount=1, MaxCount=1,
    )
    iid = r["Instances"][0]["InstanceId"]

    resolved = _resolved_user_data_from_moto(
        _moto_account_id(), _REGION, iid,
    )
    assert resolved == payload_b64, (
        f"LaunchTemplate-only UserData must resolve through moto; "
        f"got {resolved!r}, expected {payload_b64!r}"
    )


@mock_aws
def test_direct_user_data_overrides_template_when_both_present():
    """AWS contract: a direct ``--user-data`` on RunInstances overrides
    the template's UserData. moto honours this; we pin that our helper
    returns the overridden value so the boot executor runs the direct
    payload, not the template's."""
    ec2 = _client()
    template_script = b"#!/bin/bash\necho FROM_TEMPLATE > /tmp/m\n"
    override_script = b"#!/bin/bash\necho FROM_DIRECT > /tmp/m\n"
    template_b64 = base64.b64encode(template_script).decode()
    override_b64 = base64.b64encode(override_script).decode()

    ec2.create_launch_template(
        LaunchTemplateName="t-override",
        LaunchTemplateData={
            "ImageId": "ami-12c6146b",
            "InstanceType": "t2.micro",
            "UserData": template_b64,
        },
    )
    r = ec2.run_instances(
        LaunchTemplate={"LaunchTemplateName": "t-override"},
        MinCount=1, MaxCount=1,
        UserData=override_script.decode(),
    )
    iid = r["Instances"][0]["InstanceId"]

    resolved = _resolved_user_data_from_moto(
        _moto_account_id(), _REGION, iid,
    )
    assert resolved == override_b64, (
        f"direct UserData must override template UserData; "
        f"got {resolved!r}, expected override {override_b64!r}"
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@mock_aws
def test_returns_none_when_no_user_data_set():
    """A plain RunInstances with no UserData and no template must
    return ``None``. The provider then falls back to the raw request
    (which is also empty) and the boot executor short-circuits."""
    ec2 = _client()
    r = ec2.run_instances(
        ImageId="ami-12c6146b", InstanceType="t2.micro",
        MinCount=1, MaxCount=1,
    )
    iid = r["Instances"][0]["InstanceId"]

    resolved = _resolved_user_data_from_moto(
        _moto_account_id(), _REGION, iid,
    )
    assert resolved is None


@mock_aws
def test_returns_none_for_unknown_instance_id():
    """Lookup for an instance moto doesn't know about must return
    ``None`` cleanly, never raise - the provider then falls back to
    the raw request parameter."""
    resolved = _resolved_user_data_from_moto(
        _moto_account_id(), _REGION, "i-deadbeef00000000",
    )
    assert resolved is None
