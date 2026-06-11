"""Security-scanner regression: pins the response shapes for the EC2 /
SSM / Backup operations that a third-party scanner exercises.

A real scanner walks every read-side operation on a fresh account. If
any of them returns ``InternalFailure`` (the botocore "Unknown" shape),
the scanner breaks on the first call and reports the cluster as
unscannable. These tests pin every covered operation to a well-formed
AWS shape : either a typed success (empty list / record) or a typed
``ClientError`` (``ResourceNotFoundException``, ``DoesNotExistException``,
``InvalidParameterValue``, …) — never ``InternalFailure``,
``UnknownServiceError``, or ``EndpointConnectionError``.

The tests use the same ``_check_localemu_running`` session fixture as
the rest of ``tests/e2e/``: if LocalEmu is not running the suite is
skipped.
"""

from __future__ import annotations

import re

import pytest
from botocore.exceptions import ClientError


# Shapes we never want to see again from any of the operations under test.
_BAD_PATTERNS = [
    re.compile(r"InternalFailure", re.IGNORECASE),
    re.compile(r"UnknownServiceError", re.IGNORECASE),
    re.compile(r"No moto route", re.IGNORECASE),
    re.compile(r"NotImplementedError", re.IGNORECASE),
]


def _assert_not_internalfailure(exc: Exception) -> None:
    """Reject the failure shapes the 1.0.0 release was leaking."""
    blob = repr(exc)
    for pat in _BAD_PATTERNS:
        assert not pat.search(blob), (
            f"Operation regressed to a 1.0.0-style internal leak: {blob}"
        )


@pytest.fixture
def ec2_client():
    # Local import keeps this file independent of conftest fixture ordering.
    import boto3
    from botocore.config import Config
    import os
    return boto3.client(
        "ec2",
        endpoint_url=os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566"),
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 0}),
    )


@pytest.fixture
def ssm_client():
    import boto3
    from botocore.config import Config
    import os
    return boto3.client(
        "ssm",
        endpoint_url=os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566"),
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 0}),
    )


@pytest.fixture
def backup_client():
    import boto3
    from botocore.config import Config
    import os
    return boto3.client(
        "backup",
        endpoint_url=os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566"),
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 0}),
    )


# --------------------------------------------------------------------------
# PR #1 Snapshot Block Public Access
# --------------------------------------------------------------------------

class TestSnapshotBlockPublicAccess:
    def test_get_state_returns_well_formed_default(self, ec2_client):
        resp = ec2_client.get_snapshot_block_public_access_state()
        assert "State" in resp
        assert resp["State"] in {"unblocked", "block-all-sharing", "block-new-sharing"}
        assert resp.get("ManagedBy") in {"account", "declarative-policy"}

    def test_enable_then_get_is_consistent(self, ec2_client):
        ec2_client.enable_snapshot_block_public_access(State="block-all-sharing")
        assert ec2_client.get_snapshot_block_public_access_state()["State"] == "block-all-sharing"
        # reset to a known state
        ec2_client.disable_snapshot_block_public_access()

    def test_enable_with_unblocked_is_typed_error_not_internal_failure(self, ec2_client):
        with pytest.raises(ClientError) as exc:
            ec2_client.enable_snapshot_block_public_access(State="unblocked")
        _assert_not_internalfailure(exc.value)
        assert exc.value.response["Error"]["Code"] in {
            "InvalidParameterValue", "ValidationError",
        }


# --------------------------------------------------------------------------
# PR #1 Serial Console
# --------------------------------------------------------------------------

class TestSerialConsole:
    def test_get_status_returns_boolean(self, ec2_client):
        resp = ec2_client.get_serial_console_access_status()
        assert "SerialConsoleAccessEnabled" in resp
        assert isinstance(resp["SerialConsoleAccessEnabled"], bool)

    def test_enable_disable_round_trip(self, ec2_client):
        ec2_client.enable_serial_console_access()
        assert ec2_client.get_serial_console_access_status()["SerialConsoleAccessEnabled"] is True
        ec2_client.disable_serial_console_access()
        assert ec2_client.get_serial_console_access_status()["SerialConsoleAccessEnabled"] is False


# --------------------------------------------------------------------------
# PR #2 VPC Block Public Access (Options + Exclusions)
# --------------------------------------------------------------------------

class TestVpcBlockPublicAccess:
    def test_describe_options_returns_well_formed_default(self, ec2_client):
        resp = ec2_client.describe_vpc_block_public_access_options()
        opts = resp["VpcBlockPublicAccessOptions"]
        assert opts["State"] == "default-state"
        assert opts["InternetGatewayBlockMode"] in {
            "off", "block-bidirectional", "block-ingress",
        }

    def test_modify_options_transitions_synchronously(self, ec2_client):
        try:
            r = ec2_client.modify_vpc_block_public_access_options(
                InternetGatewayBlockMode="block-ingress",
            )
            assert r["VpcBlockPublicAccessOptions"]["InternetGatewayBlockMode"] == "block-ingress"
            assert r["VpcBlockPublicAccessOptions"]["State"] == "update-complete"
        finally:
            ec2_client.modify_vpc_block_public_access_options(InternetGatewayBlockMode="off")

    def test_exclusion_crud_round_trip(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.40.0.0/16")["Vpc"]["VpcId"]
        try:
            x = ec2_client.create_vpc_block_public_access_exclusion(
                VpcId=vpc, InternetGatewayExclusionMode="allow-bidirectional",
            )["VpcBlockPublicAccessExclusion"]
            assert x["ExclusionId"].startswith("vpcbpa-excl-")
            assert x["State"] in {"create-in-progress", "create-complete"}

            d = ec2_client.describe_vpc_block_public_access_exclusions(
                ExclusionIds=[x["ExclusionId"]],
            )["VpcBlockPublicAccessExclusions"]
            assert len(d) == 1 and d[0]["ExclusionId"] == x["ExclusionId"]

            ec2_client.delete_vpc_block_public_access_exclusion(
                ExclusionId=x["ExclusionId"],
            )
        finally:
            ec2_client.delete_vpc(VpcId=vpc)


# --------------------------------------------------------------------------
# PR #3 EC2 Instance Connect Endpoint
# --------------------------------------------------------------------------

class TestInstanceConnectEndpoint:
    def test_describe_empty_returns_empty_list_not_internal_failure(self, ec2_client):
        # This used to return InternalFailure ; pin the typed empty list.
        resp = ec2_client.describe_instance_connect_endpoints()
        assert "InstanceConnectEndpoints" in resp
        assert isinstance(resp["InstanceConnectEndpoints"], list)

    def test_create_describe_delete_round_trip(self, ec2_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.41.0.0/16")["Vpc"]["VpcId"]
        subnet = None
        try:
            subnet = ec2_client.create_subnet(
                VpcId=vpc, CidrBlock="10.41.1.0/24",
            )["Subnet"]["SubnetId"]
            ep = ec2_client.create_instance_connect_endpoint(
                SubnetId=subnet,
            )["InstanceConnectEndpoint"]
            assert re.match(r"^eice-[0-9a-f]{17}$", ep["InstanceConnectEndpointId"])
            assert ep["State"] in {"create-in-progress", "create-complete"}

            d = ec2_client.describe_instance_connect_endpoints(
                InstanceConnectEndpointIds=[ep["InstanceConnectEndpointId"]],
            )["InstanceConnectEndpoints"]
            assert len(d) == 1
            assert d[0]["State"] == "create-complete"

            ec2_client.delete_instance_connect_endpoint(
                InstanceConnectEndpointId=ep["InstanceConnectEndpointId"],
            )
        finally:
            if subnet:
                try:
                    ec2_client.delete_subnet(SubnetId=subnet)
                except ClientError:
                    pass
            ec2_client.delete_vpc(VpcId=vpc)


# --------------------------------------------------------------------------
# PR #5 SSM patch-state stubs
# --------------------------------------------------------------------------

class TestSsmPatchState:
    def test_describe_instance_patch_states(self, ssm_client):
        resp = ssm_client.describe_instance_patch_states(InstanceIds=["i-x"])
        assert resp["InstancePatchStates"] == []

    def test_describe_instance_patch_states_for_patch_group(self, ssm_client):
        resp = ssm_client.describe_instance_patch_states_for_patch_group(PatchGroup="g")
        assert resp["InstancePatchStates"] == []

    def test_get_patch_baseline_unknown_id_is_typed_error(self, ssm_client):
        with pytest.raises(ClientError) as exc:
            # botocore client-side validates BaselineId min length = 20.
            ssm_client.get_patch_baseline(BaselineId="pb-0000000000000000nope")
        _assert_not_internalfailure(exc.value)
        assert exc.value.response["Error"]["Code"] == "DoesNotExistException"


# --------------------------------------------------------------------------
# PR #4 Backup protected-resource overlay
# --------------------------------------------------------------------------

class TestBackupProtectedResources:
    def test_list_protected_resources_empty_is_well_formed(self, backup_client):
        # This used to return InternalFailure leaking moto's internal path.
        resp = backup_client.list_protected_resources()
        assert "Results" in resp
        assert isinstance(resp["Results"], list)

    def test_describe_unknown_is_typed_not_found(self, backup_client):
        with pytest.raises(ClientError) as exc:
            backup_client.describe_protected_resource(
                ResourceArn="arn:aws:ec2:us-east-1:000000000000:instance/i-nope",
            )
        _assert_not_internalfailure(exc.value)
        assert exc.value.response["Error"]["Code"] == "ResourceNotFoundException"
        assert exc.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    def test_create_selection_registers_protected_resource(self, backup_client):
        plan_id = backup_client.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "regression-plan",
                "Rules": [{
                    "RuleName": "d",
                    "TargetBackupVaultName": "default",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                }],
            },
        )["BackupPlanId"]
        try:
            arn = "arn:aws:rds:us-east-1:000000000000:db:scanner-test-db"
            backup_client.create_backup_selection(
                BackupPlanId=plan_id,
                BackupSelection={
                    "SelectionName": "regression-selection",
                    "IamRoleArn": "arn:aws:iam::000000000000:role/r",
                    "Resources": [arn],
                },
            )
            # Now describe the registered protected resource - must be a typed 200.
            desc = backup_client.describe_protected_resource(ResourceArn=arn)
            assert desc["ResourceType"] == "RDS"
            assert desc["ResourceArn"] == arn
        finally:
            try:
                backup_client.delete_backup_plan(BackupPlanId=plan_id)
            except ClientError:
                pass


# --------------------------------------------------------------------------
# IAM enforcement with managed policies (symbol-level smoke)
# --------------------------------------------------------------------------

class TestManagedPolicyMapEnabled:
    """Verify the IAM enforcement map function resolves managed-policy ARNs.

    The full enforcement E2E lives in ``test_s3_iam_enforcement_e2e.py`` ;
    this file pins the symbol-level helpers (managed-policy doc lookup,
    permission-boundary shape extraction, action map) so a regression
    cannot slip past them without the broader fixture being installed.
    """

    def test_action_map_returns_lambda_invoke_function_for_lambda_invoke(self):
        from localemu.services.iam_enforcement.service_action_map import map_action
        assert map_action("lambda", "Invoke") == ["lambda:InvokeFunction"]

    def test_managed_policy_doc_helper_handles_missing(self):
        from localemu.services.iam_enforcement.identity import _get_managed_policy_doc

        class _Backend:
            managed_policies = {}

        assert _get_managed_policy_doc(_Backend(), "arn:aws:iam::aws:policy/Nope") is None

    def test_extract_boundary_arn_accepts_both_shapes(self):
        from localemu.services.iam_enforcement.identity import _extract_boundary_arn
        assert _extract_boundary_arn("arn:aws:iam::aws:policy/X") == "arn:aws:iam::aws:policy/X"
        assert _extract_boundary_arn({"PermissionsBoundaryArn": "arn:y"}) == "arn:y"
        assert _extract_boundary_arn(None) is None
