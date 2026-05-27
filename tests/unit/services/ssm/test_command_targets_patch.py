"""Tests for the moto Command target-expansion patch.

Upstream moto, when Command is constructed with `targets=[]`, still
calls `_get_instance_ids_from_targets`, which constructs an empty
filter dict, which `ec2_backend.all_reservations(filters={})` treats
as "match everything" — leaking every existing EC2 instance into
Command.instance_ids. The patch short-circuits the expansion when
no targets were specified.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

# Triggers the patch
import localemu.services.ssm.patches  # noqa: F401


@mock_aws
def _make_ec2_instances(n: int) -> list[str]:
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sub = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
    )["Subnet"]
    ids: list[str] = []
    for _ in range(n):
        r = ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
        )
        ids.append(r["Instances"][0]["InstanceId"])
    return ids


class TestPatchedCommandTargets:
    @mock_aws
    def test_send_command_with_only_instance_ids_does_not_leak(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ssm = boto3.client("ssm", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
        )["Subnet"]
        ids = []
        for _ in range(5):
            r = ec2.run_instances(
                ImageId="ami-12345678", InstanceType="t2.micro",
                MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
            )
            ids.append(r["Instances"][0]["InstanceId"])

        # Send to one specific instance
        target = ids[0]
        r = ssm.send_command(
            DocumentName="AWS-RunShellScript",
            InstanceIds=[target],
            Parameters={"commands": ["echo HI"]},
        )
        assert r["Command"]["InstanceIds"] == [target], (
            f"Command should carry only the requested InstanceId; "
            f"got {r['Command']['InstanceIds']}"
        )
        assert r["Command"]["TargetCount"] == 1

    @mock_aws
    def test_send_command_with_unknown_instance_id_does_not_leak(self):
        """The original bug surfaced via SSM probes against a fresh
        instance: even an unknown InstanceId would come back in a
        bloated Command. The patch must keep the response narrow."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ssm = boto3.client("ssm", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
        )["Subnet"]
        for _ in range(3):
            ec2.run_instances(
                ImageId="ami-12345678", InstanceType="t2.micro",
                MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
            )

        r = ssm.send_command(
            DocumentName="AWS-RunShellScript",
            InstanceIds=["i-FAKEFAKEFAKEFAKE"],
            Parameters={"commands": ["echo HI"]},
        )
        assert r["Command"]["InstanceIds"] == ["i-FAKEFAKEFAKEFAKE"]
        assert r["Command"]["TargetCount"] == 1

    @mock_aws
    def test_send_command_with_real_targets_still_expands(self):
        """When the caller actually passes Targets={Key,Values}, the
        upstream behavior MUST still kick in (real AWS does this).
        The patch only skips expansion for the empty-targets case."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ssm = boto3.client("ssm", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sub = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
        )["Subnet"]
        ids = []
        for i in range(3):
            r = ec2.run_instances(
                ImageId="ami-12345678", InstanceType="t2.micro",
                MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Team", "Value": "fleet-a"}],
                }],
            )
            ids.append(r["Instances"][0]["InstanceId"])
        # An untagged extra
        r_other = ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=sub["SubnetId"],
        )
        other_id = r_other["Instances"][0]["InstanceId"]

        # Target only Team=fleet-a
        r = ssm.send_command(
            DocumentName="AWS-RunShellScript",
            Targets=[{"Key": "tag:Team", "Values": ["fleet-a"]}],
            Parameters={"commands": ["echo HI"]},
        )
        cmd_ids = set(r["Command"]["InstanceIds"])
        assert cmd_ids == set(ids), (
            f"Tagged targets should resolve to the fleet-a instances only; "
            f"got {cmd_ids}, expected {set(ids)}"
        )
        assert other_id not in cmd_ids
