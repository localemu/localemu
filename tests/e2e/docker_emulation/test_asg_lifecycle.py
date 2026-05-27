"""E2E: Auto Scaling Group lifecycle via boto3 against running LocalEmu.

Closes audit bug #14: previously, ``aws autoscaling create-auto-
scaling-group --desired-capacity 3 ...`` only recorded the metadata
in moto and launched ZERO containers. With the AutoscalingProvider +
reconciler in place, every membership-mutating verb drives the
Docker container plane via vm_manager.

What this proves end-to-end through the LocalEmu HTTP API:

  1. CreateAutoScalingGroup(DesiredCapacity=2) launches 2 containers
     tagged with the ASG group name; DescribeInstances confirms.
  2. SetDesiredCapacity(3) launches one more container.
  3. SetDesiredCapacity(1) terminates 2 containers, leaving 1.
  4. DeleteAutoScalingGroup --force-delete terminates the remaining
     container.
  5. Multi-subnet ASG: round-robin subnet distribution across the
     VPCZoneIdentifier list (fixes moto's "always first subnet" bug
     per DESIGN_asg.md §4).

Requires LocalEmu running with EC2_VM_MANAGER=docker.
"""
from __future__ import annotations

import time
import uuid

import boto3
import pytest
from botocore.config import Config

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"


def _client(name):
    return boto3.client(
        name, endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0},
                      connect_timeout=10, read_timeout=60),
    )


def _list_asg_instance_ids(ec2, group_name: str) -> list[str]:
    """Return the live (non-terminated) instance IDs tagged with the
    ASG group name. AWS auto-applies the
    ``aws:autoscaling:groupName`` tag to every ASG-launched instance,
    so this is the natural query."""
    r = ec2.describe_instances(
        Filters=[
            {"Name": "tag:aws:autoscaling:groupName", "Values": [group_name]},
        ],
    )
    return sorted(
        inst["InstanceId"]
        for res in r["Reservations"] for inst in res["Instances"]
        if inst["State"]["Name"] not in ("terminated", "shutting-down")
    )


def _wait_count(ec2, group_name: str, expected: int,
                 timeout: int = 30) -> list[str]:
    deadline = time.time() + timeout
    last: list[str] = []
    while time.time() < deadline:
        last = _list_asg_instance_ids(ec2, group_name)
        if len(last) == expected:
            return last
        time.sleep(1)
    return last


@pytest.fixture
def env():
    ec2 = _client("ec2"); asg = _client("autoscaling")
    tag = uuid.uuid4().hex[:6]
    vpc = ec2.create_vpc(CidrBlock=f"10.{231 + (hash(tag) % 20)}.0.0/16")["Vpc"]
    sub_a = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=vpc["CidrBlock"].replace("0.0/16", "1.0/24"),
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]
    sub_b = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=vpc["CidrBlock"].replace("0.0/16", "2.0/24"),
        AvailabilityZone=f"{REGION}b",
    )["Subnet"]
    lt_name = f"lt-{tag}"
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": "ami-alpine-3.20",
            "InstanceType": "t2.nano",
        },
    )["LaunchTemplate"]
    yield {
        "ec2": ec2, "asg": asg, "tag": tag,
        "vpc_id": vpc["VpcId"],
        "subnet_a": sub_a["SubnetId"], "subnet_b": sub_b["SubnetId"],
        "launch_template_id": lt["LaunchTemplateId"],
        "launch_template_name": lt_name,
    }


class TestAsgBasicLifecycle:
    def test_create_launches_real_containers(self, env):
        group_name = f"asg-create-{env['tag']}"
        env["asg"].create_auto_scaling_group(
            AutoScalingGroupName=group_name,
            LaunchTemplate={
                "LaunchTemplateId": env["launch_template_id"],
                "Version": "$Latest",
            },
            MinSize=1, MaxSize=3, DesiredCapacity=2,
            VPCZoneIdentifier=env["subnet_a"],
        )
        try:
            ids = _wait_count(env["ec2"], group_name, 2)
            assert len(ids) == 2, (
                f"CreateAutoScalingGroup(DesiredCapacity=2) should "
                f"have launched 2 instances; got {ids}"
            )
        finally:
            env["asg"].delete_auto_scaling_group(
                AutoScalingGroupName=group_name, ForceDelete=True,
            )

    def test_set_desired_capacity_scales_up_and_down(self, env):
        group_name = f"asg-scale-{env['tag']}"
        env["asg"].create_auto_scaling_group(
            AutoScalingGroupName=group_name,
            LaunchTemplate={
                "LaunchTemplateId": env["launch_template_id"],
                "Version": "$Latest",
            },
            MinSize=1, MaxSize=5, DesiredCapacity=2,
            VPCZoneIdentifier=env["subnet_a"],
        )
        try:
            assert len(_wait_count(env["ec2"], group_name, 2)) == 2

            # Scale up to 4
            env["asg"].set_desired_capacity(
                AutoScalingGroupName=group_name, DesiredCapacity=4,
            )
            after_up = _wait_count(env["ec2"], group_name, 4)
            assert len(after_up) == 4, after_up

            # Scale down to 1
            env["asg"].set_desired_capacity(
                AutoScalingGroupName=group_name, DesiredCapacity=1,
            )
            after_down = _wait_count(env["ec2"], group_name, 1)
            assert len(after_down) == 1, after_down
        finally:
            env["asg"].delete_auto_scaling_group(
                AutoScalingGroupName=group_name, ForceDelete=True,
            )

    def test_delete_force_terminates_remaining_containers(self, env):
        group_name = f"asg-del-{env['tag']}"
        env["asg"].create_auto_scaling_group(
            AutoScalingGroupName=group_name,
            LaunchTemplate={
                "LaunchTemplateId": env["launch_template_id"],
                "Version": "$Latest",
            },
            MinSize=0, MaxSize=3, DesiredCapacity=2,
            VPCZoneIdentifier=env["subnet_a"],
        )
        assert len(_wait_count(env["ec2"], group_name, 2)) == 2

        env["asg"].delete_auto_scaling_group(
            AutoScalingGroupName=group_name, ForceDelete=True,
        )
        # DescribeAutoScalingGroups no longer lists the group
        groups = env["asg"].describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name],
        )["AutoScalingGroups"]
        assert groups == [], groups
        # And all instances are gone (terminated)
        assert _wait_count(env["ec2"], group_name, 0, timeout=20) == []


class TestAsgMultiSubnet:
    def test_round_robin_distributes_across_subnets(self, env):
        """With 2 subnets + DesiredCapacity=4, AWS spreads 2 per
        subnet. moto's upstream behavior was 'all in the first
        subnet'; the reconciler's round-robin fixes this."""
        group_name = f"asg-multi-{env['tag']}"
        env["asg"].create_auto_scaling_group(
            AutoScalingGroupName=group_name,
            LaunchTemplate={
                "LaunchTemplateId": env["launch_template_id"],
                "Version": "$Latest",
            },
            MinSize=1, MaxSize=4, DesiredCapacity=4,
            VPCZoneIdentifier=f"{env['subnet_a']},{env['subnet_b']}",
        )
        try:
            ids = _wait_count(env["ec2"], group_name, 4, timeout=45)
            assert len(ids) == 4
            # Group by SubnetId — should be 2 in each
            r = env["ec2"].describe_instances(InstanceIds=ids)
            subnet_counts: dict[str, int] = {}
            for res in r["Reservations"]:
                for inst in res["Instances"]:
                    sub = inst.get("SubnetId")
                    if sub:
                        subnet_counts[sub] = subnet_counts.get(sub, 0) + 1
            assert subnet_counts.get(env["subnet_a"], 0) == 2 and \
                   subnet_counts.get(env["subnet_b"], 0) == 2, (
                f"Expected even split across subnets; got {subnet_counts}"
            )
        finally:
            env["asg"].delete_auto_scaling_group(
                AutoScalingGroupName=group_name, ForceDelete=True,
            )
