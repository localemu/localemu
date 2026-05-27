"""E2E: aws ec2 reboot-instances against running LocalEmu.

Before the fix the handler raised NotImplementedError; every
RebootInstances call returned an Internal error to the user.

This E2E proves:
  1. aws ec2 reboot-instances succeeds (no NotImplementedError)
  2. The container is actually restarted (Docker State.StartedAt advances)
  3. The instance stays 'running' in DescribeInstances (matches AWS:
     RebootInstances does NOT cycle the state machine)
  4. The host port mapping survives the restart (so the user's SSH
     into the rebooted instance doesn't see a different port)
"""
from __future__ import annotations

import time
import uuid

import boto3
import pytest
from botocore.config import Config

import docker as docker_sdk

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"


def _ec2():
    return boto3.client(
        "ec2",
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0},
                      connect_timeout=10, read_timeout=120),
    )


def _docker():
    return docker_sdk.from_env()


@pytest.fixture
def instance():
    """Launch a single t2.nano instance against LocalEmu. Tear down after."""
    ec2 = _ec2()
    tag = uuid.uuid4().hex[:6]
    # Use the built-in alpine AMI to keep this fast
    resp = ec2.run_instances(
        ImageId="ami-alpine-3.20",  # localemu built-in
        InstanceType="t2.nano",
        MinCount=1, MaxCount=1,
    )
    iid = resp["Instances"][0]["InstanceId"]
    # Wait for running
    deadline = time.time() + 30
    state = None
    while time.time() < deadline:
        d = ec2.describe_instances(InstanceIds=[iid])
        state = d["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            break
        time.sleep(1)
    assert state == "running", f"instance {iid} stuck at {state}"
    yield iid
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except Exception:
        pass


def _container_startedat(container_name):
    """Return Docker State.StartedAt (string)."""
    c = _docker().containers.get(container_name)
    c.reload()
    return c.attrs["State"]["StartedAt"]


def _container_running(container_name):
    c = _docker().containers.get(container_name)
    c.reload()
    return c.attrs["State"]["Running"]


def _host_port_for_22(container_name):
    c = _docker().containers.get(container_name)
    c.reload()
    ports = c.attrs["NetworkSettings"]["Ports"] or {}
    binding = ports.get("22/tcp")
    if not binding:
        return None
    return binding[0]["HostPort"]


class TestRebootInstances:
    def test_reboot_instance_actually_restarts_container(self, instance):
        ec2 = _ec2()
        container = f"localemu-ec2-{instance}"
        # Record StartedAt BEFORE reboot
        before = _container_startedat(container)
        host_port_before = _host_port_for_22(container)
        # Reboot via the AWS API — this is the path that used to NotImplementedError
        ec2.reboot_instances(InstanceIds=[instance])
        # Wait for the StartedAt to change (Docker restart fires SIGTERM/SIGKILL)
        deadline = time.time() + 30
        after = before
        while time.time() < deadline and after == before:
            time.sleep(1)
            try:
                after = _container_startedat(container)
            except Exception:
                pass
        assert after != before, (
            f"Container {container} StartedAt did not advance after reboot. "
            f"Before: {before} After: {after}"
        )
        # Container is still running after the restart
        assert _container_running(container), (
            f"Container {container} not running after reboot"
        )
        # Host port for SSH preserved (Docker restart keeps port bindings)
        host_port_after = _host_port_for_22(container)
        assert host_port_before == host_port_after, (
            f"Host port changed across reboot: "
            f"{host_port_before} -> {host_port_after}"
        )

    def test_instance_stays_running_in_describe(self, instance):
        ec2 = _ec2()
        ec2.reboot_instances(InstanceIds=[instance])
        # AWS contract: RebootInstances does NOT change the instance
        # state machine. The instance stays 'running' throughout.
        time.sleep(2)
        d = ec2.describe_instances(InstanceIds=[instance])
        state = d["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state == "running", (
            f"Instance should stay 'running' after reboot; got {state}"
        )

    def test_reboot_unknown_instance_raises_invalid_id(self):
        """Sanity: RebootInstances on a non-existent instance returns
        the right AWS error (not InternalError as the old NotImplementedError
        would have)."""
        ec2 = _ec2()
        from botocore.exceptions import ClientError
        with pytest.raises(ClientError) as excinfo:
            ec2.reboot_instances(InstanceIds=["i-deadbeef00000000"])
        # InvalidInstanceID.NotFound is what AWS returns
        code = excinfo.value.response.get("Error", {}).get("Code", "")
        assert "Invalid" in code or "NotFound" in code, (
            f"Expected InvalidInstanceID-shape error, got {code}"
        )
