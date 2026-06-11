"""End-to-end tests for ``ec2:SourceDestCheck`` data-plane forwarding
(PR-006 subsystem C).

Each test:
  1. Creates a VPC / subnet / instance with default ``SourceDestCheck=true``.
  2. Verifies ``net.ipv4.ip_forward=0`` inside the container.
  3. Calls ``ec2:ModifyInstanceAttribute --no-source-dest-check``.
  4. Verifies ``net.ipv4.ip_forward=1`` inside the container.
  5. Restarts the container and re-verifies the marker file persists
     the change.

Skips cleanly on hosts without Docker.
"""
from __future__ import annotations

import shutil
import subprocess
import time

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host; SourceDestCheck E2E cannot run",
)


def _wait_running(cname: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", cname],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip() == "true":
            return
        time.sleep(0.5)
    raise AssertionError(f"container {cname} did not reach Running within {timeout}s")


def _ip_forward(cname: str) -> str:
    r = subprocess.run(
        ["docker", "exec", cname, "cat", "/proc/sys/net/ipv4/ip_forward"],
        capture_output=True, text=True, timeout=10,
    )
    return (r.stdout or "").strip()


def _has_marker(cname: str) -> bool:
    r = subprocess.run(
        ["docker", "exec", cname, "test", "-f",
         "/var/lib/localemu/source-dest-check-disabled"],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0


def _iptables_forward_policy(cname: str) -> str:
    """Return the FORWARD chain's default policy: 'ACCEPT' or 'DROP'."""
    r = subprocess.run(
        ["docker", "exec", cname, "iptables", "-S", "FORWARD"],
        capture_output=True, text=True, timeout=10,
    )
    # First line shape: ``-P FORWARD ACCEPT`` or ``-P FORWARD DROP``.
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("-P FORWARD"):
            return line.split()[-1].upper()
    return "UNKNOWN"


def _iptables_forward_dump(cname: str) -> str:
    """Full ``iptables -S FORWARD`` output for diagnostic asserts."""
    r = subprocess.run(
        ["docker", "exec", cname, "iptables", "-S", "FORWARD"],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout or ""


def _make_vpc_subnet(ec2):
    vpc = ec2.create_vpc(CidrBlock="10.236.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.236.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    return vpc, sub


def _cleanup_vpc(ec2, vpc, sub):
    for fn in (
        lambda: ec2.delete_subnet(SubnetId=sub),
        lambda: ec2.delete_vpc(VpcId=vpc),
    ):
        try:
            fn()
        except Exception:
            pass


def _run_instance(ec2, sub):
    iid = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sub,
    )["Instances"][0]["InstanceId"]
    cname = f"localemu-ec2-{iid}"
    _wait_running(cname)
    return iid, cname


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_default_instance_has_source_dest_check_enabled(ec2_client):
    """Fresh instances default to ip_forward=0 (the secure default)."""
    vpc, sub = _make_vpc_subnet(ec2_client)
    try:
        iid, cname = _run_instance(ec2_client, sub)
        try:
            assert _ip_forward(cname) == "0"
            assert not _has_marker(cname)
        finally:
            ec2_client.terminate_instances(InstanceIds=[iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub)


def test_default_instance_has_forward_chain_policy_drop(ec2_client):
    """The decisive evidence the PR-006 LeadDev asked for: a fresh
    instance's iptables FORWARD chain must be ``-P FORWARD DROP``,
    not the Docker default of ACCEPT.

    Without this, the secure (SourceDestCheck=true) and insecure
    (SourceDestCheck=false) states are indistinguishable on the wire
    — forwarding works regardless of the attribute, and the Quiet
    Router scenario (E4) is silently always-on.
    """
    vpc, sub = _make_vpc_subnet(ec2_client)
    try:
        iid, cname = _run_instance(ec2_client, sub)
        try:
            policy = _iptables_forward_policy(cname)
            dump = _iptables_forward_dump(cname)
            assert policy == "DROP", (
                f"FORWARD policy on a default instance is {policy!r}; "
                f"must be DROP for SourceDestCheck=true to actually drop "
                f"forwarded packets.\nFull dump:\n{dump}"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub)


def test_modify_instance_attribute_disable_source_dest_check_enables_forwarding(ec2_client):
    """PR-006 scenario E4 reproduction (Quiet Router)."""
    vpc, sub = _make_vpc_subnet(ec2_client)
    try:
        iid, cname = _run_instance(ec2_client, sub)
        try:
            # Disable SDC via the AWS API.
            ec2_client.modify_instance_attribute(
                InstanceId=iid, SourceDestCheck={"Value": False},
            )
            # Allow the docker exec to land.
            time.sleep(2)
            assert _ip_forward(cname) == "1", (
                "ec2:ModifyInstanceAttribute --no-source-dest-check did not "
                "enable net.ipv4.ip_forward inside the instance container"
            )
            assert _iptables_forward_policy(cname) == "ACCEPT", (
                "FORWARD policy must flip to ACCEPT when SourceDestCheck "
                "is disabled — otherwise the kernel forwards but iptables "
                "still drops, and forwarding silently fails"
            )
            assert _has_marker(cname), (
                "marker file /var/lib/localemu/source-dest-check-disabled was "
                "not created — restart persistence will be lost"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub)


def test_toggle_back_to_source_dest_check_true_disables_forwarding(ec2_client):
    """Setting SourceDestCheck back to true must re-secure the kernel
    AND the iptables FORWARD chain."""
    vpc, sub = _make_vpc_subnet(ec2_client)
    try:
        iid, cname = _run_instance(ec2_client, sub)
        try:
            ec2_client.modify_instance_attribute(
                InstanceId=iid, SourceDestCheck={"Value": False},
            )
            time.sleep(2)
            assert _ip_forward(cname) == "1"
            assert _iptables_forward_policy(cname) == "ACCEPT"

            ec2_client.modify_instance_attribute(
                InstanceId=iid, SourceDestCheck={"Value": True},
            )
            time.sleep(2)
            assert _ip_forward(cname) == "0", (
                "toggling SourceDestCheck back to true must disable kernel "
                "forwarding, restoring the AWS-default secure state"
            )
            assert _iptables_forward_policy(cname) == "DROP", (
                "FORWARD policy must flip back to DROP when SDC is "
                "re-enabled — otherwise the previous --no-source-dest-check "
                "window's ACCEPT state silently survives"
            )
            # The explicit ACCEPT rule the disabled window inserted must
            # also be gone — otherwise it overrides the DROP policy.
            dump = _iptables_forward_dump(cname)
            assert "-A FORWARD -j ACCEPT" not in dump, (
                f"residual ``-A FORWARD -j ACCEPT`` rule from a prior "
                f"--no-source-dest-check window was not cleaned up:\n{dump}"
            )
            assert not _has_marker(cname), (
                "marker file must be removed when SourceDestCheck is re-enabled"
            )
        finally:
            ec2_client.terminate_instances(InstanceIds=[iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub)


def test_marker_file_survives_container_restart(ec2_client):
    """``docker restart`` must keep the SDC=false state."""
    vpc, sub = _make_vpc_subnet(ec2_client)
    try:
        iid, cname = _run_instance(ec2_client, sub)
        try:
            ec2_client.modify_instance_attribute(
                InstanceId=iid, SourceDestCheck={"Value": False},
            )
            time.sleep(2)
            assert _ip_forward(cname) == "1"

            # Restart the container directly (bypassing AWS APIs).
            subprocess.run(["docker", "restart", cname], check=True, timeout=30)
            _wait_running(cname)
            # Give the entrypoint script time to replay the marker.
            time.sleep(2)
            assert _ip_forward(cname) == "1", (
                "restart persistence broken: net.ipv4.ip_forward fell back "
                "to 0 after a container restart even though the marker "
                "file requested forwarding"
            )
            assert _iptables_forward_policy(cname) == "ACCEPT", (
                "restart persistence broken: FORWARD policy fell back to "
                "DROP after restart even though the marker file requested "
                "forwarding"
            )
            assert _has_marker(cname)
        finally:
            ec2_client.terminate_instances(InstanceIds=[iid])
    finally:
        _cleanup_vpc(ec2_client, vpc, sub)
