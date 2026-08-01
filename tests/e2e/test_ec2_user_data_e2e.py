"""End-to-end tests for EC2 user-data execution at instance boot.

These tests run against a live LocalEmu instance with a Docker backend.
Each test:
  1. Creates a VPC + subnet via boto3
  2. Calls ``ec2.run_instances`` with a user-data payload
  3. Waits for the LocalEmu instance container to be running
  4. ``docker exec`` into the container and asserts the side-effect of
     the user-data - the file the script wrote, the package it installed,
     the user it created, ...

They cover the full cloud-init compatible translator
(:mod:`localemu.services.ec2.docker.user_data`):

* shebang script
* ``#cloud-config`` with ``runcmd`` + ``write_files``
* ``#cloud-config`` with ``users`` + ``ssh_authorized_keys``
* gzip-wrapped payload
* MIME multipart with mixed parts
* the one-shot guard (a second run is a no-op)

The tests skip cleanly if Docker isn't available so they don't fail the
suite on host machines without it. They run lazily - each test creates
its own instance and tears it down on teardown.
"""
from __future__ import annotations

import base64
import gzip
import json
import shutil
import subprocess
import time
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host; EC2 container E2E cannot run",
)


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def vpc_and_subnet(ec2_client):
    """Create a VPC + subnet, tear them down at module end."""
    vpc = ec2_client.create_vpc(CidrBlock="10.230.0.0/16")["Vpc"]["VpcId"]
    sub = ec2_client.create_subnet(
        VpcId=vpc, CidrBlock="10.230.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    yield vpc, sub
    # Best-effort cleanup; ignore failures so a test that already
    # tore down its own bits doesn't fail teardown.
    try:
        ec2_client.delete_subnet(SubnetId=sub)
    except Exception:
        pass
    try:
        ec2_client.delete_vpc(VpcId=vpc)
    except Exception:
        pass


def _run_instance(ec2, subnet_id: str, user_data: bytes, *, ami: str = "ami-ubuntu-22.04") -> tuple[str, str]:
    """RunInstances with the given user-data bytes; return (instance_id, container_name).

    ``user_data`` is the raw bytes; boto3 auto-base64-encodes when given a
    bytes value, matching the AWS-CLI default and the reproduction.
    """
    r = ec2.run_instances(
        ImageId=ami, InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
    )
    iid = r["Instances"][0]["InstanceId"]
    cname = f"localemu-ec2-{iid}"
    _wait_container_running(cname, timeout=90)
    return iid, cname


def _wait_container_running(cname: str, timeout: float = 60.0) -> None:
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


def _wait_for(predicate, *, timeout: float = 30.0, interval: float = 0.5) -> bool:
    """Poll ``predicate`` until it returns truthy or ``timeout`` elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _docker_exec(cname: str, *argv: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", cname, *argv],
        capture_output=True, text=True, timeout=timeout,
    )


def _cat_in(cname: str, path: str) -> str:
    return _docker_exec(cname, "cat", path).stdout


def _terminate(ec2, iid: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[iid])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Shebang script (the reproduction case)
# ---------------------------------------------------------------------------


def test_shebang_user_data_executes_and_writes_marker(ec2_client, vpc_and_subnet):
    """The reproduction: ``#!/bin/bash; echo PWNED > /tmp/pwned``."""
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    ud = f"#!/bin/bash\necho PWNED-{tag} > /tmp/pwned_marker\n".encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: f"PWNED-{tag}" in _cat_in(cname, "/tmp/pwned_marker"),
            timeout=30,
        ), (
            "user-data shebang script did not execute: /tmp/pwned_marker "
            "either missing or has wrong content. Check "
            "/var/log/cloud-init-output.log inside the container."
        )
    finally:
        _terminate(ec2_client, iid)


def test_shebang_writes_cloud_init_standard_log_paths(ec2_client, vpc_and_subnet):
    """The spec requires cloud-init-style log paths."""
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    ud = f"#!/bin/sh\necho LOG-{tag}\n".encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        # Process log must contain a start + complete line.
        assert _wait_for(
            lambda: "localemu-cloud-init: starting" in _cat_in(cname, "/var/log/cloud-init.log"),
            timeout=30,
        ), "/var/log/cloud-init.log missing or did not capture the start line"
        assert _wait_for(
            lambda: "localemu-cloud-init: complete" in _cat_in(cname, "/var/log/cloud-init.log"),
            timeout=15,
        ), "/var/log/cloud-init.log did not capture the complete line"
        # Output log must contain the user's stdout.
        assert _wait_for(
            lambda: f"LOG-{tag}" in _cat_in(cname, "/var/log/cloud-init-output.log"),
            timeout=15,
        ), "/var/log/cloud-init-output.log did not capture the user's stdout"
        # Back-compat symlink must point at the output log.
        legacy = _cat_in(cname, "/var/log/user-data.log")
        assert f"LOG-{tag}" in legacy, "user-data.log symlink missing user's stdout"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# Guard / one-shot semantics
# ---------------------------------------------------------------------------


def test_guard_file_prevents_second_run(ec2_client, vpc_and_subnet):
    """Re-invoking the script inside the container must short-circuit."""
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    ud = f"#!/bin/sh\nprintf 'RUN ' >> /tmp/runcount && echo {tag} >> /tmp/runcount\n".encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: tag in _cat_in(cname, "/tmp/runcount"),
            timeout=30,
        ), "first run never produced /tmp/runcount"
        first = _cat_in(cname, "/tmp/runcount")
        # Invoke the wrapper a second time manually.
        _docker_exec(cname, "/var/lib/localemu/user-data.sh")
        second = _cat_in(cname, "/tmp/runcount")
        assert first == second, (
            "guard file failed: second invocation re-ran the script "
            f"(content before: {first!r}, after: {second!r})"
        )
        # Sanity: the guard file exists.
        r = _docker_exec(cname, "test", "-f", "/var/lib/localemu/user-data-ran")
        assert r.returncode == 0, "/var/lib/localemu/user-data-ran not present"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# #cloud-config: runcmd + write_files
# ---------------------------------------------------------------------------


def test_cloud_config_runcmd_and_write_files(ec2_client, vpc_and_subnet):
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    motd_body = f"hello from cloud-init {tag}\n"
    ud = (
        "#cloud-config\n"
        "write_files:\n"
        f"  - path: /etc/motd-{tag}\n"
        f"    content: |\n"
        f"      {motd_body.strip()}\n"
        f"    permissions: '0644'\n"
        "runcmd:\n"
        f"  - echo RAN-{tag} > /tmp/runcmd-out\n"
    ).encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: f"RAN-{tag}" in _cat_in(cname, "/tmp/runcmd-out"),
            timeout=30,
        ), "runcmd directive did not execute"
        assert _wait_for(
            lambda: tag in _cat_in(cname, f"/etc/motd-{tag}"),
            timeout=10,
        ), "write_files directive did not produce the expected file"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# #cloud-config: users + ssh_authorized_keys
# ---------------------------------------------------------------------------


def test_cloud_config_users_directive_creates_user_with_sudoers(ec2_client, vpc_and_subnet):
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:6]
    username = f"alice{tag}"
    ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAAD-fake-test-key alice@e2e"

    ud = (
        "#cloud-config\n"
        "users:\n"
        f"  - name: {username}\n"
        "    shell: /bin/bash\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    ssh_authorized_keys:\n"
        f"      - {ssh_key}\n"
    ).encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: _docker_exec(cname, "id", username).returncode == 0,
            timeout=30,
        ), f"user {username} was never created"
        sudoers = _cat_in(cname, f"/etc/sudoers.d/{username}")
        assert "NOPASSWD" in sudoers, "sudoers directive did not write the NOPASSWD line"
        auth = _cat_in(cname, f"/home/{username}/.ssh/authorized_keys")
        assert ssh_key in auth, "ssh_authorized_keys did not land in authorized_keys"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# Gzip-wrapped payload
# ---------------------------------------------------------------------------


def test_gzip_wrapped_user_data_is_decompressed_and_executed(ec2_client, vpc_and_subnet):
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    inner = f"#!/bin/sh\necho GZ-{tag} > /tmp/gz-marker\n".encode()
    ud = gzip.compress(inner)
    assert ud[:2] == b"\x1f\x8b"

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: f"GZ-{tag}" in _cat_in(cname, "/tmp/gz-marker"),
            timeout=30,
        ), "gzip-wrapped user-data did not execute after decompression"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# MIME multipart
# ---------------------------------------------------------------------------


def test_mime_multipart_with_shellscript_and_cloud_config_parts(ec2_client, vpc_and_subnet):
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    boundary = "LECRBOUNDARY"
    parts = [
        f"--{boundary}",
        "Content-Type: text/x-shellscript",
        "",
        f"#!/bin/sh\necho SH-{tag} > /tmp/sh-marker\n",
        f"--{boundary}",
        "Content-Type: text/cloud-config",
        "",
        f"runcmd:\n  - echo CC-{tag} > /tmp/cc-marker\n",
        f"--{boundary}--",
    ]
    ud = (
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\n"
        "MIME-Version: 1.0\n\n"
        + "\n".join(parts)
    ).encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: f"SH-{tag}" in _cat_in(cname, "/tmp/sh-marker"),
            timeout=30,
        ), "MIME shellscript part did not run"
        assert _wait_for(
            lambda: f"CC-{tag}" in _cat_in(cname, "/tmp/cc-marker"),
            timeout=15,
        ), "MIME cloud-config part did not run"
    finally:
        _terminate(ec2_client, iid)


# ---------------------------------------------------------------------------
# Cloud-config-archive (JSON list embedded in user-data)
# ---------------------------------------------------------------------------


def test_cloud_config_archive_runs_each_entry(ec2_client, vpc_and_subnet):
    """Single archive part with multiple inner entries - verifies recursion."""
    _vpc, subnet = vpc_and_subnet
    tag = uuid.uuid4().hex[:8]
    archive = json.dumps([
        {
            "type": "text/x-shellscript",
            "content": f"#!/bin/sh\necho ARCH-SH-{tag} > /tmp/arch-sh\n",
        },
        {
            "type": "text/cloud-config",
            "content": f"runcmd:\n  - echo ARCH-CC-{tag} > /tmp/arch-cc\n",
        },
    ])
    boundary = "ARCHBND"
    ud = (
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\n"
        "MIME-Version: 1.0\n\n"
        f"--{boundary}\n"
        "Content-Type: text/cloud-config-archive\n\n"
        f"{archive}\n"
        f"--{boundary}--\n"
    ).encode()

    iid, cname = _run_instance(ec2_client, subnet, ud)
    try:
        assert _wait_for(
            lambda: f"ARCH-SH-{tag}" in _cat_in(cname, "/tmp/arch-sh"),
            timeout=30,
        ), "archive shellscript entry did not run"
        assert _wait_for(
            lambda: f"ARCH-CC-{tag}" in _cat_in(cname, "/tmp/arch-cc"),
            timeout=15,
        ), "archive cloud-config entry did not run"
    finally:
        _terminate(ec2_client, iid)
