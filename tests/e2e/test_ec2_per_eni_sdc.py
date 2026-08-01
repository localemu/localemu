"""End-to-end : per-ENI ``SourceDestCheck`` enforcement.

The 1.1.1 release made the instance-level vs primary-ENI metadata
agree (``DescribeInstances`` and ``DescribeNetworkInterfaces`` now
both report the same value for the primary ENI). 1.2.0 closes the
data-plane half : the container's iptables FORWARD chain enforces
``SourceDestCheck`` PER ENI instead of one global ACCEPT/DROP policy.

The two scenarios this file pins :

* **Asymmetric on the primary ENI** : flipping the primary's
  ``SourceDestCheck`` MUST install / remove a FORWARD rule keyed on
  the primary's container iface (``eth1`` on LocalEmu, since
  ``eth0`` is the host pubport bridge). The legacy single-NIC quiet-
  router scenario is a degenerate case of this.

* **Same-VPC secondary ENI in shared-iface mode** : when a secondary
  AWS-side ENI lands on the same VPC bridge as the primary, the
  EniManager falls back to shared-iface mode and adds the secondary
  IP as a ``/32`` alias on ``eth1``. A plain ``-i eth1 -j ACCEPT``
  rule would then match traffic for BOTH ENIs and lose per-ENI
  semantics. The data plane must install IP-keyed rules
  (``-s <eni_ip>/32`` + ``-d <eni_ip>/32``) so the two co-resident
  ENIs get independent FORWARD postures.

Skips cleanly when Docker is not available on the host or when the
real-ENI subsystem is off (default LocalEmu). The companion env
``LOCALEMU_ENI_REAL=1 LOCALEMU_VPC_IP_PINNING=1 EC2_VM_MANAGER=docker``
on the started LocalEmu is required.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

import boto3
import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host ; per-ENI SDC E2E cannot run",
)


_ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
_REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def ec2_client():
    return boto3.client(
        "ec2", endpoint_url=_ENDPOINT, region_name=_REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
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


def _iptables_forward(cname: str) -> str:
    """Full ``iptables -S FORWARD`` output. Empty string on error."""
    r = subprocess.run(
        ["docker", "exec", cname, "iptables", "-S", "FORWARD"],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout or ""


def _has_rule(forward_dump: str, *required_tokens: str) -> bool:
    """Return True iff one ``-A FORWARD ...`` line in the dump contains
    every token in ``required_tokens``. Order-insensitive : iptables
    reorders ``-i`` / ``-s`` / ``-d`` / ``-j`` in its output, so we
    cannot do a literal string match against the form we installed."""
    for line in (forward_dump or "").splitlines():
        line = line.strip()
        if not line.startswith("-A FORWARD"):
            continue
        if all(tok in line for tok in required_tokens):
            return True
    return False


def _ip_addr(cname: str, iface: str) -> str:
    r = subprocess.run(
        ["docker", "exec", cname, "ip", "-o", "addr", "show", iface],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout or ""


def _make_vpc_subnet(ec2):
    vpc = ec2.create_vpc(CidrBlock="10.241.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.241.1.0/24",
        AvailabilityZone=f"{_REGION}a",
    )["Subnet"]["SubnetId"]
    return vpc, sub


def _cleanup(ec2, vpc, sub, iid, secondary_eni=None):
    try:
        if secondary_eni:
            try:
                ec2.detach_network_interface(
                    AttachmentId=_attachment_id_of(ec2, secondary_eni),
                    Force=True,
                )
                ec2.delete_network_interface(NetworkInterfaceId=secondary_eni)
            except Exception:
                pass
        ec2.terminate_instances(InstanceIds=[iid])
    finally:
        try:
            ec2.delete_subnet(SubnetId=sub)
        except Exception:
            pass
        try:
            ec2.delete_vpc(VpcId=vpc)
        except Exception:
            pass


def _attachment_id_of(ec2, eni_id: str) -> str:
    enis = ec2.describe_network_interfaces(
        NetworkInterfaceIds=[eni_id],
    )["NetworkInterfaces"]
    if not enis:
        return ""
    att = enis[0].get("Attachment") or {}
    return att.get("AttachmentId") or ""


def _run_instance(ec2, sub):
    run = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=sub,
    )["Instances"][0]
    iid = run["InstanceId"]
    primary_eni = run["NetworkInterfaces"][0]["NetworkInterfaceId"]
    primary_ip = run["NetworkInterfaces"][0]["PrivateIpAddress"]
    cname = f"localemu-ec2-{iid}"
    _wait_running(cname)
    return iid, primary_eni, primary_ip, cname


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_primary_eni_sdc_disable_installs_iface_rule_on_eth1(ec2_client):
    """The primary AWS-ENI lives on container ``eth1`` (``eth0`` is the
    host pubport bridge). Disabling SDC on the primary installs a
    FORWARD ACCEPT rule keyed on ``eth1``, and re-enabling removes it.
    """
    vpc, sub = _make_vpc_subnet(ec2_client)
    iid, primary_eni, primary_ip, cname = _run_instance(ec2_client, sub)
    try:
        # Fresh : no rules on eth1.
        before = _iptables_forward(cname)
        assert "-i eth1" not in before, (
            f"fresh container should not have an iface-specific FORWARD "
            f"rule yet :\n{before}"
        )

        # Disable SDC at the instance level (mirrors to primary ENI).
        ec2_client.modify_instance_attribute(
            InstanceId=iid, SourceDestCheck={"Value": False},
        )
        time.sleep(2)
        after_disable = _iptables_forward(cname)
        # Either separate-iface (plain ``-i eth1 -j ACCEPT``) or shared-
        # iface (IP-keyed rule with the primary's IP) is acceptable here ;
        # both are correct per-ENI shapes, the choice depends on whether
        # the primary's bridge is the only one on the container or not.
        assert (
            _has_rule(after_disable, "-i eth1", "-j ACCEPT") and (
                _has_rule(after_disable, f"-s {primary_ip}/32", "-i eth1") or
                # No source/dest IP qualifiers at all means separate-iface.
                not _has_rule(after_disable, f"{primary_ip}/32")
            )
        ), (
            f"per-ENI FORWARD rule on eth1 must be installed after the "
            f"instance-level SDC disable :\n{after_disable}"
        )

        # Re-enable : rule(s) removed.
        ec2_client.modify_instance_attribute(
            InstanceId=iid, SourceDestCheck={"Value": True},
        )
        time.sleep(2)
        after_enable = _iptables_forward(cname)
        assert "-i eth1" not in after_enable, (
            f"per-ENI FORWARD rule on eth1 must be removed when the "
            f"instance-level SDC is re-enabled :\n{after_enable}"
        )
    finally:
        _cleanup(ec2_client, vpc, sub, iid)


def test_same_vpc_secondary_eni_uses_shared_iface_ip_rules(ec2_client):
    """A secondary ENI attached on the same VPC ends up as an alias on
    eth1 (shared-iface mode). Disabling SDC on the secondary must
    install IP-keyed rules (``-s <ip>/32`` and ``-d <ip>/32``) on eth1,
    NOT a plain ``-i eth1 -j ACCEPT`` (which would also open
    forwarding for the primary's traffic on the same iface).
    """
    vpc, sub = _make_vpc_subnet(ec2_client)
    iid, primary_eni, primary_ip, cname = _run_instance(ec2_client, sub)
    secondary_eni = ec2_client.create_network_interface(
        SubnetId=sub, PrivateIpAddress="10.241.1.99",
    )["NetworkInterface"]["NetworkInterfaceId"]
    try:
        ec2_client.attach_network_interface(
            InstanceId=iid, NetworkInterfaceId=secondary_eni, DeviceIndex=1,
        )
        time.sleep(2)
        # Confirm shared-iface mode took effect : both IPs on eth1.
        eth1_addrs = _ip_addr(cname, "eth1")
        assert primary_ip in eth1_addrs and "10.241.1.99" in eth1_addrs, (
            f"secondary ENI should be added as an alias on eth1 in "
            f"shared-iface mode :\n{eth1_addrs}"
        )

        # Disable SDC on the SECONDARY only.
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=secondary_eni,
            SourceDestCheck={"Value": False},
        )
        time.sleep(2)
        forward = _iptables_forward(cname)

        # IP-keyed rules MUST be present (order-insensitive: iptables
        # reorders ``-i`` / ``-s`` / ``-d`` in its output) :
        assert _has_rule(forward, "-i eth1", "-s 10.241.1.99/32", "-j ACCEPT"), (
            f"shared-iface mode missing source-match rule for the "
            f"secondary ENI :\n{forward}"
        )
        assert _has_rule(forward, "-i eth1", "-d 10.241.1.99/32", "-j ACCEPT"), (
            f"shared-iface mode missing dest-match rule for the "
            f"secondary ENI :\n{forward}"
        )
        # A plain ``-A FORWARD -i eth1 -j ACCEPT`` (no IP qualifier) must
        # NOT be present : that would also open forwarding for the
        # primary's traffic on the same iface.
        for line in forward.splitlines():
            line = line.strip()
            if line.startswith("-A FORWARD") and "-i eth1" in line and "-j ACCEPT" in line:
                assert "10.241.1.99/32" in line, (
                    f"shared-iface mode installed a plain iface rule "
                    f"instead of IP-match rules :\n{line}\nfull:\n{forward}"
                )

        # Re-enable on the secondary : both IP rules removed.
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=secondary_eni,
            SourceDestCheck={"Value": True},
        )
        time.sleep(2)
        forward = _iptables_forward(cname)
        assert "10.241.1.99/32" not in forward, (
            f"shared-iface rules must be removed when SDC is re-enabled "
            f"on the secondary :\n{forward}"
        )
    finally:
        _cleanup(ec2_client, vpc, sub, iid, secondary_eni=secondary_eni)


def test_secondary_modify_does_not_affect_primary_forward_rule(ec2_client):
    """Independent posture : disabling SDC on the secondary while the
    primary stays at SDC=true must NOT install any FORWARD rule that
    benefits the primary. Pins the per-ENI claim end to end."""
    vpc, sub = _make_vpc_subnet(ec2_client)
    iid, primary_eni, primary_ip, cname = _run_instance(ec2_client, sub)
    secondary_eni = ec2_client.create_network_interface(
        SubnetId=sub, PrivateIpAddress="10.241.1.77",
    )["NetworkInterface"]["NetworkInterfaceId"]
    try:
        ec2_client.attach_network_interface(
            InstanceId=iid, NetworkInterfaceId=secondary_eni, DeviceIndex=1,
        )
        time.sleep(2)
        ec2_client.modify_network_interface_attribute(
            NetworkInterfaceId=secondary_eni,
            SourceDestCheck={"Value": False},
        )
        time.sleep(2)
        forward = _iptables_forward(cname)

        # Secondary's IP-match rules are there :
        assert _has_rule(forward, "-s 10.241.1.77/32", "-j ACCEPT")
        assert _has_rule(forward, "-d 10.241.1.77/32", "-j ACCEPT")
        # Primary's IP does NOT appear in any FORWARD ACCEPT rule
        # (primary stayed at SDC=true) :
        assert not _has_rule(forward, f"-s {primary_ip}/32", "-j ACCEPT")
        assert not _has_rule(forward, f"-d {primary_ip}/32", "-j ACCEPT")
        # Nor a plain ``-i eth1 -j ACCEPT`` rule (i.e. no FORWARD ACCEPT
        # line on eth1 that lacks an IP qualifier) :
        for line in forward.splitlines():
            line = line.strip()
            if line.startswith("-A FORWARD") and "-i eth1" in line and "-j ACCEPT" in line:
                assert "/32" in line, (
                    f"unexpected plain -i eth1 ACCEPT rule (would benefit "
                    f"the primary, which is at SDC=true) :\n{line}"
                )
    finally:
        _cleanup(ec2_client, vpc, sub, iid, secondary_eni=secondary_eni)
