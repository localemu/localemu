"""E2E: NACL stateless contract via boto3 against running LocalEmu.

AWS NACLs are stateless: every packet (request AND response) is
evaluated against the inbound/outbound rules independently. Unlike
Security Groups, conntrack does NOT auto-permit return traffic.

What this proves end-to-end through the LocalEmu HTTP API:

  1. Custom NACL rules submitted via CreateNetworkAclEntry actually
     reach the container's iptables (real enforcement, not metadata).
  2. A deny-egress rule blocks outbound TCP — request never leaves.
  3. STATELESS: allow-all-egress + ingress-only-on-22 breaks an
     HTTP request to port 80 on the peer, because the peer's
     response packet (going back to the client's high ephemeral
     port) is dropped by the ingress chain. A stateful firewall
     would have auto-permitted it via conntrack ESTABLISHED.
  4. Once the ephemeral port range is explicitly allowed inbound,
     the HTTP request succeeds — proving the stateless contract is
     honored when both directions are independently permitted.

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


def _ec2():
    return boto3.client(
        "ec2", endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0},
                      connect_timeout=10, read_timeout=120),
    )


def _ssm():
    return boto3.client(
        "ssm", endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        config=Config(retries={"max_attempts": 0},
                      connect_timeout=10, read_timeout=120),
    )


def _wait_running(ec2, iid: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = ec2.describe_instances(InstanceIds=[iid])
        st = r["Reservations"][0]["Instances"][0]["State"]["Name"]
        if st == "running":
            return True
        time.sleep(1)
    return False


def _ssm_run(ssm, iid: str, cmd: str, timeout: int = 30) -> tuple[int, str]:
    r = ssm.send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[iid], Parameters={"commands": [cmd]},
    )
    cid = r["Command"]["CommandId"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except Exception:
            time.sleep(1); continue
        if inv.get("Status") in ("Success", "Failed", "TimedOut", "Cancelled"):
            return (int(inv.get("ResponseCode", -1)),
                    (inv.get("StandardOutputContent") or ""))
        time.sleep(1)
    return -1, ""


def _purge_nacl_entries(ec2, nacl_id: str) -> None:
    """Delete every custom entry on a NACL (keeps only rule 32767)."""
    nacls = ec2.describe_network_acls(
        NetworkAclIds=[nacl_id],
    )["NetworkAcls"]
    if not nacls:
        return
    for entry in nacls[0].get("Entries", []):
        if entry.get("RuleNumber", 0) >= 32767:
            continue
        try:
            ec2.delete_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=entry["RuleNumber"],
                Egress=entry["Egress"],
            )
        except Exception:
            pass


def _set_nacl_to_allow_all(ec2, nacl_id: str) -> None:
    """Reset a NACL to the AWS default-NACL ruleset (allow-all 100 +
    32767 implicit deny). Lets a test return the env to baseline."""
    _purge_nacl_entries(ec2, nacl_id)
    for egress in (False, True):
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100, Protocol="-1", RuleAction="allow",
            Egress=egress, CidrBlock="0.0.0.0/0",
        )


@pytest.fixture(scope="module")
def env():
    """Two ubuntu instances in the same subnet, SSM-reachable.

    Module-scoped so each test mutates the NACL without paying for a
    fresh container boot every time. Tests restore the NACL to
    allow-all in their own finally blocks to avoid cross-test bleed.
    """
    ec2 = _ec2()
    tag = uuid.uuid4().hex[:6]
    vpc_cidr = f"10.{210 + (hash(tag) % 40)}.0.0/16"
    subnet_cidr = vpc_cidr.replace("0.0/16", "1.0/24")
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]
    subnet = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=subnet_cidr,
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]
    # Look up the default NACL for this VPC
    nacls = ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}],
    )["NetworkAcls"]
    default_nacl = next(n for n in nacls if n.get("IsDefault"))
    nacl_id = default_nacl["NetworkAclId"]

    key = f"nacl-{tag}"
    ec2.create_key_pair(KeyName=key)
    a = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"], KeyName=key,
    )["Instances"][0]
    b = ec2.run_instances(
        ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
        MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"], KeyName=key,
    )["Instances"][0]
    ia, ib = a["InstanceId"], b["InstanceId"]
    assert _wait_running(ec2, ia), f"A stuck"
    assert _wait_running(ec2, ib), f"B stuck"
    da = ec2.describe_instances(InstanceIds=[ia])["Reservations"][0]["Instances"][0]
    db = ec2.describe_instances(InstanceIds=[ib])["Reservations"][0]["Instances"][0]
    ipa, ipb = da["PrivateIpAddress"], db["PrivateIpAddress"]

    # Start an HTTP server on B for the data-plane probes
    ssm = _ssm()
    _ssm_run(
        ssm, ib,
        "mkdir -p /srv/n && echo NACL-OK > /srv/n/p.txt && "
        "(pkill -f 'http.server 19090' 2>/dev/null; true) && "
        "nohup sh -c 'cd /srv/n && python3 -m http.server 19090' "
        "> /var/log/nacl.log 2>&1 &",
        timeout=30,
    )
    time.sleep(3)

    # Start from a clean allow-all NACL — the LocalEmu apply path is
    # triggered by CreateNetworkAclEntry, so we explicitly create the
    # 100-allow rules even though moto would have defaulted them.
    _set_nacl_to_allow_all(ec2, nacl_id)
    time.sleep(2)

    yield {
        "ec2": ec2, "ssm": ssm,
        "vpc_id": vpc["VpcId"], "subnet_id": subnet["SubnetId"],
        "nacl_id": nacl_id,
        "ia": ia, "ib": ib, "ipa": ipa, "ipb": ipb,
    }

    # Teardown
    try:
        ec2.terminate_instances(InstanceIds=[ia, ib])
    except Exception:
        pass
    try:
        ec2.delete_key_pair(KeyName=key)
    except Exception:
        pass


def _http_probe_a_to_b(ssm, ia, ipb) -> tuple[int, str]:
    """Run curl from A to B's HTTP server. RC=0 + body in stdout on
    success, RC!=0 or empty body on failure."""
    return _ssm_run(
        ssm, ia,
        f"curl -sf --max-time 4 http://{ipb}:19090/p.txt || echo PROBE-FAIL",
        timeout=20,
    )


class TestNaclStatelessContract:
    def test_baseline_allow_all_permits_traffic(self, env):
        rc, out = _http_probe_a_to_b(env["ssm"], env["ia"], env["ipb"])
        assert "NACL-OK" in out and "PROBE-FAIL" not in out, (
            f"Baseline allow-all should permit TCP A->B; got rc={rc} out={out!r}"
        )

    def test_deny_egress_blocks_outbound(self, env):
        """Add a deny-egress-all rule at the lowest rule number;
        ordered before the 100-allow. The SYN can't leave A."""
        ec2 = env["ec2"]
        nacl_id = env["nacl_id"]
        try:
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=50, Protocol="-1",
                RuleAction="deny", Egress=True, CidrBlock="0.0.0.0/0",
            )
            time.sleep(2)
            rc, out = _http_probe_a_to_b(env["ssm"], env["ia"], env["ipb"])
            assert "PROBE-FAIL" in out, (
                f"Deny-egress should block TCP A->B; got rc={rc} out={out!r}"
            )
        finally:
            _set_nacl_to_allow_all(ec2, nacl_id)
            time.sleep(2)

    def test_stateless_response_blocked_when_ephemeral_ingress_missing(self, env):
        """The single shared NACL applies to both A and B. We:
          - allow all egress (A's SYN can leave; B's SYN-ACK can leave)
          - allow ingress only on TCP 19090 (B's HTTP server port)
        So A->B SYN reaches B's server (dport 19090 allowed). B sends
        SYN-ACK back to A's high ephemeral port. That return packet
        hits A's NACL_IN with dport in the ephemeral range — no rule
        matches, default DROP fires. A stateful firewall would have
        auto-permitted via conntrack ESTABLISHED; AWS NACL does not."""
        ec2 = env["ec2"]
        nacl_id = env["nacl_id"]
        try:
            _purge_nacl_entries(ec2, nacl_id)
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=100, Protocol="-1",
                RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0",
            )
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=100, Protocol="6",
                RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0",
                PortRange={"From": 19090, "To": 19090},
            )
            time.sleep(2)
            rc, out = _http_probe_a_to_b(env["ssm"], env["ia"], env["ipb"])
            assert "PROBE-FAIL" in out, (
                "Stateless contract violated: SYN-ACK to A's ephemeral port "
                f"should be dropped by A's NACL_IN. rc={rc} out={out!r}"
            )
        finally:
            _set_nacl_to_allow_all(ec2, nacl_id)
            time.sleep(2)

    def test_explicit_ephemeral_ingress_allows_response(self, env):
        """Same as above but ingress ALSO allows the Linux ephemeral
        range 32768-60999. Now A's NACL_IN matches the SYN-ACK and
        the HTTP request succeeds end-to-end, proving the stateless
        contract is honored when both directions are explicitly opened."""
        ec2 = env["ec2"]
        nacl_id = env["nacl_id"]
        try:
            _purge_nacl_entries(ec2, nacl_id)
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=100, Protocol="-1",
                RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0",
            )
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=100, Protocol="6",
                RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0",
                PortRange={"From": 19090, "To": 19090},
            )
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id, RuleNumber=110, Protocol="6",
                RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0",
                PortRange={"From": 32768, "To": 60999},
            )
            time.sleep(2)
            rc, out = _http_probe_a_to_b(env["ssm"], env["ia"], env["ipb"])
            assert "NACL-OK" in out and "PROBE-FAIL" not in out, (
                "Explicit ephemeral ingress should permit response; "
                f"got rc={rc} out={out!r}"
            )
        finally:
            _set_nacl_to_allow_all(ec2, nacl_id)
            time.sleep(2)
