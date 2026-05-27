"""E2E: Security Group cross-reference (UserIdGroupPairs) via boto3.

Proves end-to-end that an SG rule whose source is another SG (sg-id,
not a CIDR) resolves to the concrete IPs of the source-SG members
and denies everything else.

What this exercises against the running LocalEmu:

  1. Allow path: instance in SG-WEB connects to instance in SG-DB on
     the referenced port. SG-DB's rule says "allow TCP 19091 from
     SG-WEB"; the iptables chain on the DB instance must include a
     /32 entry for the WEB instance's IP.
  2. Deny path: an instance in a third SG (not referenced by SG-DB)
     is blocked. Proves the cross-ref is NOT silently widened to
     0.0.0.0/0 (the previous LocalEmu bug).
  3. Late-join: a second instance launched into SG-WEB AFTER the
     cross-ref rule was created must also be allowed — proves the
     AddressIndex is updated as new ENIs come in, and the SG
     re-apply path picks them up.

Requires LocalEmu running with
``LOCALEMU_VPC_IP_PINNING=1 EC2_VM_MANAGER=docker``.
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
        if r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running":
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


def _http_probe(ssm, source_iid: str, dst_ip: str, port: int = 19091) -> str:
    """Return the body of curl src->dst:port, or 'FAIL' on any failure."""
    _, out = _ssm_run(
        ssm, source_iid,
        f"curl -sf --max-time 4 http://{dst_ip}:{port}/p.txt || echo SG-FAIL",
        timeout=20,
    )
    return out


@pytest.fixture(scope="module")
def env():
    """Build the SG topology + the DB-side HTTP server. Three SGs:
        SG-WEB     (client allowed by cross-ref)
        SG-OTHER   (client NOT allowed)
        SG-DB      (server; allows TCP 19091 from SG-WEB only)
    Two initial instances:
        i-web    in SG-WEB
        i-db     in SG-DB, running python http.server on 19091
        i-other  in SG-OTHER
    Late-join in tests adds i-web2 to SG-WEB.
    """
    ec2 = _ec2()
    tag = uuid.uuid4().hex[:6]
    vpc_cidr = f"10.{160 + (hash(tag) % 30)}.0.0/16"
    subnet_cidr = vpc_cidr.replace("0.0/16", "1.0/24")
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]
    subnet = ec2.create_subnet(
        VpcId=vpc["VpcId"], CidrBlock=subnet_cidr,
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]

    sg_web = ec2.create_security_group(
        GroupName=f"sg-web-{tag}", Description="cross-ref web",
        VpcId=vpc["VpcId"],
    )["GroupId"]
    sg_db = ec2.create_security_group(
        GroupName=f"sg-db-{tag}", Description="cross-ref db",
        VpcId=vpc["VpcId"],
    )["GroupId"]
    sg_other = ec2.create_security_group(
        GroupName=f"sg-other-{tag}", Description="cross-ref other",
        VpcId=vpc["VpcId"],
    )["GroupId"]

    # SG-DB ingress: TCP 19091 from SG-WEB (UserIdGroupPairs reference)
    ec2.authorize_security_group_ingress(
        GroupId=sg_db,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 19091, "ToPort": 19091,
            "UserIdGroupPairs": [{"GroupId": sg_web}],
        }],
    )

    key = f"sgx-{tag}"
    ec2.create_key_pair(KeyName=key)

    def _launch(sg_id: str) -> str:
        r = ec2.run_instances(
            ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=subnet["SubnetId"],
            KeyName=key, SecurityGroupIds=[sg_id],
        )["Instances"][0]
        return r["InstanceId"]

    i_web = _launch(sg_web)
    i_db = _launch(sg_db)
    i_other = _launch(sg_other)
    for iid in (i_web, i_db, i_other):
        assert _wait_running(ec2, iid), f"{iid} stuck"

    def _ip(iid):
        d = ec2.describe_instances(InstanceIds=[iid])
        return d["Reservations"][0]["Instances"][0]["PrivateIpAddress"]

    ip_web, ip_db, ip_other = _ip(i_web), _ip(i_db), _ip(i_other)

    # Start the HTTP server on the DB instance
    ssm = _ssm()
    _ssm_run(
        ssm, i_db,
        "mkdir -p /srv/sg && echo SG-OK > /srv/sg/p.txt && "
        "(pkill -f 'http.server 19091' 2>/dev/null; true) && "
        "nohup sh -c 'cd /srv/sg && python3 -m http.server 19091' "
        "> /var/log/sg.log 2>&1 &",
        timeout=30,
    )
    time.sleep(3)

    yield {
        "ec2": ec2, "ssm": ssm,
        "vpc_id": vpc["VpcId"], "subnet_id": subnet["SubnetId"],
        "sg_web": sg_web, "sg_db": sg_db, "sg_other": sg_other,
        "i_web": i_web, "i_db": i_db, "i_other": i_other,
        "ip_web": ip_web, "ip_db": ip_db, "ip_other": ip_other,
        "key": key,
    }

    # Teardown
    try:
        ids = [v for k, v in [
            ("i_web", i_web), ("i_db", i_db), ("i_other", i_other),
        ] if v]
        late = locals().get("late")
        ec2.terminate_instances(InstanceIds=ids)
    except Exception:
        pass
    try:
        ec2.delete_key_pair(KeyName=key)
    except Exception:
        pass


class TestSgCrossReference:
    def test_referenced_sg_member_can_connect(self, env):
        out = _http_probe(env["ssm"], env["i_web"], env["ip_db"])
        assert "SG-OK" in out and "SG-FAIL" not in out, (
            f"SG-WEB instance must be allowed by SG-DB cross-ref. out={out!r}"
        )

    def test_unrelated_sg_member_is_blocked(self, env):
        """SG-OTHER is not listed in SG-DB's UserIdGroupPairs, so its
        IP must not appear in the iptables ACCEPT list. The default
        DROP at the end of the chain takes over and the request fails.
        Before the AddressIndex resolution path was wired up, this
        used to be silently widened to 0.0.0.0/0 — proving the
        cross-ref is now actually enforced."""
        out = _http_probe(env["ssm"], env["i_other"], env["ip_db"])
        assert "SG-FAIL" in out and "SG-OK" not in out, (
            "SG-OTHER must NOT be allowed by SG-DB cross-ref. "
            f"out={out!r} (silent allow-all regression?)"
        )

    def test_late_join_to_referenced_sg_is_allowed(self, env):
        """Launch a new instance into SG-WEB AFTER the cross-ref rule
        exists. The AddressIndex must learn the new IP and the SG
        re-apply path must push it into SG-DB's iptables. The new
        instance should then reach SG-DB on the referenced port."""
        ec2 = env["ec2"]
        r = ec2.run_instances(
            ImageId="ami-ubuntu-22.04", InstanceType="t2.micro",
            MinCount=1, MaxCount=1, SubnetId=env["subnet_id"],
            KeyName=env["key"], SecurityGroupIds=[env["sg_web"]],
        )["Instances"][0]
        i_web2 = r["InstanceId"]
        try:
            assert _wait_running(ec2, i_web2), "late-join web2 stuck"
            # Brief settle so the SG re-apply hooks finish
            time.sleep(3)
            out = _http_probe(env["ssm"], i_web2, env["ip_db"])
            assert "SG-OK" in out and "SG-FAIL" not in out, (
                "Late-join SG-WEB member must be allowed via cross-ref. "
                f"out={out!r} (AddressIndex stale or re-apply skipped?)"
            )
        finally:
            try:
                ec2.terminate_instances(InstanceIds=[i_web2])
            except Exception:
                pass
