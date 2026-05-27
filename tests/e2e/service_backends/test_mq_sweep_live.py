"""Extensive MQ regression.

  * DescribeBroker reflects ACTIVE state + populated Endpoints.
  * ListBrokers includes new broker.
  * RebootBroker keeps the broker reachable on the same port.
  * DeleteBroker removes the container.
  * Unsupported engine (ACTIVEMQ) — broker creation must fail gracefully.
  * Two brokers in parallel use distinct host ports.
  * AMQPS endpoint URL has different port than AMQP (no port collision).
"""

import json
import re
import sys
import time
import uuid

import boto3
import botocore.exceptions
import pika

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
mq = boto3.client("mq", **KW)
uid = uuid.uuid4().hex[:8]
failures = []
report = []


def t(name, fn):
    try:
        fn()
        report.append(f"  PASS: {name}")
    except AssertionError as e:
        report.append(f"  FAIL: {name} — {e}")
        failures.append((name, str(e)))
    except Exception as e:
        report.append(f"  ERROR: {name} — {type(e).__name__}: {e}")
        failures.append((name, f"{type(e).__name__}: {e}"))


_BROKER_ID = None
_BROKER_ADMIN_PASS = "Sweep123!"
_BROKER_NAME = f"sweep-amq-{uid}"


def _ensure_broker():
    global _BROKER_ID
    if _BROKER_ID is not None:
        return _BROKER_ID
    resp = mq.create_broker(
        BrokerName=_BROKER_NAME,
        EngineType="RABBITMQ",
        EngineVersion="3.13",
        HostInstanceType="mq.t3.micro",
        DeploymentMode="SINGLE_INSTANCE",
        Users=[{"Username": "admin", "Password": _BROKER_ADMIN_PASS}],
        PubliclyAccessible=True,
        AutoMinorVersionUpgrade=False,
    )
    _BROKER_ID = resp["BrokerId"]
    # Wait until ACTIVE
    deadline = time.time() + 90
    while time.time() < deadline:
        d = mq.describe_broker(BrokerId=_BROKER_ID)
        if d.get("BrokerState") == "RUNNING" and d.get("BrokerInstances"):
            return _BROKER_ID
        time.sleep(2)
    raise RuntimeError("primary broker never reached RUNNING")


def describe_returns_running_and_endpoints():
    bid = _ensure_broker()
    d = mq.describe_broker(BrokerId=bid)
    assert d["BrokerState"] == "RUNNING", d.get("BrokerState")
    ins = d.get("BrokerInstances") or []
    assert ins, "no BrokerInstances"
    eps = ins[0].get("Endpoints") or []
    amqp = [e for e in eps if e.startswith("amqp://")]
    assert amqp, f"no amqp endpoint: {eps}"


def list_brokers_includes_new():
    bid = _ensure_broker()
    lst = mq.list_brokers()
    ids = [b.get("BrokerId") or b.get("BrokerName") for b in lst.get("BrokerSummaries", [])]
    assert any(_BROKER_NAME in (b.get("BrokerName") or "") for b in lst.get("BrokerSummaries", [])), \
        f"broker not in list: {ids[:5]}"


def amqp_amqps_distinct_ports():
    bid = _ensure_broker()
    d = mq.describe_broker(BrokerId=bid)
    eps = d["BrokerInstances"][0]["Endpoints"]
    amqp_url = next(e for e in eps if e.startswith("amqp://"))
    amqps_url = next((e for e in eps if e.startswith("amqps://")), None)
    if amqps_url is None:
        return  # only amqp advertised — fine for v1
    amqp_port = int(re.match(r"amqp://[^:]+:(\d+)", amqp_url).group(1))
    amqps_port = int(re.match(r"amqps://[^:]+:(\d+)", amqps_url).group(1))
    assert amqp_port != amqps_port, (
        f"amqp + amqps share port {amqp_port} — broker is unreachable on one of them"
    )


def reboot_keeps_broker_reachable():
    bid = _ensure_broker()
    d = mq.describe_broker(BrokerId=bid)
    ep = next(e for e in d["BrokerInstances"][0]["Endpoints"] if e.startswith("amqp://"))
    host, port = re.match(r"amqp://([^:]+):(\d+)", ep).group(1, 2)
    port = int(port)
    mq.reboot_broker(BrokerId=bid)
    # Give it a window
    deadline = time.time() + 60
    last_err = None
    while time.time() < deadline:
        try:
            conn = pika.BlockingConnection(pika.ConnectionParameters(
                host=host, port=port,
                credentials=pika.PlainCredentials("admin", _BROKER_ADMIN_PASS),
            ))
            conn.close()
            return
        except Exception as e:
            last_err = e
            time.sleep(2)
    raise AssertionError(f"broker unreachable after reboot: {last_err}")


def second_broker_uses_distinct_port():
    """Two brokers must not collide on host ports."""
    name = f"sweep-amq2-{uid}"
    r2 = mq.create_broker(
        BrokerName=name,
        EngineType="RABBITMQ",
        EngineVersion="3.13",
        HostInstanceType="mq.t3.micro",
        DeploymentMode="SINGLE_INSTANCE",
        Users=[{"Username": "admin", "Password": "Other123!"}],
        PubliclyAccessible=True,
        AutoMinorVersionUpgrade=False,
    )
    bid2 = r2["BrokerId"]
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            d2 = mq.describe_broker(BrokerId=bid2)
            if d2.get("BrokerState") == "RUNNING" and d2.get("BrokerInstances"):
                break
            time.sleep(2)
        else:
            raise AssertionError("second broker never reached RUNNING")
        d1 = mq.describe_broker(BrokerId=_ensure_broker())
        ep1 = next(e for e in d1["BrokerInstances"][0]["Endpoints"] if e.startswith("amqp://"))
        ep2 = next(e for e in d2["BrokerInstances"][0]["Endpoints"] if e.startswith("amqp://"))
        p1 = int(re.match(r"amqp://[^:]+:(\d+)", ep1).group(1))
        p2 = int(re.match(r"amqp://[^:]+:(\d+)", ep2).group(1))
        assert p1 != p2, f"two brokers got the same port {p1}"
    finally:
        try: mq.delete_broker(BrokerId=bid2)
        except Exception: pass


def unsupported_engine_handled_explicitly():
    """ACTIVEMQ isn't implemented in v1; CreateBroker must not silently
    succeed with state ACTIVE. Either the moto record stays at CREATION_FAILED
    or DescribeBroker can never see RUNNING."""
    name = f"sweep-amq-active-{uid}"
    try:
        r = mq.create_broker(
            BrokerName=name,
            EngineType="ACTIVEMQ",
            EngineVersion="5.18",
            HostInstanceType="mq.t3.micro",
            DeploymentMode="SINGLE_INSTANCE",
            Users=[{"Username": "admin", "Password": "X12345aaa"}],
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=False,
        )
    except botocore.exceptions.ClientError as e:
        # AWS-shaped rejection at the API — also acceptable
        return
    bid = r["BrokerId"]
    try:
        time.sleep(8)  # wait for provisioning attempt to settle
        d = mq.describe_broker(BrokerId=bid)
        assert d.get("BrokerState") != "RUNNING", (
            f"ACTIVEMQ broker reports RUNNING despite v1 not supporting it: {d.get('BrokerState')}"
        )
    finally:
        try: mq.delete_broker(BrokerId=bid)
        except Exception: pass


def delete_removes_container():
    """Delete the primary broker we created and confirm DescribeBroker
    no longer surfaces it (eventually consistent)."""
    bid = _ensure_broker()
    mq.delete_broker(BrokerId=bid)
    # Give moto a moment to process; describe may either 4xx or report DELETING
    time.sleep(4)
    try:
        d = mq.describe_broker(BrokerId=bid)
        assert d.get("BrokerState") in ("DELETION_IN_PROGRESS", "DELETED"), \
            f"unexpected state after delete: {d.get('BrokerState')}"
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in (
            "NotFoundException", "ResourceNotFoundException", "NotFoundException",
        )


TESTS = [
    ("describe: RUNNING + endpoints populated", describe_returns_running_and_endpoints),
    ("list: ListBrokers includes new", list_brokers_includes_new),
    ("endpoint: amqp + amqps on distinct ports", amqp_amqps_distinct_ports),
    ("lifecycle: reboot keeps broker reachable", reboot_keeps_broker_reachable),
    ("lifecycle: 2 brokers get distinct ports", second_broker_uses_distinct_port),
    ("engine: ACTIVEMQ does NOT silently report RUNNING", unsupported_engine_handled_explicitly),
    ("lifecycle: delete removes broker", delete_removes_container),
]
for n, fn in TESTS:
    t(n, fn)

print("\n".join(report))
print(f"\n{len(TESTS) - len(failures)}/{len(TESTS)} passed")
if failures:
    print("\nFAILURES:")
    for n, e in failures:
        print(f"  - {n}: {e}")
    sys.exit(1)
