"""Extensive Kafka (MSK) regression.

  * DescribeCluster reflects ACTIVE state.
  * ListClusters includes new cluster.
  * GetBootstrapBrokers returns non-empty 127.0.0.1:<port>.
  * ListNodes returns a populated NodeInfoList.
  * Produce 5 messages, consume them back in order via kafka-python.
  * Topic auto-creation works (default in our env vars).
  * DeleteCluster removes the container.
"""

import sys
import time
import uuid

import boto3
import botocore.exceptions
from kafka import KafkaConsumer, KafkaProducer

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
mskc = boto3.client("kafka", **KW)

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


_CLUSTER_ARN = None
_BOOTSTRAP = None
_CLUSTER_NAME = f"sweep-msk-{uid}"


def _ensure_cluster():
    global _CLUSTER_ARN, _BOOTSTRAP
    if _CLUSTER_ARN is not None:
        return _CLUSTER_ARN, _BOOTSTRAP
    r = mskc.create_cluster(
        ClusterName=_CLUSTER_NAME,
        KafkaVersion="3.7.1",
        NumberOfBrokerNodes=1,
        BrokerNodeGroupInfo={"InstanceType": "kafka.t3.small",
                             "ClientSubnets": ["subnet-x"]},
    )
    _CLUSTER_ARN = r["ClusterArn"]
    deadline = time.time() + 180
    while time.time() < deadline:
        d = mskc.describe_cluster(ClusterArn=_CLUSTER_ARN)
        st = d.get("ClusterInfo", {}).get("State")
        if st == "ACTIVE":
            _BOOTSTRAP = mskc.get_bootstrap_brokers(
                ClusterArn=_CLUSTER_ARN,
            )["BootstrapBrokerString"]
            if _BOOTSTRAP:
                return _CLUSTER_ARN, _BOOTSTRAP
        if st == "FAILED":
            raise RuntimeError("cluster reached FAILED")
        time.sleep(2)
    raise RuntimeError("cluster never reached ACTIVE")


def describe_returns_active():
    arn, _ = _ensure_cluster()
    d = mskc.describe_cluster(ClusterArn=arn)
    info = d.get("ClusterInfo") or {}
    assert info.get("State") == "ACTIVE", info.get("State")
    assert info.get("NumberOfBrokerNodes") == 1


def list_clusters_includes_new():
    _ensure_cluster()
    r = mskc.list_clusters()
    names = [c.get("ClusterName") for c in r.get("ClusterInfoList", [])]
    assert _CLUSTER_NAME in names, f"{_CLUSTER_NAME} not in {names[:5]}"


def get_bootstrap_brokers_is_localhost():
    _, bootstrap = _ensure_cluster()
    assert bootstrap.startswith("127.0.0.1:"), bootstrap
    port = int(bootstrap.split(":")[1])
    assert 1024 < port < 65536, port


def list_nodes_returns_one():
    arn, _ = _ensure_cluster()
    r = mskc.list_nodes(ClusterArn=arn)
    nodes = r.get("NodeInfoList", [])
    assert len(nodes) == 1, f"expected 1 node, got {len(nodes)}: {nodes}"
    n0 = nodes[0]
    assert n0.get("NodeType") == "BROKER"
    assert n0["BrokerNodeInfo"]["BrokerId"] == 1.0


def produce_consume_5_messages():
    _, bootstrap = _ensure_cluster()
    topic = f"t-{uid}"
    msgs = [f"msg-{uid}-{i}".encode() for i in range(5)]
    p = None
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            p = KafkaProducer(bootstrap_servers=bootstrap.split(","),
                              api_version_auto_timeout_ms=30000,
                              request_timeout_ms=30000)
            break
        except Exception:
            time.sleep(2)
    assert p is not None, "producer never connected"
    for m in msgs:
        p.send(topic, value=m).get(timeout=30)
    p.flush(timeout=10)
    p.close(timeout=10)
    c = KafkaConsumer(
        topic, bootstrap_servers=bootstrap.split(","),
        auto_offset_reset="earliest", group_id=f"g-{uid}",
        consumer_timeout_ms=20_000,
    )
    received = []
    for m in c:
        received.append(m.value)
        if len(received) >= 5:
            break
    c.close()
    assert received == msgs, f"order/content mismatch: got {received} want {msgs}"


def delete_cluster_works():
    arn, _ = _ensure_cluster()
    mskc.delete_cluster(ClusterArn=arn)
    time.sleep(5)
    try:
        d = mskc.describe_cluster(ClusterArn=arn)
        # AWS-compatible: should report DELETING or NotFound
        assert d.get("ClusterInfo", {}).get("State") in (
            "DELETING", "DELETED",
        ), f"state after delete: {d.get('ClusterInfo', {}).get('State')}"
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in (
            "NotFoundException", "ResourceNotFoundException",
        )


TESTS = [
    ("describe: ClusterInfo.State=ACTIVE", describe_returns_active),
    ("list: ListClusters includes new", list_clusters_includes_new),
    ("bootstrap: returns 127.0.0.1:<port>", get_bootstrap_brokers_is_localhost),
    ("list: ListNodes returns NodeInfoList", list_nodes_returns_one),
    ("wire: produce + consume 5 messages in order", produce_consume_5_messages),
    ("lifecycle: DeleteCluster removes", delete_cluster_works),
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
