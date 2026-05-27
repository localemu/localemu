"""Live E2E for Amazon MSK — provision a real Apache Kafka broker via
CreateCluster, then produce + consume a message through it with
kafka-python.

Validates the full path:
  1. boto3 ``kafka.create_cluster`` triggers a real apache/kafka:3.7.1
     KRaft container.
  2. ``describe_cluster`` cycles to ACTIVE once the container's port
     accepts TCP + Kafka's controller has finished electing.
  3. ``get_bootstrap_brokers`` returns ``127.0.0.1:<host-port>``.
  4. kafka-python KafkaProducer pushes a message to a topic.
  5. KafkaConsumer (earliest, same group) reads it back.
  6. ``delete_cluster`` removes the container.

Falsy outcomes:
  * Container never reaches ACTIVE => readiness probe broke.
  * Producer hangs => listener mis-advertised.
  * Consumer reads empty => topic auto-create off OR wrong bootstrap.
"""

import sys
import time
import uuid

import boto3
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

ENDPOINT = "http://localhost:4566"
KW = dict(
    endpoint_url=ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

mskc = boto3.client("kafka", **KW)

uid = uuid.uuid4().hex[:8]
name = f"le-kafka-e2e-{uid}"

print(f"creating cluster {name}…")
resp = mskc.create_cluster(
    ClusterName=name,
    KafkaVersion="3.7.1",
    NumberOfBrokerNodes=1,
    BrokerNodeGroupInfo={
        "InstanceType": "kafka.t3.small",
        "ClientSubnets": ["subnet-x"],
    },
)
cluster_arn = resp["ClusterArn"]
print(f"ClusterArn={cluster_arn}")

deadline = time.time() + 180
bootstrap = ""
while time.time() < deadline:
    desc = mskc.describe_cluster(ClusterArn=cluster_arn)
    state = desc.get("ClusterInfo", {}).get("State") or ""
    if state == "ACTIVE":
        bootstrap = mskc.get_bootstrap_brokers(
            ClusterArn=cluster_arn,
        )["BootstrapBrokerString"]
        if bootstrap:
            break
    if state == "FAILED":
        print("FAIL: cluster creation reported FAILED")
        sys.exit(1)
    time.sleep(2)

if not bootstrap:
    print("FAIL: cluster did not become ACTIVE in 180s")
    try:
        mskc.delete_cluster(ClusterArn=cluster_arn)
    except Exception:
        pass
    sys.exit(1)

print(f"bootstrap brokers: {bootstrap}")
topic = f"le-topic-{uid}"
message_body = f"hello-kafka-{uid}".encode()

print(f"producing 1 message to topic {topic}…")
producer = None
last_err = None
deadline = time.time() + 60
while time.time() < deadline:
    try:
        producer = KafkaProducer(
            bootstrap_servers=bootstrap.split(","),
            api_version_auto_timeout_ms=30000,
            request_timeout_ms=30000,
            max_block_ms=30000,
        )
        break
    except KafkaError as e:
        last_err = e
        time.sleep(2)
if producer is None:
    print(f"FAIL: KafkaProducer could not connect within 60s: {last_err}")
    try:
        mskc.delete_cluster(ClusterArn=cluster_arn)
    except Exception:
        pass
    sys.exit(1)

future = producer.send(topic, value=message_body)
record_metadata = future.get(timeout=30)
print(f"sent to {record_metadata.topic}-{record_metadata.partition}@{record_metadata.offset}")
producer.flush(timeout=10)
producer.close(timeout=10)

print("consuming 1 message…")
consumer = KafkaConsumer(
    topic,
    bootstrap_servers=bootstrap.split(","),
    auto_offset_reset="earliest",
    group_id=f"le-grp-{uid}",
    consumer_timeout_ms=30_000,
    api_version_auto_timeout_ms=30000,
)
received = []
for msg in consumer:
    received.append(msg.value)
    if msg.value == message_body:
        break
consumer.close()

print("deleting cluster…")
mskc.delete_cluster(ClusterArn=cluster_arn)

if message_body not in received:
    print(f"FAIL: expected {message_body!r} but got {received!r}")
    sys.exit(1)

print(f"\nPASS: real Kafka cluster provisioned, kafka-python round-trip succeeded for uid={uid}")
