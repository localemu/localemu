"""Live E2E for Amazon MQ — provision a real RabbitMQ broker, then
publish + consume a message through it with pika.

This exercises the full MQ path:
  1. AWS CreateBroker → BrokerManager starts a real rabbitmq:3.13-management
     container and waits for AMQP to accept TCP.
  2. DescribeBroker returns the localhost:<port> endpoints rewritten
     from the AWS dns-name shape so a real pika client can parse them.
  3. We publish a message, then basic_get it back — confirming the
     broker is processing wire traffic end-to-end.
  4. DeleteBroker removes the container.
"""

import re
import sys
import time
import uuid

import boto3
import pika

ENDPOINT = "http://localhost:4566"
KW = dict(
    endpoint_url=ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

mq = boto3.client("mq", **KW)

uid = uuid.uuid4().hex[:8]
broker_name = f"mq-e2e-{uid}"
admin_pass = "Password123!"

print(f"creating broker {broker_name}…")
resp = mq.create_broker(
    BrokerName=broker_name,
    EngineType="RABBITMQ",
    EngineVersion="3.13",
    HostInstanceType="mq.t3.micro",
    DeploymentMode="SINGLE_INSTANCE",
    Users=[{"Username": "admin", "Password": admin_pass}],
    PubliclyAccessible=True,
    AutoMinorVersionUpgrade=False,
)
broker_id = resp["BrokerId"]
print(f"BrokerId={broker_id}")

# Wait for broker reachable via DescribeBroker
deadline = time.time() + 90
amqp_url = None
while time.time() < deadline:
    desc = mq.describe_broker(BrokerId=broker_id)
    if desc.get("BrokerState") != "RUNNING":
        time.sleep(2)
        continue
    instances = desc.get("BrokerInstances") or []
    if not instances:
        time.sleep(1)
        continue
    endpoints = instances[0].get("Endpoints") or []
    for ep in endpoints:
        if ep.startswith("amqp://"):
            amqp_url = ep
            break
    if amqp_url:
        break
    time.sleep(1)

if not amqp_url:
    print("FAIL: no amqp endpoint after broker reached RUNNING")
    try:
        mq.delete_broker(BrokerId=broker_id)
    except Exception:
        pass
    sys.exit(1)

print(f"amqp endpoint: {amqp_url}")
match = re.match(r"amqp://([^:/]+):(\d+)", amqp_url)
assert match, f"could not parse amqp url: {amqp_url}"
host, port = match.group(1), int(match.group(2))

# Pika round-trip — pika's connection_attempts/retry_delay only kicks
# in on socket-level errors. AMQP handshake-level resets (e.g. broker
# busy finishing init) raise IncompatibleProtocolError immediately, so
# we wrap the connect ourselves and retry on those for up to 30s.
queue_name = f"queue-{uid}"
print(f"publishing 1 message to queue {queue_name}…")
credentials = pika.PlainCredentials("admin", admin_pass)
params = pika.ConnectionParameters(host=host, port=port, credentials=credentials)
conn = None
last_err = None
deadline = time.time() + 30
while time.time() < deadline:
    try:
        conn = pika.BlockingConnection(params)
        break
    except (pika.exceptions.IncompatibleProtocolError, pika.exceptions.AMQPConnectionError) as e:
        last_err = e
        time.sleep(1)
if conn is None:
    raise RuntimeError(f"pika could not connect within 30s: {last_err}")
try:
    ch = conn.channel()
    ch.queue_declare(queue=queue_name, durable=False, auto_delete=True)
    ch.basic_publish(exchange="", routing_key=queue_name, body=f"hello-{uid}")
    method, _props, body = ch.basic_get(queue=queue_name, auto_ack=True)
    if method is None:
        # Tiny delay for the queue to settle, then retry once.
        time.sleep(0.5)
        method, _props, body = ch.basic_get(queue=queue_name, auto_ack=True)
finally:
    try:
        conn.close()
    except Exception:
        pass

print(f"received: {body!r}")
expected = f"hello-{uid}".encode()
assert body == expected, f"body mismatch: {body!r} != {expected!r}"

# Cleanup
print("deleting broker…")
mq.delete_broker(BrokerId=broker_id)

print(f"\nPASS: real RabbitMQ broker provisioned, AMQP round-trip succeeded for uid={uid}")
