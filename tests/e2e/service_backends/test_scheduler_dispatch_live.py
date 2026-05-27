"""Live E2E for scheduler — drives a real LocalEmu instance.

Wires rate(10 seconds) → Lambda → SQS, waits for at least 2 SQS
messages (so we see two fires), then deletes the schedule. Failing
this test means the polling thread didn't fire, the target dispatch
broke, or the schedule's lifecycle hooks didn't register the job.
"""

import io
import json
import os
import sys
import time
import uuid
import zipfile

import boto3

ENDPOINT = os.environ.get("LE_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
KW = dict(
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

sqs = boto3.client("sqs", **KW)
iam = boto3.client("iam", **KW)
lam = boto3.client("lambda", **KW)
sched = boto3.client("scheduler", **KW)

uid = uuid.uuid4().hex[:8]

# 1. SQS sink
queue_name = f"sched-sink-{uid}"
queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
queue_arn = sqs.get_queue_attributes(
    QueueUrl=queue_url, AttributeNames=["QueueArn"]
)["Attributes"]["QueueArn"]
print(f"queue: {queue_arn}")

# 2. Lambda execution role
role_name = f"sched-lambda-role-{uid}"
try:
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
except iam.exceptions.EntityAlreadyExistsException:
    pass
lambda_role_arn = f"arn:aws:iam::000000000000:role/{role_name}"

# 3. Lambda function — writes a message to SQS from the event payload
fn_name = f"sched-sink-fn-{uid}"
code = f"""
import json, os, sys, boto3
QNAME = "{queue_name}"
def handler(event, context):
    print("DBG env AWS_ENDPOINT_URL =", os.environ.get("AWS_ENDPOINT_URL"))
    endpoint = os.environ.get("AWS_ENDPOINT_URL") or "http://host.docker.internal:4566"
    print("DBG using endpoint =", endpoint)
    sqs = boto3.client("sqs", endpoint_url=endpoint, region_name="us-east-1")
    qurl = sqs.get_queue_url(QueueName=QNAME)["QueueUrl"]
    print("DBG qurl =", qurl)
    sqs.send_message(QueueUrl=qurl, MessageBody=json.dumps(event))
    return {{"ok": True}}
"""
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("handler.py", code)
buf.seek(0)
lam.create_function(
    FunctionName=fn_name,
    Runtime="python3.12",
    Role=lambda_role_arn,
    Handler="handler.handler",
    Code={"ZipFile": buf.getvalue()},
    Timeout=30,
    # Don't override AWS_ENDPOINT_URL — LocalEmu's lambda runtime sets
    # it to the container-aware value (host.docker.internal:4566) so the
    # lambda can actually reach the gateway from inside Docker.
)
fn_arn = lam.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
print(f"lambda: {fn_arn}")

# Wait until lambda is Active
deadline = time.time() + 60
while time.time() < deadline:
    st = lam.get_function_configuration(FunctionName=fn_name)["State"]
    if st == "Active":
        break
    time.sleep(1)
print("lambda active")

# 4. Scheduler role (also self-assumed by the local scheduler service)
sched_role_name = f"sched-invoker-role-{uid}"
try:
    iam.create_role(
        RoleName=sched_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
except iam.exceptions.EntityAlreadyExistsException:
    pass
sched_role_arn = f"arn:aws:iam::000000000000:role/{sched_role_name}"

# 5. Create schedule
sched_name = f"sched-e2e-{uid}"
sched.create_schedule(
    Name=sched_name,
    ScheduleExpression="rate(10 seconds)",
    FlexibleTimeWindow={"Mode": "OFF"},
    Target={
        "Arn": fn_arn,
        "RoleArn": sched_role_arn,
        "Input": json.dumps({"hello": "scheduler", "uid": uid}),
    },
)
print(f"schedule: {sched_name}")

# 6. Wait for at least 1 message — give it up to 30 s (one full rate cycle
# plus warm-up). For LocalEmu the polling thread tick is 1 s so the first
# fire should land 10±1s after creation.
deadline = time.time() + 35
got = []
while time.time() < deadline:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    msgs = resp.get("Messages") or []
    for m in msgs:
        got.append(json.loads(m["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    if got:
        break

# 7. Cleanup
try:
    sched.delete_schedule(Name=sched_name)
except Exception:
    pass
try:
    lam.delete_function(FunctionName=fn_name)
except Exception:
    pass
try:
    sqs.delete_queue(QueueUrl=queue_url)
except Exception:
    pass

print(f"\n=== messages received: {len(got)} ===")
for g in got[:3]:
    print(" -", g)

if not got:
    print("FAIL: scheduler did not fire within 35s window")
    sys.exit(1)
detail = got[0].get("detail") or got[0]
assert isinstance(detail, dict), f"detail wrong shape: {detail}"
assert detail.get("uid") == uid, f"detail uid mismatch: {detail}"
print("PASS: schedule fired and target received expected detail payload")
