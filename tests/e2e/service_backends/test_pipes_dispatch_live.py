"""Live E2E for EventBridge Pipes — SQS source → Lambda target.

Wires a real pipe against a real LocalEmu: messages land in the source
SQS, the pipe poller picks them up, the events TargetSenderFactory
invokes the Lambda target, and the Lambda writes a beacon into a sink
SQS we can poll. Failing this test means polling never started, the
target dispatch failed, or the lifecycle hooks didn't wire correctly.
"""

import io
import json
import os
import sys
import time
import uuid
import zipfile

import boto3

ENDPOINT = "http://localhost:4566"
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
pipes = boto3.client("pipes", **KW)

uid = uuid.uuid4().hex[:8]

# 1. Source SQS queue (the pipe polls this) + sink SQS queue (the
# Lambda writes here so the test can confirm delivery).
src_name = f"pipe-src-{uid}"
sink_name = f"pipe-sink-{uid}"
src_url = sqs.create_queue(QueueName=src_name)["QueueUrl"]
sink_url = sqs.create_queue(QueueName=sink_name)["QueueUrl"]
src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
    "Attributes"
]["QueueArn"]
print(f"src queue: {src_arn}")
print(f"sink queue: {sink_url}")

# 2. Lambda role
lambda_role_name = f"pipe-lambda-role-{uid}"
try:
    iam.create_role(
        RoleName=lambda_role_name,
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
lambda_role_arn = f"arn:aws:iam::000000000000:role/{lambda_role_name}"

# 3. Lambda function — writes the received event into the sink queue.
fn_name = f"pipe-fn-{uid}"
code = f"""
import json, os, boto3
SINK_NAME = "{sink_name}"
def handler(event, context):
    sqs = boto3.client("sqs", endpoint_url=os.environ["AWS_ENDPOINT_URL"])
    qurl = sqs.get_queue_url(QueueName=SINK_NAME)["QueueUrl"]
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

# 4. Pipe role (assumed as pipes.amazonaws.com)
pipe_role_name = f"pipe-role-{uid}"
try:
    iam.create_role(
        RoleName=pipe_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
except iam.exceptions.EntityAlreadyExistsException:
    pass
pipe_role_arn = f"arn:aws:iam::000000000000:role/{pipe_role_name}"

# 5. CreatePipe
pipe_name = f"pipe-{uid}"
pipes.create_pipe(
    Name=pipe_name,
    Source=src_arn,
    Target=fn_arn,
    RoleArn=pipe_role_arn,
    DesiredState="RUNNING",
    SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
)
print(f"pipe created: {pipe_name}")

# 6. Send a message to the source queue
payload = {"hello": "pipes", "uid": uid}
sqs.send_message(QueueUrl=src_url, MessageBody=json.dumps(payload))
print(f"posted message to source queue with uid={uid}")

# 7. Wait for the sink queue to receive the lambda's write
deadline = time.time() + 45
got = []
while time.time() < deadline:
    resp = sqs.receive_message(
        QueueUrl=sink_url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
    )
    msgs = resp.get("Messages") or []
    for m in msgs:
        body = json.loads(m["Body"])
        got.append(body)
        sqs.delete_message(QueueUrl=sink_url, ReceiptHandle=m["ReceiptHandle"])
    if got:
        break

# 8. Cleanup
try:
    pipes.delete_pipe(Name=pipe_name)
except Exception as e:
    print(f"delete_pipe failed: {e}")
try:
    lam.delete_function(FunctionName=fn_name)
except Exception:
    pass
try:
    sqs.delete_queue(QueueUrl=src_url)
except Exception:
    pass
try:
    sqs.delete_queue(QueueUrl=sink_url)
except Exception:
    pass

print(f"\n=== sink messages received: {len(got)} ===")
for g in got[:3]:
    print(" -", g)

if not got:
    print("FAIL: pipe did not deliver any event within 45s")
    sys.exit(1)

# The lambda receives a list of SQS-record-shaped events from the pipe.
event_list = got[0] if isinstance(got[0], list) else [got[0]]
print("\nfirst record shape:", list(event_list[0].keys()) if isinstance(event_list, list) and event_list else event_list)
# We just want to confirm the payload made it through; AWS-style SQS
# records carry the original body inside a "body" field.
body_field = None
if isinstance(event_list, list) and event_list:
    body_field = event_list[0].get("body") or event_list[0].get("Body")
elif isinstance(got[0], dict):
    body_field = got[0].get("body")
assert body_field is not None, f"body not in event: {got[0]}"
inner = json.loads(body_field) if isinstance(body_field, str) else body_field
assert inner.get("uid") == uid, f"uid mismatch: {inner}"
print("PASS: pipe forwarded SQS message → Lambda target, payload uid preserved")
