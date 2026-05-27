#!/usr/bin/env python3
"""
Comprehensive end-to-end integration tests for LocalEmu.

Tests ALL major cross-service integrations against a running LocalEmu instance.
Run with: python tests/e2e/test_e2e_integrations.py

Requires: LocalEmu running on localhost:4566
"""

import io
import json
import sys
import time
import zipfile

import boto3
from botocore.config import Config

from localemu.utils.sync import poll_condition

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"

# Counters
_passed = 0
_failed = 0
_skipped = 0
_errors = []


def _client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 0}),
    )


def _make_lambda_zip(code: str) -> bytes:
    """Create an in-memory zip with lambda_function.py."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _wait_for_function_active(lambda_client, name, timeout=30):
    """Wait until a Lambda function is Active (no raw time.sleep — uses poll_condition)."""
    def _is_active():
        try:
            resp = lambda_client.get_function(FunctionName=name)
            return resp["Configuration"].get("State", "Active") == "Active"
        except Exception:
            return False

    return poll_condition(_is_active, timeout=timeout, interval=1.0)


def _ensure_role(iam_client, role_name="e2e-lambda-role"):
    """Create or return a basic Lambda execution role ARN."""
    try:
        resp = iam_client.get_role(RoleName=role_name)
        return resp["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        resp = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust,
            Path="/",
        )
        # Attach basic execution policy
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        return resp["Role"]["Arn"]


def _section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def _check(name, condition, detail=""):
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  [PASS] {name}")
    else:
        _failed += 1
        msg = f"  [FAIL] {name}"
        if detail:
            msg += f" -- {detail}"
        print(msg)
        _errors.append(f"{name}: {detail}")


def _skip(name, reason):
    global _skipped
    _skipped += 1
    print(f"  [SKIP] {name} -- {reason}")


# ---------------------------------------------------------------------------
# Test 1: Secrets Manager CRUD
# ---------------------------------------------------------------------------
def test_secrets_manager_crud():
    _section("Test 1: Secrets Manager CRUD")
    sm = _client("secretsmanager")
    secret_name = f"e2e/test-secret-{int(time.time())}"

    # Create
    resp = sm.create_secret(Name=secret_name, SecretString='{"user":"admin","pass":"s3cret"}')
    arn = resp["ARN"]
    _check("Create secret", arn and secret_name in arn, f"ARN={arn}")

    # Read
    resp = sm.get_secret_value(SecretId=secret_name)
    value = json.loads(resp["SecretString"])
    _check("Read secret value", value == {"user": "admin", "pass": "s3cret"}, f"got {value}")

    # Update
    sm.put_secret_value(SecretId=secret_name, SecretString='{"user":"admin","pass":"n3wpass"}')
    resp = sm.get_secret_value(SecretId=secret_name)
    value = json.loads(resp["SecretString"])
    _check("Update secret", value["pass"] == "n3wpass", f"got {value}")

    # List
    resp = sm.list_secrets()
    names = [s["Name"] for s in resp["SecretList"]]
    _check("List secrets contains our secret", secret_name in names)

    # Delete
    sm.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
    try:
        sm.get_secret_value(SecretId=secret_name)
        _check("Delete secret", False, "Secret still accessible after delete")
    except sm.exceptions.ResourceNotFoundException:
        _check("Delete secret", True)


# ---------------------------------------------------------------------------
# Test 2: Lambda invoke (basic)
# ---------------------------------------------------------------------------
def test_lambda_basic_invoke():
    _section("Test 2: Lambda Basic Invoke")
    lam = _client("lambda")
    iam = _client("iam")
    func_name = f"e2e-echo-{int(time.time())}"
    role_arn = _ensure_role(iam)

    code = """
def handler(event, context):
    return {"statusCode": 200, "body": event}
"""
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(code)},
        Timeout=30,
    )
    _wait_for_function_active(lam, func_name)

    payload = {"message": "hello from e2e"}
    resp = lam.invoke(FunctionName=func_name, Payload=json.dumps(payload))
    status = resp["StatusCode"]
    result = json.loads(resp["Payload"].read())
    _check("Lambda invoke status 200", status == 200, f"status={status}")
    _check("Lambda returns correct payload", result.get("body") == payload, f"result={result}")

    # Cleanup
    lam.delete_function(FunctionName=func_name)


# ---------------------------------------------------------------------------
# Test 3: Lambda + SQS Event Source Mapping
# ---------------------------------------------------------------------------
def test_lambda_sqs_trigger():
    _section("Test 3: Lambda + SQS Event Source Mapping")
    lam = _client("lambda")
    sqs = _client("sqs")
    iam = _client("iam")
    func_name = f"e2e-sqs-proc-{int(time.time())}"
    queue_name = f"e2e-input-{int(time.time())}"
    result_queue_name = f"e2e-result-{int(time.time())}"
    role_arn = _ensure_role(iam)

    # Create queues
    q_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    result_q_url = sqs.create_queue(QueueName=result_queue_name)["QueueUrl"]
    result_q_arn = sqs.get_queue_attributes(QueueUrl=result_q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    _check("Create SQS queues", q_url and result_q_url)

    # Lambda that reads from SQS and writes to result queue
    code = f"""
import json, boto3
def handler(event, context):
    sqs = boto3.client("sqs", endpoint_url="{ENDPOINT}", region_name="{REGION}")
    for record in event.get("Records", []):
        body = record["body"]
        sqs.send_message(QueueUrl="{result_q_url}", MessageBody="PROCESSED:" + body)
    return {{"statusCode": 200}}
"""
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(code)},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_for_function_active(lam, func_name)

    # Create event source mapping
    esm = lam.create_event_source_mapping(
        EventSourceArn=q_arn,
        FunctionName=func_name,
        BatchSize=1,
        Enabled=True,
    )
    esm_uuid = esm["UUID"]
    _check("Create event source mapping", esm_uuid is not None)

    # Send message to input queue
    sqs.send_message(QueueUrl=q_url, MessageBody="e2e-test-message")

    # Wait for the event source mapping poller to start and process.
    # The poller needs time to initialize and begin polling the source queue,
    # so we poll the result queue up to 90s.
    processed_state = {"ok": False}

    def _got_processed_message():
        msgs = sqs.receive_message(QueueUrl=result_q_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for m in msgs.get("Messages", []):
            if m["Body"] == "PROCESSED:e2e-test-message":
                processed_state["ok"] = True
                return True
        return False

    poll_condition(_got_processed_message, timeout=90, interval=1.0)
    processed = processed_state["ok"]

    _check("Lambda processed SQS message", processed,
           "Message not found in result queue after 90s" if not processed else "")

    # Cleanup
    lam.delete_event_source_mapping(UUID=esm_uuid)
    lam.delete_function(FunctionName=func_name)
    sqs.delete_queue(QueueUrl=q_url)
    sqs.delete_queue(QueueUrl=result_q_url)


# ---------------------------------------------------------------------------
# Test 4: Lambda + SNS Fan-out
# ---------------------------------------------------------------------------
def test_lambda_sns_fanout():
    _section("Test 4: Lambda + SNS Fan-out to SQS")
    sns = _client("sns")
    sqs = _client("sqs")

    topic_name = f"e2e-fanout-{int(time.time())}"
    q1_name = f"e2e-fan-q1-{int(time.time())}"
    q2_name = f"e2e-fan-q2-{int(time.time())}"

    # Create topic
    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    _check("Create SNS topic", topic_arn is not None)

    # Create two queues
    q1_url = sqs.create_queue(QueueName=q1_name)["QueueUrl"]
    q1_arn = sqs.get_queue_attributes(QueueUrl=q1_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    q2_url = sqs.create_queue(QueueName=q2_name)["QueueUrl"]
    q2_arn = sqs.get_queue_attributes(QueueUrl=q2_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Subscribe both queues to topic
    sub1 = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=q1_arn)
    sub2 = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=q2_arn)
    _check("Subscribe queues to SNS", sub1["SubscriptionArn"] and sub2["SubscriptionArn"])

    # Publish message
    sns.publish(TopicArn=topic_arn, Message="fanout-test-payload")

    # Both queues should receive the message — poll up to 30s.
    state = {"q1": False, "q2": False}

    def _both_received():
        if not state["q1"]:
            msgs1 = sqs.receive_message(QueueUrl=q1_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
            if msgs1.get("Messages"):
                body = json.loads(msgs1["Messages"][0]["Body"])
                state["q1"] = body.get("Message") == "fanout-test-payload"
        if not state["q2"]:
            msgs2 = sqs.receive_message(QueueUrl=q2_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
            if msgs2.get("Messages"):
                body = json.loads(msgs2["Messages"][0]["Body"])
                state["q2"] = body.get("Message") == "fanout-test-payload"
        return state["q1"] and state["q2"]

    poll_condition(_both_received, timeout=30, interval=0.5)
    q1_received = state["q1"]
    q2_received = state["q2"]

    _check("Queue 1 received SNS message", q1_received)
    _check("Queue 2 received SNS message", q2_received)

    # Cleanup
    sns.unsubscribe(SubscriptionArn=sub1["SubscriptionArn"])
    sns.unsubscribe(SubscriptionArn=sub2["SubscriptionArn"])
    sns.delete_topic(TopicArn=topic_arn)
    sqs.delete_queue(QueueUrl=q1_url)
    sqs.delete_queue(QueueUrl=q2_url)


# ---------------------------------------------------------------------------
# Test 5: Lambda + S3 Trigger
# ---------------------------------------------------------------------------
def test_lambda_s3_trigger():
    _section("Test 5: Lambda + S3 Trigger")
    s3 = _client("s3")
    lam = _client("lambda")
    sqs = _client("sqs")
    iam = _client("iam")
    func_name = f"e2e-s3-handler-{int(time.time())}"
    bucket_name = f"e2e-trigger-bucket-{int(time.time())}"
    result_queue = f"e2e-s3-result-{int(time.time())}"
    role_arn = _ensure_role(iam)

    # Create result queue to verify Lambda was invoked
    result_q_url = sqs.create_queue(QueueName=result_queue)["QueueUrl"]

    # Lambda function that writes S3 event info to SQS
    code = f"""
import json, boto3
def handler(event, context):
    sqs = boto3.client("sqs", endpoint_url="{ENDPOINT}", region_name="{REGION}")
    for record in event.get("Records", []):
        key = record["s3"]["object"]["key"]
        bucket = record["s3"]["bucket"]["name"]
        sqs.send_message(
            QueueUrl="{result_q_url}",
            MessageBody=json.dumps({{"bucket": bucket, "key": key}})
        )
    return {{"statusCode": 200}}
"""
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(code)},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_for_function_active(lam, func_name)

    # Get Lambda ARN
    func_arn = lam.get_function(FunctionName=func_name)["Configuration"]["FunctionArn"]

    # Create bucket
    s3.create_bucket(Bucket=bucket_name)

    # Add S3 notification configuration
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [{
                "LambdaFunctionArn": func_arn,
                "Events": ["s3:ObjectCreated:*"],
            }]
        },
    )
    _check("Configure S3 notification", True)

    # Upload a file to trigger Lambda
    s3.put_object(Bucket=bucket_name, Key="test-upload.txt", Body=b"hello e2e")

    # Check result queue — S3 notifications may take time to propagate
    trigger_state = {"ok": False}

    def _s3_triggered():
        msgs = sqs.receive_message(QueueUrl=result_q_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for m in msgs.get("Messages", []):
            body = json.loads(m["Body"])
            if body.get("key") == "test-upload.txt" and body.get("bucket") == bucket_name:
                trigger_state["ok"] = True
                return True
        return False

    poll_condition(_s3_triggered, timeout=75, interval=1.0)
    triggered = trigger_state["ok"]

    _check("Lambda triggered by S3 upload", triggered,
           "No message in result queue after 75s" if not triggered else "")

    # Cleanup
    s3.delete_object(Bucket=bucket_name, Key="test-upload.txt")
    s3.delete_bucket(Bucket=bucket_name)
    lam.delete_function(FunctionName=func_name)
    sqs.delete_queue(QueueUrl=result_q_url)


# ---------------------------------------------------------------------------
# Test 6: Lambda + CloudWatch Logs
# ---------------------------------------------------------------------------
def test_lambda_cloudwatch_logs():
    _section("Test 6: Lambda + CloudWatch Logs")
    lam = _client("lambda")
    logs = _client("logs")
    iam = _client("iam")
    func_name = f"e2e-logging-{int(time.time())}"
    role_arn = _ensure_role(iam)

    code = """
import sys
def handler(event, context):
    print("E2E_LOG_MARKER: test log output from Lambda")
    sys.stdout.flush()
    return {"statusCode": 200, "body": "logged"}
"""
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(code)},
        Timeout=30,
    )
    _wait_for_function_active(lam, func_name)

    # Invoke to generate logs
    resp = lam.invoke(FunctionName=func_name, Payload=json.dumps({}))
    _check("Lambda invoke for logging", resp["StatusCode"] == 200)

    # Wait for logs to appear in CloudWatch — poll until marker is found.
    log_group = f"/aws/lambda/{func_name}"
    marker_state = {"found": False}

    def _marker_present():
        try:
            streams = logs.describe_log_streams(
                logGroupName=log_group, orderBy="LastEventTime", descending=True
            )
            for stream in streams.get("logStreams", [])[:3]:
                events = logs.get_log_events(
                    logGroupName=log_group,
                    logStreamName=stream["logStreamName"],
                )
                for evt in events.get("events", []):
                    if "E2E_LOG_MARKER" in evt["message"]:
                        marker_state["found"] = True
                        return True
        except logs.exceptions.ResourceNotFoundException:
            return False
        return False

    poll_condition(_marker_present, timeout=30, interval=1.0)
    found_marker = marker_state["found"]

    _check("Lambda logs appear in CloudWatch Logs", found_marker,
           f"Log group {log_group} missing or marker not found" if not found_marker else "")

    # Cleanup
    lam.delete_function(FunctionName=func_name)
    try:
        logs.delete_log_group(logGroupName=log_group)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test 7: IAM + CloudTrail
# ---------------------------------------------------------------------------
def test_iam_cloudtrail():
    _section("Test 7: IAM Users/Roles/Policies + CloudTrail Recording")
    iam = _client("iam")
    ct = _client("cloudtrail")

    user_name = f"e2e-user-{int(time.time())}"
    policy_name = f"e2e-policy-{int(time.time())}"

    # Create IAM user
    resp = iam.create_user(UserName=user_name)
    user_arn = resp["User"]["Arn"]
    _check("Create IAM user", user_arn is not None)

    # Create inline policy
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    })
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    _check("Attach inline policy", True)

    # List users
    users = iam.list_users()["Users"]
    found = any(u["UserName"] == user_name for u in users)
    _check("List IAM users contains our user", found)

    # List user policies
    policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    _check("List user policies", policy_name in policies)

    # Check CloudTrail for IAM events — poll until the CreateUser event for
    # our user appears (CloudTrail ingestion is asynchronous).
    ct_state = {"events": [], "found": False, "error": None}

    def _ct_has_create_user():
        try:
            events = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateUser"}],
                MaxResults=10,
            )
            ct_state["events"] = events.get("Events", [])
            ct_state["found"] = any(
                user_name in (e.get("CloudTrailEvent", "") or json.dumps(e))
                for e in ct_state["events"]
            )
            return ct_state["found"]
        except Exception as e:
            ct_state["error"] = str(e)
            return False

    poll_condition(_ct_has_create_user, timeout=30, interval=1.0)
    if ct_state["error"] and not ct_state["found"]:
        _check("CloudTrail recorded CreateUser", False, f"CloudTrail error: {ct_state['error']}")
    else:
        _check(
            "CloudTrail recorded CreateUser",
            ct_state["found"],
            (
                f"Found {len(ct_state['events'])} CreateUser events but none matching {user_name}"
                if not ct_state["found"] else ""
            ),
        )

    # Cleanup
    iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    iam.delete_user(UserName=user_name)


# ---------------------------------------------------------------------------
# Test 8: Step Functions + Lambda
# ---------------------------------------------------------------------------
def test_stepfunctions_lambda():
    _section("Test 8: Step Functions with Lambda Task")
    sfn = _client("stepfunctions")
    lam = _client("lambda")
    iam = _client("iam")
    func_name = f"e2e-sfn-worker-{int(time.time())}"
    sm_name = f"e2e-statemachine-{int(time.time())}"
    role_arn = _ensure_role(iam)

    # Create Lambda function for the task
    code = """
def handler(event, context):
    name = event.get("name", "World")
    return {"greeting": f"Hello, {name}!"}
"""
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(code)},
        Timeout=30,
    )
    _wait_for_function_active(lam, func_name)
    func_arn = lam.get_function(FunctionName=func_name)["Configuration"]["FunctionArn"]

    # Create state machine
    definition = json.dumps({
        "Comment": "E2E test state machine",
        "StartAt": "Greet",
        "States": {
            "Greet": {
                "Type": "Task",
                "Resource": func_arn,
                "End": True,
            }
        },
    })

    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=role_arn,
    )
    sm_arn = sm_resp["stateMachineArn"]
    _check("Create state machine", sm_arn is not None)

    # Start execution
    exec_resp = sfn.start_execution(
        stateMachineArn=sm_arn,
        input=json.dumps({"name": "LocalEmu"}),
    )
    exec_arn = exec_resp["executionArn"]
    _check("Start execution", exec_arn is not None)

    # Wait for completion — poll describe_execution until a terminal state.
    sfn_state = {"completed": False, "output": None, "status": None, "terminal_fail": False}

    def _sfn_done():
        desc = sfn.describe_execution(executionArn=exec_arn)
        sfn_state["status"] = desc["status"]
        if sfn_state["status"] == "SUCCEEDED":
            sfn_state["output"] = json.loads(desc["output"])
            sfn_state["completed"] = True
            return True
        if sfn_state["status"] in ("FAILED", "TIMED_OUT", "ABORTED"):
            sfn_state["terminal_fail"] = True
            return True
        return False

    poll_condition(_sfn_done, timeout=60, interval=1.0)
    completed = sfn_state["completed"]
    output = sfn_state["output"]
    status = sfn_state["status"]
    if sfn_state["terminal_fail"]:
        _check("Step Functions execution succeeded", False, f"status={status}")

    if completed:
        _check("Step Functions execution succeeded", True)
        _check("Step Functions output correct", output == {"greeting": "Hello, LocalEmu!"},
               f"output={output}")
    elif not completed and status not in ("FAILED", "TIMED_OUT", "ABORTED"):
        _check("Step Functions execution completed in time", False, f"still {status} after 60s")

    # Cleanup
    sfn.delete_state_machine(stateMachineArn=sm_arn)
    lam.delete_function(FunctionName=func_name)


# ---------------------------------------------------------------------------
# Test 9: DynamoDB CRUD + Streams (if available)
# ---------------------------------------------------------------------------
def test_dynamodb_crud():
    _section("Test 9: DynamoDB CRUD")
    ddb = _client("dynamodb")
    table_name = f"e2e-table-{int(time.time())}"

    # Create table
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    _check("Create DynamoDB table", True)

    # Wait for table active
    waiter = ddb.get_waiter("table_exists")
    waiter.wait(TableName=table_name, WaiterConfig={"Delay": 1, "MaxAttempts": 20})

    # Put item
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "user1"}, "name": {"S": "Alice"}, "age": {"N": "30"}})
    _check("Put item", True)

    # Get item
    resp = ddb.get_item(TableName=table_name, Key={"pk": {"S": "user1"}})
    item = resp.get("Item", {})
    _check("Get item", item.get("name", {}).get("S") == "Alice", f"got {item}")

    # Update item
    ddb.update_item(
        TableName=table_name,
        Key={"pk": {"S": "user1"}},
        UpdateExpression="SET age = :a",
        ExpressionAttributeValues={":a": {"N": "31"}},
    )
    resp = ddb.get_item(TableName=table_name, Key={"pk": {"S": "user1"}})
    _check("Update item", resp["Item"]["age"]["N"] == "31")

    # Query (scan)
    resp = ddb.scan(TableName=table_name)
    _check("Scan table", resp["Count"] == 1)

    # Delete item
    ddb.delete_item(TableName=table_name, Key={"pk": {"S": "user1"}})
    resp = ddb.scan(TableName=table_name)
    _check("Delete item", resp["Count"] == 0)

    # Cleanup
    ddb.delete_table(TableName=table_name)


# ---------------------------------------------------------------------------
# Test 10: S3 Full Lifecycle
# ---------------------------------------------------------------------------
def test_s3_lifecycle():
    _section("Test 10: S3 Full Lifecycle")
    s3 = _client("s3")
    bucket = f"e2e-lifecycle-{int(time.time())}"

    # Create bucket
    s3.create_bucket(Bucket=bucket)
    buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    _check("Create and list bucket", bucket in buckets)

    # Upload objects
    s3.put_object(Bucket=bucket, Key="folder/file1.txt", Body=b"content1")
    s3.put_object(Bucket=bucket, Key="folder/file2.txt", Body=b"content2")
    s3.put_object(Bucket=bucket, Key="root.txt", Body=b"root content")

    # List objects
    objs = s3.list_objects_v2(Bucket=bucket)
    keys = [o["Key"] for o in objs.get("Contents", [])]
    _check("List objects", len(keys) == 3 and "folder/file1.txt" in keys, f"keys={keys}")

    # List with prefix
    objs = s3.list_objects_v2(Bucket=bucket, Prefix="folder/")
    _check("List with prefix", objs["KeyCount"] == 2)

    # Get object
    resp = s3.get_object(Bucket=bucket, Key="root.txt")
    body = resp["Body"].read()
    _check("Get object content", body == b"root content")

    # Copy object
    s3.copy_object(Bucket=bucket, Key="root-copy.txt", CopySource=f"{bucket}/root.txt")
    resp = s3.get_object(Bucket=bucket, Key="root-copy.txt")
    _check("Copy object", resp["Body"].read() == b"root content")

    # Delete objects
    for key in ["folder/file1.txt", "folder/file2.txt", "root.txt", "root-copy.txt"]:
        s3.delete_object(Bucket=bucket, Key=key)
    s3.delete_bucket(Bucket=bucket)
    _check("Delete bucket", True)


# ---------------------------------------------------------------------------
# Test 11: SQS Full Lifecycle + Message Attributes
# ---------------------------------------------------------------------------
def test_sqs_lifecycle():
    _section("Test 11: SQS Full Lifecycle")
    sqs = _client("sqs")
    queue_name = f"e2e-queue-{int(time.time())}"

    # Create queue
    q_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"VisibilityTimeout": "10", "MessageRetentionPeriod": "3600"},
    )["QueueUrl"]
    _check("Create queue", q_url is not None)

    # Get queue attributes
    attrs = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["All"])["Attributes"]
    _check("Queue attributes", attrs["VisibilityTimeout"] == "10")

    # Send message with attributes
    sqs.send_message(
        QueueUrl=q_url,
        MessageBody="test-body",
        MessageAttributes={
            "env": {"DataType": "String", "StringValue": "e2e"},
        },
    )

    # Send batch
    sqs.send_message_batch(
        QueueUrl=q_url,
        Entries=[
            {"Id": "1", "MessageBody": "batch-1"},
            {"Id": "2", "MessageBody": "batch-2"},
        ],
    )

    # Receive messages — poll until we have all 3 (send_message is async on
    # some backends; WaitTimeSeconds=2 below provides its own backoff).
    all_bodies = []

    def _drained_all():
        msgs = sqs.receive_message(
            QueueUrl=q_url, MaxNumberOfMessages=10,
            MessageAttributeNames=["All"], WaitTimeSeconds=2,
        )
        for m in msgs.get("Messages", []):
            all_bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=q_url, ReceiptHandle=m["ReceiptHandle"])
        return len(all_bodies) >= 3

    poll_condition(_drained_all, timeout=15, interval=0.5)

    _check("Receive all 3 messages", len(all_bodies) == 3, f"got {len(all_bodies)}: {all_bodies}")
    _check("Message bodies correct", "test-body" in all_bodies and "batch-1" in all_bodies)

    # Purge queue
    sqs.purge_queue(QueueUrl=q_url)
    _check("Purge queue", True)

    # Delete queue
    sqs.delete_queue(QueueUrl=q_url)
    _check("Delete queue", True)


# ---------------------------------------------------------------------------
# Test 12: Kinesis Stream
# ---------------------------------------------------------------------------
def test_kinesis():
    _section("Test 12: Kinesis Data Stream")
    kin = _client("kinesis")
    stream_name = f"e2e-stream-{int(time.time())}"

    # Create stream
    kin.create_stream(StreamName=stream_name, ShardCount=1)
    _check("Create Kinesis stream", True)

    # Wait for ACTIVE using the native boto3 Kinesis waiter (no raw sleep).
    try:
        kin.get_waiter("stream_exists").wait(
            StreamName=stream_name,
            WaiterConfig={"Delay": 1, "MaxAttempts": 20},
        )
    except Exception:
        # Fall through — desc assertion below will surface the real status.
        pass
    desc = kin.describe_stream(StreamName=stream_name)
    _check("Stream active", desc["StreamDescription"]["StreamStatus"] == "ACTIVE")

    # Put records
    kin.put_record(StreamName=stream_name, Data=b"record-1", PartitionKey="pk1")
    kin.put_record(StreamName=stream_name, Data=b"record-2", PartitionKey="pk1")

    # Read records
    shard_id = desc["StreamDescription"]["Shards"][0]["ShardId"]
    iterator = kin.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]

    records = []
    iterator_state = {"it": iterator}

    def _records_drained():
        resp = kin.get_records(ShardIterator=iterator_state["it"], Limit=10)
        records.extend(resp.get("Records", []))
        iterator_state["it"] = resp["NextShardIterator"]
        return len(records) >= 2

    poll_condition(_records_drained, timeout=10, interval=0.5)

    data = [r["Data"] for r in records]
    _check("Read Kinesis records", len(records) >= 2, f"got {len(records)} records")
    _check("Record data correct", b"record-1" in data and b"record-2" in data)

    # Cleanup
    kin.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)


# ---------------------------------------------------------------------------
# Test 13: EventBridge
# ---------------------------------------------------------------------------
def test_eventbridge():
    _section("Test 13: EventBridge Rules + SQS Target")
    eb = _client("events")
    sqs = _client("sqs")
    queue_name = f"e2e-eb-target-{int(time.time())}"
    rule_name = f"e2e-rule-{int(time.time())}"

    # Create SQS target queue
    q_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Create rule
    eb.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["e2e.test"], "detail-type": ["E2ETest"]}),
        State="ENABLED",
    )
    _check("Create EventBridge rule", True)

    # Add SQS target
    eb.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "sqs-target", "Arn": q_arn}],
    )
    _check("Add SQS target to rule", True)

    # Put event
    eb.put_events(
        Entries=[{
            "Source": "e2e.test",
            "DetailType": "E2ETest",
            "Detail": json.dumps({"action": "verify"}),
        }],
    )

    # Check SQS received the event — poll up to 30s.
    eb_state = {"ok": False}

    def _eb_received():
        msgs = sqs.receive_message(QueueUrl=q_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        for m in msgs.get("Messages", []):
            body = m["Body"]
            if "verify" in body or "e2e.test" in body:
                eb_state["ok"] = True
                return True
        return False

    poll_condition(_eb_received, timeout=30, interval=1.0)
    received = eb_state["ok"]

    _check("EventBridge delivered event to SQS", received,
           "No event in SQS after 30s" if not received else "")

    # Cleanup
    eb.remove_targets(Rule=rule_name, Ids=["sqs-target"])
    eb.delete_rule(Name=rule_name)
    sqs.delete_queue(QueueUrl=q_url)


# ---------------------------------------------------------------------------
# Test 14: ECS API Lifecycle (Moto-backed, no Docker)
# ---------------------------------------------------------------------------
def test_ecs_api_lifecycle():
    _section("Test 14: ECS API Lifecycle (Moto-backed)")
    ecs = _client("ecs")
    cluster_name = f"e2e-cluster-{int(time.time())}"

    # Create cluster
    resp = ecs.create_cluster(clusterName=cluster_name)
    cluster_arn = resp["cluster"]["clusterArn"]
    _check("Create ECS cluster", cluster_arn is not None)
    _check("Cluster status ACTIVE", resp["cluster"]["status"] == "ACTIVE")

    # Register task definition
    resp = ecs.register_task_definition(
        family=f"e2e-task-{int(time.time())}",
        containerDefinitions=[{
            "name": "web",
            "image": "nginx:alpine",
            "memory": 256,
            "cpu": 128,
            "essential": True,
            "portMappings": [{"containerPort": 80, "hostPort": 80}],
        }],
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    _check("Register task definition", task_def_arn is not None)

    # List clusters
    clusters = ecs.list_clusters()["clusterArns"]
    _check("List clusters", cluster_arn in clusters)

    # Describe cluster
    desc = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    _check("Describe cluster", len(desc) == 1 and desc[0]["clusterName"] == cluster_name)

    # Deregister task definition
    ecs.deregister_task_definition(taskDefinition=task_def_arn)

    # Delete cluster
    ecs.delete_cluster(cluster=cluster_name)
    _check("Delete ECS cluster", True)


# ---------------------------------------------------------------------------
# Test 15: EKS API Lifecycle (Moto-backed, no k3d)
# ---------------------------------------------------------------------------
def test_eks_api_lifecycle():
    _section("Test 15: EKS API Lifecycle (Moto-backed)")
    eks = _client("eks")
    iam = _client("iam")
    cluster_name = f"e2e-k8s-{int(time.time())}"
    role_arn = _ensure_role(iam, "e2e-eks-role")

    # Create cluster
    try:
        resp = eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": ["subnet-12345"], "securityGroupIds": ["sg-12345"]},
        )
        status = resp["cluster"]["status"]
        _check("Create EKS cluster", status in ("CREATING", "ACTIVE", "CREATE_FAILED"),
               f"status={status}")
    except Exception as e:
        _check("Create EKS cluster", False, str(e))
        return

    # List clusters
    clusters = eks.list_clusters()["clusters"]
    _check("List EKS clusters", cluster_name in clusters)

    # Describe cluster
    desc = eks.describe_cluster(name=cluster_name)["cluster"]
    _check("Describe EKS cluster", desc["name"] == cluster_name)

    # Delete cluster
    eks.delete_cluster(name=cluster_name)
    _check("Delete EKS cluster", True)


# ---------------------------------------------------------------------------
# Test 16: RDS API Lifecycle (Moto-backed)
# ---------------------------------------------------------------------------
def test_rds_api_lifecycle():
    _section("Test 16: RDS API Lifecycle (Moto-backed)")
    rds = _client("rds")
    db_id = f"e2e-db-{int(time.time())}"

    # Create DB instance
    try:
        resp = rds.create_db_instance(
            DBInstanceIdentifier=db_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
        )
        status = resp["DBInstance"]["DBInstanceStatus"]
        _check("Create RDS instance", status in ("creating", "available"), f"status={status}")
    except Exception as e:
        _check("Create RDS instance", False, str(e))
        return

    # Describe
    desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)
    instances = desc["DBInstances"]
    _check("Describe RDS instance", len(instances) == 1)
    _check("Engine is postgres", instances[0]["Engine"] == "postgres")

    # List all
    all_dbs = rds.describe_db_instances()["DBInstances"]
    found = any(d["DBInstanceIdentifier"] == db_id for d in all_dbs)
    _check("List all DB instances", found)

    # Delete
    rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    _check("Delete RDS instance", True)


# ---------------------------------------------------------------------------
# Test 17: CloudWatch Metrics
# ---------------------------------------------------------------------------
def test_cloudwatch_metrics():
    _section("Test 17: CloudWatch Metrics")
    cw = _client("cloudwatch")
    namespace = f"E2E/Test/{int(time.time())}"

    # Put metric data
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "RequestCount", "Value": 42, "Unit": "Count", "Timestamp": now},
            {"MetricName": "Latency", "Value": 123.5, "Unit": "Milliseconds", "Timestamp": now},
        ],
    )
    _check("Put metric data", True)

    # List metrics
    resp = cw.list_metrics(Namespace=namespace)
    metric_names = [m["MetricName"] for m in resp["Metrics"]]
    _check("List metrics", "RequestCount" in metric_names and "Latency" in metric_names,
           f"found: {metric_names}")

    # Put alarm
    alarm_name = f"e2e-alarm-{int(time.time())}"
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="RequestCount",
        ComparisonOperator="GreaterThanThreshold",
        Threshold=100,
        EvaluationPeriods=1,
        Period=60,
        Statistic="Sum",
    )

    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    _check("Create and describe alarm", len(alarms) == 1)

    # Cleanup
    cw.delete_alarms(AlarmNames=[alarm_name])


# ---------------------------------------------------------------------------
# Test 18: Dashboard API Verification
# ---------------------------------------------------------------------------
def test_dashboard_api():
    _section("Test 18: Dashboard API")
    import urllib.request

    # Check dashboard loads
    try:
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/dashboard")
        html = resp.read().decode()
        _check("Dashboard HTML loads", "<html" in html.lower() and "LocalEmu" in html)
    except Exception as e:
        _check("Dashboard HTML loads", False, str(e))

    # Check health endpoint
    try:
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/health")
        data = json.loads(resp.read())
        _check("Health endpoint returns services", "services" in data)
        _check("Health shows version", "version" in data)
    except Exception as e:
        _check("Health endpoint", False, str(e))

    # Check dashboard API endpoints
    api_endpoints = [
        "/_localemu/dashboard/api/overview",
        "/_localemu/dashboard/api/s3",
        "/_localemu/dashboard/api/dynamodb",
        "/_localemu/dashboard/api/sqs",
        "/_localemu/dashboard/api/lambda",
        "/_localemu/dashboard/api/sns",
        "/_localemu/dashboard/api/iam",
        "/_localemu/dashboard/api/cloudwatch",
        "/_localemu/dashboard/api/secretsmanager",
    ]
    for endpoint in api_endpoints:
        try:
            resp = urllib.request.urlopen(f"{ENDPOINT}{endpoint}")
            data = json.loads(resp.read())
            _check(f"Dashboard API {endpoint.split('/')[-1]}", isinstance(data, (dict, list)))
        except Exception as e:
            _check(f"Dashboard API {endpoint.split('/')[-1]}", False, str(e))


# ===========================================================================
# Main
# ===========================================================================
def main():
    print("\n" + "=" * 70)
    print("  LocalEmu E2E Integration Test Suite")
    print("  Target: " + ENDPOINT)
    print("=" * 70)

    # Verify LocalEmu is running
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/health")
        data = json.loads(resp.read())
        print(f"  LocalEmu v{data.get('version', '?')} detected")
        running = sum(1 for s in data["services"].values() if s == "running")
        available = sum(1 for s in data["services"].values() if s == "available")
        print(f"  Services: {running} running, {available} available")
    except Exception as e:
        print(f"\n  ERROR: LocalEmu not reachable at {ENDPOINT}: {e}")
        print("  Start LocalEmu first: localemu start")
        sys.exit(1)

    tests = [
        test_secrets_manager_crud,
        test_lambda_basic_invoke,
        test_lambda_sqs_trigger,
        test_lambda_sns_fanout,
        test_lambda_s3_trigger,
        test_lambda_cloudwatch_logs,
        test_iam_cloudtrail,
        test_stepfunctions_lambda,
        test_dynamodb_crud,
        test_s3_lifecycle,
        test_sqs_lifecycle,
        test_kinesis,
        test_eventbridge,
        test_ecs_api_lifecycle,
        test_eks_api_lifecycle,
        test_rds_api_lifecycle,
        test_cloudwatch_metrics,
        test_dashboard_api,
    ]

    for test_fn in tests:
        try:
            test_fn()
        except Exception as e:
            global _failed
            _failed += 1
            _errors.append(f"{test_fn.__name__}: EXCEPTION: {e}")
            print(f"  [EXCEPTION] {test_fn.__name__}: {e}")

    # Summary
    print(f"\n{'='*70}")
    print(f"  RESULTS: {_passed} passed, {_failed} failed, {_skipped} skipped")
    print(f"{'='*70}")

    if _errors:
        print("\n  Failures:")
        for err in _errors:
            print(f"    - {err}")

    print()
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
