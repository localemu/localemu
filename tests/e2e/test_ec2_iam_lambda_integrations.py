#!/usr/bin/env python3
"""
E2E Integration Tests — EC2 + IAM + CloudTrail and Lambda Multi-Trigger.

Two major test scenarios:
  1. EC2 instance with IAM role → S3 access allowed/denied → CloudTrail audit
  2. Lambda triggered by 5 event sources (S3, SQS, SNS, DynamoDB Streams, EventBridge)

Requires: LocalEmu running with EC2_VM_MANAGER=docker IAM_ENFORCEMENT=1
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

_passed = 0
_failed = 0
_errors = []


def _client(service, access_key="test", secret_key="test"):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(retries={"max_attempts": 0}),
    )


def _make_lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


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


def _wait_function_active(lam, name, timeout=60):
    """Wait until Lambda function is Active using poll_condition (no raw sleep)."""
    def _is_active():
        try:
            resp = lam.get_function(FunctionName=name)
            return resp["Configuration"].get("State", "Active") == "Active"
        except Exception:
            return False

    return poll_condition(_is_active, timeout=timeout, interval=1.0)


# ===================================================================
# TEST 1: EC2 + IAM Instance Profile + S3 + CloudTrail
# ===================================================================
def test_ec2_iam_s3_cloudtrail():
    _section("TEST 1: EC2 Instance Profile + IAM Enforcement + S3 + CloudTrail")

    iam = _client("iam")
    ec2 = _client("ec2")
    s3 = _client("s3")
    ct = _client("cloudtrail")

    # --- Step 1: Create IAM role with S3 read-only policy ---
    print("\n  --- Step 1: Create IAM role with S3 read-only policy ---")
    role_name = "EC2-S3-ReadOnly-Role"
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })

    try:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Path="/")
    except iam.exceptions.EntityAlreadyExistsException:
        pass

    # Attach a policy that ONLY allows s3:GetObject and s3:ListBucket
    s3_readonly_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
            }
        ],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName="S3ReadOnly", PolicyDocument=s3_readonly_policy)
    _check("Create IAM role with S3 read-only policy", True)

    # --- Step 2: Create instance profile and associate role ---
    print("\n  --- Step 2: Create instance profile ---")
    profile_name = "EC2-S3-Profile"
    try:
        iam.create_instance_profile(InstanceProfileName=profile_name)
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    try:
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except iam.exceptions.LimitExceededException:
        pass  # Role already associated
    _check("Create instance profile with role", True)

    # --- Step 3: Create test S3 bucket and upload a file ---
    print("\n  --- Step 3: Create S3 bucket with test file ---")
    bucket_name = "e2e-iam-test-bucket"
    try:
        s3.create_bucket(Bucket=bucket_name)
    except Exception:
        pass
    s3.put_object(Bucket=bucket_name, Key="allowed-file.txt", Body=b"This file should be readable")
    _check("Create S3 bucket with test object", True)

    # --- Step 4: Launch EC2 instance with the instance profile ---
    print("\n  --- Step 4: Launch EC2 instance with instance profile ---")
    profile_arn = f"arn:aws:iam::000000000000:instance-profile/{profile_name}"
    try:
        resp = ec2.run_instances(
            ImageId="ami-ubuntu-22.04",
            MinCount=1, MaxCount=1,
            InstanceType="t2.micro",
            IamInstanceProfile={"Arn": profile_arn},
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        instance_state = resp["Instances"][0]["State"]["Name"]
        _check(f"Launch EC2 instance {instance_id}", instance_state in ("running", "pending"))
    except Exception as e:
        _check("Launch EC2 instance", False, str(e))
        instance_id = None

    # --- Step 5: Verify IMDS serves real credentials ---
    if instance_id:
        print("\n  --- Step 5: Verify IMDS credentials ---")
        import subprocess

        # Poll for the backing Docker container to become visible (instead of
        # a blind sleep). Times out at 30s and falls through to the check below.
        container_state = {"stdout": ""}

        def _container_visible():
            res = subprocess.run(
                ["docker", "ps", "--filter", f"name=localemu-ec2-{instance_id}", "--format", "{{.Names}}"],
                capture_output=True, text=True,
            )
            container_state["stdout"] = res.stdout or ""
            return instance_id in container_state["stdout"]

        poll_condition(_container_visible, timeout=30, interval=1.0)

        class _ContainersResult:
            stdout = container_state["stdout"]

        containers = _ContainersResult()
        container_running = instance_id in (containers.stdout or "")
        _check("Docker container running", container_running, containers.stdout.strip())

        # Get SSH port from describe-instances
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        tags = desc["Reservations"][0]["Instances"][0].get("Tags", [])
        ssh_port = None
        imds_port = None
        for tag in tags:
            if tag["Key"] == "localemu:ssh-port":
                ssh_port = int(tag["Value"])

        if ssh_port:
            _check(f"SSH port allocated: {ssh_port}", True)
        else:
            _check("SSH port allocated", False, "No localemu:ssh-port tag found")

        # Query IMDS from the HOST side (the base Docker image has no HTTP
        # tools — no curl, wget, or python3 — so we query from the host
        # using the IMDS port, which is what the container would do via
        # host.docker.internal).
        if container_running:
            container_name = f"localemu-ec2-{instance_id}"
            # Get the IMDS port from the container env
            imds_check = subprocess.run(
                ["docker", "exec", container_name, "printenv", "AWS_EC2_METADATA_SERVICE_ENDPOINT"],
                capture_output=True, text=True,
            )
            imds_endpoint = imds_check.stdout.strip()
            # Convert host.docker.internal to localhost for host-side queries
            imds_host_endpoint = imds_endpoint.replace("host.docker.internal", "localhost") if imds_endpoint else ""

            if imds_host_endpoint:
                import urllib.request

                # Query IMDS for role name
                try:
                    imds_role = urllib.request.urlopen(
                        f"{imds_host_endpoint}/latest/meta-data/iam/security-credentials/", timeout=5
                    ).read().decode().strip()
                except Exception as e:
                    imds_role = f"ERROR: {e}"

                _check("IMDS returns role name", imds_role == role_name,
                       f"expected '{role_name}', got '{imds_role}'")

                # Query IMDS for credentials
                if imds_role == role_name:
                    try:
                        creds_raw = urllib.request.urlopen(
                            f"{imds_host_endpoint}/latest/meta-data/iam/security-credentials/{imds_role}", timeout=5
                        ).read().decode()
                    except Exception as e:
                        creds_raw = json.dumps({"error": str(e)})

                    # Parse credentials — simulate what creds_check.stdout was
                    class _FakeResult:
                        stdout = creds_raw
                    creds_check = _FakeResult()
                    try:
                        creds = json.loads(creds_check.stdout)
                        key_id = creds.get("AccessKeyId", "")
                        # Moto generates temp keys with account-hash prefix (e.g. LSIAQ...)
                        # Real AWS uses ASIA prefix. Both indicate real STS credentials.
                        has_real_key = len(key_id) >= 16 and key_id != "ASIAEXAMPLE"
                        _check("IMDS returns real STS credentials (not hardcoded)",
                               has_real_key, f"got key: {key_id}")
                        _check("IMDS credentials have Token",
                               bool(creds.get("Token")))
                        _check("IMDS credentials have Expiration",
                               bool(creds.get("Expiration")))

                        # --- Step 6: Use IMDS credentials to access S3 ---
                        if has_real_key:
                            print("\n  --- Step 6: Test S3 access with instance credentials ---")
                            instance_s3 = _client(
                                "s3",
                                access_key=creds["AccessKeyId"],
                                secret_key=creds["SecretAccessKey"],
                            )

                            # GetObject should SUCCEED (role allows s3:GetObject)
                            try:
                                obj = instance_s3.get_object(Bucket=bucket_name, Key="allowed-file.txt")
                                body = obj["Body"].read()
                                _check("S3 GetObject with instance creds (allowed)", body == b"This file should be readable")
                            except Exception as e:
                                _check("S3 GetObject with instance creds (allowed)", False, str(e))

                            # PutObject should be DENIED (role only allows Get/List)
                            try:
                                instance_s3.put_object(Bucket=bucket_name, Key="denied-file.txt", Body=b"should fail")
                                _check("S3 PutObject with instance creds (should be denied)", False, "PutObject succeeded but should have been denied")
                            except instance_s3.exceptions.ClientError as e:
                                error_code = e.response["Error"]["Code"]
                                _check("S3 PutObject denied (AccessDenied)",
                                       error_code in ("AccessDenied", "403"),
                                       f"error code: {error_code}")
                            except Exception as e:
                                _check("S3 PutObject denied", False, str(e))

                            # --- Step 7: Verify CloudTrail recorded the denial ---
                            print("\n  --- Step 7: Verify CloudTrail records ---")

                            # Poll for CloudTrail to ingest PutObject events
                            # (asynchronous pipeline) instead of a blind sleep.
                            def _ct_has_putobject():
                                try:
                                    r = ct.lookup_events(
                                        LookupAttributes=[{
                                            "AttributeKey": "EventName",
                                            "AttributeValue": "PutObject",
                                        }],
                                        MaxResults=10,
                                    )
                                    return len(r.get("Events", [])) > 0
                                except Exception:
                                    return False

                            poll_condition(_ct_has_putobject, timeout=30, interval=1.0)
                            try:
                                ct_events = ct.lookup_events(
                                    LookupAttributes=[{
                                        "AttributeKey": "EventName",
                                        "AttributeValue": "PutObject",
                                    }],
                                    MaxResults=10,
                                )
                                events = ct_events.get("Events", [])
                                # Look for the denied PutObject
                                denied_events = []
                                for ev in events:
                                    ct_json = json.loads(ev.get("CloudTrailEvent", "{}"))
                                    if ct_json.get("errorCode"):
                                        denied_events.append(ct_json)

                                _check("CloudTrail has PutObject events", len(events) > 0,
                                       f"found {len(events)} PutObject events")

                                if denied_events:
                                    _check("CloudTrail recorded AccessDenied",
                                           any("Denied" in str(e.get("errorCode", "")) or "403" in str(e.get("errorCode", ""))
                                               for e in denied_events),
                                           f"error codes: {[e.get('errorCode') for e in denied_events]}")
                                else:
                                    _check("CloudTrail recorded AccessDenied", False,
                                           "No denied events found in CloudTrail")

                                # Verify the allowed GetObject is also recorded
                                get_events = ct.lookup_events(
                                    LookupAttributes=[{
                                        "AttributeKey": "EventName",
                                        "AttributeValue": "GetObject",
                                    }],
                                    MaxResults=10,
                                )
                                _check("CloudTrail recorded GetObject",
                                       len(get_events.get("Events", [])) > 0)

                            except Exception as e:
                                _check("CloudTrail lookup", False, str(e))

                    except json.JSONDecodeError:
                        _check("IMDS returns valid JSON credentials", False, creds_check.stdout[:200])
            else:
                _check("IMDS endpoint available", False, "No AWS_EC2_METADATA_SERVICE_ENDPOINT in container env")

    # Cleanup
    print("\n  --- Cleanup ---")
    if instance_id:
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            _check("Terminate EC2 instance", True)
        except Exception as e:
            _check("Terminate EC2 instance", False, str(e))

    try:
        s3.delete_object(Bucket=bucket_name, Key="allowed-file.txt")
        s3.delete_bucket(Bucket=bucket_name)
    except Exception:
        pass


# ===================================================================
# TEST 2: Lambda Multi-Trigger Integration
# ===================================================================
def test_lambda_multi_trigger():
    _section("TEST 2: Lambda Multi-Trigger (S3, SQS, SNS, DynamoDB Streams, EventBridge)")

    lam = _client("lambda")
    s3 = _client("s3")
    sqs = _client("sqs")
    sns = _client("sns")
    ddb = _client("dynamodb")
    eb = _client("events")
    iam = _client("iam")
    logs = _client("logs")

    # Create a shared result queue where all Lambdas write their trigger source
    result_queue_name = f"e2e-lambda-results"
    result_q_url = sqs.create_queue(QueueName=result_queue_name)["QueueUrl"]
    _check("Create result queue", result_q_url is not None)

    # Create IAM role for all Lambda functions
    role_name = "e2e-lambda-role"
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
            }),
        )
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    # Lambda needs broad permissions for ESM to work (SQS polling, DynamoDB streams, logs)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="LambdaFullAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    # Lambda code template — writes trigger source + event details to the result queue.
    # Lambda containers use LOCALEMU_HOSTNAME env var to reach the host (not localhost).
    def _make_handler(trigger_name):
        return f"""
import json, boto3, os
def handler(event, context):
    # Lambda containers can't use localhost — use LOCALEMU_HOSTNAME env var
    host = os.environ.get("LOCALEMU_HOSTNAME", "host.docker.internal")
    endpoint = f"http://{{host}}:4566"
    sqs = boto3.client("sqs", endpoint_url=endpoint, region_name="{REGION}",
                       aws_access_key_id="test", aws_secret_access_key="test")
    # Log the event for CloudWatch
    print(f"TRIGGER:{trigger_name} EVENT:" + json.dumps(event, default=str)[:500])
    # Rewrite queue URL to use the container-accessible endpoint
    queue_url = "{result_q_url}".replace("localhost", host).replace("127.0.0.1", host)
    sqs.send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps({{"trigger": "{trigger_name}", "event_keys": list(event.keys()) if isinstance(event, dict) else "not-dict"}})
    )
    return {{"statusCode": 200, "trigger": "{trigger_name}"}}
"""

    # Helper to drain result queue using poll_condition (SQS long-polling via
    # WaitTimeSeconds=3 handles backoff — no raw sleep needed).
    def _drain_results(expected_trigger, timeout=60):
        found = {"body": None}

        def _check_once():
            msgs = sqs.receive_message(
                QueueUrl=result_q_url, MaxNumberOfMessages=10, WaitTimeSeconds=3,
            )
            for m in msgs.get("Messages", []):
                body = json.loads(m["Body"])
                sqs.delete_message(QueueUrl=result_q_url, ReceiptHandle=m["ReceiptHandle"])
                if body.get("trigger") == expected_trigger:
                    found["body"] = body
                    return True
            return False

        poll_condition(_check_once, timeout=timeout, interval=0.5)
        return found["body"]

    # =======================================================
    # Trigger 1: S3 → Lambda
    # =======================================================
    print("\n  --- Trigger 1: S3 → Lambda ---")
    s3_func = "e2e-s3-trigger-handler"
    s3_bucket = "e2e-s3-trigger-bucket"

    lam.create_function(
        FunctionName=s3_func, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(_make_handler("S3"))},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_function_active(lam, s3_func)
    func_arn = lam.get_function(FunctionName=s3_func)["Configuration"]["FunctionArn"]

    s3.create_bucket(Bucket=s3_bucket)
    s3.put_bucket_notification_configuration(
        Bucket=s3_bucket,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [{
                "LambdaFunctionArn": func_arn,
                "Events": ["s3:ObjectCreated:*"],
            }]
        },
    )
    _check("Setup S3 → Lambda trigger", True)

    # Fire!
    s3.put_object(Bucket=s3_bucket, Key="trigger-test.txt", Body=b"hello from s3")
    result = _drain_results("S3", timeout=45)
    _check("S3 triggered Lambda", result is not None,
           "Lambda not triggered after 45s" if not result else f"event_keys={result.get('event_keys')}")

    # =======================================================
    # Trigger 2: SQS → Lambda (Event Source Mapping)
    # =======================================================
    print("\n  --- Trigger 2: SQS → Lambda ---")
    sqs_func = "e2e-sqs-trigger-handler"
    sqs_queue = "e2e-sqs-trigger-queue"

    lam.create_function(
        FunctionName=sqs_func, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(_make_handler("SQS"))},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_function_active(lam, sqs_func)

    q_url = sqs.create_queue(QueueName=sqs_queue)["QueueUrl"]
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    esm = lam.create_event_source_mapping(
        EventSourceArn=q_arn, FunctionName=sqs_func,
        BatchSize=1, Enabled=True,
    )
    esm_uuid = esm["UUID"]
    _check("Setup SQS → Lambda ESM", esm_uuid is not None)

    # Fire!
    sqs.send_message(QueueUrl=q_url, MessageBody="hello from sqs")
    result = _drain_results("SQS", timeout=90)
    _check("SQS triggered Lambda", result is not None,
           "Lambda not triggered after 90s" if not result else f"event_keys={result.get('event_keys')}")

    # =======================================================
    # Trigger 3: SNS → Lambda
    # =======================================================
    print("\n  --- Trigger 3: SNS → Lambda ---")
    sns_func = "e2e-sns-trigger-handler"
    topic_name = "e2e-sns-trigger-topic"

    lam.create_function(
        FunctionName=sns_func, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(_make_handler("SNS"))},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_function_active(lam, sns_func)
    sns_func_arn = lam.get_function(FunctionName=sns_func)["Configuration"]["FunctionArn"]

    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=sns_func_arn)
    _check("Setup SNS → Lambda subscription", True)

    # Fire!
    sns.publish(TopicArn=topic_arn, Message="hello from sns")
    result = _drain_results("SNS", timeout=30)
    _check("SNS triggered Lambda", result is not None,
           "Lambda not triggered after 30s" if not result else f"event_keys={result.get('event_keys')}")

    # =======================================================
    # Trigger 4: DynamoDB Streams → Lambda
    # =======================================================
    print("\n  --- Trigger 4: DynamoDB Streams → Lambda ---")
    ddb_func = "e2e-ddb-trigger-handler"
    ddb_table = "e2e-ddb-trigger-table"

    lam.create_function(
        FunctionName=ddb_func, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(_make_handler("DYNAMODB"))},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_function_active(lam, ddb_func)

    # Create table WITH streams enabled
    ddb.create_table(
        TableName=ddb_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
    )
    # Wait for the table to become ACTIVE via the native DynamoDB waiter —
    # guarantees the stream ARN is populated before we describe.
    try:
        ddb.get_waiter("table_exists").wait(
            TableName=ddb_table,
            WaiterConfig={"Delay": 1, "MaxAttempts": 30},
        )
    except Exception:
        pass
    table_desc = ddb.describe_table(TableName=ddb_table)
    stream_arn = table_desc["Table"].get("LatestStreamArn")
    _check("DynamoDB table with streams", stream_arn is not None, f"stream_arn={stream_arn}")

    ddb_esm_uuid = None
    if stream_arn:
        try:
            ddb_esm = lam.create_event_source_mapping(
                EventSourceArn=stream_arn, FunctionName=ddb_func,
                BatchSize=1, StartingPosition="TRIM_HORIZON", Enabled=True,
            )
            ddb_esm_uuid = ddb_esm["UUID"]
            _check("Setup DynamoDB Streams → Lambda ESM", ddb_esm_uuid is not None)

            # Fire!
            ddb.put_item(TableName=ddb_table, Item={"pk": {"S": "trigger-test"}, "data": {"S": "hello from dynamodb"}})
            result = _drain_results("DYNAMODB", timeout=90)
            _check("DynamoDB Streams triggered Lambda", result is not None,
                   "Lambda not triggered after 90s" if not result else f"event_keys={result.get('event_keys')}")
        except Exception as e:
            _check("DynamoDB Streams → Lambda ESM", False, f"ESM creation failed: {e}")

    # =======================================================
    # Trigger 5: EventBridge → Lambda
    # =======================================================
    print("\n  --- Trigger 5: EventBridge → Lambda ---")
    eb_func = "e2e-eb-trigger-handler"
    rule_name = "e2e-eb-trigger-rule"

    lam.create_function(
        FunctionName=eb_func, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _make_lambda_zip(_make_handler("EVENTBRIDGE"))},
        Timeout=30,
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}},
    )
    _wait_function_active(lam, eb_func)
    eb_func_arn = lam.get_function(FunctionName=eb_func)["Configuration"]["FunctionArn"]

    # Create rule matching custom events
    eb.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({
            "source": ["e2e.test"],
            "detail-type": ["LambdaTriggerTest"],
        }),
        State="ENABLED",
    )
    eb.put_targets(Rule=rule_name, Targets=[{"Id": "lambda-target", "Arn": eb_func_arn}])
    _check("Setup EventBridge → Lambda rule", True)

    # Fire!
    eb.put_events(Entries=[{
        "Source": "e2e.test",
        "DetailType": "LambdaTriggerTest",
        "Detail": json.dumps({"action": "hello from eventbridge"}),
    }])
    result = _drain_results("EVENTBRIDGE", timeout=30)
    _check("EventBridge triggered Lambda", result is not None,
           "Lambda not triggered after 30s" if not result else f"event_keys={result.get('event_keys')}")

    # =======================================================
    # Verify CloudWatch Logs from all Lambdas
    # =======================================================
    print("\n  --- Verify CloudWatch Logs ---")

    for func_name, trigger in [
        (s3_func, "S3"), (sqs_func, "SQS"), (sns_func, "SNS"),
        (ddb_func, "DYNAMODB"), (eb_func, "EVENTBRIDGE"),
    ]:
        log_group = f"/aws/lambda/{func_name}"
        # Poll each log group until the TRIGGER marker appears (replaces a
        # blind 5s flush sleep). Times out at 30s per function.
        log_state = {"has_trigger": False, "messages": 0, "error": None}

        def _log_has_trigger(lg=log_group, t=trigger):
            try:
                streams = logs.describe_log_streams(
                    logGroupName=lg, orderBy="LastEventTime", descending=True,
                )
                if not streams.get("logStreams"):
                    return False
                events = logs.get_log_events(
                    logGroupName=lg,
                    logStreamName=streams["logStreams"][0]["logStreamName"],
                )
                msgs = [e["message"] for e in events.get("events", [])]
                log_state["messages"] = len(msgs)
                if any(f"TRIGGER:{t}" in m for m in msgs):
                    log_state["has_trigger"] = True
                    return True
                return False
            except Exception as e:
                log_state["error"] = str(e)
                return False

        poll_condition(_log_has_trigger, timeout=30, interval=1.0)

        if log_state["error"] and not log_state["has_trigger"]:
            _check(f"CloudWatch Logs for {trigger} Lambda", False, log_state["error"])
        else:
            _check(
                f"CloudWatch Logs for {trigger} Lambda",
                log_state["has_trigger"],
                (
                    f"found {log_state['messages']} log entries"
                    if not log_state["has_trigger"] else ""
                ),
            )

    # =======================================================
    # Cleanup
    # =======================================================
    print("\n  --- Cleanup ---")
    for func in [s3_func, sqs_func, sns_func, ddb_func, eb_func]:
        try:
            lam.delete_function(FunctionName=func)
        except Exception:
            pass
    try:
        lam.delete_event_source_mapping(UUID=esm_uuid)
    except Exception:
        pass
    if stream_arn:
        try:
            lam.delete_event_source_mapping(UUID=ddb_esm_uuid)
        except Exception:
            pass
    try:
        eb.remove_targets(Rule=rule_name, Ids=["lambda-target"])
        eb.delete_rule(Name=rule_name)
    except Exception:
        pass
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except Exception:
        pass
    try:
        sqs.delete_queue(QueueUrl=q_url)
        sqs.delete_queue(QueueUrl=result_q_url)
    except Exception:
        pass
    try:
        ddb.delete_table(TableName=ddb_table)
    except Exception:
        pass
    try:
        s3.delete_object(Bucket=s3_bucket, Key="trigger-test.txt")
        s3.delete_bucket(Bucket=s3_bucket)
    except Exception:
        pass
    _check("Cleanup complete", True)


# ===================================================================
# Main
# ===================================================================
def main():
    print("\n" + "=" * 70)
    print("  LocalEmu E2E: EC2+IAM+CloudTrail & Lambda Multi-Trigger")
    print("  Target: " + ENDPOINT)
    print("=" * 70)

    # Verify LocalEmu is running
    try:
        import urllib.request
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/health")
        data = json.loads(resp.read())
        print(f"  LocalEmu v{data.get('version', '?')} detected")
    except Exception as e:
        print(f"\n  ERROR: LocalEmu not reachable: {e}")
        sys.exit(1)

    tests = [
        test_ec2_iam_s3_cloudtrail,
        test_lambda_multi_trigger,
    ]

    for test_fn in tests:
        try:
            test_fn()
        except Exception as e:
            import traceback
            global _failed
            _failed += 1
            _errors.append(f"{test_fn.__name__}: EXCEPTION: {e}")
            print(f"\n  [EXCEPTION] {test_fn.__name__}: {e}")
            traceback.print_exc()

    # Summary
    print(f"\n{'='*70}")
    print(f"  RESULTS: {_passed} passed, {_failed} failed")
    print(f"{'='*70}")

    if _errors:
        print("\n  Failures:")
        for err in _errors:
            print(f"    - {err}")

    print()
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
