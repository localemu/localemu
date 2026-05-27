"""Broad smoke across LocalEmu's data-plane services.

Cheap, focused, no Docker. Each test exercises the smallest contract
that proves the service can handle a real user app:
  S3            — put + get + list + delete
  SQS           — send + receive + delete
  SNS → SQS     — subscribe + publish, see message
  Lambda        — create + invoke, receive payload back
  DynamoDB      — create table + put + get item, delete
  IAM           — create role + assume role
  STS           — assume role returns Credentials
  Secrets Mgr   — create + get + delete secret
  KMS           — create key, encrypt + decrypt round-trip
  CloudWatch    — put metric data + get
  Logs          — log group + put events + get events
  EventBridge   — rule + target → SQS sink
  Step Funcs    — create Pass machine + start execution
  CloudFormation— deploy a 1-resource template (S3 bucket)
"""

import json
import sys
import time
import uuid

import boto3
import botocore.exceptions

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
KW = dict(
    endpoint_url=ENDPOINT, region_name=REGION,
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

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


# ---------------------------------------------------------------------------
def s3_put_get_list_delete():
    s3 = boto3.client("s3", **KW)
    b = f"broad-s3-{uid}"
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="k1", Body=b"hello")
    obj = s3.get_object(Bucket=b, Key="k1")
    body = obj["Body"].read()
    assert body == b"hello", body
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=b).get("Contents", [])]
    assert "k1" in keys, keys
    s3.delete_object(Bucket=b, Key="k1")
    s3.delete_bucket(Bucket=b)


def sqs_send_receive():
    sqs = boto3.client("sqs", **KW)
    qurl = sqs.create_queue(QueueName=f"broad-sqs-{uid}")["QueueUrl"]
    sqs.send_message(QueueUrl=qurl, MessageBody="hi")
    resp = sqs.receive_message(QueueUrl=qurl, WaitTimeSeconds=2)
    msgs = resp.get("Messages") or []
    assert msgs and msgs[0]["Body"] == "hi", resp
    sqs.delete_message(QueueUrl=qurl, ReceiptHandle=msgs[0]["ReceiptHandle"])
    sqs.delete_queue(QueueUrl=qurl)


def sns_publish_to_sqs():
    sns = boto3.client("sns", **KW)
    sqs = boto3.client("sqs", **KW)
    topic = sns.create_topic(Name=f"broad-topic-{uid}")["TopicArn"]
    qurl = sqs.create_queue(QueueName=f"broad-sns-sink-{uid}")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=qarn,
                  Attributes={"RawMessageDelivery": "true"})
    sns.publish(TopicArn=topic, Message="hello-sns")
    deadline = time.time() + 15
    while time.time() < deadline:
        msgs = sqs.receive_message(QueueUrl=qurl, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            assert msgs[0]["Body"] == "hello-sns", msgs[0]["Body"]
            sqs.delete_queue(QueueUrl=qurl)
            sns.delete_topic(TopicArn=topic)
            return
    raise AssertionError("SNS→SQS message never arrived")


def lambda_invoke():
    lam = boto3.client("lambda", **KW)
    iam = boto3.client("iam", **KW)
    role = f"broad-lam-{uid}"
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    import io, zipfile
    code = b"def handler(event, ctx):\n    return {'echo': event}\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("h.py", code)
    buf.seek(0)
    name = f"broad-fn-{uid}"
    lam.create_function(
        FunctionName=name, Runtime="python3.12",
        Role=f"arn:aws:iam::000000000000:role/{role}",
        Handler="h.handler", Code={"ZipFile": buf.getvalue()},
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        if lam.get_function_configuration(FunctionName=name)["State"] == "Active":
            break
        time.sleep(1)
    r = lam.invoke(FunctionName=name, Payload=b'{"x": 1}')
    payload = json.loads(r["Payload"].read())
    assert payload == {"echo": {"x": 1}}, payload
    lam.delete_function(FunctionName=name)


def dynamodb_table_put_get():
    ddb = boto3.client("dynamodb", **KW)
    table = f"broad-tbl-{uid}"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    waiter = ddb.get_waiter("table_exists")
    waiter.wait(TableName=table)
    ddb.put_item(TableName=table, Item={"pk": {"S": "k1"}, "v": {"S": "v1"}})
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}})
    assert got["Item"]["v"]["S"] == "v1", got["Item"]
    ddb.delete_table(TableName=table)


def iam_create_role_and_assume():
    iam = boto3.client("iam", **KW)
    sts = boto3.client("sts", **KW)
    role = f"broad-iam-{uid}"
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}))
    arn = f"arn:aws:iam::000000000000:role/{role}"
    r = sts.assume_role(RoleArn=arn, RoleSessionName="broad-sess")
    creds = r.get("Credentials") or {}
    assert creds.get("AccessKeyId") and creds.get("SecretAccessKey"), creds
    iam.delete_role(RoleName=role)


def secretsmanager_round_trip():
    sm = boto3.client("secretsmanager", **KW)
    name = f"broad-sec-{uid}"
    sm.create_secret(Name=name, SecretString=json.dumps({"k": "v"}))
    got = sm.get_secret_value(SecretId=name)
    assert json.loads(got["SecretString"]) == {"k": "v"}
    sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)


def kms_encrypt_decrypt():
    kms = boto3.client("kms", **KW)
    key = kms.create_key()["KeyMetadata"]["KeyId"]
    enc = kms.encrypt(KeyId=key, Plaintext=b"sweep")["CiphertextBlob"]
    dec = kms.decrypt(CiphertextBlob=enc)["Plaintext"]
    assert dec == b"sweep", dec


def cloudwatch_put_get_metric():
    cw = boto3.client("cloudwatch", **KW)
    cw.put_metric_data(
        Namespace=f"BroadSweep-{uid}",
        MetricData=[{"MetricName": "Hits", "Value": 1.0, "Unit": "Count"}],
    )
    # GetMetricData with EndTime now + 1s, StartTime now - 60s
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    r = cw.get_metric_statistics(
        Namespace=f"BroadSweep-{uid}", MetricName="Hits",
        StartTime=now - dt.timedelta(minutes=10),
        EndTime=now + dt.timedelta(minutes=1),
        Period=60, Statistics=["Sum"],
    )
    # We accept ANY return — the call just needs to succeed.
    assert "Datapoints" in r, r


def logs_put_get():
    logs = boto3.client("logs", **KW)
    grp = f"/broad/{uid}"
    stream = "s1"
    logs.create_log_group(logGroupName=grp)
    logs.create_log_stream(logGroupName=grp, logStreamName=stream)
    import time as _t
    logs.put_log_events(
        logGroupName=grp, logStreamName=stream,
        logEvents=[{"timestamp": int(_t.time() * 1000), "message": "hello"}],
    )
    r = logs.get_log_events(logGroupName=grp, logStreamName=stream)
    msgs = [e["message"] for e in r.get("events", [])]
    assert "hello" in msgs, msgs
    logs.delete_log_group(logGroupName=grp)


def eventbridge_rule_with_sqs_target():
    events = boto3.client("events", **KW)
    sqs = boto3.client("sqs", **KW)
    qurl = sqs.create_queue(QueueName=f"broad-evt-{uid}")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    rule = f"broad-rule-{uid}"
    events.put_rule(Name=rule, EventPattern=json.dumps({"source": ["broad.test"]}))
    events.put_targets(Rule=rule, Targets=[{"Id": "1", "Arn": qarn}])
    events.put_events(Entries=[{
        "Source": "broad.test", "DetailType": "t", "Detail": json.dumps({"u": uid}),
    }])
    deadline = time.time() + 15
    while time.time() < deadline:
        msgs = sqs.receive_message(QueueUrl=qurl, WaitTimeSeconds=2).get("Messages", [])
        if msgs:
            break
    assert msgs, "EventBridge rule didn't deliver to SQS"
    events.remove_targets(Rule=rule, Ids=["1"])
    events.delete_rule(Name=rule)
    sqs.delete_queue(QueueUrl=qurl)


def stepfunctions_pass_state_machine():
    sf = boto3.client("stepfunctions", **KW)
    iam = boto3.client("iam", **KW)
    role = f"broad-sfn-{uid}"
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    asl = {
        "Comment": "broad", "StartAt": "P",
        "States": {"P": {"Type": "Pass", "Result": "ok", "End": True}},
    }
    name = f"broad-sfn-{uid}"
    sm = sf.create_state_machine(
        name=name,
        definition=json.dumps(asl),
        roleArn=f"arn:aws:iam::000000000000:role/{role}",
    )["stateMachineArn"]
    ex = sf.start_execution(stateMachineArn=sm, input='{}')["executionArn"]
    deadline = time.time() + 20
    status = None
    while time.time() < deadline:
        d = sf.describe_execution(executionArn=ex)
        status = d.get("status")
        if status in ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT"):
            break
        time.sleep(1)
    assert status == "SUCCEEDED", status
    sf.delete_state_machine(stateMachineArn=sm)


def cfn_deploy_s3_bucket():
    cfn = boto3.client("cloudformation", **KW)
    s3 = boto3.client("s3", **KW)
    stack = f"broad-stack-{uid}"
    bucket = f"broad-cfn-bucket-{uid}"
    template = json.dumps({
        "Resources": {
            "B": {"Type": "AWS::S3::Bucket",
                  "Properties": {"BucketName": bucket}},
        },
    })
    cfn.create_stack(StackName=stack, TemplateBody=template)
    deadline = time.time() + 30
    while time.time() < deadline:
        s = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        if s["StackStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"):
            break
        time.sleep(1)
    assert s["StackStatus"] == "CREATE_COMPLETE", s["StackStatus"]
    # Bucket really got created
    s3.head_bucket(Bucket=bucket)
    cfn.delete_stack(StackName=stack)


TESTS = [
    ("S3 put/get/list/delete", s3_put_get_list_delete),
    ("SQS send/receive", sqs_send_receive),
    ("SNS publish → SQS subscription", sns_publish_to_sqs),
    ("Lambda create + invoke", lambda_invoke),
    ("DynamoDB table + item round-trip", dynamodb_table_put_get),
    ("IAM role + STS AssumeRole", iam_create_role_and_assume),
    ("Secrets Manager create/get/delete", secretsmanager_round_trip),
    ("KMS encrypt/decrypt round-trip", kms_encrypt_decrypt),
    ("CloudWatch put + get metric", cloudwatch_put_get_metric),
    ("CloudWatch Logs put + get events", logs_put_get),
    ("EventBridge rule → SQS target", eventbridge_rule_with_sqs_target),
    ("Step Functions Pass state machine", stepfunctions_pass_state_machine),
    ("CloudFormation S3-bucket stack", cfn_deploy_s3_bucket),
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
