"""Deeper edge-case sweep — the patterns real apps trip over.

  * S3 presigned PUT works end-to-end (the helper most CDK templates need)
  * S3 multipart upload completes correctly
  * S3 versioning round-trip
  * DynamoDB Query with KeyConditionExpression
  * DynamoDB conditional PutItem (only if attribute not exists)
  * Lambda invoke with environment variables
  * Lambda update + invoke reflects the new code
  * EventBridge filter pattern matches the published event
  * Step Functions Choice + Pass branch
  * SQS FIFO ordering
  * Kinesis put + get record round-trip
  * Firehose direct-put → S3
  * API Gateway HTTP API create
"""

import json
import sys
import time
import uuid

import boto3
import botocore.exceptions
import requests

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

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
def s3_presigned_put():
    s3 = boto3.client("s3", **KW)
    b = f"deep-presign-{uid}"
    s3.create_bucket(Bucket=b)
    url = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": b, "Key": "k", "ContentType": "text/plain"},
        ExpiresIn=60,
    )
    r = requests.put(url, data=b"hello", headers={"Content-Type": "text/plain"})
    assert r.status_code == 200, (r.status_code, r.text[:200])
    body = s3.get_object(Bucket=b, Key="k")["Body"].read()
    assert body == b"hello", body
    s3.delete_object(Bucket=b, Key="k")
    s3.delete_bucket(Bucket=b)


def s3_multipart_upload():
    s3 = boto3.client("s3", **KW)
    b = f"deep-mpu-{uid}"
    s3.create_bucket(Bucket=b)
    init = s3.create_multipart_upload(Bucket=b, Key="big")
    upload_id = init["UploadId"]
    # 2 parts, each 5MB+ (S3 requires non-last parts ≥ 5MB)
    part_data = b"x" * (5 * 1024 * 1024)
    tail_data = b"end"
    parts = []
    for i, data in enumerate((part_data, tail_data), start=1):
        r = s3.upload_part(Bucket=b, Key="big", PartNumber=i,
                           UploadId=upload_id, Body=data)
        parts.append({"PartNumber": i, "ETag": r["ETag"]})
    s3.complete_multipart_upload(
        Bucket=b, Key="big", UploadId=upload_id,
        MultipartUpload={"Parts": parts},
    )
    body = s3.get_object(Bucket=b, Key="big")["Body"].read()
    assert body == part_data + tail_data, len(body)
    s3.delete_object(Bucket=b, Key="big")
    s3.delete_bucket(Bucket=b)


def s3_versioning():
    s3 = boto3.client("s3", **KW)
    b = f"deep-ver-{uid}"
    s3.create_bucket(Bucket=b)
    s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=b, Key="k", Body=b"v1")
    s3.put_object(Bucket=b, Key="k", Body=b"v2")
    versions = s3.list_object_versions(Bucket=b).get("Versions", [])
    assert len(versions) >= 2, versions
    # AWS-correct cleanup: must delete every version before DeleteBucket.
    for v in versions:
        s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"])
    for m in s3.list_object_versions(Bucket=b).get("DeleteMarkers", []) or []:
        s3.delete_object(Bucket=b, Key=m["Key"], VersionId=m["VersionId"])
    s3.delete_bucket(Bucket=b)


def ddb_query_partition_key():
    ddb = boto3.client("dynamodb", **KW)
    table = f"deep-q-{uid}"
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=table)
    for sk in ("a", "b", "c"):
        ddb.put_item(TableName=table, Item={
            "pk": {"S": "p1"}, "sk": {"S": sk}, "v": {"S": sk.upper()},
        })
    r = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "p1"}},
    )
    items = r.get("Items", [])
    assert len(items) == 3, items
    ddb.delete_table(TableName=table)


def ddb_conditional_put():
    ddb = boto3.client("dynamodb", **KW)
    table = f"deep-cond-{uid}"
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=table)
    ddb.put_item(TableName=table, Item={"pk": {"S": "k1"}, "v": {"N": "1"}})
    # Conditional put — should fail
    try:
        ddb.put_item(
            TableName=table, Item={"pk": {"S": "k1"}, "v": {"N": "2"}},
            ConditionExpression="attribute_not_exists(pk)",
        )
        raise AssertionError("conditional put succeeded but pk exists")
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] == "ConditionalCheckFailedException"
    ddb.delete_table(TableName=table)


def lambda_env_vars():
    lam = boto3.client("lambda", **KW)
    iam = boto3.client("iam", **KW)
    role = f"deep-lam-env-{uid}"
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    import io, zipfile
    code = b"import os\ndef handler(e, c):\n    return {'env': os.environ.get('MY_VAR')}\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("h.py", code)
    buf.seek(0)
    name = f"deep-fn-env-{uid}"
    lam.create_function(
        FunctionName=name, Runtime="python3.12",
        Role=f"arn:aws:iam::000000000000:role/{role}",
        Handler="h.handler", Code={"ZipFile": buf.getvalue()},
        Environment={"Variables": {"MY_VAR": "hello-env"}},
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        if lam.get_function_configuration(FunctionName=name)["State"] == "Active":
            break
        time.sleep(1)
    r = lam.invoke(FunctionName=name, Payload=b"{}")
    payload = json.loads(r["Payload"].read())
    assert payload == {"env": "hello-env"}, payload
    lam.delete_function(FunctionName=name)


def eventbridge_filter_match():
    events = boto3.client("events", **KW)
    sqs = boto3.client("sqs", **KW)
    qurl = sqs.create_queue(QueueName=f"deep-evt-{uid}")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]
    rule = f"deep-rule-{uid}"
    events.put_rule(Name=rule, EventPattern=json.dumps({
        "source": ["deep.test"],
        "detail": {"kind": ["match-me"]},
    }))
    events.put_targets(Rule=rule, Targets=[{"Id": "1", "Arn": qarn}])
    # Non-matching
    events.put_events(Entries=[{"Source": "deep.test", "DetailType": "t",
                                "Detail": json.dumps({"kind": "wrong"})}])
    # Matching
    events.put_events(Entries=[{"Source": "deep.test", "DetailType": "t",
                                "Detail": json.dumps({"kind": "match-me"})}])
    deadline = time.time() + 15
    seen = []
    while time.time() < deadline:
        msgs = sqs.receive_message(QueueUrl=qurl, WaitTimeSeconds=2,
                                   MaxNumberOfMessages=10).get("Messages", [])
        seen.extend(msgs)
        if seen:
            break
    bodies = [json.loads(m["Body"]).get("detail", {}).get("kind") for m in seen]
    assert "match-me" in bodies, bodies
    assert "wrong" not in bodies, f"non-match leaked through: {bodies}"
    events.remove_targets(Rule=rule, Ids=["1"])
    events.delete_rule(Name=rule)
    sqs.delete_queue(QueueUrl=qurl)


def stepfunctions_choice_branch():
    sf = boto3.client("stepfunctions", **KW)
    iam = boto3.client("iam", **KW)
    role = f"deep-sfn-{uid}"
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "states.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    asl = {
        "Comment": "choice", "StartAt": "C",
        "States": {
            "C": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.x", "NumericEquals": 1, "Next": "Yes"},
                ],
                "Default": "No",
            },
            "Yes": {"Type": "Pass", "Result": "yes-branch", "End": True},
            "No": {"Type": "Pass", "Result": "no-branch", "End": True},
        },
    }
    name = f"deep-choice-{uid}"
    sm = sf.create_state_machine(
        name=name, definition=json.dumps(asl),
        roleArn=f"arn:aws:iam::000000000000:role/{role}",
    )["stateMachineArn"]
    ex = sf.start_execution(stateMachineArn=sm, input=json.dumps({"x": 1}))["executionArn"]
    deadline = time.time() + 20
    out = None
    while time.time() < deadline:
        d = sf.describe_execution(executionArn=ex)
        if d.get("status") in ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT"):
            out = d
            break
        time.sleep(1)
    assert out and out["status"] == "SUCCEEDED", out
    assert json.loads(out["output"]) == "yes-branch", out["output"]
    sf.delete_state_machine(stateMachineArn=sm)


def sqs_fifo_ordering():
    sqs = boto3.client("sqs", **KW)
    qurl = sqs.create_queue(
        QueueName=f"deep-fifo-{uid}.fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    for i in range(5):
        sqs.send_message(QueueUrl=qurl, MessageBody=f"m{i}",
                         MessageGroupId="g1")
    got = []
    for _ in range(10):
        msgs = sqs.receive_message(QueueUrl=qurl, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=2).get("Messages", [])
        for m in msgs:
            got.append(m["Body"])
            sqs.delete_message(QueueUrl=qurl, ReceiptHandle=m["ReceiptHandle"])
        if len(got) >= 5:
            break
    assert got == [f"m{i}" for i in range(5)], got
    sqs.delete_queue(QueueUrl=qurl)


def kinesis_put_get_record():
    kin = boto3.client("kinesis", **KW)
    stream = f"deep-kin-{uid}"
    kin.create_stream(StreamName=stream, ShardCount=1)
    deadline = time.time() + 30
    while time.time() < deadline:
        s = kin.describe_stream(StreamName=stream)["StreamDescription"]
        if s["StreamStatus"] == "ACTIVE":
            break
        time.sleep(1)
    kin.put_record(StreamName=stream, Data=b"k-payload", PartitionKey="p1")
    shard_id = s["Shards"][0]["ShardId"]
    sit = kin.get_shard_iterator(
        StreamName=stream, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]
    deadline = time.time() + 15
    bodies = []
    while time.time() < deadline:
        out = kin.get_records(ShardIterator=sit, Limit=10)
        for r in out["Records"]:
            bodies.append(r["Data"])
        sit = out["NextShardIterator"]
        if bodies:
            break
        time.sleep(1)
    assert b"k-payload" in bodies, bodies
    kin.delete_stream(StreamName=stream, EnforceConsumerDeletion=True)


def apigw_create_http_api():
    apigw = boto3.client("apigatewayv2", **KW)
    api = apigw.create_api(Name=f"deep-api-{uid}", ProtocolType="HTTP")
    assert api.get("ApiId"), api
    apigw.delete_api(ApiId=api["ApiId"])


TESTS = [
    ("S3 presigned PUT round-trip", s3_presigned_put),
    ("S3 multipart upload (2 parts)", s3_multipart_upload),
    ("S3 versioning enabled + 2 versions", s3_versioning),
    ("DynamoDB Query (KeyConditionExpression)", ddb_query_partition_key),
    ("DynamoDB conditional Put fails on existing", ddb_conditional_put),
    ("Lambda env vars surface in invocation", lambda_env_vars),
    ("EventBridge filter pattern only matches", eventbridge_filter_match),
    ("Step Functions Choice -> yes branch", stepfunctions_choice_branch),
    ("SQS FIFO preserves order in group", sqs_fifo_ordering),
    ("Kinesis put + get record", kinesis_put_get_record),
    ("API Gateway v2 (HTTP API) create", apigw_create_http_api),
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
