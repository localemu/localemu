"""E2E integration tests for LocalEmu services — pytest edition.

Converted from test_e2e_integrations.py to use proper pytest fixtures,
assertions, and cleanup. Each test is independent and uses fixtures
for boto3 clients.

Run with: pytest tests/e2e/test_services_e2e.py -v
Requires: LocalEmu running on localhost:4566
"""

import io
import json
import time
import zipfile

import pytest

from .conftest import poll_until

REGION = "us-east-1"


def _make_lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------
class TestSecretsManager:
    def test_crud(self, secretsmanager_client):
        sm = secretsmanager_client
        name = f"e2e/pytest-{int(time.time())}"

        # Create
        resp = sm.create_secret(Name=name, SecretString='{"user":"admin","pass":"s3cret"}')
        assert name in resp["ARN"]

        # Read
        resp = sm.get_secret_value(SecretId=name)
        assert json.loads(resp["SecretString"]) == {"user": "admin", "pass": "s3cret"}

        # Update
        sm.put_secret_value(SecretId=name, SecretString='{"user":"admin","pass":"n3wpass"}')
        resp = sm.get_secret_value(SecretId=name)
        assert json.loads(resp["SecretString"])["pass"] == "n3wpass"

        # List
        resp = sm.list_secrets()
        assert name in [s["Name"] for s in resp["SecretList"]]

        # Delete
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
        with pytest.raises(sm.exceptions.ResourceNotFoundException):
            sm.get_secret_value(SecretId=name)


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------
class TestLambda:
    def test_basic_invoke(self, lambda_client, lambda_role):
        func_name = f"e2e-echo-pytest-{int(time.time())}"
        code = 'def handler(event, context): return {"echo": event, "status": "ok"}'

        lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=lambda_role,
            Handler="lambda_function.handler",
            Code={"ZipFile": _make_lambda_zip(code)},
            Timeout=30,
        )
        try:
            # Wait for function to be active
            assert poll_until(
                lambda: lambda_client.get_function(FunctionName=func_name)
                ["Configuration"].get("State", "Active") == "Active",
                timeout=30,
            )

            resp = lambda_client.invoke(
                FunctionName=func_name,
                Payload=json.dumps({"hello": "world"}),
            )
            payload = json.loads(resp["Payload"].read())
            assert payload["status"] == "ok"
            assert payload["echo"]["hello"] == "world"
        finally:
            lambda_client.delete_function(FunctionName=func_name)

    def test_sqs_trigger(self, lambda_client, sqs_client, lambda_role):
        func_name = f"e2e-sqs-trigger-{int(time.time())}"
        queue_name = f"e2e-trigger-queue-{int(time.time())}"

        # Create queue
        q_resp = sqs_client.create_queue(QueueName=queue_name)
        queue_url = q_resp["QueueUrl"]
        q_attrs = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        queue_arn = q_attrs["Attributes"]["QueueArn"]

        code = """
import json
results = []
def handler(event, context):
    for record in event.get('Records', []):
        results.append(record['body'])
    return {'processed': len(event.get('Records', []))}
"""
        lambda_client.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=lambda_role,
            Handler="lambda_function.handler",
            Code={"ZipFile": _make_lambda_zip(code)},
            Timeout=30,
        )
        try:
            poll_until(
                lambda: lambda_client.get_function(FunctionName=func_name)
                ["Configuration"].get("State", "Active") == "Active",
                timeout=30,
            )

            # Create event source mapping
            esm_resp = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn,
                FunctionName=func_name,
                BatchSize=1,
            )
            esm_uuid = esm_resp["UUID"]

            # Send message
            sqs_client.send_message(QueueUrl=queue_url, MessageBody="pytest-trigger-test")

            # Wait for message to be consumed
            poll_until(
                lambda: sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=["ApproximateNumberOfMessages"],
                )["Attributes"]["ApproximateNumberOfMessages"] == "0",
                timeout=30,
            )

            lambda_client.delete_event_source_mapping(UUID=esm_uuid)
        finally:
            lambda_client.delete_function(FunctionName=func_name)
            sqs_client.delete_queue(QueueUrl=queue_url)


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------
class TestDynamoDB:
    def test_crud(self, dynamodb_client):
        table_name = f"e2e-pytest-{int(time.time())}"

        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        try:
            # Wait for table active
            poll_until(
                lambda: dynamodb_client.describe_table(TableName=table_name)
                ["Table"]["TableStatus"] == "ACTIVE",
                timeout=30,
            )

            # PutItem
            dynamodb_client.put_item(
                TableName=table_name,
                Item={"pk": {"S": "key1"}, "data": {"S": "value1"}},
            )

            # GetItem
            resp = dynamodb_client.get_item(
                TableName=table_name,
                Key={"pk": {"S": "key1"}},
            )
            assert resp["Item"]["data"]["S"] == "value1"

            # Query
            resp = dynamodb_client.scan(TableName=table_name)
            assert resp["Count"] == 1

            # DeleteItem
            dynamodb_client.delete_item(
                TableName=table_name,
                Key={"pk": {"S": "key1"}},
            )
            resp = dynamodb_client.scan(TableName=table_name)
            assert resp["Count"] == 0
        finally:
            dynamodb_client.delete_table(TableName=table_name)


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------
class TestS3:
    def test_lifecycle(self, s3_client):
        bucket = f"e2e-pytest-{int(time.time())}"

        s3_client.create_bucket(Bucket=bucket)
        try:
            # Put object
            s3_client.put_object(Bucket=bucket, Key="test.txt", Body=b"hello pytest")

            # Get object
            resp = s3_client.get_object(Bucket=bucket, Key="test.txt")
            assert resp["Body"].read() == b"hello pytest"

            # List objects
            resp = s3_client.list_objects_v2(Bucket=bucket)
            assert resp["KeyCount"] == 1

            # Copy object
            s3_client.copy_object(
                Bucket=bucket, Key="test-copy.txt",
                CopySource={"Bucket": bucket, "Key": "test.txt"},
            )
            resp = s3_client.list_objects_v2(Bucket=bucket)
            assert resp["KeyCount"] == 2

            # Delete objects
            s3_client.delete_object(Bucket=bucket, Key="test.txt")
            s3_client.delete_object(Bucket=bucket, Key="test-copy.txt")
        finally:
            # Cleanup: delete all remaining objects then bucket
            try:
                resp = s3_client.list_objects_v2(Bucket=bucket)
                for obj in resp.get("Contents", []):
                    s3_client.delete_object(Bucket=bucket, Key=obj["Key"])
                s3_client.delete_bucket(Bucket=bucket)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# SQS
# ---------------------------------------------------------------------------
class TestSQS:
    def test_lifecycle(self, sqs_client):
        queue_name = f"e2e-pytest-{int(time.time())}"

        resp = sqs_client.create_queue(QueueName=queue_name)
        queue_url = resp["QueueUrl"]
        try:
            # Send
            sqs_client.send_message(QueueUrl=queue_url, MessageBody="pytest-msg-1")

            # Receive
            resp = sqs_client.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5,
            )
            messages = resp.get("Messages", [])
            assert len(messages) == 1
            assert messages[0]["Body"] == "pytest-msg-1"

            # Delete message
            sqs_client.delete_message(
                QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"],
            )

            # Verify empty
            resp = sqs_client.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1,
            )
            assert len(resp.get("Messages", [])) == 0
        finally:
            sqs_client.delete_queue(QueueUrl=queue_url)


# ---------------------------------------------------------------------------
# Kinesis
# ---------------------------------------------------------------------------
class TestKinesis:
    def test_stream(self, kinesis_client):
        stream_name = f"e2e-pytest-{int(time.time())}"

        kinesis_client.create_stream(StreamName=stream_name, ShardCount=1)
        try:
            # Wait for active
            poll_until(
                lambda: kinesis_client.describe_stream(StreamName=stream_name)
                ["StreamDescription"]["StreamStatus"] == "ACTIVE",
                timeout=30,
            )

            # Put record
            kinesis_client.put_record(
                StreamName=stream_name,
                Data=b"pytest-kinesis-data",
                PartitionKey="pk1",
            )

            # Read from shard
            desc = kinesis_client.describe_stream(StreamName=stream_name)
            shard_id = desc["StreamDescription"]["Shards"][0]["ShardId"]
            iter_resp = kinesis_client.get_shard_iterator(
                StreamName=stream_name,
                ShardId=shard_id,
                ShardIteratorType="TRIM_HORIZON",
            )

            records_resp = kinesis_client.get_records(
                ShardIterator=iter_resp["ShardIterator"], Limit=10,
            )
            assert len(records_resp["Records"]) >= 1
            assert records_resp["Records"][0]["Data"] == b"pytest-kinesis-data"
        finally:
            kinesis_client.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)


# ---------------------------------------------------------------------------
# EventBridge
# ---------------------------------------------------------------------------
class TestEventBridge:
    def test_put_events(self, events_client):
        resp = events_client.put_events(
            Entries=[{
                "Source": "e2e.pytest",
                "DetailType": "TestEvent",
                "Detail": json.dumps({"key": "value"}),
            }]
        )
        assert resp["FailedEntryCount"] == 0


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------
class TestCloudWatch:
    def test_metrics(self, cloudwatch_client):
        namespace = "E2E/Pytest"
        metric_name = "TestMetric"

        cloudwatch_client.put_metric_data(
            Namespace=namespace,
            MetricData=[{
                "MetricName": metric_name,
                "Value": 42.0,
                "Unit": "Count",
            }],
        )

        resp = cloudwatch_client.list_metrics(Namespace=namespace)
        metric_names = [m["MetricName"] for m in resp["Metrics"]]
        assert metric_name in metric_names


# ---------------------------------------------------------------------------
# ECS API
# ---------------------------------------------------------------------------
class TestECS:
    def test_cluster_lifecycle(self, ecs_client):
        cluster_name = f"e2e-pytest-{int(time.time())}"

        resp = ecs_client.create_cluster(clusterName=cluster_name)
        assert resp["cluster"]["clusterName"] == cluster_name
        assert resp["cluster"]["status"] == "ACTIVE"

        try:
            resp = ecs_client.describe_clusters(clusters=[cluster_name])
            assert len(resp["clusters"]) == 1
            assert resp["clusters"][0]["clusterName"] == cluster_name

            resp = ecs_client.list_clusters()
            arns = resp["clusterArns"]
            assert any(cluster_name in arn for arn in arns)
        finally:
            ecs_client.delete_cluster(cluster=cluster_name)


# ---------------------------------------------------------------------------
# RDS API
# ---------------------------------------------------------------------------
class TestRDS:
    def test_instance_lifecycle(self, rds_client):
        db_id = f"e2e-pytest-{int(time.time())}"

        resp = rds_client.create_db_instance(
            DBInstanceIdentifier=db_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="testpassword123",
        )
        assert resp["DBInstance"]["DBInstanceIdentifier"] == db_id

        try:
            resp = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
            assert len(resp["DBInstances"]) == 1
            assert resp["DBInstances"][0]["Engine"] == "postgres"
        finally:
            rds_client.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True,
            )


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------
class TestCloudTrail:
    def test_lookup_events(self, cloudtrail_client, s3_client):
        # Perform an action that gets recorded
        bucket = f"e2e-ct-pytest-{int(time.time())}"
        s3_client.create_bucket(Bucket=bucket)
        try:
            # Give CloudTrail a moment to record
            poll_until(
                lambda: len(
                    cloudtrail_client.lookup_events(MaxResults=5)
                    .get("Events", [])
                ) > 0,
                timeout=10,
            )

            resp = cloudtrail_client.lookup_events(MaxResults=50)
            events = resp.get("Events", [])
            assert len(events) > 0

            # Verify event structure
            event = events[0]
            assert "EventId" in event
            assert "EventTime" in event
            assert "EventName" in event
        finally:
            s3_client.delete_bucket(Bucket=bucket)


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------
class TestDashboard:
    def test_health_endpoint(self, localemu_endpoint):
        import urllib.request
        resp = urllib.request.urlopen(f"{localemu_endpoint}/_localemu/health")
        data = json.loads(resp.read())
        assert "services" in data
        assert isinstance(data["services"], dict)

    def test_dashboard_endpoints(self, localemu_endpoint):
        import urllib.request
        endpoints = [
            "overview", "s3", "dynamodb", "sqs", "lambda", "sns",
            "iam", "cloudwatch", "secretsmanager",
        ]
        for ep in endpoints:
            resp = urllib.request.urlopen(
                f"{localemu_endpoint}/_localemu/dashboard/api/{ep}"
            )
            data = json.loads(resp.read())
            assert isinstance(data, (dict, list)), f"Dashboard API {ep} returned unexpected type"
