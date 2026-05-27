"""E2E: S3 Select actually filters/projects (not "return all rows").

Requires LocalEmu running on localhost:4566. Run with:
    pytest tests/e2e/test_s3_select_e2e.py -v
"""

import json
import uuid

import pytest


def _run_select(s3, bucket, key, expression, input_ser, output_ser):
    resp = s3.select_object_content(
        Bucket=bucket, Key=key, Expression=expression, ExpressionType="SQL",
        InputSerialization=input_ser, OutputSerialization=output_ser,
    )
    payload = b""
    for event in resp["Payload"]:
        if "Records" in event:
            payload += event["Records"]["Payload"]
    return payload.decode("utf-8")


@pytest.fixture
def bucket(s3_client):
    name = f"select-{uuid.uuid4().hex[:8]}"
    s3_client.create_bucket(Bucket=name)
    yield name
    try:
        for obj in s3_client.list_objects_v2(Bucket=name).get("Contents", []) or []:
            s3_client.delete_object(Bucket=name, Key=obj["Key"])
        s3_client.delete_bucket(Bucket=name)
    except Exception:
        pass


class TestS3Select:
    def test_csv_where_filter_and_projection(self, s3_client, bucket):
        s3_client.put_object(
            Bucket=bucket, Key="data.csv",
            Body=b"alice,30\nbob,20\ncarol,40\n",
        )
        out = _run_select(
            s3_client, bucket, "data.csv",
            "SELECT s._1 FROM s3object s WHERE CAST(s._2 AS INTEGER) > 25",
            {"CSV": {"FileHeaderInfo": "NONE"}}, {"JSON": {}},
        )
        rows = [json.loads(line) for line in out.strip().splitlines()]
        # only the rows with age > 25, and only the projected column
        assert sorted(r["_1"] for r in rows) == ["alice", "carol"]
        assert all(set(r.keys()) == {"_1"} for r in rows)

    def test_csv_header_named_columns(self, s3_client, bucket):
        s3_client.put_object(
            Bucket=bucket, Key="people.csv",
            Body=b"name,age\nalice,30\nbob,20\n",
        )
        out = _run_select(
            s3_client, bucket, "people.csv",
            "SELECT s.name FROM s3object s WHERE CAST(s.age AS INTEGER) < 25",
            {"CSV": {"FileHeaderInfo": "USE"}}, {"JSON": {}},
        )
        rows = [json.loads(line) for line in out.strip().splitlines()]
        assert [r["name"] for r in rows] == ["bob"]

    def test_json_lines_filter(self, s3_client, bucket):
        body = b'{"name":"alice","age":30}\n{"name":"bob","age":20}\n'
        s3_client.put_object(Bucket=bucket, Key="data.json", Body=body)
        out = _run_select(
            s3_client, bucket, "data.json",
            "SELECT s.name FROM s3object s WHERE s.age > 25",
            {"JSON": {"Type": "LINES"}}, {"JSON": {}},
        )
        rows = [json.loads(line) for line in out.strip().splitlines()]
        assert [r["name"] for r in rows] == ["alice"]
