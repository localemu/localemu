"""Records read from a Kinesis source stream must reach the delivery code base64 encoded.

The Kinesis consumer returns the raw record bytes. The delivery code (S3, search domains,
HTTP endpoints, Lambda processors) base64-decodes ``Data``, like for a PutRecord request.
Without the re-encoding, every record from a ``KinesisStreamAsSource`` delivery stream failed
with ``Incorrect padding`` and nothing reached the destination.
"""
import base64
import json
from unittest import mock

from localemu.services.firehose.provider import FirehoseProvider


def test_process_records_base64_encodes_data_from_kinesis():
    provider = FirehoseProvider()
    raw = (json.dumps({"n": 1}) + "\n").encode()
    with mock.patch.object(provider, "_put_records") as put_records:
        provider._process_records("000000000000", "us-east-1", "ds", [{"Data": raw}])

    (account_id, region, stream, records), _ = put_records.call_args
    assert (account_id, region, stream) == ("000000000000", "us-east-1", "ds")
    assert base64.b64decode(records[0]["Data"]) == raw


def test_process_records_keeps_every_record_of_the_batch():
    provider = FirehoseProvider()
    batch = [{"Data": f"row-{i}\n".encode()} for i in range(3)]
    with mock.patch.object(provider, "_put_records") as put_records:
        provider._process_records("000000000000", "us-east-1", "ds", batch)

    records = put_records.call_args[0][3]
    assert [base64.b64decode(r["Data"]) for r in records] == [b"row-0\n", b"row-1\n", b"row-2\n"]
