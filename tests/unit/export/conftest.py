"""Shared fixtures for the export/import test suite.

Fixtures here:

* :func:`seeded_infra` — creates one of each of the v1 resource types in
  the running LocalEmu (S3 bucket, DynamoDB table, Lambda function, IAM
  role, SQS queue, SNS topic). Requires LocalEmu running — marked
  ``integration``.
* :func:`empty_snapshot` — minimal in-memory :class:`Snapshot` for pure
  unit tests.
* :func:`sample_snapshot` — :class:`Snapshot` with one resource per v1
  service, useful for writer / importer round-trip checks.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from _pytest.config import Config

from localemu import config as localemu_config
from localemu import constants
from localemu.export import SCHEMA_VERSION
from localemu.export.ir import Ref, Resource, Snapshot


# --------------------------------------------------------------------------- #
# Session configuration — start an in-process LocalEmu gateway                #
# --------------------------------------------------------------------------- #
#
# The importer integration test exercises a real boto3 round-trip through a
# LocalEmu gateway (``CreateBucket`` → ``HeadBucket`` → ``ListBuckets``). CI
# boxes generally don't have a LocalEmu daemon running out-of-band, so we
# rely on the in-process runtime plugin (``start_localemu``) to provide one
# for the duration of the session. Mirrors ``tests/integration/conftest.py``
# and ``tests/aws/conftest.py``.
#
# If a developer already has a LocalEmu daemon bound on port 4566 (common
# in local dev), the in-process ``listenTCP`` call loses the race and logs
# a ``CannotListenError`` — which is fine: the session-scoped ``aws_client``
# will use that pre-existing daemon as its target and the importer test
# passes against it. Either way, *some* LocalEmu is answering on 4566 by
# the time the tests run.


def pytest_configure(config: Config) -> None:
    """Opt the export test session into the in-process LocalEmu plugin.

    Idempotent — safe to combine with other conftests that also flip the
    flag (e.g. when running the export suite alongside integration tests).
    """
    config.option.start_localemu = True
    localemu_config.FORCE_SHUTDOWN = False
    localemu_config.GATEWAY_LISTEN = localemu_config.UniqueHostAndPortList(
        [localemu_config.HostAndPort(host="0.0.0.0", port=constants.DEFAULT_PORT_EDGE)]
    )


# --------------------------------------------------------------------------- #
# Pure in-memory fixtures                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def empty_snapshot() -> Snapshot:
    """An otherwise-empty snapshot with only the required scalar fields."""
    return Snapshot(
        schema_version=SCHEMA_VERSION,
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
    )


@pytest.fixture
def sample_snapshot() -> Snapshot:
    """Snapshot with one resource per v1-covered service.

    The resources are wired together in a way that exercises the
    reference resolver and topological sorter: the Lambda references the
    IAM role by ARN, the SNS topic references the Lambda as a
    subscription, etc. Attribute values are realistic enough for writer
    golden-file tests but short enough to diff by hand.
    """
    role_arn = "arn:aws:iam::000000000000:role/test-lambda-role"
    fn_arn = "arn:aws:lambda:us-east-1:000000000000:function:sample-fn"
    topic_arn = "arn:aws:sns:us-east-1:000000000000:sample-topic"
    queue_url = "http://localhost:4566/000000000000/sample-queue"

    iam_role = Resource(
        service="iam",
        resource_type="role",
        resource_id="test-lambda-role",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": role_arn,
            "assume_role_policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        },
        tags={"env": "test"},
    )
    s3_bucket = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="sample-bucket",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": f"arn:aws:s3:::sample-bucket",
            "versioning": "Enabled",
        },
        tags={"env": "test"},
    )
    dynamodb_table = Resource(
        service="dynamodb",
        resource_type="table",
        resource_id="sample-table",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:dynamodb:us-east-1:000000000000:table/sample-table",
            "billing_mode": "PAY_PER_REQUEST",
            "hash_key": "pk",
            "attribute_definitions": [{"name": "pk", "type": "S"}],
        },
    )
    lambda_fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="sample-fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": fn_arn,
            "handler": "index.handler",
            "runtime": "python3.11",
            "role": role_arn,  # resolver should turn this into a Ref
            "environment": {
                "variables": {
                    "DB_PASSWORD": "super-secret-password",
                    "LOG_LEVEL": "INFO",
                }
            },
        },
    )
    sqs_queue = Resource(
        service="sqs",
        resource_type="queue",
        resource_id="sample-queue",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:sqs:us-east-1:000000000000:sample-queue",
            "url": queue_url,
            "visibility_timeout": 30,
        },
    )
    sns_topic = Resource(
        service="sns",
        resource_type="topic",
        resource_id="sample-topic",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": topic_arn,
            "subscriptions": [{"endpoint": fn_arn, "protocol": "lambda"}],
        },
    )

    snapshot = Snapshot(
        schema_version=SCHEMA_VERSION,
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=[
            iam_role,
            s3_bucket,
            dynamodb_table,
            lambda_fn,
            sqs_queue,
            sns_topic,
        ],
    )
    return snapshot


@pytest.fixture
def simple_resource() -> Resource:
    """A single S3 bucket resource, useful for tiny serializer tests."""
    return Resource(
        service="s3",
        resource_type="bucket",
        resource_id="unit-bucket",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::unit-bucket"},
        tags={},
    )


# --------------------------------------------------------------------------- #
# Integration fixture — requires a live LocalEmu                              #
# --------------------------------------------------------------------------- #


@pytest.fixture
def seeded_infra(aws_client: Any) -> Any:  # noqa: ANN401 - dynamic boto clients
    """Seed one resource per v1 service so collectors/importer have state.

    Seeding happens on two planes simultaneously:

    1. **HTTP plane** (``aws_client`` → LocalEmu gateway): required by the
       importer test which asserts, via ``aws_client.s3.list_buckets``, that
       a resource survived the full boto3 round-trip into LocalEmu.

    2. **In-process plane** (direct writes to
       ``localemu.services.*.models`` stores and the moto DynamoDB
       backend): required by the collectors, which read authoritative
       state from in-process stores rather than re-querying over HTTP.
       When the test process talks to an *external* LocalEmu daemon (or
       when moto's ``BotocoreStubber`` intercepts client-side), resources
       never land in the test process's in-memory stores — so we must
       populate them ourselves for the collectors to see anything.

    The two planes describe the **same** logical resources (same names /
    ARNs / account / region); teardown cleans both.

    The fixture tolerates per-service failures — collector tests skip on
    missing keys so a degraded environment still exercises what it can.
    """
    tag = uuid.uuid4().hex[:8]
    account_id = "000000000000"
    region = "us-east-1"
    created: dict[str, str] = {}
    cleanup_fns: list[Any] = []

    # -------- S3 --------
    try:
        bucket = f"exp-bucket-{tag}"
        try:
            aws_client.s3.create_bucket(Bucket=bucket)
        except Exception:
            # External LocalEmu unavailable — collectors still work via the
            # in-process seed below. The importer test, which needs the
            # HTTP round-trip, will fail its own assertion in that case;
            # that is the correct signal, not a silent skip.
            pass

        try:
            from localemu.aws.api.s3 import Owner
            from localemu.services.s3.models import S3Bucket, s3_stores

            store = s3_stores[account_id][region]
            owner = Owner(ID="test-owner", DisplayName="test-owner")
            store.buckets[bucket] = S3Bucket(
                name=bucket,
                account_id=account_id,
                bucket_region=region,
                owner=owner,
            )
        except Exception:
            pass

        created["bucket"] = bucket

        def _del_bucket(b: str = bucket) -> None:
            try:
                objs = aws_client.s3.list_objects_v2(Bucket=b).get("Contents", [])
                for o in objs:
                    aws_client.s3.delete_object(Bucket=b, Key=o["Key"])
                aws_client.s3.delete_bucket(Bucket=b)
            except Exception:
                pass
            try:
                from localemu.services.s3.models import s3_stores

                s3_stores[account_id][region].buckets.pop(b, None)
            except Exception:
                pass

        cleanup_fns.append(_del_bucket)
    except Exception:
        pass

    # -------- DynamoDB --------
    try:
        table = f"exp-table-{tag}"
        try:
            aws_client.dynamodb.create_table(
                TableName=table,
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
            )
        except Exception:
            pass

        try:
            import moto.backends as moto_backends
            from moto.dynamodb.models import Table as MotoTable

            backend = moto_backends.get_backend("dynamodb")[account_id][region]
            if table not in backend.tables:
                moto_table = MotoTable(
                    table_name=table,
                    account_id=account_id,
                    region=region,
                    schema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                    attr=[{"AttributeName": "pk", "AttributeType": "S"}],
                    billing_mode="PAY_PER_REQUEST",
                )
                backend.tables[table] = moto_table
        except Exception:
            pass

        created["table"] = table

        def _del_table(t: str = table) -> None:
            try:
                aws_client.dynamodb.delete_table(TableName=t)
            except Exception:
                pass
            try:
                import moto.backends as moto_backends

                moto_backends.get_backend("dynamodb")[account_id][region].tables.pop(
                    t, None
                )
            except Exception:
                pass

        cleanup_fns.append(_del_table)
    except Exception:
        pass

    # IAM role
    try:
        role_name = f"exp-role-{tag}"
        assume = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        aws_client.iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume)
        )
        created["role"] = role_name

        def _del_role(r: str = role_name) -> None:
            try:
                aws_client.iam.delete_role(RoleName=r)
            except Exception:
                pass

        cleanup_fns.append(_del_role)
    except Exception:
        pass

    # SQS
    try:
        queue_name = f"exp-queue-{tag}"
        qurl = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        created["queue"] = queue_name
        created["queue_url"] = qurl

        def _del_queue(u: str = qurl) -> None:
            try:
                aws_client.sqs.delete_queue(QueueUrl=u)
            except Exception:
                pass

        cleanup_fns.append(_del_queue)
    except Exception:
        pass

    # -------- SNS --------
    try:
        topic_name = f"exp-topic-{tag}"
        topic_arn = f"arn:aws:sns:{region}:{account_id}:{topic_name}"
        try:
            topic_arn = aws_client.sns.create_topic(Name=topic_name)["TopicArn"]
        except Exception:
            pass

        try:
            from localemu.services.sns.models import sns_stores

            store = sns_stores[account_id][region]
            if topic_arn not in store.topics:
                store.topics[topic_arn] = {
                    "arn": topic_arn,
                    "name": topic_name,
                    "attributes": {
                        "DisplayName": "",
                        "Policy": "",
                    },
                    "data_protection_policy": None,
                    "subscriptions": [],
                }
        except Exception:
            pass

        created["topic"] = topic_name
        created["topic_arn"] = topic_arn

        def _del_topic(a: str = topic_arn) -> None:
            try:
                aws_client.sns.delete_topic(TopicArn=a)
            except Exception:
                pass
            try:
                from localemu.services.sns.models import sns_stores

                sns_stores[account_id][region].topics.pop(a, None)
            except Exception:
                pass

        cleanup_fns.append(_del_topic)
    except Exception:
        pass

    yield created

    # Cleanup in reverse creation order.
    for fn in reversed(cleanup_fns):
        try:
            fn()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def make_resource():
    """Factory for ad-hoc :class:`Resource` objects in tests."""

    def _make(
        service: str,
        resource_type: str,
        resource_id: str,
        attributes: dict[str, Any] | None = None,
        region: str = "us-east-1",
        account_id: str = "000000000000",
        tags: dict[str, str] | None = None,
    ) -> Resource:
        return Resource(
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            account_id=account_id,
            region=region,
            attributes=dict(attributes or {}),
            tags=dict(tags or {}),
        )

    return _make


@pytest.fixture
def ref_factory():
    """Factory for :class:`Ref` objects in tests."""

    def _make(service: str, resource_type: str, resource_id: str, attribute: str = "arn") -> Ref:
        return Ref(
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            attribute=attribute,
        )

    return _make
