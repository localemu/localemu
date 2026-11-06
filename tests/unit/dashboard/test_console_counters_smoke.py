"""Every console counter and lister runs without raising.

``_count_resources_uncached`` swallows exceptions (logging a warning and
returning 0) and ``ResourcesResource.on_get`` turns them into
``"backend error"``, so a broken counter shows up as an innocent-looking
0 in the console. This calls each one directly, unscoped and scoped to an
account, and fails on any exception or swallowed-error warning.
"""
from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from localemu.dashboard import api

LISTED = [
    "s3", "sqs", "lambda", "dynamodb", "sns", "logs", "ecs", "eks", "ec2", "rds",
    "opensearch", "secretsmanager", "stepfunctions", "kinesis", "events",
    "apigateway", "apigatewayv2", "iam", "vpc", "security-groups", "nat-gateways",
    "vpc-peering", "vpc-endpoints", "route53", "elbv2", "kms", "ssm", "cloudtrail",
    "ecr", "batch", "pipes", "scheduler", "wafv2", "glue",
]


@pytest.mark.parametrize("scope", [None, "000000000000", "123456789012"])
@pytest.mark.parametrize("service", sorted(api.COUNTED_SERVICES))
def test_counter_runs_cleanly(service, scope, caplog):
    caplog.set_level(logging.WARNING, logger=api.LOG.name)
    with api.account_scope(scope):
        n = api._count_resources_uncached(service)
    assert isinstance(n, int) and n >= 0
    assert not [r for r in caplog.records if "could not count resources" in r.getMessage()]


@pytest.mark.parametrize("scope", [None, "123456789012"])
@pytest.mark.parametrize("service", LISTED)
def test_lister_runs_cleanly(service, scope):
    with api.account_scope(scope):
        rows = api.ResourcesResource._list_resources(service)
    assert isinstance(rows, list)


def test_lambda_counter_and_scope_see_seeded_function():
    from localemu.services.lambda_.invocation.models import lambda_stores

    store = lambda_stores["123456789012"]["us-east-1"]
    store.functions["smoke-fn"] = SimpleNamespace(function_name="smoke-fn")
    try:
        with api.account_scope("123456789012"):
            assert api._count_resources_uncached("lambda") == 1
        with api.account_scope("210987654321"):
            assert api._count_resources_uncached("lambda") == 0
        assert api._count_resources_uncached("lambda") >= 1
    finally:
        store.functions.pop("smoke-fn", None)
