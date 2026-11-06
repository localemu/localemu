"""Account scoping of the console counters / listers, the per-account
summary endpoint, and Docker container classification.

Seeds the real stores (LocalEmu-native S3 store, moto's DynamoDB backend)
in two accounts and checks that the overview / resources endpoints and
the account summary report each account's own resources.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu.dashboard import api
from localemu.dashboard.system import classify_container

A1 = "000000000000"
A2 = "222233334444"


def _req(args: dict):
    r = MagicMock()
    r.args = args
    r.headers = {}
    r.remote_addr = "127.0.0.1"
    return r


@pytest.fixture
def two_account_ddb():
    from moto.dynamodb.models import dynamodb_backends

    seeded = []
    for acct, names in ((A1, ["t-a1"]), (A2, ["t-a2-x", "t-a2-y"])):
        backend = dynamodb_backends[acct]["us-east-1"]
        for n in names:
            backend.tables[n] = SimpleNamespace(name=n, item_count=0, items=[])
            seeded.append((backend, n))
    api._count_cache.clear()
    api._count_cache_scoped.clear()
    try:
        yield
    finally:
        for backend, n in seeded:
            backend.tables.pop(n, None)
        api._count_cache.clear()
        api._count_cache_scoped.clear()


@pytest.fixture
def two_account_s3():
    from localemu.services.s3.models import s3_stores

    s1 = s3_stores[A1]["us-east-1"]
    s2 = s3_stores[A2]["us-east-1"]
    s1.buckets["scope-b1"] = SimpleNamespace(name="scope-b1")
    s2.buckets["scope-b2"] = SimpleNamespace(name="scope-b2")
    api._count_cache.clear()
    api._count_cache_scoped.clear()
    try:
        yield
    finally:
        s1.buckets.pop("scope-b1", None)
        s2.buckets.pop("scope-b2", None)
        api._count_cache.clear()
        api._count_cache_scoped.clear()


def test_scope_restricts_moto_backend_counts(two_account_ddb):
    total = api._count_resources("dynamodb")
    with api.account_scope(A2):
        a2 = api._count_resources("dynamodb")
    with api.account_scope(A1):
        a1 = api._count_resources("dynamodb")
    assert a2 == 2
    assert a1 >= 1
    assert total >= a1 + a2


def test_scope_restricts_native_store_counts(two_account_s3):
    with api.account_scope(A2):
        assert api._count_resources("s3") == 1
    with api.account_scope("999999999999"):
        assert api._count_resources("s3") == 0


def test_unscoped_default_is_all_accounts(two_account_s3):
    assert api._ACCOUNT_SCOPE.get() is None
    assert api._count_resources("s3") >= 2


def test_scoped_cache_is_separate_and_invalidated(two_account_s3):
    from localemu.services.s3.models import s3_stores

    with api.account_scope(A2):
        assert api._count_resources("s3") == 1
    s3_stores[A2]["us-east-1"].buckets["scope-b3"] = SimpleNamespace(name="scope-b3")
    try:
        with api.account_scope(A2):
            assert api._count_resources("s3") == 1          # cached (5 s TTL)
        api.invalidate_count_cache("s3")
        with api.account_scope(A2):
            assert api._count_resources("s3") == 2
    finally:
        s3_stores[A2]["us-east-1"].buckets.pop("scope-b3", None)


def test_resources_endpoint_lists_only_selected_account(two_account_ddb):
    body = json.loads(api.ResourcesResource().on_get(_req({"account": A2}), service="dynamodb").data)
    names = {r["name"] for r in body["resources"]}
    assert names == {"t-a2-x", "t-a2-y"}


def test_invalid_account_param_means_all_accounts(two_account_ddb):
    assert api._valid_account_param("12") is None
    assert api._valid_account_param("abcdefghijkl") is None
    assert api._valid_account_param(A2) == A2
    body = json.loads(api.ResourcesResource().on_get(_req({"account": "nope"}), service="dynamodb").data)
    names = {r["name"] for r in body["resources"]}
    assert {"t-a1", "t-a2-x", "t-a2-y"} <= names


def test_account_summary_uses_real_counters(two_account_ddb, two_account_s3, monkeypatch):
    from localemu.accounts import get_registry

    reg = get_registry()
    if A2 not in reg:
        reg.create(A2, name="scope-test")
    try:
        body = json.loads(api.AccountSummaryResource().on_get(_req({}), account_id=A2).data)
    finally:
        reg.delete(A2)
    assert body["resources"]["dynamodb"] == 2
    assert body["resources"]["s3"] == 1
    assert body["total"] == sum(body["resources"].values())
    assert body["services_in_use"] >= 2
    assert "cloudtrail" not in body["resources"]


@pytest.mark.parametrize("container,expected", [
    ({"name": "localemu-ec2-i-1", "labels": {"localemu.service": "ec2"}}, "ec2"),
    ({"name": "x", "labels": {"localemu.service": "imds-sidecar"}}, "ec2"),
    ({"name": "x", "labels": {"localemu.service": "msk"}}, "kafka"),
    ({"name": "localemu-bedrock-ollama", "labels": {"localemu.service": "bedrock-ollama"}}, "bedrock"),
    ({"name": "x", "labels": {"localemu.service": "nat-gateway"}}, "vpc"),
    ({"name": "localemu-mq-b-1", "labels": {}}, "mq"),
    ({"name": "k3d-localemu-eks-demo-server-0", "labels": {"app": "k3d"}}, "eks"),
    ({"name": "localemu-main-lambda-fn-abc123", "labels": {}}, "lambda"),
    ({"name": "postgres", "labels": {}}, None),
    ({"name": "k3d-other-cluster-server-0", "labels": {}}, None),
])
def test_classify_container(container, expected):
    assert classify_container(container) == expected
