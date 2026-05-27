"""Pins the dashboard resource counters to the real stores.

The dashboard sidebar showed 0 for every API Gateway and EventBridge
resource because the count/list code either had no entry for the
service (apigateway, apigatewayv2) or iterated the wrong backend
(events used `_iter_moto_backends` although EventBridge is a native
LocalEmu AccountRegionBundle store, not moto). Tests seed each store
directly with the minimum shape the counter needs and assert that the
count / list helpers find them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from localemu.dashboard.api import (
    ResourcesResource,
    _count_apigateway,
    _count_apigatewayv2,
    _count_cognito_idp,
    _count_events,
    _rds_parameter_group_names,
)


@pytest.fixture
def events_store_with_rule():
    from localemu.services.events.models import events_stores

    store = events_stores["000000000000"]["us-east-1"]
    bus = SimpleNamespace(rules={})
    rule = SimpleNamespace(state="ENABLED", targets=[])
    bus.rules["test-rule"] = rule

    store.event_buses["test-bus"] = bus
    try:
        yield ("test-bus", "test-rule")
    finally:
        store.event_buses.pop("test-bus", None)


def test_count_events_uses_native_store(events_store_with_rule):
    assert _count_events() >= 1


def test_list_events_finds_seeded_rule(events_store_with_rule):
    bus_name, rule_name = events_store_with_rule
    rules = ResourcesResource._list_events()
    matched = [r for r in rules if r["name"] == rule_name and r["bus"] == bus_name]
    assert matched, f"expected to find seeded rule {rule_name}, got: {rules}"
    assert matched[0]["state"] == "ENABLED"
    assert matched[0]["targets"] == 0


@pytest.fixture
def apigatewayv2_api_seeded():
    """Inject a fake API into moto's apigatewayv2 backend."""
    from moto.apigatewayv2.models import apigatewayv2_backends

    backend = apigatewayv2_backends["000000000000"]["us-east-1"]
    api_id = "test-v2-api"
    backend.apis[api_id] = SimpleNamespace(
        name="le-test-api",
        protocol_type="HTTP",
        routes={"r1": object()},
        stages={"$default": object()},
    )
    try:
        yield api_id
    finally:
        backend.apis.pop(api_id, None)


def test_count_apigatewayv2_counts_moto_apis(apigatewayv2_api_seeded):
    assert _count_apigatewayv2() >= 1


def test_list_apigatewayv2_returns_seeded_api(apigatewayv2_api_seeded):
    api_id = apigatewayv2_api_seeded
    apis = ResourcesResource._list_apigatewayv2()
    matched = [a for a in apis if a["api_id"] == api_id]
    assert matched, f"expected api_id {api_id} in list, got: {apis}"
    assert matched[0]["protocol"] == "HTTP"
    assert matched[0]["name"] == "le-test-api"
    assert matched[0]["routes"] == 1
    assert matched[0]["stages"] == 1


@pytest.fixture
def apigateway_rest_seeded():
    """Inject a fake REST API into LocalEmu's native apigateway store."""
    from localemu.services.apigateway.models import apigateway_stores

    store = apigateway_stores["000000000000"]["us-east-1"]
    api_id = "test-rest-api"
    container = SimpleNamespace(
        rest_api=SimpleNamespace(name="le-test-rest", description="seeded for the test")
    )
    store.rest_apis[api_id] = container
    try:
        yield api_id
    finally:
        store.rest_apis.pop(api_id, None)


def test_count_apigateway_counts_rest_apis(apigateway_rest_seeded):
    assert _count_apigateway() >= 1


def test_list_apigateway_returns_seeded_rest_api(apigateway_rest_seeded):
    api_id = apigateway_rest_seeded
    apis = ResourcesResource._list_apigateway()
    matched = [a for a in apis if a["api_id"] == api_id]
    assert matched, f"expected api_id {api_id} in list, got: {apis}"
    assert matched[0]["protocol"] == "REST"
    assert matched[0]["name"] == "le-test-rest"


# ---------------------------------------------------------------------------
# cognito-idp count + sidebar visibility
# ---------------------------------------------------------------------------
# The sidebar's visibility rule is "always-show set OR resources > 0", and
# cognito-idp is not in the always-show set, so a missing _count_cognito_idp
# branch let the count fall through to 0 and the user pool the user just
# created never appeared in the sidebar.


@pytest.fixture
def cognito_pool_seeded():
    from moto.cognitoidp.models import cognitoidp_backends

    backend = cognitoidp_backends["000000000000"]["us-east-1"]
    pool_id = "us-east-1_testpool0001"
    pool = SimpleNamespace(id=pool_id, name="test-pool", arn="arn:aws:cognito-idp:us-east-1:000000000000:userpool/" + pool_id)
    backend.user_pools[pool_id] = pool
    try:
        yield pool_id
    finally:
        backend.user_pools.pop(pool_id, None)


def test_count_cognito_idp_counts_user_pools(cognito_pool_seeded):
    assert _count_cognito_idp() >= 1


# ---------------------------------------------------------------------------
# RDS detail handler: 'method' object is not iterable regression
# ---------------------------------------------------------------------------
# moto's DBInstance.db_parameter_groups is a method, not a property, so the
# naive list-comprehension on the dashboard detail handler raised
# "'method' object is not iterable" and the endpoint returned 500.


def test_rds_parameter_group_names_resolves_method_form():
    """A moto-style instance with db_parameter_groups as a method works."""
    pg = SimpleNamespace(name="default.postgres16")
    db = SimpleNamespace(db_parameter_groups=lambda: [pg])
    assert _rds_parameter_group_names(db) == ["default.postgres16"]


def test_rds_parameter_group_names_resolves_attribute_form():
    """A legacy-style instance with db_parameter_groups as a list works."""
    pg = SimpleNamespace(name="default.mysql8")
    db = SimpleNamespace(db_parameter_groups=[pg])
    assert _rds_parameter_group_names(db) == ["default.mysql8"]


def test_rds_parameter_group_names_handles_missing_attribute():
    db = SimpleNamespace()
    assert _rds_parameter_group_names(db) == []


def test_rds_parameter_group_names_falls_back_to_db_parameter_group_name():
    """Some moto versions name the field db_parameter_group_name."""
    pg = SimpleNamespace(db_parameter_group_name="custom-pg")
    db = SimpleNamespace(db_parameter_groups=[pg])
    assert _rds_parameter_group_names(db) == ["custom-pg"]
