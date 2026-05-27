"""
Regression tests for LocalEmu's CloudTrail Lake Query APIs.

These drive the handlers directly rather than going through the gateway
so the tests are fast and deterministic. A dedicated
``_run_query_sync`` hook is used where the ordinary lifecycle (QUEUED ->
RUNNING -> FINISHED via background thread) would race with assertions.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import pytest

from localemu.services.cloudtrail import provider as ct_provider
from localemu.services.cloudtrail.event_store import CloudTrailEvent, get_event_store
from localemu.services.cloudtrail.query_store import (
    FINISHED,
    FAILED,
    CANCELLED,
    QUEUED,
    RUNNING,
    get_query_store,
    run_query_sync,
)


DS_ARN = "arn:aws:cloudtrail:us-east-1:000000000000:eventdatastore/11111111-1111-1111-1111-111111111111"


class _Ctx:
    account_id = "000000000000"
    region = "us-east-1"
    partition = "aws"


@pytest.fixture(autouse=True)
def _clean_stores():
    """Reset both stores before each test and seed a known event set."""
    es = get_event_store()
    es.reset()
    get_query_store().reset()

    now = datetime.now(timezone.utc)
    # 3 CreateBucket, 2 PutObject, 1 GetObject, 1 CreateQueue
    seed = (
        ("CreateBucket", "s3.amazonaws.com"),
        ("CreateBucket", "s3.amazonaws.com"),
        ("CreateBucket", "s3.amazonaws.com"),
        ("PutObject", "s3.amazonaws.com"),
        ("PutObject", "s3.amazonaws.com"),
        ("GetObject", "s3.amazonaws.com"),
        ("CreateQueue", "sqs.amazonaws.com"),
    )
    for i, (name, source) in enumerate(seed):
        es.record(
            CloudTrailEvent(
                event_id=f"e-{i}-{uuid.uuid4()}",
                event_time=now,
                event_source=source,
                event_name=name,
                aws_region="us-east-1",
                source_ip="127.0.0.1",
                user_agent="ut",
                account_id="000000000000",
                read_only=name.startswith("Get"),
                username="alice",
                access_key_id="AKIA",
                error_code=None,
                error_message=None,
                resources=[],
                request_id=f"req-{i}",
            )
        )
    yield
    es.reset()
    get_query_store().reset()


# ---------------------------------------------------------------------------
# StartQuery + Describe + GetResults
# ---------------------------------------------------------------------------
def _start(sql: str):
    return ct_provider._handle_start_query(_Ctx(), {"QueryStatement": sql})


def test_start_query_returns_queryid_in_queued_or_running_state():
    r = _start(f"SELECT eventName, count(*) FROM {DS_ARN} GROUP BY eventName")
    qid = r["QueryId"]
    assert qid
    q = get_query_store().get(qid)
    # The background thread may or may not have run yet.
    assert q.status in (QUEUED, RUNNING, FINISHED)


def test_describe_query_eventually_finished():
    r = _start(f"SELECT eventName, count(*) FROM {DS_ARN} GROUP BY eventName")
    qid = r["QueryId"]
    run_query_sync(qid)  # deterministic
    desc = ct_provider._handle_describe_query(_Ctx(), {"QueryId": qid})
    assert desc["QueryId"] == qid
    assert desc["QueryStatus"] == FINISHED
    assert desc["QueryStatistics"]["EventsScanned"] == 7
    assert desc["QueryStatistics"]["EventsMatched"] >= 1
    assert "CreationTime" in desc["QueryStatistics"]


def test_get_query_results_event_counts_match_event_store():
    r = _start(f"SELECT eventName, count(*) FROM {DS_ARN} GROUP BY eventName")
    qid = r["QueryId"]
    run_query_sync(qid)
    res = ct_provider._handle_get_query_results(_Ctx(), {"QueryId": qid})
    assert res["QueryStatus"] == FINISHED
    # Row format: list of [{col: val}, ...]
    counts = {}
    for row in res["QueryResultRows"]:
        merged = {}
        for kv in row:
            merged.update(kv)
        counts[merged["eventName"]] = int(merged["count(*)"])
    assert counts == {
        "CreateBucket": 3,
        "PutObject": 2,
        "GetObject": 1,
        "CreateQueue": 1,
    }
    assert res["QueryStatistics"]["TotalResultsCount"] == 4


def test_get_query_results_with_where_filter():
    sql = (
        f"SELECT eventName, count(*) FROM {DS_ARN} "
        f"WHERE eventSource = 's3.amazonaws.com' "
        f"GROUP BY eventName"
    )
    qid = _start(sql)["QueryId"]
    run_query_sync(qid)
    res = ct_provider._handle_get_query_results(_Ctx(), {"QueryId": qid})
    names = set()
    for row in res["QueryResultRows"]:
        merged = {}
        for kv in row:
            merged.update(kv)
        names.add(merged["eventName"])
    assert names == {"CreateBucket", "PutObject", "GetObject"}


def test_invalid_sql_moves_query_to_failed_with_errormessage():
    qid = _start("THIS IS NOT SQL")["QueryId"]
    run_query_sync(qid)
    desc = ct_provider._handle_describe_query(_Ctx(), {"QueryId": qid})
    assert desc["QueryStatus"] == FAILED
    assert "LocalEmu only supports simple" in desc["ErrorMessage"]


def test_unsupported_column_fails_query():
    qid = _start(
        f"SELECT someMadeUpColumn, count(*) FROM {DS_ARN} GROUP BY someMadeUpColumn"
    )["QueryId"]
    run_query_sync(qid)
    desc = ct_provider._handle_describe_query(_Ctx(), {"QueryId": qid})
    assert desc["QueryStatus"] == FAILED
    assert "Unsupported column" in desc["ErrorMessage"]


# ---------------------------------------------------------------------------
# CancelQuery
# ---------------------------------------------------------------------------
def test_cancel_query_moves_to_cancelled():
    # Create a query but don't run it — force the state directly.
    store = get_query_store()
    q = store.create(statement=f"SELECT eventName FROM {DS_ARN}")
    # Don't schedule — we want to cancel from QUEUED.
    res = ct_provider._handle_cancel_query(_Ctx(), {"QueryId": q.query_id})
    assert res["QueryStatus"] == CANCELLED
    assert store.get(q.query_id).status == CANCELLED


def test_cancel_unknown_query_raises():
    from localemu.aws.api.core import CommonServiceException

    with pytest.raises(CommonServiceException):
        ct_provider._handle_cancel_query(_Ctx(), {"QueryId": "does-not-exist"})


# ---------------------------------------------------------------------------
# ListQueries
# ---------------------------------------------------------------------------
def test_list_queries_filters_by_event_data_store():
    other_arn = (
        "arn:aws:cloudtrail:us-east-1:000000000000:"
        "eventdatastore/22222222-2222-2222-2222-222222222222"
    )
    _start(f"SELECT eventName FROM {DS_ARN}")
    _start(f"SELECT eventName FROM {DS_ARN}")
    _start(f"SELECT eventName FROM {other_arn}")

    res = ct_provider._handle_list_queries(_Ctx(), {"EventDataStore": DS_ARN})
    assert len(res["Queries"]) == 2
    for q in res["Queries"]:
        assert "QueryId" in q and "QueryStatus" in q and "CreationTime" in q

    res2 = ct_provider._handle_list_queries(_Ctx(), {"EventDataStore": other_arn})
    assert len(res2["Queries"]) == 1


def test_list_queries_requires_event_data_store():
    from localemu.aws.api.core import CommonServiceException

    with pytest.raises(CommonServiceException):
        ct_provider._handle_list_queries(_Ctx(), {})


# ---------------------------------------------------------------------------
# SearchSampleQueries
# ---------------------------------------------------------------------------
def test_search_sample_queries_returns_at_least_three():
    res = ct_provider._handle_search_sample_queries(_Ctx(), {"SearchPhrase": "event"})
    assert len(res["SearchResults"]) >= 3
    for s in res["SearchResults"]:
        assert s["Name"] and s["Description"] and s["SQL"]
        assert 0.0 <= s["Relevance"] <= 1.0


def test_search_sample_queries_empty_phrase_returns_all():
    res = ct_provider._handle_search_sample_queries(_Ctx(), {"SearchPhrase": ""})
    assert len(res["SearchResults"]) >= 3


# ---------------------------------------------------------------------------
# GenerateQuery
# ---------------------------------------------------------------------------
def test_generate_query_with_event_names_prompt():
    res = ct_provider._handle_generate_query(
        _Ctx(),
        {"Prompt": "top event names", "EventDataStores": [DS_ARN]},
    )
    assert "SELECT" in res["QueryStatement"]
    assert "GROUP BY eventName" in res["QueryStatement"]
    assert DS_ARN in res["QueryStatement"]


def test_generate_query_with_unrecognised_prompt_raises():
    from localemu.aws.api.core import CommonServiceException

    with pytest.raises(CommonServiceException) as ei:
        ct_provider._handle_generate_query(
            _Ctx(),
            {"Prompt": "something the model does not understand at all",
             "EventDataStores": [DS_ARN]},
        )
    assert "not recognised" in str(ei.value) or "recognises prompts" in str(ei.value)


# ---------------------------------------------------------------------------
# Lifecycle via the scheduler (end-to-end, no direct sync call)
# ---------------------------------------------------------------------------
def test_scheduler_drives_query_to_finished_within_2s():
    r = _start(f"SELECT eventName, count(*) FROM {DS_ARN} GROUP BY eventName")
    qid = r["QueryId"]
    deadline = time.time() + 2.0
    while time.time() < deadline:
        q = get_query_store().get(qid)
        if q.status in (FINISHED, FAILED):
            break
        time.sleep(0.05)
    assert get_query_store().get(qid).status == FINISHED
