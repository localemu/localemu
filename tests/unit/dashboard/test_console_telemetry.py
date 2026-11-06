"""Console request telemetry (dashboard/telemetry.py).

Covers the aggregation the requests/s chart, the error / IAM-denial
counters, the live-call feed and the recently-changed table are built
from, the resource extraction used for those tables, and the capture of
IAM_ENFORCEMENT=soft audit denials from the real enforcer logger.
"""
from __future__ import annotations

import logging

import pytest

from localemu.dashboard import telemetry as tm
from localemu.dashboard.telemetry import Telemetry, describe_resource


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _call(ts, status=200, service="s3", op="ListBuckets", **kw):
    rec = {"ts": ts, "status": status, "service": service, "operation": op,
           "account_id": kw.pop("account_id", "000000000000")}
    rec.update(kw)
    return rec


class TestRequestMetrics:
    def test_series_buckets_per_second_and_ends_at_now(self):
        clock = _Clock(1_000_000.4)
        t = Telemetry(clock=clock)
        for ts in (999_998.1, 999_998.9, 999_999.5, 1_000_000.2):
            t.record(_call(ts))
        m = t.request_metrics(window=10)
        assert len(m["series"]) == 10
        assert m["series"][-1]["t"] == 1_000_000
        by_t = {p["t"]: p["n"] for p in m["series"]}
        assert by_t[999_998] == 2
        assert by_t[999_999] == 1
        assert by_t[1_000_000] == 1
        assert m["rps_last_second"] == 1          # second 999_999
        assert m["rps_10s_avg"] == 0.3            # 3 calls in the 10 full seconds before now
        assert m["requests_window"] == 4

    def test_errors_and_denials_counted_in_15_min_window_only(self):
        clock = _Clock(2_000_000.0)
        t = Telemetry(clock=clock)
        t.record(_call(2_000_000 - 1000, status=500))           # older than 15 min
        t.record(_call(2_000_000 - 10, status=404))
        t.record(_call(2_000_000 - 5, status=503))
        t.record(_call(2_000_000 - 3, status=403, denied="enforced", op="GetSecretValue",
                       principal={"arn": "arn:aws:iam::000000000000:user/ci"}))
        t.record(_call(2_000_000 - 2, status=200, denied="audit"))
        m = t.request_metrics(window=60)
        assert m["errors_15m"] == 3      # 404, 503, 403 (the 500 aged out)
        assert m["server_errors_15m"] == 1
        assert m["denied_15m"] == 2
        assert m["last_denial"]["denied"] == "audit"
        assert m["since_start"] == {"calls": 5, "errors": 4, "denied": 2}
        marks = [p for p in m["series"] if p["e4"] or p["e5"] or p["denied"]]
        assert len(marks) == 4

    def test_latency_percentiles_use_last_five_minutes(self):
        clock = _Clock(3_000_000.0)
        t = Telemetry(clock=clock)
        t.record(_call(3_000_000 - 400, latency_ms=9999.0))    # outside latency window
        for i, ms in enumerate([1.0, 2.0, 3.0, 4.0, 100.0]):
            t.record(_call(3_000_000 - 10 + i, latency_ms=ms))
        m = t.request_metrics()
        assert m["latency_samples"] == 5
        assert m["p50_ms"] == 3.0
        assert 96.0 <= m["p99_ms"] <= 100.0

    def test_no_traffic_reports_none_not_zero_latency(self):
        m = Telemetry(clock=_Clock(10.0)).request_metrics()
        assert m["p50_ms"] is None and m["p99_ms"] is None
        assert all(p["n"] == 0 for p in m["series"])


class TestCallsAndChanges:
    def test_calls_newest_first_with_since_cursor_and_account_filter(self):
        t = Telemetry(clock=_Clock(100.0))
        a = t.record(_call(90, account_id="111111111111"))
        b = t.record(_call(91))
        c = t.record(_call(92, account_id="111111111111"))
        assert [x["seq"] for x in t.calls()] == [c["seq"], b["seq"], a["seq"]]
        assert [x["seq"] for x in t.calls(since=a["seq"])] == [c["seq"], b["seq"]]
        assert [x["seq"] for x in t.calls(account="111111111111")] == [c["seq"], a["seq"]]

    def test_changes_keep_successful_mutations_with_a_resource_latest_per_resource(self):
        t = Telemetry(clock=_Clock(100.0))
        res = {"name": "b1", "arn": "arn:aws:s3:::b1"}
        t.record(_call(90, op="CreateBucket", mutating=True, resource=res))
        t.record(_call(91, op="PutBucketTagging", mutating=True, resource=res))
        t.record(_call(92, op="ListObjects", mutating=False, resource=res))         # read
        t.record(_call(93, op="CreateBucket", status=409, mutating=True,
                       resource={"name": "b2", "arn": ""}))                           # failed
        t.record(_call(94, op="CreateQueue", service="sqs", mutating=True, resource=None))
        ch = t.changes()
        assert [(c["service"], c["operation"]) for c in ch] == [("s3", "PutBucketTagging")]

    def test_service_activity_per_minute_and_account(self):
        clock = _Clock(60 * 1000 + 30)
        t = Telemetry(clock=clock)
        t.record(_call(60 * 1000 + 5, service="sqs"))
        t.record(_call(60 * 1000 + 6, service="sqs"))
        t.record(_call(60 * 999 + 1, service="sqs", account_id="111111111111"))
        allacc = t.service_activity(minutes=3)
        assert allacc["sqs"] == [0, 1, 2]
        one = t.service_activity(minutes=3, account="111111111111")
        assert one == {"sqs": [0, 1, 0]}


class TestDescribeResource:
    @pytest.mark.parametrize("service,op,params,response,expected", [
        ("s3", "CreateBucket", {"Bucket": "b"}, {}, {"name": "b", "arn": "arn:aws:s3:::b"}),
        ("s3", "PutObject", {"Bucket": "b", "Key": "k/x.txt"}, {}, {"name": "b/k/x.txt", "arn": "arn:aws:s3:::b/k/x.txt"}),
        ("dynamodb", "PutItem", {"TableName": "Orders"}, {},
         {"name": "Orders", "arn": "arn:aws:dynamodb:eu-west-1:111111111111:table/Orders"}),
        ("sqs", "SendMessage", {"QueueUrl": "http://localhost:4566/111111111111/jobs"}, {},
         {"name": "jobs", "arn": "arn:aws:sqs:eu-west-1:111111111111:jobs"}),
        ("lambda", "Invoke", {"FunctionName": "arn:aws:lambda:eu-west-1:111111111111:function:fn:prod"}, {},
         {"name": "fn", "arn": "arn:aws:lambda:eu-west-1:111111111111:function:fn"}),
        ("iam", "CreateRole", {"RoleName": "r"}, {}, {"name": "r", "arn": "arn:aws:iam::111111111111:role/r"}),
        ("ec2", "RunInstances", {"ImageId": "ami-0abc", "InstanceType": "t3.micro"}, {"Instances": [{"InstanceId": "i-123"}]}, {"name": "i-123", "arn": ""}),
        ("sns", "CreateTopic", {"Name": "t"}, {"TopicArn": "arn:aws:sns:eu-west-1:111111111111:t"},
         {"name": "t", "arn": "arn:aws:sns:eu-west-1:111111111111:t"}),
    ])
    def test_known_shapes(self, service, op, params, response, expected):
        assert describe_resource(service, op, params, response, "eu-west-1", "111111111111") == expected

    def test_generic_service_falls_back_to_response_arn(self):
        r = describe_resource("kafka", "CreateClusterV2", {"ClusterName": "c1"},
                              {"ClusterArn": "arn:aws:kafka:us-east-1:000000000000:cluster/c1/abc"},
                              "us-east-1", "000000000000")
        assert r == {"name": "c1", "arn": "arn:aws:kafka:us-east-1:000000000000:cluster/c1/abc"}

    def test_call_without_resource_returns_none(self):
        assert describe_resource("sts", "GetCallerIdentity", {}, {"Account": "1"}, "us-east-1", "0") is None


class TestAuditDenyCapture:
    def test_enforcer_audit_log_line_is_captured_on_this_thread(self):
        tm.install_denial_capture()
        tm._tls.denial = None
        enforcer_log = logging.getLogger(tm.ENFORCER_LOGGER)
        old = enforcer_log.level
        enforcer_log.setLevel(logging.INFO)
        try:
            # Same call the enforcer makes in IAM_ENFORCEMENT=soft mode.
            enforcer_log.warning(
                "IAM AUDIT DENY: %s",
                "User: arn:aws:iam::000000000000:user/ci is not authorized to perform: "
                "s3:ListBucket on resource: arn:aws:s3:::b because no allowing policy",
            )
            kind, reason = tm._pop_denial()
        finally:
            enforcer_log.setLevel(old)
        assert kind == "audit"
        assert reason.startswith("User: arn:aws:iam::000000000000:user/ci is not authorized")
        assert tm._pop_denial() is None   # consumed

    def test_install_is_idempotent(self):
        tm.install_denial_capture()
        tm.install_denial_capture()
        logger = logging.getLogger(tm.ENFORCER_LOGGER)
        assert logger.filters.count(tm._capture_filter) == 1


class TestResolvePrincipal:
    def test_does_not_create_iam_backend_for_unseen_account(self):
        from moto.iam.models import iam_backends

        acct = "918273645501"
        tm._principal_cache.clear()
        assert acct not in iam_backends
        assert tm.resolve_principal("AKIAUNKNOWNKEY000001", acct, "us-east-1") == {
            "arn": "", "type": "unresolved", "access_key": "AKIAUNKNOWNKEY000001",
        }
        root = tm.resolve_principal("000000000000", acct, "us-east-1")
        assert root["type"] == "Root" and root["arn"] == f"arn:aws:iam::{acct}:root"
        assert acct not in iam_backends

    def test_resolves_real_iam_user_access_key(self):
        from moto.iam.models import iam_backends

        acct = "918273645502"
        backend = iam_backends[acct]["global"]
        backend.create_user(region_name="us-east-1", user_name="ci-runner")
        key = backend.create_access_key(user_name="ci-runner")
        tm._principal_cache.clear()
        p = tm.resolve_principal(key.access_key_id, acct, "us-east-1")
        assert p == {
            "arn": f"arn:aws:iam::{acct}:user/ci-runner",
            "type": "User",
            "access_key": key.access_key_id,
        }
