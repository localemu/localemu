"""The IAM evaluator's reasoning was previously only visible as DEBUG log
lines - a blue team / lab needs to query it (``GET
/_localemu/iam/decisions``), not grep a server log file."""
from __future__ import annotations

import pytest

from localemu.services.iam_enforcement.decision_log import (
    clear_decisions,
    query_decisions,
    record_decision,
)
from localemu.services.iam_enforcement.evaluator import Decision, PolicyEvaluator
from localemu.services.iam_enforcement.identity import CallerIdentity


@pytest.fixture(autouse=True)
def _clean_log():
    clear_decisions()
    yield
    clear_decisions()


def _caller(arn="arn:aws:iam::123456789012:user/alice"):
    return CallerIdentity(
        principal_type="User", account_id="123456789012", arn=arn, username="alice",
    )


class TestRecordAndQuery:
    def test_record_then_query_round_trips(self):
        record_decision(
            decision="ALLOW", principal_arn="arn:x", account_id="123", action="s3:GetObject",
            resource="arn:aws:s3:::b/k", reason="test", source="identity", statement={"Effect": "Allow"},
        )
        results = query_decisions(limit=10)
        assert len(results) == 1
        assert results[0]["decision"] == "ALLOW"
        assert results[0]["matched_statement"] == {"Effect": "Allow"}

    def test_newest_first(self):
        record_decision(decision="ALLOW", principal_arn="a", account_id="1", action="x", resource="r", reason="")
        record_decision(decision="EXPLICIT_DENY", principal_arn="a", account_id="1", action="y", resource="r", reason="")
        results = query_decisions(limit=10)
        assert [r["action"] for r in results] == ["y", "x"]

    def test_filter_by_decision(self):
        record_decision(decision="ALLOW", principal_arn="a", account_id="1", action="x", resource="r", reason="")
        record_decision(decision="EXPLICIT_DENY", principal_arn="a", account_id="1", action="y", resource="r", reason="")
        results = query_decisions(decision="EXPLICIT_DENY")
        assert len(results) == 1 and results[0]["action"] == "y"

    def test_filter_by_principal_and_action(self):
        record_decision(decision="ALLOW", principal_arn="a", account_id="1", action="x", resource="r", reason="")
        record_decision(decision="ALLOW", principal_arn="b", account_id="1", action="x", resource="r", reason="")
        assert len(query_decisions(principal_arn="a")) == 1
        assert len(query_decisions(action="x")) == 2
        assert len(query_decisions(principal_arn="b", action="x")) == 1

    def test_limit_is_respected(self):
        for i in range(5):
            record_decision(decision="ALLOW", principal_arn="a", account_id="1", action=str(i), resource="r", reason="")
        assert len(query_decisions(limit=2)) == 2

    def test_clear_empties_the_log(self):
        record_decision(decision="ALLOW", principal_arn="a", account_id="1", action="x", resource="r", reason="")
        clear_decisions()
        assert query_decisions() == []


class TestEvaluatorRecordsEveryDecisionPath:
    """Every return path in PolicyEvaluator.evaluate() must land an entry -
    not just the allow path."""

    def _evaluate(self, caller, action, resource, conditions=None, resource_policy=None):
        return PolicyEvaluator().evaluate(
            caller, action, resource, conditions or {}, resource_policy=resource_policy,
        )

    def test_root_bypass_is_recorded(self, monkeypatch):
        caller = CallerIdentity(principal_type="Root", account_id="123456789012", arn="root", username=None)
        decision = self._evaluate(caller, "s3:GetObject", "arn:aws:s3:::b/k")
        assert decision == Decision.ALLOW
        entries = query_decisions()
        assert len(entries) == 1
        assert entries[0]["decision"] == "ALLOW"
        assert "root" in entries[0]["reason"].lower()

    def test_implicit_deny_no_policies_is_recorded(self, monkeypatch):
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator.get_identity_policies", lambda caller: []
        )
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator.get_permission_boundary", lambda caller: None
        )
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator._scp_denies",
            lambda *a, **k: False,
        )
        caller = _caller()
        decision = self._evaluate(caller, "s3:GetObject", "arn:aws:s3:::b/k")
        assert decision == Decision.IMPLICIT_DENY
        entries = query_decisions()
        assert len(entries) == 1
        assert entries[0]["decision"] == "IMPLICIT_DENY"
        assert entries[0]["principal_arn"] == caller.arn

    def test_explicit_deny_is_recorded_with_the_matched_statement(self, monkeypatch):
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}],
        }
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator.get_identity_policies",
            lambda caller: [deny_policy],
        )
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator.get_permission_boundary", lambda caller: None
        )
        monkeypatch.setattr(
            "localemu.services.iam_enforcement.evaluator._scp_denies",
            lambda *a, **k: False,
        )
        caller = _caller()
        decision = self._evaluate(caller, "s3:GetObject", "arn:aws:s3:::b/k")
        assert decision == Decision.EXPLICIT_DENY
        entries = query_decisions()
        assert len(entries) == 1
        assert entries[0]["decision"] == "EXPLICIT_DENY"
        assert entries[0]["matched_statement"]["Effect"] == "Deny"
