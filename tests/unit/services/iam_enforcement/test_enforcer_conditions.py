"""Unit tests for the request-context building in enforcer._build_conditions.

Covers the invariants we rely on elsewhere:
  - aws:MultiFactorAuthPresent is ABSENT for non-MFA callers (not "false").
  - aws:MultiFactorAuthPresent is "true" only for AssumedRole sessions whose
    sts_stores entry has mfa_authenticated=True.
  - Request-scoped keys like aws:RequestTag/* / aws:TagKeys are populated.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from localemu.services.iam_enforcement.enforcer import _build_conditions
from localemu.services.iam_enforcement.identity import CallerIdentity


def _ctx(service_request=None, headers=None, remote_addr="127.0.0.1",
         region="us-east-1", is_secure=False, url=None):
    """Build a minimal RequestContext-like object for _build_conditions."""
    request = SimpleNamespace(
        headers=(headers or {}),
        remote_addr=remote_addr,
        is_secure=is_secure,
        url=url or ("https://localhost:4566/" if is_secure else "http://localhost:4566/"),
    )
    return SimpleNamespace(
        request=request,
        service_request=service_request,
        region=region,
    )


class TestMfaPresentSemantics:
    def test_non_mfa_iam_user_key_absent(self):
        caller = CallerIdentity(
            principal_type="User",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice",
            username="alice",
            access_key_id="AKIAIOSFODNN7EXAMPLE",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds, (
            "Long-term IAM-user credentials must not include the MFA key in "
            "the request context — AWS leaves it absent."
        )

    def test_root_key_absent(self):
        caller = CallerIdentity(
            principal_type="Root",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:root",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds

    def test_assumed_role_without_mfa_key_absent(self, monkeypatch):
        """AssumedRole whose session has mfa_authenticated=False -> key absent."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {
            "ASIAFAKE": {"mfa_authenticated": False},
        }
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAFAKE",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds

    def test_assumed_role_with_mfa_key_true(self, monkeypatch):
        """AssumedRole whose session has mfa_authenticated=True -> "true"."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {
            "ASIAMFA": {"mfa_authenticated": True},
        }
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAMFA",
        )
        conds = _build_conditions(_ctx(), caller)
        assert conds.get("aws:MultiFactorAuthPresent") == "true"

    def test_assumed_role_missing_session_key_absent(self, monkeypatch):
        """AssumedRole whose session isn't tracked — fail-safe: absent."""
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {}
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAUNKNOWN",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:MultiFactorAuthPresent" not in conds


class TestTokenIssueTime:
    """aws:TokenIssueTime: AWS's condition key for the IR pattern that
    denies every action for sessions issued before a containment timestamp
    (Deny + Condition: {DateLessThan: {aws:TokenIssueTime: <now>}}), without
    touching the role's permissions for sessions minted afterwards.

    Previously absent from LocalEmu's condition context entirely — any
    policy conditioned on it silently never matched, no matter how it was
    written.
    """

    def test_assumed_role_with_issued_at_is_populated_as_iso8601(self, monkeypatch):
        import localemu.services.sts.models as sts_models

        issued = datetime(2026, 10, 8, 16, 16, 9, tzinfo=timezone.utc)
        fake_store = MagicMock()
        fake_store.sessions = {"ASIATIT": {"issued_at": issued}}
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIATIT",
        )
        conds = _build_conditions(_ctx(), caller)
        assert conds.get("aws:TokenIssueTime") == "2026-10-08T16:16:09Z"

    def test_assumed_role_missing_session_key_absent(self, monkeypatch):
        import localemu.services.sts.models as sts_models

        fake_store = MagicMock()
        fake_store.sessions = {}
        fake_bundle = {"000000000000": {"us-east-1": fake_store}}
        monkeypatch.setattr(sts_models, "sts_stores", fake_bundle)

        caller = CallerIdentity(
            principal_type="AssumedRole",
            account_id="000000000000",
            arn="arn:aws:sts::000000000000:assumed-role/R/s",
            role_name="R",
            session_name="s",
            access_key_id="ASIAUNKNOWN",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:TokenIssueTime" not in conds

    def test_iam_user_key_absent(self):
        """Long-term IAM-user credentials have no session to gate on - absent."""
        caller = CallerIdentity(
            principal_type="User",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice",
            username="alice",
            access_key_id="AKIAIOSFODNN7EXAMPLE",
        )
        conds = _build_conditions(_ctx(), caller)
        assert "aws:TokenIssueTime" not in conds

    def test_deny_conditioned_on_token_issue_time_denies_only_pre_containment_sessions(self):
        """End-to-end semantics, exercised directly against the condition
        evaluator: a session issued before the containment Deny is denied;
        a session issued at/after it is not."""
        from localemu.services.iam_enforcement.condition_evaluator import matches_conditions

        stmt = {
            "Effect": "Deny",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2026-10-08T16:16:11Z"}},
        }
        pre_containment = {"aws:TokenIssueTime": "2026-10-08T16:16:09Z"}
        post_containment = {"aws:TokenIssueTime": "2026-10-08T16:16:11Z"}

        assert matches_conditions(stmt, pre_containment) is True
        assert matches_conditions(stmt, post_containment) is False


class TestRequestTagKeys:
    """aws:RequestTag/* and aws:TagKeys are built from the request params."""

    def test_request_tags_populated_from_list_shape(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(service_request={"Tags": [
            {"Key": "env", "Value": "prod"},
            {"Key": "team", "Value": "sre"},
        ]})
        conds = _build_conditions(ctx, caller)
        assert conds["aws:RequestTag/env"] == "prod"
        assert conds["aws:RequestTag/team"] == "sre"
        assert sorted(conds["aws:TagKeys"]) == ["env", "team"]

    def test_request_tags_populated_from_dict_shape(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(service_request={"Tags": {"env": "prod"}})
        conds = _build_conditions(ctx, caller)
        assert conds["aws:RequestTag/env"] == "prod"
        assert conds["aws:TagKeys"] == ["env"]


class TestStandardContextKeys:
    def test_principal_and_request_keys_present(self):
        caller = CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )
        ctx = _ctx(headers={"User-Agent": "boto3/1.x"}, remote_addr="203.0.113.5",
                   region="eu-west-1")
        conds = _build_conditions(ctx, caller)
        assert conds["aws:PrincipalArn"] == "arn:aws:iam::000000000000:user/alice"
        assert conds["aws:PrincipalAccount"] == "000000000000"
        assert conds["aws:PrincipalType"] == "User"
        assert conds["aws:SourceIp"] == "203.0.113.5"
        assert conds["aws:UserAgent"] == "boto3/1.x"
        assert conds["aws:RequestedRegion"] == "eu-west-1"
        assert conds["aws:username"] == "alice"


class TestSecureTransport:
    """aws:SecureTransport reflects the request scheme, not a hard-coded value."""

    def _caller(self):
        return CallerIdentity(
            principal_type="User", account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/alice", username="alice",
        )

    def test_http_is_false(self):
        conds = _build_conditions(_ctx(is_secure=False), self._caller())
        assert conds["aws:SecureTransport"] == "false"

    def test_https_is_true(self):
        conds = _build_conditions(_ctx(is_secure=True), self._caller())
        assert conds["aws:SecureTransport"] == "true"

    def test_fallback_on_url_prefix(self):
        """If is_secure raises, fall back to URL prefix sniff."""
        class FailingRequest:
            headers: dict = {}
            remote_addr = "127.0.0.1"
            url = "https://localhost:4566/_something"

            @property
            def is_secure(self):
                raise RuntimeError("wsgi env missing")

        ctx = SimpleNamespace(
            request=FailingRequest(),
            service_request=None,
            region="us-east-1",
        )
        conds = _build_conditions(ctx, self._caller())
        assert conds["aws:SecureTransport"] == "true"

    def test_fallback_on_all_failure_is_false(self):
        """If both is_secure and url sniff fail, default to false (fail-safe)."""
        class FailingRequest:
            headers: dict = {}
            remote_addr = "127.0.0.1"

            @property
            def is_secure(self):
                raise RuntimeError("wsgi env missing")

            @property
            def url(self):
                raise RuntimeError("url unavailable")

        ctx = SimpleNamespace(
            request=FailingRequest(),
            service_request=None,
            region="us-east-1",
        )
        conds = _build_conditions(ctx, self._caller())
        assert conds["aws:SecureTransport"] == "false"


class TestSessionTokenIdentities:
    """GetSessionToken / GetFederationToken credentials resolve to the user
    that requested them, not to an unknown caller."""

    @staticmethod
    def _cfg(kind, **extra):
        from datetime import timedelta

        base = {
            "tags": {}, "transitive_tags": [], "iam_context": {}, "source_identity": "",
            "expiration": datetime.now(timezone.utc) + timedelta(hours=1),
            "issued_at": datetime.now(timezone.utc), "session_policies": [],
            "mfa_authenticated": False, "session_kind": kind,
        }
        base.update(extra)
        return base

    def _install(self, monkeypatch, cfg, users):
        import localemu.services.sts.models as sts_models
        import moto.iam.models as iam_models

        store = MagicMock()
        store.sessions = {"ASIAKEY": cfg}
        monkeypatch.setattr(sts_models, "sts_stores", {"000000000000": {"us-east-1": store}})
        backend = MagicMock()
        backend.users = users
        monkeypatch.setattr(iam_models, "iam_backends", {"000000000000": {"global": backend}})

    def test_session_token_acts_as_the_user(self, monkeypatch):
        from localemu.services.iam_enforcement.identity import _resolve_user_session

        user = MagicMock(); user.name = "dev"; user.arn = "arn:aws:iam::000000000000:user/dev"; user.tags = {}
        self._install(monkeypatch, self._cfg("session-token", base_username="dev"), {"dev": user})
        who = _resolve_user_session("ASIAKEY", "000000000000")
        assert (who.principal_type, who.arn, who.username) == ("User", user.arn, "dev")

    def test_federated_user_has_its_own_arn_and_the_users_policies(self, monkeypatch):
        from localemu.services.iam_enforcement.identity import _resolve_user_session

        user = MagicMock(); user.name = "dev"; user.arn = "arn:aws:iam::000000000000:user/dev"
        self._install(monkeypatch, self._cfg("federated", base_username="dev", federated_name="fed1"), {"dev": user})
        who = _resolve_user_session("ASIAKEY", "000000000000")
        assert who.principal_type == "FederatedUser"
        assert who.arn == "arn:aws:sts::000000000000:federated-user/fed1"
        assert who.username == "dev"

    def test_root_session_is_root(self, monkeypatch):
        from localemu.services.iam_enforcement.identity import _resolve_user_session

        self._install(monkeypatch, self._cfg("root"), {})
        assert _resolve_user_session("ASIAKEY", "000000000000").principal_type == "Root"

    def test_expired_session_does_not_resolve(self, monkeypatch):
        from datetime import timedelta

        from localemu.services.iam_enforcement.identity import _resolve_user_session

        cfg = self._cfg("session-token", base_username="dev", expiration=datetime.now(timezone.utc) - timedelta(seconds=1))
        self._install(monkeypatch, cfg, {"dev": MagicMock()})
        assert _resolve_user_session("ASIAKEY", "000000000000") is None

    def test_unknown_key_and_deleted_user_do_not_resolve(self, monkeypatch):
        from localemu.services.iam_enforcement.identity import _resolve_user_session

        self._install(monkeypatch, self._cfg("session-token", base_username="gone"), {})
        assert _resolve_user_session("ASIAKEY", "000000000000") is None
        assert _resolve_user_session("OTHER", "000000000000") is None

    def test_get_session_token_needs_no_iam_permission(self):
        from localemu.services.iam_enforcement.enforcer import _EXEMPT_ACTIONS

        assert "sts:GetSessionToken" in _EXEMPT_ACTIONS
        assert "sts:GetFederationToken" not in _EXEMPT_ACTIONS


class TestDynamoDbLeadingKeys:
    """``dynamodb:LeadingKeys`` is the standard tenant-isolation condition
    key - it was previously never populated, so a policy conditioning on it
    silently never matched (the condition was always "absent")."""

    def _ddb_ctx(self, operation_name, service_request, account_id="123456789012", region="us-east-1"):
        request = SimpleNamespace(headers={}, remote_addr="127.0.0.1", is_secure=False, url="http://x/")
        return SimpleNamespace(
            request=request,
            service_request=service_request,
            region=region,
            account_id=account_id,
            service=SimpleNamespace(service_name="dynamodb"),
            operation=SimpleNamespace(name=operation_name),
        )

    def _caller(self):
        return CallerIdentity(
            principal_type="User", account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/alice", username="alice",
        )

    def _make_table(self, account_id="123456789012", region="us-east-1", table_name="T", hash_key="userId"):
        import boto3

        ddb = boto3.client("dynamodb", region_name=region)
        ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": hash_key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": hash_key, "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

    @pytest.fixture(autouse=True)
    def _aws(self):
        from moto import mock_aws

        with mock_aws():
            yield

    def test_get_item_populates_leading_keys_from_the_hash_key(self):
        self._make_table()
        ctx = self._ddb_ctx("GetItem", {"TableName": "T", "Key": {"userId": {"S": "alice"}}})
        conditions = _build_conditions(ctx, self._caller())
        assert conditions["dynamodb:LeadingKeys"] == "alice"

    def test_put_item_populates_leading_keys_from_item(self):
        self._make_table()
        ctx = self._ddb_ctx("PutItem", {"TableName": "T", "Item": {"userId": {"S": "bob"}, "x": {"S": "y"}}})
        conditions = _build_conditions(ctx, self._caller())
        assert conditions["dynamodb:LeadingKeys"] == "bob"

    def test_query_is_not_covered_key_absent_not_crashing(self):
        """Documented scope limit - Query/Scan parsing isn't implemented;
        must stay absent (not raise, not a wrong guess)."""
        self._make_table()
        ctx = self._ddb_ctx("Query", {"TableName": "T", "KeyConditionExpression": "userId = :u"})
        conditions = _build_conditions(ctx, self._caller())
        assert "dynamodb:LeadingKeys" not in conditions

    def test_unknown_table_does_not_crash(self):
        ctx = self._ddb_ctx("GetItem", {"TableName": "NoSuchTable", "Key": {"userId": {"S": "x"}}})
        conditions = _build_conditions(ctx, self._caller())
        assert "dynamodb:LeadingKeys" not in conditions

    def test_minimal_context_without_service_attribute_does_not_crash(self):
        """Regression pin: _build_conditions is also called with the
        bare-bones fixture used throughout this file (no .service/.operation
        at all) - must degrade gracefully, not AttributeError."""
        conditions = _build_conditions(_ctx(), self._caller())
        assert "dynamodb:LeadingKeys" not in conditions


class TestDynamoDbAttributesAndSelect:
    """``dynamodb:Attributes`` (column-level restriction, e.g. hiding a
    sensitive attribute via ``ForAllValues:StringEquals``) and
    ``dynamodb:Select`` (forcing ``SPECIFIC_ATTRIBUTES`` so a caller can't
    wildcard-read every column) - fine-grained isolation condition keys
    the tenant-isolation labs (s12/s20) need alongside LeadingKeys."""

    def _ddb_ctx(self, operation_name, service_request):
        request = SimpleNamespace(headers={}, remote_addr="127.0.0.1", is_secure=False, url="http://x/")
        return SimpleNamespace(
            request=request,
            service_request=service_request,
            region="us-east-1",
            account_id="123456789012",
            service=SimpleNamespace(service_name="dynamodb"),
            operation=SimpleNamespace(name=operation_name),
        )

    def _caller(self):
        return CallerIdentity(
            principal_type="User", account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/alice", username="alice",
        )

    def test_put_item_attributes_from_item_keys(self):
        ctx = self._ddb_ctx("PutItem", {
            "TableName": "T",
            "Item": {"id": {"S": "1"}, "name": {"S": "Alice"}, "ssn": {"S": "x"}},
        })
        conditions = _build_conditions(ctx, self._caller())
        assert sorted(conditions["dynamodb:Attributes"]) == ["id", "name", "ssn"]

    def test_get_item_attributes_from_attributes_to_get_legacy_param(self):
        ctx = self._ddb_ctx("GetItem", {"TableName": "T", "Key": {}, "AttributesToGet": ["id", "name"]})
        conditions = _build_conditions(ctx, self._caller())
        assert conditions["dynamodb:Attributes"] == ["id", "name"]

    def test_get_item_attributes_from_projection_expression_with_placeholders(self):
        ctx = self._ddb_ctx("GetItem", {
            "TableName": "T", "Key": {},
            "ProjectionExpression": "id, #n, meta.nested[0]",
            "ExpressionAttributeNames": {"#n": "name"},
        })
        conditions = _build_conditions(ctx, self._caller())
        # "meta.nested[0]" reduces to its top-level attribute "meta" -
        # dynamodb:Attributes only documents top-level attribute names.
        assert conditions["dynamodb:Attributes"] == ["id", "name", "meta"]

    def test_query_select_is_populated(self):
        ctx = self._ddb_ctx("Query", {"TableName": "T", "Select": "SPECIFIC_ATTRIBUTES"})
        conditions = _build_conditions(ctx, self._caller())
        assert conditions["dynamodb:Select"] == "SPECIFIC_ATTRIBUTES"

    def test_select_absent_for_get_item_not_a_query_or_scan_concept(self):
        ctx = self._ddb_ctx("GetItem", {"TableName": "T", "Key": {}})
        conditions = _build_conditions(ctx, self._caller())
        assert "dynamodb:Select" not in conditions

    def test_update_item_attributes_not_covered_absent_not_crashing(self):
        """Documented scope limit - UpdateExpression/legacy AttributeUpdates
        parsing isn't implemented; must stay absent, not a wrong guess."""
        ctx = self._ddb_ctx("UpdateItem", {
            "TableName": "T", "Key": {"id": {"S": "1"}},
            "UpdateExpression": "SET #n = :v", "ExpressionAttributeNames": {"#n": "name"},
        })
        conditions = _build_conditions(ctx, self._caller())
        assert "dynamodb:Attributes" not in conditions
