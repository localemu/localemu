"""CloudTrail reports the caller as it is: root, IAM user, assumed role or anonymous."""
import json

from localemu.constants import ANONYMOUS_ACCESS_KEY_ID
from localemu.services.cloudtrail import recording_hook
from localemu.services.cloudtrail.event_store import create_event_from_context
from localemu.services.iam_enforcement import identity
from localemu.services.iam_enforcement.identity import CallerIdentity


def _patch(monkeypatch, caller):
    monkeypatch.setattr(identity, "resolve_caller", lambda *a, **k: caller)


def test_assumed_role_session_is_reported_with_its_issuing_role(monkeypatch):
    _patch(monkeypatch, CallerIdentity("AssumedRole", "000000000000", "arn:aws:sts::000000000000:assumed-role/guest/sess",
                                       role_name="guest", session_name="sess"))
    ident, name = recording_hook._caller_identity("LSIAEXAMPLE", "000000000000", "us-east-1")
    assert ident["type"] == "AssumedRole" and ident["arn"].endswith("assumed-role/guest/sess")
    assert ident["sessionContext"]["sessionIssuer"]["arn"] == "arn:aws:iam::000000000000:role/guest"
    assert name == "sess"


def test_root_and_user_and_anonymous(monkeypatch):
    _patch(monkeypatch, CallerIdentity("Root", "000000000000", "arn:aws:iam::000000000000:root"))
    assert recording_hook._caller_identity("AKIAROOT", "000000000000", "us-east-1")[0]["type"] == "Root"
    _patch(monkeypatch, CallerIdentity("User", "000000000000", "arn:aws:iam::000000000000:user/alice", username="alice"))
    assert recording_hook._caller_identity("AKIAALICE", "000000000000", "us-east-1") == (
        {"type": "IAMUser", "principalId": "AKIAALICE", "arn": "arn:aws:iam::000000000000:user/alice",
         "userName": "alice", "accountId": "000000000000", "accessKeyId": "AKIAALICE"}, "alice")
    ident, _ = recording_hook._caller_identity(ANONYMOUS_ACCESS_KEY_ID, "000000000000", "us-east-1")
    assert ident == {"type": "AWSAccount", "principalId": "", "accountId": "ANONYMOUS_PRINCIPAL"}


def test_event_json_uses_the_resolved_identity():
    event = create_event_from_context("sts", "GetCallerIdentity", account_id="000000000000",
                                      user_identity={"type": "AssumedRole", "arn": "arn:aws:sts::000000000000:assumed-role/r/s"})
    assert json.loads(event.to_cloudtrail_event_json())["userIdentity"]["type"] == "AssumedRole"


def test_legacy_shape_when_identity_is_unknown():
    event = create_event_from_context("sts", "GetCallerIdentity", account_id="000000000000", access_key_id="AKIAX", username="AKIAX")
    assert json.loads(event.to_cloudtrail_event_json())["userIdentity"]["type"] == "IAMUser"
