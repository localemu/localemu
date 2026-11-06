"""AssumeRole on a role that does not exist is refused like a trust-policy refusal (enforcement mode)."""
import pytest

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.services.sts.provider import StsProvider


def _context():
    ctx = RequestContext(None)
    ctx.account_id, ctx.region = "123456789012", "us-east-1"
    ctx.request = type("R", (), {"headers": {"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260101/us-east-1/sts/aws4_request"}})()
    return ctx


def test_missing_role_is_access_denied_in_enforcement_mode(monkeypatch):
    monkeypatch.setenv("IAM_ENFORCEMENT", "1")
    with pytest.raises(CommonServiceException) as err:
        StsProvider().assume_role(_context(), "arn:aws:iam::123456789012:role/nope", "session")
    assert err.value.code == "AccessDenied"
    assert "not authorized to perform: sts:AssumeRole" in err.value.message
