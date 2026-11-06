"""Custom and profile user attributes appear as ID-token claims."""
import boto3
from moto import mock_aws

from localemu.services.cognito_idp.provider import _get_user_claims


@mock_aws
def test_custom_and_profile_attributes_become_claims():
    cu = boto3.client("cognito-idp", region_name="us-east-1")
    pool = cu.create_user_pool(PoolName="p", Schema=[{"Name": "role", "AttributeDataType": "String", "Mutable": True}])["UserPool"]["Id"]
    cu.admin_create_user(UserPoolId=pool, Username="eve", UserAttributes=[
        {"Name": "custom:role", "Value": "admin"}, {"Name": "given_name", "Value": "Eve"}, {"Name": "email", "Value": "e@x.io"}])
    assert _get_user_claims(pool, "eve", "123456789012", "us-east-1") == {"custom:role": "admin", "given_name": "Eve"}


import pytest

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.services.cognito_idp.provider import _check_client_may_write


def _client(write_attributes=None):
    cu = boto3.client("cognito-idp", region_name="us-east-1")
    pool = cu.create_user_pool(PoolName="p", Schema=[{"Name": "role", "AttributeDataType": "String", "Mutable": True}])["UserPool"]["Id"]
    kwargs = {"WriteAttributes": write_attributes} if write_attributes is not None else {}
    return cu.create_user_pool_client(UserPoolId=pool, ClientName="web", **kwargs)["UserPoolClient"]["ClientId"]


def _ctx():
    ctx = RequestContext(None)
    ctx.account_id, ctx.region = "123456789012", "us-east-1"
    return ctx


@mock_aws
def test_client_without_write_list_cannot_set_verification_flags_but_can_set_custom_attributes():
    client = _client()
    _check_client_may_write(_ctx(), client, [{"Name": "custom:role", "Value": "staff"}])
    with pytest.raises(CommonServiceException) as err:
        _check_client_may_write(_ctx(), client, [{"Name": "email_verified", "Value": "true"}])
    assert err.value.code == "NotAuthorizedException"


@mock_aws
def test_client_with_write_list_cannot_write_other_attributes():
    client = _client(["email"])
    _check_client_may_write(_ctx(), client, [{"Name": "email", "Value": "a@b.io"}])
    with pytest.raises(CommonServiceException) as err:
        _check_client_may_write(_ctx(), client, [{"Name": "custom:role", "Value": "staff"}])
    assert "custom:role" in err.value.message
