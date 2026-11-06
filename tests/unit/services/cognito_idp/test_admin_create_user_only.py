"""``AdminCreateUserConfig.AllowAdminCreateUserOnly`` was stored (moto's own
backend) but never checked - a pool configured to require admin-created
accounts still let anyone self-register via plain ``SignUp``."""
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from localemu.aws.api import CommonServiceException
from localemu.services.cognito_idp.provider import _check_admin_create_user_only

REGION = "us-east-1"
ACCOUNT = "123456789012"


def _ctx():
    return SimpleNamespace(account_id=ACCOUNT, region=REGION)


@mock_aws
def test_admin_only_pool_rejects_self_service_signup():
    idp = boto3.client("cognito-idp", region_name=REGION)
    pool = idp.create_user_pool(PoolName="p", AdminCreateUserConfig={"AllowAdminCreateUserOnly": True})
    client = idp.create_user_pool_client(UserPoolId=pool["UserPool"]["Id"], ClientName="c")

    with pytest.raises(CommonServiceException) as err:
        _check_admin_create_user_only(_ctx(), client["UserPoolClient"]["ClientId"])
    assert err.value.code == "NotAuthorizedException"


@mock_aws
def test_normal_pool_is_unaffected():
    idp = boto3.client("cognito-idp", region_name=REGION)
    pool = idp.create_user_pool(PoolName="p")
    client = idp.create_user_pool_client(UserPoolId=pool["UserPool"]["Id"], ClientName="c")

    _check_admin_create_user_only(_ctx(), client["UserPoolClient"]["ClientId"])  # must not raise


def test_unknown_client_id_does_not_raise():
    _check_admin_create_user_only(_ctx(), "does-not-exist")  # must not raise
