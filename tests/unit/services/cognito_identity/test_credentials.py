"""Cognito Identity pools hand out the credentials of the pool's IAM role."""
import json

import pytest
from moto import mock_aws

import boto3

from localemu.aws.api import CommonServiceException, RequestContext
from localemu.services.cognito_identity import provider as cip


def _ctx(region="us-east-1", account="123456789012"):
    ctx = RequestContext(None)
    ctx.account_id, ctx.region = account, region
    return ctx


def _trust(pool_id, amr):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
            },
        }],
    }


@pytest.fixture
def pool():
    with mock_aws():
        ci = boto3.client("cognito-identity", region_name="us-east-1")
        pool_id = ci.create_identity_pool(IdentityPoolName="p", AllowUnauthenticatedIdentities=True)["IdentityPoolId"]
        yield pool_id


def _identity(pool_id):
    backend = cip._backend(_ctx(), pool_id)
    ident = "us-east-1:" + "i" * 8
    cip._state(backend)["identities"][ident] = {"pool": pool_id, "logins": []}
    return ident


def test_unauthenticated_identity_gets_the_unauthenticated_role(pool):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="guest", AssumeRolePolicyDocument=json.dumps(_trust(pool, "unauthenticated")))
    cip._handle_set_roles(_ctx(), {"IdentityPoolId": pool, "Roles": {"unauthenticated": "arn:aws:iam::123456789012:role/guest"}})
    out = cip._handle_get_credentials(_ctx(), {"IdentityId": _identity(pool)})
    assert out["Credentials"]["AccessKeyId"] and out["Credentials"]["SessionToken"]


def test_role_trusting_another_pool_is_refused(pool):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="guest", AssumeRolePolicyDocument=json.dumps(_trust("us-east-1:other", "unauthenticated")))
    cip._handle_set_roles(_ctx(), {"IdentityPoolId": pool, "Roles": {"unauthenticated": "arn:aws:iam::123456789012:role/guest"}})
    with pytest.raises(CommonServiceException) as err:
        cip._handle_get_credentials(_ctx(), {"IdentityId": _identity(pool)})
    assert err.value.code == "InvalidIdentityPoolConfigurationException"


def test_unauthenticated_access_can_be_disabled():
    with mock_aws():
        ci = boto3.client("cognito-identity", region_name="us-east-1")
        pool_id = ci.create_identity_pool(IdentityPoolName="p", AllowUnauthenticatedIdentities=False)["IdentityPoolId"]
        cip._handle_set_roles(_ctx(), {"IdentityPoolId": pool_id, "Roles": {"unauthenticated": "arn:aws:iam::123456789012:role/guest"}})
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_credentials(_ctx(), {"IdentityId": _identity(pool_id)})
        assert err.value.code == "NotAuthorizedException"


def test_rules_mapping_selects_role_from_claim():
    attached = {"RoleMappings": {"prov:client": {"Type": "Rules", "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {"Rules": [{"Claim": "custom:role", "MatchType": "Equals", "Value": "admin", "RoleARN": "arn:admin"}]}}}}
    claims = [{"_provider": "prov", "aud": "client", "custom:role": "admin"}]
    assert cip._role_from_mapping(attached, claims, None) == "arn:admin"
    assert cip._role_from_mapping(attached, [{"_provider": "prov", "aud": "client", "custom:role": "user"}], None) is None


def test_deny_resolution_refuses_unmatched_logins():
    attached = {"RoleMappings": {"prov": {"Type": "Rules", "AmbiguousRoleResolution": "Deny", "RulesConfiguration": {"Rules": []}}}}
    with pytest.raises(CommonServiceException):
        cip._role_from_mapping(attached, [{"_provider": "prov", "aud": "c"}], None)


def test_token_type_mapping_selects_the_preferred_role():
    """Type: "Token" role mapping - selects from cognito:roles/cognito:preferred_role
    claims the way AWS does, as opposed to the Rules-type mapping tested above."""
    attached = {"RoleMappings": {"prov:client": {"Type": "Token"}}}
    with_preferred = {"_provider": "prov", "aud": "client", "cognito:preferred_role": "arn:preferred",
                       "cognito:roles": ["arn:preferred", "arn:other"]}
    assert cip._role_from_mapping(attached, [with_preferred], None) == "arn:preferred"

    single_role_no_preference = {"_provider": "prov", "aud": "client", "cognito:roles": ["arn:only"]}
    assert cip._role_from_mapping(attached, [single_role_no_preference], None) == "arn:only"

    ambiguous_no_preference = {"_provider": "prov", "aud": "client",
                                "cognito:roles": ["arn:one", "arn:two"]}
    assert cip._role_from_mapping(attached, [ambiguous_no_preference], None) is None

    custom_role_must_be_among_claimed_roles = {"_provider": "prov", "aud": "client",
                                                "cognito:roles": ["arn:one", "arn:two"]}
    assert cip._role_from_mapping(attached, [custom_role_must_be_among_claimed_roles], "arn:one") == "arn:one"
    assert cip._role_from_mapping(attached, [custom_role_must_be_among_claimed_roles], "arn:not-claimed") is None


def test_authenticated_identity_with_a_real_verified_login_gets_credentials(pool):
    """The end-to-end authenticated path: a real LocalEmu-issued, cryptographically
    verified Cognito User Pool token, fed through Logins, selects the authenticated
    role and returns usable credentials - not just the unauthenticated path the
    other tests exercise."""
    from localemu.services.cognito_idp import oidc, tokens
    from localemu.services.cognito_idp.keys import generate_key_pair

    user_pool_id = "us-east-1_realUserPool"
    client_id = "app-client-1234567890"
    private_key, kid = generate_key_pair()
    oidc.register_pool_keys(user_pool_id, private_key, kid)
    try:
        provider_name = f"cognito-idp.us-east-1.amazonaws.com/{user_pool_id}"
        ci = boto3.client("cognito-identity", region_name="us-east-1")
        ci.update_identity_pool(
            IdentityPoolId=pool, IdentityPoolName="p", AllowUnauthenticatedIdentities=True,
            CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_id}],
        )

        id_token = tokens.generate_id_token(
            pool_id=user_pool_id, region="us-east-1", client_id=client_id, username="alice",
            sub="sub-1", private_key=private_key, kid=kid, token_validity=3600,
        )

        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(RoleName="authed", AssumeRolePolicyDocument=json.dumps(_trust(pool, "authenticated")))
        cip._handle_set_roles(_ctx(), {
            "IdentityPoolId": pool,
            "Roles": {"authenticated": "arn:aws:iam::123456789012:role/authed"},
        })

        identity_id = _identity(pool)
        out = cip._handle_get_credentials(_ctx(), {
            "IdentityId": identity_id,
            "Logins": {provider_name: id_token},
        })
        assert out["Credentials"]["AccessKeyId"] and out["Credentials"]["SessionToken"]
        assert out["IdentityId"] == identity_id
    finally:
        oidc._pool_keys.pop(user_pool_id, None)


class TestMalformedInputIsAnAwsShapedErrorNotACrash:
    """The 4 custom handlers used to let a bare KeyError escape uncaught for
    malformed/missing IdentityId/IdentityPoolId - Skeleton.invoke() only catches
    ServiceException/NotImplementedError, so it surfaced as a raw InternalFailure
    instead of a real AWS error. These pin the fix."""

    def test_get_credentials_missing_identity_id(self):
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_credentials(_ctx(), {})
        assert err.value.code == "InvalidParameterException"

    def test_get_credentials_malformed_identity_id(self):
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_credentials(_ctx(), {"IdentityId": "not-a-valid-identity-id"})
        assert err.value.code == "InvalidParameterException"

    def test_get_identity_pool_roles_malformed_pool_id(self):
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_roles(_ctx(), {"IdentityPoolId": "garbage"})
        assert err.value.code == "InvalidParameterException"

    def test_set_identity_pool_roles_malformed_pool_id(self):
        with pytest.raises(CommonServiceException) as err:
            cip._handle_set_roles(_ctx(), {
                "IdentityPoolId": "garbage",
                "Roles": {"unauthenticated": "arn:aws:iam::123456789012:role/guest"},
            })
        assert err.value.code == "InvalidParameterException"

    def test_get_id_missing_identity_pool_id(self):
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_id(_ctx(), {})
        assert err.value.code == "InvalidParameterException"

    def test_well_formed_but_unknown_id_is_still_resource_not_found(self, pool):
        """Regression guard: the malformed-ID fix must not change the
        already-correct behavior for a well-formed-but-nonexistent ID."""
        with pytest.raises(CommonServiceException) as err:
            cip._handle_get_credentials(_ctx(), {"IdentityId": "us-east-1:" + "z" * 8})
        assert err.value.code == "ResourceNotFoundException"


def test_malformed_trust_policy_document_fails_safe_not_a_crash(pool):
    """A role whose assume-role policy document isn't valid JSON must deny
    (InvalidIdentityPoolConfigurationException), not raise an uncaught
    JSONDecodeError."""
    iam = boto3.client("iam", region_name="us-east-1")
    # moto's create_role stores whatever string it's given verbatim when it's
    # not valid JSON it can parse itself for its own validation - this models
    # a corrupted/hand-edited trust policy on the role.
    role = iam.create_role(RoleName="broken-trust", AssumeRolePolicyDocument=json.dumps(_trust(pool, "unauthenticated")))["Role"]
    role_obj = next(
        r for r in __import__("moto.iam.models", fromlist=["iam_backends"]).iam_backends["123456789012"]["global"].roles.values()
        if r.name == "broken-trust"
    )
    role_obj.assume_role_policy_document = "{not valid json"

    cip._handle_set_roles(_ctx(), {"IdentityPoolId": pool, "Roles": {"unauthenticated": role["Arn"]}})
    with pytest.raises(CommonServiceException) as err:
        cip._handle_get_credentials(_ctx(), {"IdentityId": _identity(pool)})
    assert err.value.code == "InvalidIdentityPoolConfigurationException"
