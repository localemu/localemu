"""``AssumeRoleWithWebIdentity`` must actually verify the token's signature
against a REGISTERED OIDC provider's JWKS, and evaluate the trust policy's
``Condition`` against the token's claims - previously neither happened, so
any structurally-shaped token (forged signature included) was accepted."""
import json

import boto3
import pytest
from moto import mock_aws

from localemu.services.sts.oidc_local import mint_test_token, verify_web_identity_token
from localemu.services.sts.provider import (
    _find_registered_oidc_provider,
    _trust_policy_allows_web_identity,
)

ACCOUNT_ID = "123456789012"
ISSUER = "token.actions.githubusercontent.com"
PROVIDER_URL = f"https://{ISSUER}"


@pytest.fixture(autouse=True)
def patched():
    from localemu.services.iam.iam_patches import apply_iam_patches

    apply_iam_patches()


@mock_aws
def test_registered_provider_is_found_by_issuer():
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_open_id_connect_provider(
        Url=PROVIDER_URL, ThumbprintList=["0" * 40], ClientIDList=["sts.amazonaws.com"]
    )
    provider = _find_registered_oidc_provider(ACCOUNT_ID, PROVIDER_URL)
    assert provider is not None
    assert provider.arn == created["OpenIDConnectProviderArn"]

    assert _find_registered_oidc_provider(ACCOUNT_ID, "https://unregistered.example.com") is None


@mock_aws
def test_forged_token_fails_verification_against_a_registered_provider():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_open_id_connect_provider(
        Url=PROVIDER_URL, ThumbprintList=["0" * 40], ClientIDList=["sts.amazonaws.com"]
    )
    provider = _find_registered_oidc_provider(ACCOUNT_ID, PROVIDER_URL)

    forged = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.forged_signature"
    assert verify_web_identity_token(forged, provider) is None


@mock_aws
def test_locally_minted_token_verifies_successfully():
    iam = boto3.client("iam", region_name="us-east-1")
    created = iam.create_open_id_connect_provider(
        Url=PROVIDER_URL, ThumbprintList=["0" * 40], ClientIDList=["sts.amazonaws.com"]
    )
    provider_arn = created["OpenIDConnectProviderArn"]
    provider = _find_registered_oidc_provider(ACCOUNT_ID, PROVIDER_URL)

    token = mint_test_token(provider_arn, {"sub": "repo:myorg/myrepo:ref:refs/heads/main"})
    claims = verify_web_identity_token(token, provider)
    # mint_test_token forces `iss` to the registered provider's own URL -
    # a real token's issuer is never caller-controlled either, and
    # AssumeRoleWithWebIdentity's provider lookup depends on it being
    # present (see test_federated_principal_arn_with_wildcard_sub_condition
    # for the real-world repro this fixes).
    assert claims == {
        "sub": "repo:myorg/myrepo:ref:refs/heads/main",
        "iss": f"https://{ISSUER}",
    }


def test_trust_condition_on_sub_is_enforced_once_verified():
    """Sanity check at the trust-policy level: the Condition on
    ``<issuer>:sub`` must actually gate access once claims are supplied."""
    import json as _json
    from types import SimpleNamespace

    role = SimpleNamespace(
        name="r",
        assume_role_policy_document=_json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": ISSUER},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringLike": {f"{ISSUER}:sub": "repo:myorg/*"}},
            }],
        }),
    )

    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL, claims={"sub": "repo:otherorg/otherrepo"}
    ) is False
    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL, claims={"sub": "repo:myorg/myrepo"}
    ) is True


def test_federated_principal_arn_with_wildcard_sub_condition():
    """Real-world repro (the lab's own trust policy shape): a registered
    OIDC provider's trust policy names the provider ARN as the Federated
    principal (AWS's documented convention), not the bare issuer URL.

    Two real bugs lived here before the fix:
      1. The ``Federated: <provider_arn>`` match was compared against the
         issuer URL by substring - an ARN and a URL share no common
         prefix, so it could never match structurally.
      2. Once (1) was fixed, the condition-key prefix was built from the
         *matched* principal entry (the ARN) instead of the IdP's bare
         hostname, so ``token.actions.githubusercontent.com:sub`` in the
         policy was compared against a context key like
         ``arn:aws:iam::...:oidc-provider/token.actions.githubusercontent.com:sub``
         - never equal, so the condition silently always failed.
    """
    import json as _json
    from types import SimpleNamespace

    provider_arn = f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/{ISSUER}"
    role = SimpleNamespace(
        name="r",
        assume_role_policy_document=_json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringLike": {f"{ISSUER}:sub": "repo:*"},
                    "StringEquals": {f"{ISSUER}:aud": "sts.amazonaws.com"},
                },
            }],
        }),
    )

    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL,
        claims={"sub": "repo:myorg/myrepo:ref:refs/heads/main", "aud": "sts.amazonaws.com"},
        provider_arn=provider_arn,
    ) is True
    # Wrong repo prefix - the wildcard must actually restrict, not rubber-stamp.
    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL,
        claims={"sub": "pull_request:myorg/myrepo", "aud": "sts.amazonaws.com"},
        provider_arn=provider_arn,
    ) is False
    # Wrong audience.
    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL,
        claims={"sub": "repo:myorg/myrepo:ref:refs/heads/main", "aud": "not-sts"},
        provider_arn=provider_arn,
    ) is False
    # A provider_arn that doesn't match this statement's Federated value
    # at all must not accidentally match via some other path.
    assert _trust_policy_allows_web_identity(
        role, PROVIDER_URL,
        claims={"sub": "repo:myorg/myrepo:ref:refs/heads/main", "aud": "sts.amazonaws.com"},
        provider_arn="arn:aws:iam::999999999999:oidc-provider/other.example.com",
    ) is False


def test_unregistered_issuer_keeps_the_old_structural_only_behaviour():
    """No OIDC provider registered for this issuer at all (e.g. LocalEmu's
    own Cognito issuer never goes through CreateOpenIDConnectProvider) -
    the pre-existing wildcard/alias matching must keep working."""
    from types import SimpleNamespace

    role = SimpleNamespace(
        name="r",
        assume_role_policy_document=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "*"},
                "Action": "sts:AssumeRoleWithWebIdentity",
            }],
        }),
    )
    assert _trust_policy_allows_web_identity(role, "https://unregistered.example.com", claims=None) is True
