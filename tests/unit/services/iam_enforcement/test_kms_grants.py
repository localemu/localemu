"""``kms:CreateGrant`` must actually authorize the grantee - previously
grants were stored but the enforcer only ever read moto's native KMS
backend (which LocalEmu's KMS provider never populates, same as S3), so a
grant had zero effect on authorization."""
from types import SimpleNamespace

from localemu.services.iam_enforcement.enforcer import (
    _kms_grant_allows,
    _resolve_native_kms_key,
)
from localemu.services.kms.models import kms_stores

REGION = "us-east-1"
GRANTEE_ARN = "arn:aws:iam::111111111111:user/attacker"


def _make_key(account_id: str, key_id: str):
    store = kms_stores[account_id][REGION]
    key = SimpleNamespace(policy=None, metadata={"KeyId": key_id})
    store.keys[key_id] = key
    return store, key


def _add_grant(store, key_id: str, grantee: str, operations: list[str], grant_id: str = "g1"):
    store.grants[grant_id] = SimpleNamespace(
        metadata={"KeyId": key_id, "GranteePrincipal": grantee, "Operations": operations}
    )


def test_resolve_native_kms_key_by_arn_and_bare_id():
    account = "222222222222"
    key_id = "33333333-3333-3333-3333-333333333333"
    store, key = _make_key(account, key_id)

    assert _resolve_native_kms_key(account, REGION, f"arn:aws:kms:{REGION}:{account}:key/{key_id}") is key
    assert _resolve_native_kms_key(account, REGION, key_id) is key
    assert _resolve_native_kms_key(account, REGION, "nonexistent-key-id") is None


def test_grant_authorizes_exactly_the_covered_operation():
    account = "333333333333"
    key_id = "44444444-4444-4444-4444-444444444444"
    resource_arn = f"arn:aws:kms:{REGION}:{account}:key/{key_id}"
    store, _ = _make_key(account, key_id)
    _add_grant(store, key_id, GRANTEE_ARN, ["Decrypt"])

    assert _kms_grant_allows(GRANTEE_ARN, "kms:Decrypt", resource_arn, account, REGION) is True
    assert _kms_grant_allows(GRANTEE_ARN, "kms:Encrypt", resource_arn, account, REGION) is False
    assert _kms_grant_allows("arn:aws:iam::111111111111:user/someone-else", "kms:Decrypt", resource_arn, account, REGION) is False


def test_grant_on_a_different_key_does_not_leak_across_keys():
    account = "444444444444"
    key_id_a = "55555555-5555-5555-5555-555555555555"
    key_id_b = "66666666-6666-6666-6666-666666666666"
    store, _ = _make_key(account, key_id_a)
    _, _ = _make_key(account, key_id_b)
    _add_grant(store, key_id_a, GRANTEE_ARN, ["Decrypt"])

    arn_a = f"arn:aws:kms:{REGION}:{account}:key/{key_id_a}"
    arn_b = f"arn:aws:kms:{REGION}:{account}:key/{key_id_b}"
    assert _kms_grant_allows(GRANTEE_ARN, "kms:Decrypt", arn_a, account, REGION) is True
    assert _kms_grant_allows(GRANTEE_ARN, "kms:Decrypt", arn_b, account, REGION) is False


def test_non_kms_action_is_never_grant_eligible():
    assert _kms_grant_allows(GRANTEE_ARN, "s3:GetObject", "arn:aws:s3:::bucket/key", "000000000000", REGION) is False
