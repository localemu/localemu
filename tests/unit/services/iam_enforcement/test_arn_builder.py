"""Unit tests for localemu.services.iam_enforcement.arn_builder."""

import pytest

from localemu.services.iam_enforcement.arn_builder import build_resource_arn


REGION = "us-east-1"
ACCOUNT = "000000000000"


def _moto_ciphertext_blob(key_id: str) -> bytes:
    """Build a real moto-structured ciphertext blob for a given key_id,
    without needing an actual encryption key/backend."""
    from moto.kms.utils import Ciphertext, _serialize_ciphertext_blob

    return _serialize_ciphertext_blob(
        Ciphertext(key_id=key_id, iv=b"\x00" * 12, ciphertext=b"data", tag=b"\x00" * 16)
    )


class TestKmsArnFromCiphertext:
    """``Decrypt``/``ReEncrypt`` don't require a ``KeyId`` param - real AWS
    (and LocalEmu) resolve the key from the ciphertext itself. Without this,
    every Decrypt call evaluated against a ``key/*`` wildcard resource,
    silently matching ANY resource-scoped policy or grant for the WRONG
    key as long as a wildcard-resource statement existed somewhere."""

    def test_key_id_resolved_from_ciphertext_when_absent(self):
        blob = _moto_ciphertext_blob("11111111-1111-1111-1111-111111111111")
        arn = build_resource_arn("kms", "Decrypt", {"CiphertextBlob": blob}, REGION, ACCOUNT)
        assert arn == f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"

    def test_explicit_key_id_still_wins_over_ciphertext(self):
        blob = _moto_ciphertext_blob("11111111-1111-1111-1111-111111111111")
        arn = build_resource_arn(
            "kms", "ReEncrypt", {"KeyId": "22222222-2222-2222-2222-222222222222", "CiphertextBlob": blob},
            REGION, ACCOUNT,
        )
        assert arn == f"arn:aws:kms:{REGION}:{ACCOUNT}:key/22222222-2222-2222-2222-222222222222"

    def test_falls_back_to_wildcard_when_neither_is_present(self):
        arn = build_resource_arn("kms", "ListAliases", {}, REGION, ACCOUNT)
        assert arn == f"arn:aws:kms:{REGION}:{ACCOUNT}:key/*"

    def test_garbage_ciphertext_falls_back_to_wildcard_without_raising(self):
        arn = build_resource_arn("kms", "Decrypt", {"CiphertextBlob": b"not-a-real-blob"}, REGION, ACCOUNT)
        assert arn == f"arn:aws:kms:{REGION}:{ACCOUNT}:key/*"


class TestEcrArn:
    """ECR's wire field name is lowercase-first ``repositoryName`` (per
    botocore's own service model) - the generic fallback only checked the
    PascalCase ``RepositoryName``, which never matched a real request, so
    every ECR call evaluated against a wildcard resource and could never
    be pinned to a Resource-scoped policy or repository policy."""

    def test_repository_name_resolves_to_a_real_arn(self):
        arn = build_resource_arn("ecr", "GetDownloadUrlForLayer", {"repositoryName": "my-repo"}, REGION, ACCOUNT)
        assert arn == f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/my-repo"

    def test_missing_repository_name_falls_back_to_wildcard(self):
        arn = build_resource_arn("ecr", "DescribeRepositories", {}, REGION, ACCOUNT)
        assert arn == f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/*"


class TestRoute53Arn:
    """Route53 HostedZoneId accepts both '/hostedzone/X' and bare 'X'.

    Route53's APIs return zone IDs prefixed with '/hostedzone/'; users pass
    them back verbatim. The ARN form is 'arn:aws:route53:::hostedzone/X'.
    The builder must strip the prefix WITHOUT mangling zone IDs whose body
    happens to contain characters from the prefix alphabet.
    """

    @pytest.mark.parametrize(
        "hosted_zone_id, expected_body",
        [
            ("/hostedzone/Z1ABC123", "Z1ABC123"),
            ("Z1ABC123", "Z1ABC123"),
            # Regression: lstrip("/hostedzone/") would mangle these because
            # 'h', 'o', 's', 't', 'e', 'd', 'z', 'n' are in the set.
            ("/hostedzone/hosted-zone-x", "hosted-zone-x"),
            ("/hostedzone/one", "one"),
            ("hoste", "hoste"),
        ],
        ids=[
            "canonical-prefixed",
            "bare-id",
            "body-shares-prefix-chars",
            "body-is-subset-of-prefix",
            "pathological-prefix-chars-only",
        ],
    )
    def test_hosted_zone_id_prefix_stripped_correctly(self, hosted_zone_id, expected_body):
        arn = build_resource_arn(
            service="route53",
            operation="GetHostedZone",
            request_params={"HostedZoneId": hosted_zone_id},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == f"arn:aws:route53:::hostedzone/{expected_body}"

    def test_missing_hosted_zone_id_uses_wildcard(self):
        arn = build_resource_arn(
            service="route53",
            operation="ListHostedZones",
            request_params={},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == "arn:aws:route53:::hostedzone/*"

    def test_id_parameter_alternative(self):
        """Some Route53 operations use 'Id' instead of 'HostedZoneId'."""
        arn = build_resource_arn(
            service="route53",
            operation="GetHostedZone",
            request_params={"Id": "/hostedzone/Z9XYZ"},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == "arn:aws:route53:::hostedzone/Z9XYZ"


class TestEventsArnFromPutEventsEntries:
    """``PutEvents`` has no top-level ``EventBusName`` -- each entry in
    ``Entries`` carries its own. Without reading it from there, every
    PutEvents call resolved to the ``default`` bus regardless of which
    bus the entries actually targeted, so a policy scoped to a custom
    bus (e.g. a least-privilege Lambda role) could never authorize a
    PutEvents call that was correctly routed to that bus."""

    def test_event_bus_resolved_from_first_entry(self):
        arn = build_resource_arn(
            "events", "PutEvents",
            {"Entries": [{"Source": "pay.ledger", "DetailType": "x", "Detail": "{}", "EventBusName": "le-pay-bus"}]},
            REGION, ACCOUNT,
        )
        assert arn == f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/le-pay-bus"

    def test_falls_back_to_default_when_entry_omits_event_bus_name(self):
        arn = build_resource_arn(
            "events", "PutEvents",
            {"Entries": [{"Source": "x", "DetailType": "y", "Detail": "{}"}]},
            REGION, ACCOUNT,
        )
        assert arn == f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/default"

    def test_other_events_actions_still_use_the_top_level_event_bus_name(self):
        """PutRule/DescribeRule/etc. carry EventBusName at the top level,
        not nested in an Entries list -- must not regress."""
        arn = build_resource_arn(
            "events", "PutRule",
            {"Name": "my-rule", "EventBusName": "le-pay-bus"},
            REGION, ACCOUNT,
        )
        assert arn == f"arn:aws:events:{REGION}:{ACCOUNT}:rule/le-pay-bus/my-rule"


def test_bedrock_runtime_invoke_model_resource_is_the_foundation_model_arn() -> None:
    from localemu.services.iam_enforcement.arn_builder import _bedrock_runtime_arn

    assert (
        _bedrock_runtime_arn({"modelId": "meta.llama3-1-8b-instruct-v1:0"}, "us-east-1", "000000000000")
        == "arn:aws:bedrock:us-east-1::foundation-model/meta.llama3-1-8b-instruct-v1:0"
    )
    arn = "arn:aws:bedrock:us-east-1:000000000000:inference-profile/us.x"
    assert _bedrock_runtime_arn({"modelId": arn}, "us-east-1", "000000000000") == arn
