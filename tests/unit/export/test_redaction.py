"""Unit tests for :mod:`localemu.export.redaction`."""

from __future__ import annotations

import json

from localemu.export.ir import Resource, Snapshot
from localemu.export.redaction import REDACTED, redact_secrets


def _lambda(env: dict[str, str]) -> Resource:
    return Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"environment": {"variables": env}},
    )


def _ssm_param(value: str, secure: bool = True) -> Resource:
    return Resource(
        service="ssm",
        resource_type="parameter",
        resource_id="/my/p",
        account_id="000000000000",
        region="us-east-1",
        attributes={"type": "SecureString" if secure else "String", "value": value},
    )


def _secret(value: str) -> Resource:
    return Resource(
        service="secretsmanager",
        resource_type="secret",
        resource_id="my-secret",
        account_id="000000000000",
        region="us-east-1",
        attributes={"secret_string": value},
    )


def test_redaction_default_lambda_env() -> None:
    r = _lambda({"DB_PASSWORD": "hunter2", "LOG_LEVEL": "INFO"})
    out, paths = redact_secrets(r, include_secrets=False)
    env_vars = out.attributes["environment"]["variables"]
    # Per-key sensitivity: secret-pattern keys redacted, benign ones preserved.
    assert env_vars["DB_PASSWORD"] == REDACTED
    assert env_vars["LOG_LEVEL"] == "INFO"
    assert paths, "should record at least one redacted path"
    # Paths are prefixed with the logical id.
    assert all(p.startswith("lambda_function_fn.") for p in paths)


def test_include_secrets_preserves() -> None:
    r = _lambda({"DB_PASSWORD": "hunter2"})
    out, paths = redact_secrets(r, include_secrets=True)
    assert out is r
    assert paths == []
    assert out.attributes["environment"]["variables"]["DB_PASSWORD"] == "hunter2"


def test_ssm_securestring_redacted() -> None:
    r = _ssm_param("top-secret")
    out, paths = redact_secrets(r, include_secrets=False)
    assert out.attributes["value"] == REDACTED
    assert any(p.endswith(".attributes.value") for p in paths)


def test_secretsmanager_always_redacted() -> None:
    r = _secret("correct-horse-battery-staple")
    out, paths = redact_secrets(r, include_secrets=False)
    assert out.attributes["secret_string"] == REDACTED
    assert any(p.endswith(".attributes.secret_string") for p in paths)


def test_generic_sensitive_key_name() -> None:
    """Keys like ``api_key`` outside the per-service rules still redact."""
    r = Resource(
        service="custom",
        resource_type="thing",
        resource_id="t",
        account_id="000000000000",
        region="us-east-1",
        attributes={"config": {"api_key": "abc123", "region": "us-east-1"}},
    )
    out, paths = redact_secrets(r, include_secrets=False)
    assert out.attributes["config"]["api_key"] == REDACTED
    assert out.attributes["config"]["region"] == "us-east-1"
    assert any("api_key" in p for p in paths)


def test_nested_list_of_env_like_dicts() -> None:
    r = _lambda({"TOKEN": "xyz"})
    out, _ = redact_secrets(r, include_secrets=False)
    assert out.attributes["environment"]["variables"]["TOKEN"] == REDACTED


def test_original_resource_not_mutated() -> None:
    r = _lambda({"DB_PASSWORD": "hunter2"})
    original_env = dict(r.attributes["environment"]["variables"])
    redact_secrets(r, include_secrets=False)
    assert r.attributes["environment"]["variables"] == original_env


def test_snapshot_contains_no_plaintext_secrets_when_include_false(sample_snapshot: Snapshot) -> None:
    """After redaction, a snapshot dump must not contain known secret values."""
    redacted = []
    for r in sample_snapshot.resources:
        out, paths = redact_secrets(r, include_secrets=False)
        redacted.append(out)
        sample_snapshot.redacted_secrets.extend(paths)
    sample_snapshot.resources = redacted

    dumped = json.dumps(
        [
            {
                "service": r.service,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "attributes": r.attributes,
            }
            for r in sample_snapshot.resources
        ],
        default=str,
    )
    assert "super-secret-password" not in dumped
    # Sanity: list of paths is non-empty because the sample has a Lambda env.
    assert any("lambda_function_sample_fn" in p for p in sample_snapshot.redacted_secrets)


def test_non_sensitive_plain_attributes_preserved() -> None:
    r = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="b",
        account_id="000000000000",
        region="us-east-1",
        attributes={"versioning": "Enabled", "region": "us-east-1"},
    )
    out, paths = redact_secrets(r, include_secrets=False)
    assert out.attributes == r.attributes
    assert paths == []
