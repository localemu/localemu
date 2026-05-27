"""Unit tests for the secrets-to-variables pass."""

from __future__ import annotations

from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.secrets import _Sentinel, extract_secrets


def _snap(*resources: Resource) -> Snapshot:
    return Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=list(resources),
    )


def test_extracts_lambda_env_var_as_secret() -> None:
    r = Resource(
        service="lambda",
        resource_type="function",
        resource_id="myfn",
        account_id="123456789012",
        region="us-east-1",
        attributes={
            "environment": {
                "variables": {"DB_PASSWORD": "hunter2", "LOG_LEVEL": "INFO"}
            }
        },
    )
    result = extract_secrets(_snap(r))
    # Per-key sensitivity: only DB_PASSWORD matches; LOG_LEVEL stays plain.
    assert len(result.slots) == 1
    by_name = {s.attribute_path: s for s in result.slots}
    assert "environment.variables.DB_PASSWORD" in by_name
    assert by_name["environment.variables.DB_PASSWORD"].sample_value == "hunter2"
    env = result.snapshot.resources[0].attributes["environment"]["variables"]
    assert isinstance(env["DB_PASSWORD"], _Sentinel)
    assert env["LOG_LEVEL"] == "INFO"


def test_ssm_securestring_is_secret_but_string_is_not() -> None:
    secure = Resource(
        service="ssm",
        resource_type="parameter",
        resource_id="/secure",
        account_id="123456789012",
        region="us-east-1",
        attributes={"type": "SecureString", "value": "topsecret"},
    )
    plain = Resource(
        service="ssm",
        resource_type="parameter",
        resource_id="/plain",
        account_id="123456789012",
        region="us-east-1",
        attributes={"type": "String", "value": "hello"},
    )
    result = extract_secrets(_snap(secure, plain))
    assert len(result.slots) == 1
    assert result.slots[0].resource_id == "/secure"
    # ``plain`` keeps its literal value.
    assert result.snapshot.resources[1].attributes["value"] == "hello"


def test_sample_value_empty_when_source_is_redacted() -> None:
    r = Resource(
        service="secretsmanager",
        resource_type="secret",
        resource_id="s",
        account_id="123456789012",
        region="us-east-1",
        attributes={"secret_string": "***REDACTED***"},
    )
    result = extract_secrets(_snap(r))
    assert len(result.slots) == 1
    assert result.slots[0].sample_value is None
