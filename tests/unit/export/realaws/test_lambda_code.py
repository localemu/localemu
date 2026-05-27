"""Unit tests for the Lambda code packaging phase."""

from __future__ import annotations

from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.lambda_code import prepare_lambda_code


def _snap(*resources: Resource) -> Snapshot:
    return Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=list(resources),
    )


def test_emits_bucket_and_object_and_rewires_lambda() -> None:
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="myfn",
        account_id="123456789012",
        region="us-east-1",
        attributes={
            "function_name": "myfn",
            "runtime": "python3.11",
            "handler": "index.handler",
            "code_zip": b"PK\x03\x04fakezip",
        },
    )
    result = prepare_lambda_code(_snap(fn), "123456789012", "us-east-1")
    services = sorted((r.service, r.resource_type) for r in result.snapshot.resources)
    assert ("s3", "bucket") in services
    assert ("s3", "object") in services
    assert ("lambda", "function") in services

    fn_after = next(
        r for r in result.snapshot.resources
        if r.service == "lambda" and r.resource_type == "function"
    )
    # No raw bytes left on the function.
    assert "code_zip" not in fn_after.attributes
    assert "zip_bytes" not in fn_after.attributes
    assert fn_after.attributes["s3_bucket"].startswith("localemu-export-deploy-")
    assert fn_after.attributes["s3_key"] == "functions/myfn.zip"

    # Sidecar file written under lambda/.
    assert "lambda/myfn.zip" in result.sidecar_files


def test_skips_lambda_without_code() -> None:
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="nocode",
        account_id="123456789012",
        region="us-east-1",
        attributes={"function_name": "nocode", "runtime": "python3.11"},
    )
    result = prepare_lambda_code(_snap(fn), "123456789012", "us-east-1")
    assert result.skipped == [("nocode", "no code bytes available — function created without inline code")]
    # The lambda function is dropped from the snapshot.
    assert not any(
        r.service == "lambda" for r in result.snapshot.resources
    )


def test_deployment_bucket_name_is_deterministic() -> None:
    def make() -> Snapshot:
        return _snap(
            Resource(
                service="lambda",
                resource_type="function",
                resource_id="f",
                account_id="123456789012",
                region="us-east-1",
                attributes={"function_name": "f", "code_zip": b"zip"},
            )
        )

    a = prepare_lambda_code(make(), "123456789012", "us-east-1")
    b = prepare_lambda_code(make(), "123456789012", "us-east-1")
    assert a.deployment_bucket_logical_id == b.deployment_bucket_logical_id
