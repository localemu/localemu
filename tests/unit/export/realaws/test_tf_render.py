"""End-to-end unit tests for Terraform rendering (no AWS, no subprocess)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from localemu.export.ir import Resource, Snapshot
from localemu.export.realaws.exporter import RealAwsExporter
from localemu.export.realaws.lambda_code import prepare_lambda_code
from localemu.export.realaws.preflight import AwsCredentials
from localemu.export.realaws.rewrite import rewrite_snapshot
from localemu.export.realaws.secrets import extract_secrets
from localemu.export.references import resolve_references


def _pipeline(snap: Snapshot) -> tuple[Snapshot, list]:
    snap = rewrite_snapshot(snap, "123456789012", "us-east-1")
    lr = prepare_lambda_code(snap, "123456789012", "us-east-1")
    sr = extract_secrets(lr.snapshot)
    return resolve_references(sr.snapshot), sr.slots


def test_renders_s3_lambda_iam(tmp_path: Path) -> None:
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=[
            Resource(
                service="s3", resource_type="bucket", resource_id="my-bucket",
                account_id="000000000000", region="us-east-1",
                attributes={
                    "bucket_name": "my-bucket",
                    "arn": "arn:aws:s3:::my-bucket",
                    "versioning": True,
                },
                tags={"Env": "dev"},
            ),
            Resource(
                service="iam", resource_type="role", resource_id="lambdarole",
                account_id="000000000000", region="us-east-1",
                attributes={
                    "role_name": "lambdarole",
                    "arn": "arn:aws:iam::000000000000:role/lambdarole",
                    "assume_role_policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            ),
            Resource(
                service="lambda", resource_type="function", resource_id="myfn",
                account_id="000000000000", region="us-east-1",
                attributes={
                    "function_name": "myfn",
                    "handler": "index.handler",
                    "runtime": "python3.11",
                    "role": "arn:aws:iam::000000000000:role/lambdarole",
                    "arn": "arn:aws:lambda:us-east-1:000000000000:function:myfn",
                    "code_zip": b"PK\x03\x04fake",
                    "environment": {"variables": {"DB_PASSWORD": "hunter2"}},
                },
            ),
        ],
    )
    final, slots = _pipeline(snap)
    ex = RealAwsExporter(
        creds=AwsCredentials(),
        target_account="123456789012",
        target_region="us-east-1",
    )
    unsupported = ex._write_terraform(final, tmp_path, slots)
    assert unsupported == []

    main_tf = (tmp_path / "main.tf").read_text()
    # Real-AWS resource types.
    assert "aws_s3_bucket" in main_tf
    assert "aws_iam_role" in main_tf
    assert "aws_lambda_function" in main_tf
    assert "aws_s3_object" in main_tf
    # IAM role reference is resolved, not left as a literal ARN.
    assert "role = aws_iam_role.lambdarole.arn" in main_tf
    # Lambda env var matching a secret pattern replaced with a TF variable.
    assert "var.secret_lambda_function_myfn_db_password" in main_tf
    # No LocalEmu account id leaks through.
    assert "000000000000" not in main_tf

    # providers.tf pins the target account.
    providers_tf = (tmp_path / "providers.tf").read_text()
    assert "allowed_account_ids" in providers_tf
    assert 'source  = "hashicorp/aws"' in providers_tf

    # variables.tf declares the secret.
    variables_tf = (tmp_path / "variables.tf").read_text()
    assert "secret_lambda_function_myfn_db" in variables_tf
    assert "sensitive   = true" in variables_tf

    # Sidecar zip was written.
    assert (tmp_path / "lambda" / "myfn.zip").exists()


@pytest.mark.skipif(
    shutil.which("terraform") is None, reason="terraform not installed"
)
def test_terraform_validates(tmp_path: Path) -> None:
    """Rendered output must pass ``terraform validate``.

    Does not hit AWS; ``init -backend=false`` and ``validate`` are offline.
    """
    snap = Snapshot(
        schema_version="2.0",
        exported_at="2026-04-14T00:00:00Z",
        localemu_version="test",
        resources=[
            Resource(
                service="s3", resource_type="bucket", resource_id="bk",
                account_id="000000000000", region="us-east-1",
                attributes={
                    "bucket_name": "bk",
                    "arn": "arn:aws:s3:::bk",
                },
            ),
        ],
    )
    final, slots = _pipeline(snap)
    ex = RealAwsExporter(
        creds=AwsCredentials(),
        target_account="123456789012",
        target_region="us-east-1",
    )
    ex._write_terraform(final, tmp_path, slots)

    # terraform init -backend=false does not talk to AWS.
    init = subprocess.run(
        ["terraform", "init", "-backend=false", "-input=false"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert init.returncode == 0, init.stderr
    val = subprocess.run(
        ["terraform", "validate"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert val.returncode == 0, val.stdout + val.stderr
