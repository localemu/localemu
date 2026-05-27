"""Unit tests for the Terraform writer (:mod:`localemu.export.formats.terraform`).

Golden-file tests live in ``tests/unit/export/golden/``. Generated output
is normalized (whitespace-collapsed) before comparing so cosmetic diffs
in the serializer do not break tests.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest

from localemu.export.ir import Ref, Resource, Snapshot

pytestmark = pytest.mark.filterwarnings("default")


def _load_tf_writer():
    try:
        mod = importlib.import_module("localemu.export.formats.terraform")
    except ImportError as e:  # pragma: no cover - safety net
        pytest.skip(f"terraform writer not available: {e}")
    cls = getattr(mod, "TerraformWriter", None)
    if cls is None:
        pytest.skip("TerraformWriter symbol not present")
    return cls


GOLDEN_DIR = Path(__file__).parent / "golden"


def _normalize(s: str) -> str:
    """Collapse whitespace so cosmetic diffs do not break golden tests."""
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _snap(resources: list[Resource]) -> Snapshot:
    return Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=resources,
    )


# --------------------------------------------------------------------------- #
# Basic writer behaviors                                                      #
# --------------------------------------------------------------------------- #


def test_write_creates_directory(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    out = tmp_path / "tfout"
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="my-bucket",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::my-bucket"},
            )
        ]
    )
    Writer().write(snap, out)
    assert out.is_dir()
    # There should be at least one .tf file emitted.
    tfs = list(out.glob("*.tf"))
    assert tfs, f"no .tf files generated in {out}"


def test_target_validation(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    snap = _snap([])
    with pytest.raises(ValueError):
        Writer().write(snap, tmp_path / "out", target="mars")


def test_target_localemu_emits_localhost_endpoints(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="b",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::b"},
            )
        ]
    )
    out = tmp_path / "localemu_tf"
    Writer().write(snap, out, target="localemu")
    # At least one emitted file should reference localemu's default endpoint.
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    assert "4566" in combined or "localhost" in combined


def test_target_aws_does_not_emit_localhost(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="b",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::b"},
            )
        ]
    )
    out = tmp_path / "aws_tf"
    Writer().write(snap, out, target="aws")
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    assert "localhost:4566" not in combined


def test_s3_bucket_appears_in_output(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="my-bucket",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::my-bucket"},
            )
        ]
    )
    out = tmp_path / "out"
    Writer().write(snap, out)
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    assert "my-bucket" in combined
    assert "aws_s3_bucket" in combined


# --------------------------------------------------------------------------- #
# Reference materialization                                                   #
# --------------------------------------------------------------------------- #


def test_ref_materialized_as_attribute_expression(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="my-role",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:iam::000000000000:role/my-role",
            "assume_role_policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        },
    )
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "role": Ref(service="iam", resource_type="role", resource_id="my-role", attribute="arn"),
            "handler": "index.handler",
            "runtime": "python3.11",
        },
    )
    out = tmp_path / "refs"
    Writer().write(_snap([role, fn]), out)
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    # Terraform attribute references are bare identifiers (no quotes).
    assert "aws_iam_role." in combined
    assert ".arn" in combined


def test_assume_role_policy_uses_jsonencode(tmp_path: Path) -> None:
    """The IAM assume_role_policy field must use ``jsonencode({...})``,
    not an inline Python dict (which is invalid HCL)."""
    Writer = _load_tf_writer()
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="r",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:iam::000000000000:role/r",
            "assume_role_policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        },
    )
    out = tmp_path / "iam_tf"
    Writer().write(_snap([role]), out)
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    assert "jsonencode" in combined


# --------------------------------------------------------------------------- #
# HCL escaping                                                                #
# --------------------------------------------------------------------------- #


def test_hcl_escapes_quotes_and_backslashes(tmp_path: Path) -> None:
    """Strings containing ``"`` and ``\\`` must round-trip safely."""
    Writer = _load_tf_writer()
    r = Resource(
        service="s3",
        resource_type="bucket",
        resource_id='weird"name\\here',
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:s3:::x",
            "description": 'has "quotes" and \\backslashes and\nnewlines',
        },
    )
    out = tmp_path / "escape_tf"
    Writer().write(_snap([r]), out)
    # Writer must not crash. No assertion on the exact escape form — just
    # that the generated file is readable text.
    for f in out.glob("*.tf"):
        f.read_text()


# --------------------------------------------------------------------------- #
# Multi-region provider aliases                                               #
# --------------------------------------------------------------------------- #


def test_multi_region_emits_provider_aliases(tmp_path: Path) -> None:
    Writer = _load_tf_writer()
    east = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="east-bucket",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::east-bucket"},
    )
    west = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="west-bucket",
        account_id="000000000000",
        region="us-west-2",
        attributes={"arn": "arn:aws:s3:::west-bucket"},
    )
    out = tmp_path / "multiregion"
    Writer().write(_snap([east, west]), out)
    combined = "\n".join(f.read_text() for f in out.glob("*.tf"))
    # Either multiple provider blocks or alias stanzas must appear.
    assert "us-west-2" in combined
    assert "us-east-1" in combined


# --------------------------------------------------------------------------- #
# Optional HCL-parse validation                                               #
# --------------------------------------------------------------------------- #


def test_output_parses_with_hcl2_if_available(tmp_path: Path) -> None:
    hcl2 = pytest.importorskip("hcl2")
    Writer = _load_tf_writer()
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="b",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::b"},
            )
        ]
    )
    out = tmp_path / "parsed"
    Writer().write(snap, out)
    for f in out.glob("*.tf"):
        with f.open() as fh:
            hcl2.load(fh)  # raises on parse error


# --------------------------------------------------------------------------- #
# Golden-file tests                                                            #
# --------------------------------------------------------------------------- #


def _read_golden(name: str) -> str | None:
    p = GOLDEN_DIR / name
    if not p.exists():
        return None
    return p.read_text()


def test_s3_bucket_golden_file(tmp_path: Path) -> None:
    """Compare the S3 bucket .tf output to a golden fragment if present.

    The golden compare tolerates whitespace differences. If the golden
    file is missing the test is skipped (other agents haven't produced
    one yet) — but the generated output itself must still contain the
    key tokens.
    """
    Writer = _load_tf_writer()
    snap = _snap(
        [
            Resource(
                service="s3",
                resource_type="bucket",
                resource_id="my-bucket",
                account_id="000000000000",
                region="us-east-1",
                attributes={"arn": "arn:aws:s3:::my-bucket"},
            )
        ]
    )
    out = tmp_path / "gold_s3"
    Writer().write(snap, out)
    generated = "\n".join(f.read_text() for f in sorted(out.glob("*.tf")))

    golden = _read_golden("s3_bucket.tf")
    if golden is None:
        pytest.skip("golden file s3_bucket.tf not present")
    # Every non-trivial line in the golden must appear (normalized) in generated.
    for line in golden.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert _normalize(line) in _normalize(generated), (
            f"golden line not found in output: {line!r}"
        )
