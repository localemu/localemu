"""Fast-path test for ``S3Code._download_archive_to_file``.

Lambda code zips live in a LocalEmu-internal bucket
(``awslambda-*-tasks``). When persistence restores state after a restart,
reading them back through boto3 → ``localhost:4566`` is a self-wrapping
round-trip: the data is already in the process and the in-container HTTP
loopback may not be routing yet. The fast path reads bytes directly from
the ``EphemeralS3ObjectStore``.
"""

from __future__ import annotations

import io
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from localemu.services.lambda_.invocation import lambda_models
from localemu.services.lambda_.invocation.lambda_models import (
    S3Code,
    _INTERNAL_LAMBDA_BUCKET_RE,
    _try_read_archive_from_local_store,
)
from localemu.services.s3.storage.ephemeral import (
    EphemeralS3ObjectStore,
    LockedSpooledTemporaryFile,
)


def _plant_bytes(
    backend: EphemeralS3ObjectStore,
    bucket: str,
    key: str,
    version_id: str | None,
    data: bytes,
) -> None:
    """Insert ``data`` under the hash key the fast path will look up."""
    stub = SimpleNamespace(key=key, version_id=version_id)
    key_hash = EphemeralS3ObjectStore._key_from_s3_object(stub)
    bucket_tmp = os.path.join(backend.root_directory, bucket)
    os.makedirs(bucket_tmp, exist_ok=True)
    spooled = LockedSpooledTemporaryFile(dir=bucket_tmp, max_size=512 * 1024)
    spooled.write(data)
    spooled.seek(0)
    backend._filesystem[bucket]["keys"][key_hash] = spooled


@pytest.fixture
def ephemeral_backend(tmp_path):
    return EphemeralS3ObjectStore(root_directory=str(tmp_path))


def _service_plugins_mock(backend):
    service = MagicMock()
    service._provider._storage_backend = backend
    plugins = MagicMock()
    plugins.get_service.return_value = service
    return plugins


class TestInternalBucketRegex:
    def test_matches_all_regions(self):
        assert _INTERNAL_LAMBDA_BUCKET_RE.match("awslambda-us-east-1-tasks")
        assert _INTERNAL_LAMBDA_BUCKET_RE.match("awslambda-eu-west-3-tasks")
        assert _INTERNAL_LAMBDA_BUCKET_RE.match("awslambda-ap-southeast-2-tasks")

    def test_rejects_non_internal(self):
        assert not _INTERNAL_LAMBDA_BUCKET_RE.match("my-bucket")
        assert not _INTERNAL_LAMBDA_BUCKET_RE.match("awslambda-tasks")
        assert not _INTERNAL_LAMBDA_BUCKET_RE.match("prefix-awslambda-us-east-1-tasks")
        assert not _INTERNAL_LAMBDA_BUCKET_RE.match("awslambda-us-east-1-tasks-suffix")


class TestTryReadArchiveFromLocalStore:
    def test_returns_false_for_user_bucket(self, ephemeral_backend):
        plugins = _service_plugins_mock(ephemeral_backend)
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket="user-bucket",
                key="some/key",
                version_id=None,
                target_file=io.BytesIO(),
            )
        assert ok is False
        plugins.get_service.assert_not_called()

    def test_reads_bytes_verbatim(self, ephemeral_backend):
        bucket = "awslambda-us-east-1-tasks"
        key = "snapshots/000000000000/fn-abc"
        payload = b"PK\x03\x04fake-zip-bytes"
        _plant_bytes(ephemeral_backend, bucket, key, None, payload)
        plugins = _service_plugins_mock(ephemeral_backend)
        target = io.BytesIO()
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket=bucket, key=key, version_id=None, target_file=target,
            )
        assert ok is True
        target.seek(0)
        assert target.read() == payload

    def test_version_id_affects_hash(self, ephemeral_backend):
        bucket = "awslambda-us-east-1-tasks"
        key = "snapshots/000000000000/fn-abc"
        _plant_bytes(ephemeral_backend, bucket, key, "v1", b"version-one")
        _plant_bytes(ephemeral_backend, bucket, key, "v2", b"version-two")
        plugins = _service_plugins_mock(ephemeral_backend)
        target = io.BytesIO()
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket=bucket, key=key, version_id="v2", target_file=target,
            )
        assert ok is True
        target.seek(0)
        assert target.read() == b"version-two"

    def test_returns_false_when_key_missing(self, ephemeral_backend):
        plugins = _service_plugins_mock(ephemeral_backend)
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket="awslambda-us-east-1-tasks",
                key="snapshots/000000000000/not-there",
                version_id=None,
                target_file=io.BytesIO(),
            )
        assert ok is False

    def test_returns_false_for_non_ephemeral_backend(self):
        service = MagicMock()
        service._provider._storage_backend = object()  # not ephemeral
        plugins = MagicMock()
        plugins.get_service.return_value = service
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket="awslambda-us-east-1-tasks",
                key="x", version_id=None,
                target_file=io.BytesIO(),
            )
        assert ok is False

    def test_never_raises_on_errors(self):
        plugins = MagicMock()
        plugins.get_service.side_effect = RuntimeError("boom")
        with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins):
            ok = _try_read_archive_from_local_store(
                bucket="awslambda-us-east-1-tasks",
                key="x", version_id=None,
                target_file=io.BytesIO(),
            )
        assert ok is False


class TestS3CodeDownload:
    """Full S3Code._download_archive_to_file exercises both paths."""

    def _build_s3code(self, bucket, key):
        return S3Code(
            id="code-id",
            account_id="000000000000",
            s3_bucket=bucket,
            s3_key=key,
            s3_object_version=None,
            code_sha256="sha",
            code_size=16,
        )

    def test_fast_path_does_not_call_boto3(self, ephemeral_backend, tmp_path):
        bucket = "awslambda-us-east-1-tasks"
        key = "snapshots/000000000000/fn-xyz"
        payload = b"local-bytes-for-lambda"
        _plant_bytes(ephemeral_backend, bucket, key, None, payload)

        plugins = _service_plugins_mock(ephemeral_backend)
        code = self._build_s3code(bucket, key)
        out = tmp_path / "out.zip"
        with out.open("w+b") as f:
            with patch("localemu.services.plugins.SERVICE_PLUGINS", plugins), \
                 patch.object(lambda_models, "connect_to",
                              side_effect=AssertionError("HTTP must not run")):
                code._download_archive_to_file(f)
        assert out.read_bytes() == payload

    def test_http_path_for_user_bucket(self, tmp_path):
        bucket = "user-bucket"
        key = "user/key.zip"
        payload = b"user-uploaded-bytes"
        client = MagicMock()

        def _download(Bucket, Key, Fileobj, ExtraArgs):  # noqa: N803
            Fileobj.write(payload)

        client.download_fileobj.side_effect = _download
        connect_result = MagicMock()
        connect_result.s3 = client

        code = self._build_s3code(bucket, key)
        out = tmp_path / "out.zip"
        with out.open("w+b") as f:
            with patch.object(lambda_models, "connect_to",
                              return_value=connect_result):
                code._download_archive_to_file(f)
        assert out.read_bytes() == payload
        client.download_fileobj.assert_called_once()
