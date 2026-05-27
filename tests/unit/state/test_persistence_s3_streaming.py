"""S3 body persistence streams to disk per-object instead of buffering
every byte into one in-memory dict before pickling.

The legacy implementation read every S3 object body into memory at
save time and pickled them as a single dict — a 5 GiB upload OOMed
the process. The streaming layout writes one file per object under
``state/assets/s3_bodies/<bucket>/<key>.body`` with a sibling
``_index.json``; both the save and restore paths now copy in fixed
4 MiB chunks.
"""

from __future__ import annotations

import io
import json
import os

import pytest


ACCOUNT = "000000000000"
REGION = "us-east-1"


@pytest.fixture
def data_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _register_pickle_fixes():
    from localemu.state.persistence import _register_pickle_fixes

    _register_pickle_fixes()


class _FakeSpooledFile:
    """Mimics the LockedSpooledTemporaryFile API the save path uses.

    Only the subset that ``_save_s3_bodies`` actually touches:
    ``position_lock`` (any context-manager), ``tell``, ``seek``, and
    chunked ``read``. ``write`` populates the initial body.
    """

    def __init__(self, body: bytes):
        self._buf = io.BytesIO(body)

        import threading

        self.position_lock = threading.RLock()

    def tell(self) -> int:
        return self._buf.tell()

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)


class _FakeBackend:
    def __init__(self, root_directory: str, filesystem: dict):
        self.root_directory = root_directory
        self._filesystem = filesystem


def _install_fake_backend(monkeypatch, backend: _FakeBackend) -> None:
    import localemu.state.persistence as p

    monkeypatch.setattr(p, "_get_s3_backend", lambda: backend)


class TestStreamingSave:
    def test_single_small_object_writes_per_key_layout(self, data_dir, monkeypatch):
        from localemu.state.persistence import SaveOrchestrator

        body = b"hello-world-" * 32
        backend = _FakeBackend(
            root_directory=data_dir,
            filesystem={
                "my-bucket": {
                    "keys": {"abc123hash": _FakeSpooledFile(body)}
                }
            },
        )
        _install_fake_backend(monkeypatch, backend)

        assets_dir = os.path.join(data_dir, "state", "assets")
        os.makedirs(assets_dir, exist_ok=True)
        saved, errors = [], []
        SaveOrchestrator()._save_s3_bodies(assets_dir, saved, errors)

        assert saved == ["s3_bodies"]
        assert not errors

        # Index file enumerates the bucket -> key list.
        index_path = os.path.join(assets_dir, "s3_bodies", "_index.json")
        assert os.path.exists(index_path)
        with open(index_path) as f:
            index = json.load(f)
        assert "my-bucket" in index
        assert index["my-bucket"] == ["abc123hash"]

        # One physical .body file holds the bytes verbatim, no pickle wrap.
        from localemu.state.persistence import _safe_dirname, _safe_filename

        body_path = os.path.join(
            assets_dir,
            "s3_bodies",
            _safe_dirname("my-bucket"),
            _safe_filename("abc123hash") + ".body",
        )
        assert os.path.exists(body_path)
        with open(body_path, "rb") as f:
            assert f.read() == body

    def test_streaming_save_does_not_buffer_whole_body(self, data_dir, monkeypatch):
        """Streaming guarantee: the save path must never call read(-1) on
        a spooled file (which would slurp the whole body into RAM). It
        must request fixed chunks so peak resident memory stays bounded
        no matter how large the object is."""
        from localemu.state.persistence import SaveOrchestrator

        observed_reads: list[int] = []

        class _RecordingSpooled(_FakeSpooledFile):
            def read(self, n: int = -1) -> bytes:
                observed_reads.append(n)
                return super().read(n)

        body = b"X" * (10 * 1024 * 1024)  # 10 MiB
        backend = _FakeBackend(
            root_directory=data_dir,
            filesystem={
                "bigbucket": {"keys": {"k1": _RecordingSpooled(body)}}
            },
        )
        _install_fake_backend(monkeypatch, backend)

        assets_dir = os.path.join(data_dir, "state", "assets")
        os.makedirs(assets_dir, exist_ok=True)
        SaveOrchestrator()._save_s3_bodies(assets_dir, [], [])

        assert observed_reads, "Save must call read() at least once"
        # All read() calls must specify an explicit chunk size — never -1
        # (read-all) and never larger than the configured stream chunk.
        chunk = SaveOrchestrator._S3_BODY_STREAM_CHUNK
        for n in observed_reads:
            assert n != -1, "read(-1) defeats the streaming guarantee"
            assert n <= chunk, f"read chunk {n} exceeds bound {chunk}"

    def test_removed_keys_are_pruned_on_resave(self, data_dir, monkeypatch):
        """Re-saving must wipe per-key files for objects that were deleted
        between snapshots — otherwise a deleted-then-restored bucket
        would silently bring deleted objects back from the dead."""
        from localemu.state.persistence import SaveOrchestrator

        assets_dir = os.path.join(data_dir, "state", "assets")
        os.makedirs(assets_dir, exist_ok=True)

        # First snapshot: two keys.
        backend1 = _FakeBackend(
            root_directory=data_dir,
            filesystem={
                "b": {"keys": {
                    "k_keep": _FakeSpooledFile(b"keep"),
                    "k_drop": _FakeSpooledFile(b"drop"),
                }}
            },
        )
        _install_fake_backend(monkeypatch, backend1)
        SaveOrchestrator()._save_s3_bodies(assets_dir, [], [])

        # Second snapshot: only one key remains.
        backend2 = _FakeBackend(
            root_directory=data_dir,
            filesystem={
                "b": {"keys": {"k_keep": _FakeSpooledFile(b"keep")}}
            },
        )
        _install_fake_backend(monkeypatch, backend2)
        SaveOrchestrator()._save_s3_bodies(assets_dir, [], [])

        from localemu.state.persistence import _safe_dirname, _safe_filename

        bucket_dir = os.path.join(
            assets_dir, "s3_bodies", _safe_dirname("b")
        )
        files = sorted(os.listdir(bucket_dir))
        assert files == [_safe_filename("k_keep") + ".body"], files


class TestStreamingRestoreCompat:
    def test_round_trip_streaming(self, data_dir, monkeypatch):
        """Save streamed -> reset -> restore streamed -> bytes match."""
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        body = b"streamed-body-" * 5000
        assets_dir = os.path.join(data_dir, "state", "assets")
        os.makedirs(assets_dir, exist_ok=True)
        backend = _FakeBackend(
            root_directory=data_dir,
            filesystem={"bk": {"keys": {"abcdef0123": _FakeSpooledFile(body)}}},
        )
        _install_fake_backend(monkeypatch, backend)
        SaveOrchestrator()._save_s3_bodies(assets_dir, [], [])

        # Reset: drop the spooled file, then restore.
        restored_fs = {"bk": {"keys": {}}}
        restored_backend = _FakeBackend(
            root_directory=data_dir, filesystem=restored_fs,
        )
        _install_fake_backend(monkeypatch, restored_backend)
        LoadOrchestrator()._restore_s3_bodies(assets_dir)

        assert "abcdef0123" in restored_fs["bk"]["keys"]
        restored = restored_fs["bk"]["keys"]["abcdef0123"]
        restored.seek(0)
        assert restored.read() == body

    def test_legacy_single_file_layout_still_loads(self, data_dir, monkeypatch):
        """Snapshots taken before the streaming layout (a dill'd
        ``{bucket: {key: bytes}}`` dict at ``s3_bodies.state``) must still
        restore — operators upgrading mid-flight shouldn't lose data."""
        import dill

        from localemu.state.persistence import LoadOrchestrator

        assets_dir = os.path.join(data_dir, "state", "assets")
        os.makedirs(assets_dir, exist_ok=True)
        legacy = {"oldbucket": {"oldkey": b"legacy-payload"}}
        with open(os.path.join(assets_dir, "s3_bodies.state"), "wb") as f:
            dill.dump(legacy, f)

        restored_fs = {"oldbucket": {"keys": {}}}
        restored_backend = _FakeBackend(
            root_directory=data_dir, filesystem=restored_fs,
        )
        _install_fake_backend(monkeypatch, restored_backend)
        LoadOrchestrator()._restore_s3_bodies(assets_dir)

        restored = restored_fs["oldbucket"]["keys"]["oldkey"]
        restored.seek(0)
        assert restored.read() == b"legacy-payload"
