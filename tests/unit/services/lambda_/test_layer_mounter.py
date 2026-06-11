"""Unit tests for ``localemu.services.lambda_.invocation.layer_mounter``.

The tests build synthetic ``LayerVersion``-shaped objects whose ``code``
attribute is a tiny stub that mimics
:class:`localemu.services.lambda_.invocation.lambda_models.S3Code`'s
contract: ``prepare_for_execution()`` materialises a directory and
``get_unzipped_code_location()`` returns its path. That keeps the tests
fast and independent of S3 / Docker / the Lambda runtime.

Coverage:

* No-layer function -> ``None``.
* Single layer -> staging contains the layer's tree at ``/opt/...``.
* Two layers, ordering -> second overwrites first at conflicting
  paths; non-conflicting paths from both survive.
* Symlinks inside a layer are preserved.
* Per-layer-version cache is reused across functions.
* Per-function staging cache is reused unless the layer set changes.
* Broken layer (``code.prepare_for_execution`` raises) propagates.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
from pathlib import Path

import pytest

from localemu.services.lambda_.invocation import layer_mounter
from localemu.services.lambda_.invocation.layer_mounter import (
    _LAYER_CACHE_ROOT,
    _MERGED_ROOT,
    prepare_merged_opt,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_cache_roots(monkeypatch, tmp_path):
    """Re-root the module's cache dirs at a fresh tmp dir per test.

    Without this, parallel test runs would race on the global
    ``/tmp/lambda/layers`` cache and break each other's expectations.
    """
    layers_root = tmp_path / "layers"
    merged_root = layers_root / "_merged"
    monkeypatch.setattr(layer_mounter, "_LAYER_CACHE_ROOT", layers_root)
    monkeypatch.setattr(layer_mounter, "_MERGED_ROOT", merged_root)
    # Also clear the per-arn-lock dict so stale locks from a previous
    # test don't survive into this one.
    layer_mounter._LAYER_LOCKS.clear()


class _FakeCode:
    """Minimal stand-in for ``S3Code`` — produces files on demand."""

    def __init__(self, files: dict[str, bytes | str], code_sha256: str = "sha"):
        self._files = files
        self._dir: Path | None = None
        self.code_sha256 = code_sha256
        self.prepare_calls = 0

    def prepare_for_execution(self) -> None:
        self.prepare_calls += 1
        if self._dir is not None and self._dir.exists():
            return
        self._dir = Path(tempfile.mkdtemp(prefix="fake-layer-"))
        for rel, body in self._files.items():
            target = self._dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(body, str) and body.startswith("__symlink_to__:"):
                # Sentinel for tests that need to assert symlink survival.
                link_target = body[len("__symlink_to__:"):]
                target.symlink_to(link_target)
            else:
                target.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))

    def get_unzipped_code_location(self) -> Path:
        assert self._dir is not None
        return self._dir


class _Layer:
    """Stand-in for ``LayerVersion`` — only the fields ``layer_mounter`` reads."""

    def __init__(self, name: str, version: int, code: _FakeCode):
        self.layer_arn = f"arn:aws:lambda:us-east-1:000000000000:layer:{name}"
        self.layer_version_arn = f"{self.layer_arn}:{version}"
        self.version = version
        self.code = code


class _FunctionVersion:
    """Stand-in for ``FunctionVersion`` — exposes ``config.layers`` + ``qualified_arn``."""

    def __init__(self, layers: list[_Layer], qualified_arn: str = "fn-test"):
        self.qualified_arn = qualified_arn
        self.config = _Cfg(layers)


class _Cfg:
    def __init__(self, layers: list[_Layer]):
        self.layers = layers


def _list_files(path: Path) -> dict[str, bytes]:
    """Return a {relative-path: contents} map of all regular files under ``path``."""
    out: dict[str, bytes] = {}
    for p in path.rglob("*"):
        if p.is_file() and not p.is_symlink():
            out[str(p.relative_to(path))] = p.read_bytes()
    return out


# ---------------------------------------------------------------------------
# No-layer / single-layer
# ---------------------------------------------------------------------------


def test_no_layers_returns_none():
    fn = _FunctionVersion(layers=[])
    assert prepare_merged_opt(fn) is None


def test_single_layer_extracted_into_staging():
    code = _FakeCode({"python/layermod.py": b"MARK = 'LAYER-CODE-RAN'\n"})
    layer = _Layer("pwn-layer", 1, code)
    fn = _FunctionVersion(layers=[layer])

    staging = prepare_merged_opt(fn)
    assert staging is not None
    files = _list_files(staging)
    assert files == {"python/layermod.py": b"MARK = 'LAYER-CODE-RAN'\n"}


def test_single_layer_with_multiple_paths_preserves_directory_shape():
    code = _FakeCode({
        "python/pkg/__init__.py": b"",
        "python/pkg/util.py": b"# u\n",
        "nodejs/node_modules/lib/index.js": b"// n\n",
        "bin/tool.sh": b"#!/bin/sh\necho hi\n",
        "lib/libsomething.so": b"\x7fELFwhatever",
    })
    layer = _Layer("pwn-layer", 1, code)
    fn = _FunctionVersion(layers=[layer])

    staging = prepare_merged_opt(fn)
    assert staging is not None
    files = _list_files(staging)
    # All four standard subdirs present.
    assert "python/pkg/util.py" in files
    assert "nodejs/node_modules/lib/index.js" in files
    assert "bin/tool.sh" in files
    assert "lib/libsomething.so" in files


# ---------------------------------------------------------------------------
# Ordering: later overwrites earlier
# ---------------------------------------------------------------------------


def test_two_layers_later_overwrites_earlier_at_conflicting_path():
    a = _FakeCode({
        "python/shared.py": b"VERSION = 'from-A'\n",
        "python/only_a.py": b"# only A\n",
    }, code_sha256="aaa")
    b = _FakeCode({
        "python/shared.py": b"VERSION = 'from-B'\n",
        "python/only_b.py": b"# only B\n",
    }, code_sha256="bbb")
    layer_a = _Layer("alpha", 1, a)
    layer_b = _Layer("bravo", 1, b)
    fn = _FunctionVersion(layers=[layer_a, layer_b])

    staging = prepare_merged_opt(fn)
    files = _list_files(staging)
    # Conflicting file -> later layer wins.
    assert files["python/shared.py"] == b"VERSION = 'from-B'\n"
    # Non-conflicting files from BOTH layers survive.
    assert files["python/only_a.py"] == b"# only A\n"
    assert files["python/only_b.py"] == b"# only B\n"


def test_three_layers_apply_in_configured_order():
    """Last write wins — not alphabetical, not arn-order."""
    a = _FakeCode({"python/x.py": b"A"}, code_sha256="a")
    b = _FakeCode({"python/x.py": b"B"}, code_sha256="b")
    c = _FakeCode({"python/x.py": b"C"}, code_sha256="c")
    fn = _FunctionVersion(layers=[_Layer("a", 1, a), _Layer("b", 1, b), _Layer("c", 1, c)])

    staging = prepare_merged_opt(fn)
    assert _list_files(staging) == {"python/x.py": b"C"}


# ---------------------------------------------------------------------------
# Symlinks preserved
# ---------------------------------------------------------------------------


def test_symlinks_inside_layer_are_preserved():
    """Some node_modules layers ship symlinks inside the tree."""
    code = _FakeCode({
        "nodejs/node_modules/foo/index.js": b"module.exports = 'foo'\n",
        "nodejs/node_modules/.bin/foo": "__symlink_to__:../foo/index.js",
    })
    layer = _Layer("syms", 1, code)
    fn = _FunctionVersion(layers=[layer])

    staging = prepare_merged_opt(fn)
    link = staging / "nodejs" / "node_modules" / ".bin" / "foo"
    assert link.is_symlink()
    assert os.readlink(link) == "../foo/index.js"


# ---------------------------------------------------------------------------
# Caching semantics
# ---------------------------------------------------------------------------


def test_same_function_called_twice_reuses_staging():
    code = _FakeCode({"python/m.py": b"v=1\n"})
    layer = _Layer("x", 1, code)
    fn = _FunctionVersion(layers=[layer])

    first = prepare_merged_opt(fn)
    second = prepare_merged_opt(fn)
    assert first == second
    # The cache marker file ensures the second call did NOT rebuild.
    # We detect "did not rebuild" by counting prepare_for_execution calls.
    assert code.prepare_calls == 1


def test_layer_set_change_invalidates_function_staging():
    code_v1 = _FakeCode({"python/m.py": b"v=1\n"}, code_sha256="v1")
    layer_v1 = _Layer("x", 1, code_v1)
    fn = _FunctionVersion(layers=[layer_v1])
    prepare_merged_opt(fn)

    # Now swap in a different layer version — same arn root, new sha + version.
    code_v2 = _FakeCode({"python/m.py": b"v=2\n"}, code_sha256="v2")
    layer_v2 = _Layer("x", 2, code_v2)
    fn.config = _Cfg([layer_v2])

    staging = prepare_merged_opt(fn)
    assert _list_files(staging) == {"python/m.py": b"v=2\n"}


def test_two_functions_sharing_a_layer_extract_only_once(tmp_path):
    """The per-layer-version cache must be the same on disk for both."""
    shared_code = _FakeCode({"python/util.py": b"# shared\n"})
    shared = _Layer("shared", 1, shared_code)

    fn_a = _FunctionVersion(layers=[shared], qualified_arn="fnA")
    fn_b = _FunctionVersion(layers=[shared], qualified_arn="fnB")

    staging_a = prepare_merged_opt(fn_a)
    staging_b = prepare_merged_opt(fn_b)

    # Different staging dirs (one per function id) ...
    assert staging_a != staging_b
    # ... but the underlying code was unzipped exactly once.
    assert shared_code.prepare_calls == 1
    # And both stagings contain the same content.
    assert _list_files(staging_a) == _list_files(staging_b)


# ---------------------------------------------------------------------------
# Failure surfaces — no silent skipping
# ---------------------------------------------------------------------------


def test_layer_whose_code_prepare_raises_propagates():
    class _BrokenCode(_FakeCode):
        def prepare_for_execution(self) -> None:
            raise RuntimeError("layer ZIP unreadable")

    code = _BrokenCode({})
    layer = _Layer("broken", 1, code)
    fn = _FunctionVersion(layers=[layer])

    with pytest.raises(RuntimeError, match="layer ZIP unreadable"):
        prepare_merged_opt(fn)


def test_layer_with_no_code_attribute_is_skipped_not_crash():
    """A partially-restored layer (e.g. mid-persistence) has ``code=None``.

    Real AWS would never expose such a layer to the runtime; tolerating
    it here means a corrupt state surfaces as 'layer skipped', not a
    crash at cold-start time."""
    valid_code = _FakeCode({"python/keeps.py": b"ok\n"})
    good = _Layer("good", 1, valid_code)
    broken = _Layer("broken", 1, None)  # type: ignore[arg-type]
    fn = _FunctionVersion(layers=[broken, good])

    staging = prepare_merged_opt(fn)
    assert _list_files(staging) == {"python/keeps.py": b"ok\n"}


# ---------------------------------------------------------------------------
# Thread-safety — parallel invokes of the same function don't double-extract
# ---------------------------------------------------------------------------


def test_parallel_prepare_for_same_function_is_serialised():
    code = _FakeCode({"python/x.py": b"v=1\n"})
    layer = _Layer("p", 1, code)
    fn = _FunctionVersion(layers=[layer])

    results: list[Path] = []
    errors: list[BaseException] = []

    def worker():
        try:
            results.append(prepare_merged_opt(fn))
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(set(results)) == 1  # all threads converged on the same staging
    # And prepare_for_execution ran exactly once.
    assert code.prepare_calls == 1
