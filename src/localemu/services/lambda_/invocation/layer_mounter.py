"""Mount Lambda layers into the function's execution environment under ``/opt``.

Real AWS extracts each attached layer's ZIP into ``/opt`` before the
function's handler runs. The standard subdirectories are picked up
implicitly by the runtime images:

* ``/opt/python`` and ``/opt/python/lib/python<ver>/site-packages``
  are added to ``PYTHONPATH``.
* ``/opt/nodejs/node_modules`` is on ``NODE_PATH``.
* ``/opt/bin`` is on ``PATH``.
* ``/opt/lib`` and ``/opt/lib64`` are on ``LD_LIBRARY_PATH``.
* ``/opt/extensions/<name>`` executables are launched by the Lambda
  Extensions API (Phase 2 — out of scope for this module; the files
  still land at the right path so Phase 2 can pick them up).

Two AWS semantics to honour:

* **Order matters.** ``UpdateFunctionConfiguration --layers <a> <b>``
  means layer ``a`` is applied first and layer ``b`` is applied
  second. Files in ``b`` overwrite files in ``a`` at conflicting
  paths.
* **Layers are read-only at runtime.** We extract once per layer
  version into a host-side cache and copy the merged tree into the
  container; we never mount with write permissions.

The module is **side-effect-free at import**: nothing happens until
:func:`prepare_merged_opt` is called from the runtime executor.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Iterable

LOG = logging.getLogger(__name__)

# Per-layer-version cache: the unzipped tree lives here so repeat invokes
# of the same function don't re-fetch + re-unzip every time. Key shape:
# ``<tmp>/lambda/layers/<layer_arn-safe>/<version>/unzipped/``
_LAYER_CACHE_ROOT = Path(tempfile.gettempdir()) / "lambda" / "layers"

# Per-function merged staging: a host-side ``/opt`` for the function's
# attached layers, recomputed when the layer list changes. Key shape:
# ``<tmp>/lambda/layers/_merged/<function_id>/opt/``
_MERGED_ROOT = _LAYER_CACHE_ROOT / "_merged"

# Guards parallel calls to :func:`prepare_merged_opt` for the same
# function from racing each other (multiple invocations of the same
# function in parallel triggering layer extraction concurrently).
_PREPARE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


def prepare_merged_opt(function_version) -> Path | None:
    """Materialise the function's attached layers into a host-side ``/opt``.

    Returns the path to a directory whose **contents** (not the directory
    itself) the runtime executor must copy into the container at ``/opt``.
    Returns ``None`` when no layers are attached: the caller should skip
    the copy entirely so an empty ``/opt`` does not shadow content the
    base image might ship there.

    Errors during layer fetch / unzip / merge are logged with the
    layer ARN and re-raised — Lambda's behaviour matches: an invocation
    against a broken layer fails the cold-start. We do NOT swallow.
    """
    layers = _attached_layers(function_version)
    if not layers:
        return None

    # The function_id is stable for the lifetime of a published version;
    # using it as the staging-dir key means a published version's layers
    # are extracted once and reused across invocations.
    function_id = _function_cache_key(function_version)

    with _PREPARE_LOCK:
        staging = _MERGED_ROOT / function_id / "opt"
        # If staging exists and the layer set hasn't changed, reuse.
        marker = staging.parent / "layer-set.txt"
        wanted = _layer_set_marker(layers)
        if staging.exists() and marker.exists() and marker.read_text() == wanted:
            LOG.debug(
                "layer_mounter: reusing cached /opt staging for function %s",
                function_id,
            )
            return staging

        # Fresh build: wipe previous staging (if any), then merge.
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)

        for layer in layers:
            layer_dir = _unzip_layer_to_cache(layer)
            _overlay_directory(src=layer_dir, dst=staging)

        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(wanted)
        LOG.info(
            "layer_mounter: merged %d layer(s) for function %s -> %s",
            len(layers), function_id, staging,
        )
        return staging


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _attached_layers(function_version) -> list:
    """Return the layer-version objects attached to the function, in order.

    The model field is ``function_version.config.layers``; each entry is
    a :class:`LayerVersion`. We guard against a missing ``config`` for
    test fakes that pass a minimal object.
    """
    config = getattr(function_version, "config", None)
    if config is None:
        return []
    raw = getattr(config, "layers", None) or []
    # Skip layer entries with no code (a partially-restored / broken
    # state) rather than crash later in unzip.
    return [layer for layer in raw if getattr(layer, "code", None) is not None]


def _function_cache_key(function_version) -> str:
    """A stable, filesystem-safe key identifying this published version.

    Real ``FunctionVersion`` has ``qualified_arn`` which already contains
    everything we need (account, region, function name, version). We
    sanitise to keep ``/`` and ``:`` out of the path segment.
    """
    qarn = (
        getattr(function_version, "qualified_arn", None)
        or getattr(function_version, "id", None)
        or "anon"
    )
    return _sanitise_path_segment(str(qarn))


def _layer_set_marker(layers: Iterable) -> str:
    """A serialised representation of the layer arns + versions.

    Used as the cache-invalidation key: if the function gets a new
    layer attached, the marker changes and the staging is rebuilt.
    """
    parts = []
    for layer in layers:
        arn = getattr(layer, "layer_version_arn", None) or ""
        ver = getattr(layer, "version", "") or ""
        sha = getattr(getattr(layer, "code", None), "code_sha256", "") or ""
        parts.append(f"{arn}|{ver}|{sha}")
    return "\n".join(parts)


def _sanitise_path_segment(value: str) -> str:
    safe = []
    for ch in value:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        else:
            safe.append("_")
    return "".join(safe)


# ---- per-layer-version cache ----------------------------------------------

_LAYER_LOCKS: dict[str, threading.Lock] = {}
_LAYER_LOCKS_GUARD = threading.Lock()


def _layer_lock_for(arn: str) -> threading.Lock:
    """One :class:`threading.Lock` per layer-version arn for unzip races."""
    with _LAYER_LOCKS_GUARD:
        lock = _LAYER_LOCKS.get(arn)
        if lock is None:
            lock = threading.Lock()
            _LAYER_LOCKS[arn] = lock
        return lock


def _unzip_layer_to_cache(layer) -> Path:
    """Ensure the layer's ZIP is unzipped on disk and return the unzip dir.

    Reuses the host-side cache key
    ``<tmp>/lambda/layers/<layer_arn>/<version>/unzipped`` so that two
    functions sharing the same layer-version (the typical "shared
    utilities layer" pattern) only pay the extraction cost once.
    """
    arn = getattr(layer, "layer_version_arn", "") or ""
    version = getattr(layer, "version", "0")
    key = f"{_sanitise_path_segment(arn)}/v{version}"
    cache_dir = _LAYER_CACHE_ROOT / key / "unzipped"

    with _layer_lock_for(arn):
        if cache_dir.exists() and any(cache_dir.iterdir()):
            return cache_dir

        # Reuse the function-code unzip helper: ``S3Code`` already knows
        # how to download from the internal awslambda-* bucket OR fall
        # back to boto3, and unzips to its own cache. We just need to
        # copy that unzip into our layer cache so the layer extraction
        # path is independent of ``S3Code``'s own cache-eviction.
        code = layer.code
        code.prepare_for_execution()
        src = code.get_unzipped_code_location()
        if not Path(src).exists():
            raise RuntimeError(
                f"layer_mounter: code.prepare_for_execution() did not "
                f"produce {src} for layer {arn} v{version}"
            )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
        # ``shutil.copytree`` is the cheapest correct option here: layers
        # are read-only at runtime so hard-link copy would also be valid,
        # but copytree is portable across host filesystems and keeps the
        # mental model simple. ``symlinks=True`` is mandatory because
        # ``node_modules`` layers ship ``.bin/`` symlinks pointing at
        # the package's actual entrypoint, and the runtime expects
        # them at the symlink shape (resolving here would put the same
        # bytes at two paths and break tools that ``readlink`` their
        # own dispatch script).
        shutil.copytree(src, cache_dir, symlinks=True)
        LOG.debug(
            "layer_mounter: extracted layer %s v%s -> %s",
            arn, version, cache_dir,
        )
        return cache_dir


# ---- merge (later overwrites earlier) -------------------------------------


def _overlay_directory(*, src: Path, dst: Path) -> None:
    """Merge ``src`` into ``dst``: later files replace earlier files.

    We implement this manually rather than ``shutil.copytree(dst,
    dirs_exist_ok=True)`` because ``copytree``'s default behaviour
    refuses to replace files when permissions differ on some
    filesystems, and we want a hard "later wins" semantics matching
    real AWS.
    """
    src = Path(src)
    dst = Path(dst)
    for entry in src.rglob("*"):
        rel = entry.relative_to(src)
        target = dst / rel
        # ``is_symlink`` MUST be checked before ``is_dir``: a symlink
        # pointing at a directory makes ``is_dir`` return True (it
        # follows the link), so the obvious-looking order silently
        # drops the symlink.
        if entry.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            link_target = entry.readlink()
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(link_target)
        elif entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                # Real AWS doesn't merge directory contents at the file
                # level beyond a simple overwrite — the later layer's
                # file fully replaces the earlier layer's file.
                target.unlink()
            shutil.copy2(entry, target)
