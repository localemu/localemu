"""
Persistence engine — SaveOrchestrator and LoadOrchestrator for LocalEmu state.

Save flow (ON_SHUTDOWN):
    1. Invoke ``on_before_state_save()`` on every loaded provider so they can
       flush runtime caches (e.g. S3 storage backend flushing buffers).
    2. Serialize every registered native store (``AccountRegionBundle``)
       while holding its own lock, so request handlers cannot mutate the
       graph mid-pickle (which would raise ``RuntimeError: dict changed
       size during iteration``).
    3. Serialize every instantiated moto backend.
    4. Dump non-bundle state (CloudTrail native module state, CloudTrail
       event store, S3 object bodies, DynamoDB SQLite snapshot files).
    5. Write a ``_manifest.json`` describing what was saved.

The save runs at ``on_infra_shutdown`` priority 0 via ``SHUTDOWN_HANDLERS``
— i.e. BEFORE services are stopped (priority -10). This is load-bearing:
``S3Provider.on_before_stop()`` calls ``_storage_backend.close()`` which
clears every ``LockedSpooledTemporaryFile`` from the ephemeral filesystem.
Saving after service shutdown would persist metadata for S3 objects whose
bodies have already been wiped.

Load flow (ON_STARTUP, priority 5, before services accept requests):
    1. Read and version-check ``_manifest.json``.
    2. Load each service in topological ``LOAD_ORDER``. Native stores are
       merged into the live ``AccountRegionBundle`` in a way that preserves
       the identity of the live ``_universal`` / ``_global`` dicts — the
       shared-dict invariant used by ``CrossAccountAttribute`` /
       ``CrossRegionAttribute`` descriptors depends on those identities.
    3. Restore CloudTrail native module state, CloudTrail events, S3 bodies
       and DynamoDB SQLite snapshot assets.
    4. Invoke ``on_after_state_load()`` on every loaded provider so they
       can rebuild volatile runtime state (Lambda execution environments,
       EventBridge rule services, CloudWatch alarm schedulers, …).
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone

import dill

from localemu import config
from localemu.state.registry import LOAD_ORDER, MOTO_SERVICES, NATIVE_STORES
from localemu.version import __version__ as _LOCALEMU_VERSION

LOG = logging.getLogger(__name__)

def _safe_dirname(name: str) -> str:
    """Hash any S3 bucket name into a path-safe directory name.

    Bucket names allow dots and hyphens and could collide with relative
    paths on disk (``../escape``), so we hash + take the original name
    only as a debugging hint. The hash is what we actually use for the
    on-disk layout; collisions are vanishingly unlikely at 16 hex chars.
    """
    import hashlib

    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    return digest


def _safe_filename(name: str) -> str:
    """Same idea for object-key hashes — they're already hex strings from
    the S3 backend, but we still hash to clamp length and reject path
    separators in case of unexpected inputs."""
    import hashlib

    if all(c in "0123456789abcdef" for c in name) and 8 <= len(name) <= 128:
        return name
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:32]


def _get_s3_backend():
    """Return the live ``EphemeralS3ObjectStore`` backing the S3 provider,
    or ``None`` if the S3 service hasn't been loaded or is backed by a
    non-ephemeral store.
    """
    try:
        from localemu.services.plugins import SERVICE_PLUGINS
        from localemu.services.s3.storage.ephemeral import EphemeralS3ObjectStore

        svc = SERVICE_PLUGINS.get_service("s3")
        if not svc:
            return None
        provider = getattr(svc, "_provider", None)
        if not provider:
            return None
        backend = getattr(provider, "_storage_backend", None)
        if isinstance(backend, EphemeralS3ObjectStore):
            return backend
    except Exception:
        LOG.debug("S3 body persistence: failed to obtain backend", exc_info=True)
    return None


def _iter_loaded_services():
    """Yield ``(name, service, lifecycle_hook)`` for every service plugin
    that has been loaded (and therefore has a concrete ``Service`` instance
    with a lifecycle hook attached).

    The lifecycle hook is usually the provider itself — see
    ``Service.for_provider``: if the provider inherits
    ``ServiceLifecycleHook``, it IS the lifecycle hook. The provider is
    where ``on_before_state_save`` / ``on_after_state_load`` are defined
    (never on the ``Service`` wrapper), so iterating ``SERVICE_PLUGINS``
    and reading ``service.on_after_state_load`` directly — as the previous
    implementation did — always missed every hook.
    """
    try:
        from localemu.services.plugins import SERVICE_PLUGINS
    except ImportError:
        return
    for name, service in SERVICE_PLUGINS.items():
        lifecycle_hook = getattr(service, "lifecycle_hook", None)
        if lifecycle_hook is None:
            continue
        yield name, service, lifecycle_hook


def _invoke_hook(name: str, lifecycle_hook, hook_name: str) -> None:
    """Invoke a named state-lifecycle hook. Failures are logged, never raised."""
    hook = getattr(lifecycle_hook, hook_name, None)
    if not callable(hook):
        return
    try:
        hook()
    except Exception:
        LOG.warning("Hook %s.%s failed", name, hook_name, exc_info=True)


# Single-writer guard: scheduled save + on-shutdown save must not overlap,
# and neither may overlap a manual ``/_localemu/state/save`` POST. dill
# serializing the same object graph twice concurrently is undefined.
_SAVE_LOCK = threading.Lock()


class SaveOrchestrator:
    def save(self, data_dir: str) -> dict:
        # Skip if another save is in flight — it's racing for the same
        # target files anyway, and two dill.dump calls against a live
        # graph are not well defined.
        acquired = _SAVE_LOCK.acquire(blocking=False)
        if not acquired:
            LOG.info("Persistence save already in progress — skipping")
            return {"skipped": True}

        try:
            return self._save(data_dir)
        finally:
            _SAVE_LOCK.release()

    def _save(self, data_dir: str) -> dict:
        state_dir = os.path.join(data_dir, "state")
        api_dir = os.path.join(state_dir, "api_states")
        assets_dir = os.path.join(state_dir, "assets")
        os.makedirs(api_dir, exist_ok=True)
        os.makedirs(assets_dir, exist_ok=True)

        saved: list[str] = []
        errors: list[tuple[str, str]] = []

        # 1. Pre-save hooks — give every provider a chance to flush runtime
        # caches into its persisted state before we take the snapshot.
        for name, _service, lifecycle_hook in _iter_loaded_services():
            _invoke_hook(name, lifecycle_hook, "on_before_state_save")

        # 2. S3 object bodies. Must run BEFORE services shut down (our
        # caller guarantees this by registering the save on SHUTDOWN_HANDLERS
        # at on_infra_shutdown priority 0, ahead of service teardown at
        # priority -10). Bodies live in SpooledTemporaryFile objects inside
        # EphemeralS3ObjectStore._filesystem — the store's ``close()`` wipes
        # them. We capture bytes while the store is still populated.
        self._save_s3_bodies(assets_dir, saved, errors)

        # 3. Native stores (AccountRegionBundle per service).
        for name, (mod_path, var_name) in NATIVE_STORES.items():
            try:
                mod = __import__(mod_path, fromlist=[var_name])
                store = getattr(mod, var_name)
                self._atomic_dump(api_dir, name, store, lock=getattr(store, "lock", None))
                saved.append(name)
            except Exception as e:
                LOG.warning("Failed to save native store %s: %s", name, e)
                errors.append((name, str(e)))

        # 4. Moto backends — only those that have been instantiated.
        import moto.backends as mb
        for svc in MOTO_SERVICES:
            try:
                bd = mb.get_backend(svc)
                backends = {}
                for acct, region_map in list(bd.items()):
                    if not isinstance(region_map, dict):
                        continue
                    for region, backend in list(region_map.items()):
                        backends[(acct, region)] = backend
                if backends:
                    self._atomic_dump(api_dir, f"{svc}.moto", backends)
                    saved.append(f"{svc}.moto")
            except Exception as e:
                LOG.warning("Failed to save moto backend %s: %s", svc, e)
                errors.append((f"{svc}.moto", str(e)))

        # 5. Non-bundle stores.
        self._save_cloudtrail_event_store()
        self._save_cloudtrail_native_state(api_dir, saved, errors)

        # 6. DynamoDB SQLite snapshot files.
        self._save_ddb_assets(assets_dir, errors)

        # 7. on_after_state_save hooks — symmetry with before-hooks.
        for name, _service, lifecycle_hook in _iter_loaded_services():
            _invoke_hook(name, lifecycle_hook, "on_after_state_save")

        # 8. Manifest — written last so a reader that sees a manifest knows
        # every referenced .state file is fully flushed.
        manifest = {
            "version": _LOCALEMU_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": saved,
            "errors": errors,
            "format": "dill",
        }
        self._atomic_write_json(
            os.path.join(state_dir, "_manifest.json"), manifest
        )

        LOG.info(
            "Persistence save complete: %d services saved, %d errors (dir=%s)",
            len(saved), len(errors), state_dir,
        )
        return manifest

    # ------------------------------------------------------------------
    # Atomic write primitives
    # ------------------------------------------------------------------
    def _atomic_dump(self, directory: str, name: str, obj, lock=None) -> None:
        """Pickle *obj* to ``directory/name.state`` atomically, optionally
        holding *lock* for the duration of the pickle walk so concurrent
        mutations can't tear the object graph under us.
        """
        path = os.path.join(directory, f"{name}.state")
        tmp = path + ".tmp"
        try:
            with open(tmp, "wb") as f:
                if lock is not None:
                    with lock:
                        dill.dump(obj, f)
                else:
                    dill.dump(obj, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception:
            # Best-effort cleanup of the temp file. The previous file at
            # ``path`` is untouched because os.replace ran last (or not at all).
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise

    def _atomic_write_json(self, path: str, obj) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ------------------------------------------------------------------
    # S3 object bodies
    # ------------------------------------------------------------------
    # Chunk size for streaming S3 object bodies between the spooled
    # in-memory file and disk. 4 MiB keeps the resident-memory cost
    # bounded regardless of object size — a 5 GiB upload now peaks at
    # 4 MiB during persistence instead of holding the full body.
    _S3_BODY_STREAM_CHUNK = 4 * 1024 * 1024

    def _save_s3_bodies(self, assets_dir: str, saved: list, errors: list) -> None:
        """Capture S3 object bodies from the live ``EphemeralS3ObjectStore``.

        Each body lives in a ``LockedSpooledTemporaryFile``. Small objects
        (<512 KB by default) stay in memory; larger ones spill to a temp
        file under ``root_directory``. We stream the bytes from each
        spooled file directly to a per-key file on disk so the persistence
        path never holds an entire object in memory — the previous
        implementation pickled every body into one ``s3_bodies.state`` file,
        which OOMed once a single upload exceeded available RAM.
        """
        backend = _get_s3_backend()
        if backend is None:
            return

        bodies_root = os.path.join(assets_dir, "s3_bodies")
        try:
            # Wipe any prior streamed layout — the snapshot is the source of
            # truth, stale per-key files from a deleted object would otherwise
            # come back to life on restore.
            if os.path.isdir(bodies_root):
                import shutil

                shutil.rmtree(bodies_root)
            os.makedirs(bodies_root, exist_ok=True)
        except Exception as e:
            LOG.warning("Failed to prepare S3 bodies directory: %s", e, exc_info=True)
            errors.append(("s3_bodies", str(e)))
            return

        bucket_count = 0
        object_count = 0
        index: dict[str, list[str]] = {}
        try:
            for bucket_name, bucket_fs in backend._filesystem.items():
                keys = bucket_fs.get("keys") or {}
                if not keys:
                    continue
                bucket_dir = os.path.join(bodies_root, _safe_dirname(bucket_name))
                os.makedirs(bucket_dir, exist_ok=True)
                bucket_keys: list[str] = []
                for key_hash, spooled_file in keys.items():
                    target = os.path.join(bucket_dir, _safe_filename(key_hash) + ".body")
                    tmp = target + ".tmp"
                    try:
                        with spooled_file.position_lock:
                            current = spooled_file.tell()
                            spooled_file.seek(0)
                            with open(tmp, "wb") as out:
                                while True:
                                    chunk = spooled_file.read(self._S3_BODY_STREAM_CHUNK)
                                    if not chunk:
                                        break
                                    out.write(chunk)
                                out.flush()
                                os.fsync(out.fileno())
                            spooled_file.seek(current)
                        os.replace(tmp, target)
                    except Exception:
                        LOG.warning(
                            "Could not stream S3 body for %s/%s — skipping",
                            bucket_name, key_hash, exc_info=True,
                        )
                        try:
                            os.unlink(tmp)
                        except FileNotFoundError:
                            pass
                        continue
                    bucket_keys.append(key_hash)
                if bucket_keys:
                    index[bucket_name] = bucket_keys
                    bucket_count += 1
                    object_count += len(bucket_keys)
            if index:
                self._atomic_write_json(
                    os.path.join(bodies_root, "_index.json"), index
                )
                saved.append("s3_bodies")
                LOG.info(
                    "Saved S3 bodies: %d buckets, %d objects (streamed)",
                    bucket_count, object_count,
                )
        except Exception as e:
            LOG.warning("Failed to save S3 bodies: %s", e, exc_info=True)
            errors.append(("s3_bodies", str(e)))

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    def _save_cloudtrail_event_store(self) -> None:
        """Delegate to the event store's own atomic save path. Its target
        location is derived from config.dirs.data directly; we don't pass
        a directory."""
        try:
            from localemu.services.cloudtrail.event_store import get_event_store

            get_event_store().save_to_disk()
        except Exception:
            LOG.warning("Failed to save CloudTrail event store", exc_info=True)

    def _save_cloudtrail_native_state(self, api_dir: str, saved: list, errors: list) -> None:
        try:
            from localemu.services.cloudtrail import provider as ct_provider

            native_state: dict = {
                "event_data_stores": getattr(ct_provider, "_event_data_stores", {}),
            }
            try:
                import localemu.services.cloudtrail.native as native_mod

                for attr in (
                    "_channels",
                    "_dashboards",
                    "_imports",
                    "_resource_policies",
                    "_federation_state",
                    "_org_delegated_admins",
                    "_event_configurations",
                ):
                    val = getattr(native_mod, attr, None)
                    if val is not None:
                        native_state[attr] = val
            except ImportError:
                pass
            self._atomic_dump(api_dir, "cloudtrail_native", native_state)
            saved.append("cloudtrail_native")
        except Exception as e:
            LOG.warning("Failed to save CloudTrail native state", exc_info=True)
            errors.append(("cloudtrail_native", str(e)))

    # ------------------------------------------------------------------
    # DynamoDB SQLite snapshot assets
    # ------------------------------------------------------------------
    def _save_ddb_assets(self, assets_dir: str, errors: list) -> None:
        try:
            import shutil

            ddb_data = os.path.join(config.dirs.data, "dynamodb")
            ddb_assets = os.path.join(assets_dir, "dynamodb")
            if os.path.isdir(ddb_data):
                if os.path.exists(ddb_assets):
                    shutil.rmtree(ddb_assets)
                shutil.copytree(ddb_data, ddb_assets)
        except Exception as e:
            LOG.warning("Failed to copy DynamoDB assets", exc_info=True)
            errors.append(("dynamodb_assets", str(e)))


class LoadOrchestrator:
    def load(self, data_dir: str, *, trigger_post_load_hooks: bool = True) -> bool:
        """Load all persisted state from *data_dir* into the live runtime.

        ``trigger_post_load_hooks`` (default True) controls whether the
        orchestrator eagerly loads services with persisted state and
        invokes their ``on_after_state_load`` hook. Production use wants
        this — without it, Lambda functions restored from disk have no
        version manager and any Invoke call 409s with
        ``ResourceConflictException``. Unit tests that don't spin up the
        full plugin runtime should pass ``False``.
        """
        self._trigger_post_load_hooks = trigger_post_load_hooks
        state_dir = os.path.join(data_dir, "state")
        api_dir = os.path.join(state_dir, "api_states")
        manifest_path = os.path.join(state_dir, "_manifest.json")

        if not os.path.exists(manifest_path):
            LOG.info("No persisted state found — cold start (%s)", state_dir)
            return False

        with open(manifest_path) as f:
            manifest = json.load(f)

        saved_version = manifest.get("version", "")
        current_version = _LOCALEMU_VERSION
        if not self._versions_compatible(saved_version, current_version):
            LOG.warning(
                "State version %s incompatible with %s — starting fresh",
                saved_version, current_version,
            )
            return False

        LOG.info(
            "Loading persisted state from %s (%d services, saved %s)",
            state_dir, len(manifest["services"]), manifest["timestamp"],
        )

        # on_before_state_load hooks.
        for name, _service, lifecycle_hook in _iter_loaded_services():
            _invoke_hook(name, lifecycle_hook, "on_before_state_load")

        # Load in topological order (Tier 0 → Tier 4).
        loaded = 0
        for tier in LOAD_ORDER:
            for service_name in tier:
                if service_name in manifest["services"]:
                    if self._load_native(api_dir, service_name):
                        loaded += 1
                moto_name = f"{service_name}.moto"
                if moto_name in manifest["services"]:
                    if self._load_moto(api_dir, moto_name):
                        loaded += 1

        # Load anything else that made it into the manifest but isn't in
        # LOAD_ORDER (new services added since the manifest was written).
        tiered = {s for tier in LOAD_ORDER for s in tier}
        _special = {"cloudtrail_native", "s3_bodies"}
        for svc in manifest["services"]:
            if svc in _special:
                continue
            if svc in tiered:
                continue
            if svc.endswith(".moto"):
                base = svc[: -len(".moto")]
                if base in tiered:
                    continue
                if self._load_moto(api_dir, svc):
                    loaded += 1
            else:
                if self._load_native(api_dir, svc):
                    loaded += 1

        # CloudTrail native module state + event store (JSON, not dill).
        self._load_cloudtrail_native(api_dir)
        self._load_cloudtrail_event_store()

        # Assets: S3 bodies, DynamoDB SQLite snapshot files.
        self._restore_assets(os.path.join(state_dir, "assets"))

        # on_after_state_load hooks. Must run AFTER all stores are live
        # because the hooks typically re-derive runtime caches from the
        # freshly loaded state (Lambda execution envs, Events rule services,
        # CloudWatch alarm scheduler).
        #
        # Load is invoked from an ``on_infra_start`` priority-5 hook, BEFORE
        # any service has been lazily loaded. ``SERVICE_PLUGINS.items()`` is
        # therefore empty at this point — iterating it would skip every
        # hook. We instead derive the set of services that need to be
        # eagerly loaded from the manifest, then require + start each in
        # topological order so the hook can see its fully-initialized
        # provider (version managers, event rule services, alarm scheduler
        # threads, etc.).
        if getattr(self, "_trigger_post_load_hooks", True):
            self._fire_post_load_hooks(manifest.get("services", []))

        LOG.info("Persistence load complete: %d stores restored", loaded)
        return True

    # ------------------------------------------------------------------
    # Post-load hook firing (eager service start)
    # ------------------------------------------------------------------
    # Map NATIVE_STORES registry names → plugin/service names used by
    # ``SERVICE_PLUGINS``. These differ in only a handful of cases where
    # a module-level store is named after a Python-safe identifier
    # (e.g. ``lambda_`` to avoid the reserved keyword) while the plugin
    # registered in ``plux.ini`` uses the AWS service name (``lambda``).
    _HOOK_SERVICE_NAME_MAP = {
        "lambda_": "lambda",
        # "events_v1" shares state shape with "events" but has no
        # standalone plugin in SERVICE_PLUGINS — hooks for it are
        # handled under "events".
        "events_v1": "events",
    }

    def _fire_post_load_hooks(self, manifest_services: list) -> None:
        """Eagerly load services with persisted state and fire their
        ``on_after_state_load`` hook.

        Only services whose provider *overrides* ``on_after_state_load``
        (i.e. does something beyond the ``StateLifecycleHook`` no-op) are
        force-started. The no-op default is skipped so we don't pay the
        cold-start cost (Docker containers, background workers, etc.)
        for services that have nothing to do. In practice this limits
        eager starts to Lambda, EventBridge, CloudWatch, DynamoDB v2,
        Scheduler, and a handful of others — the services whose runtime
        state must be reconstructed from their persisted config.
        """
        from localemu.services.plugins import SERVICE_PLUGINS, ServiceStateException
        from localemu.state.core import StateLifecycleHook

        # The unoverridden method on the base class. We compare against
        # the underlying function object (``__func__``) so subclasses
        # that only *inherit* the default are excluded.
        _default_post_load = StateLifecycleHook.on_after_state_load

        _non_service = {"cloudtrail_native", "s3_bodies"}
        resolved: list[str] = []
        seen: set[str] = set()

        def _add(plugin_name: str) -> None:
            if plugin_name and plugin_name not in seen:
                seen.add(plugin_name)
                resolved.append(plugin_name)

        # Walk LOAD_ORDER first so hooks fire in dependency order.
        manifest_set = set(manifest_services)
        for tier in LOAD_ORDER:
            for registry_name in tier:
                if registry_name in manifest_set:
                    _add(self._HOOK_SERVICE_NAME_MAP.get(registry_name, registry_name))
                moto_name = f"{registry_name}.moto"
                if moto_name in manifest_set:
                    _add(self._HOOK_SERVICE_NAME_MAP.get(registry_name, registry_name))

        for svc in manifest_services:
            if svc in _non_service:
                continue
            base = svc[: -len(".moto")] if svc.endswith(".moto") else svc
            _add(self._HOOK_SERVICE_NAME_MAP.get(base, base))

        # ``list_available()`` enumerates every service with a registered
        # plux plugin — whether or not it has been lazy-loaded. ``_services``
        # would only contain services already instantiated, which at
        # startup is empty; iterating it would make us skip every hook.
        available_plugins = set(SERVICE_PLUGINS.list_available())

        for plugin_name in resolved:
            if plugin_name not in available_plugins:
                # Service isn't registered in this process (e.g., narrowed
                # via the SERVICES env var) — skip silently.
                continue

            try:
                service = SERVICE_PLUGINS.require(plugin_name)
            except ServiceStateException:
                LOG.debug("Skipping post-load hook for %s: service not startable",
                          plugin_name)
                continue
            except Exception:
                LOG.warning("Skipping post-load hook for %s: require() failed",
                            plugin_name, exc_info=True)
                continue

            lifecycle_hook = getattr(service, "lifecycle_hook", None)
            if lifecycle_hook is None:
                continue

            # Skip the no-op default. Avoids log noise from services
            # (S3, SQS, Secrets, ...) whose restore is complete once the
            # store bundle is in place.
            bound = getattr(lifecycle_hook, "on_after_state_load", None)
            impl = getattr(bound, "__func__", None) if bound is not None else None
            if impl is None or impl is _default_post_load:
                continue

            _invoke_hook(plugin_name, lifecycle_hook, "on_after_state_load")

    # ------------------------------------------------------------------
    # Native stores
    # ------------------------------------------------------------------
    def _load_native(self, api_dir: str, service_name: str) -> bool:
        """Merge a persisted ``AccountRegionBundle`` into the live one.

        Identity of the live ``_universal`` dict (cross-account attrs) and
        of each RegionBundle's ``_global`` dict (cross-region attrs) must
        be preserved: stores hold a direct reference to those dicts, and
        new stores created after load will get the live bundle's dicts.
        If we replaced ``live._universal`` with the deserialized one, the
        stores just loaded would be out of sync with stores created later.
        We mutate in place instead.
        """
        path = os.path.join(api_dir, f"{service_name}.state")
        if not os.path.exists(path):
            return False
        mapping = NATIVE_STORES.get(service_name)
        if mapping is None:
            LOG.warning("Unknown native store in manifest: %s", service_name)
            return False
        try:
            with open(path, "rb") as f:
                restored = dill.load(f)

            mod_path, var_name = mapping
            mod = __import__(mod_path, fromlist=[var_name])
            live = getattr(mod, var_name)

            # Cross-account state: mutate live._universal in place so every
            # already-registered back-reference keeps pointing at the right
            # dict.
            restored_universal = getattr(restored, "_universal", None)
            if isinstance(restored_universal, dict):
                live._universal.clear()
                live._universal.update(restored_universal)

            # Walk the restored bundle via raw dict access — going through
            # ``__getitem__`` would validate account IDs (unnecessary; they
            # were already validated when saved) and also traverse the
            # restored bundle's lock (we've reset it, but there's no value
            # in re-acquiring).
            for acct_id, restored_region_bundle in dict.items(restored):
                if not isinstance(restored_region_bundle, dict):
                    continue
                # Instantiate live RegionBundle if missing. live[acct_id]
                # uses the live lock (which is fresh, not deserialized).
                live_region_bundle = live[acct_id]

                # Cross-region state: mutate live._global in place.
                restored_global = getattr(restored_region_bundle, "_global", None)
                if isinstance(restored_global, dict):
                    live_region_bundle._global.clear()
                    live_region_bundle._global.update(restored_global)

                for region, restored_store in dict.items(restored_region_bundle):
                    # Install the restored store object, but rebind its
                    # shared-dict back-refs to the LIVE bundle's dicts so
                    # cross-region/cross-account attrs work uniformly with
                    # stores created later (which will inherit the live
                    # bundle's dicts from RegionBundle.__getitem__).
                    restored_store._global = live_region_bundle._global
                    restored_store._universal = live._universal
                    dict.__setitem__(live_region_bundle, region, restored_store)

            LOG.debug("Restored native store: %s", service_name)
            return True
        except Exception:
            LOG.warning(
                "Failed to restore native store %s — skipping",
                service_name, exc_info=True,
            )
            return False

    # ------------------------------------------------------------------
    # Moto backends
    # ------------------------------------------------------------------
    def _load_moto(self, api_dir: str, moto_name: str) -> bool:
        path = os.path.join(api_dir, f"{moto_name}.state")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                restored = dill.load(f)
            svc = moto_name[: -len(".moto")]
            import moto.backends as mb

            bd = mb.get_backend(svc)
            for (acct, rgn), backend in restored.items():
                live = bd[acct][rgn]
                live.__dict__.update(backend.__dict__)
            LOG.debug("Restored moto backend: %s", svc)
            return True
        except Exception:
            LOG.warning(
                "Failed to restore moto backend %s — skipping",
                moto_name, exc_info=True,
            )
            return False

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    def _load_cloudtrail_event_store(self) -> None:
        try:
            from localemu.services.cloudtrail.event_store import get_event_store

            get_event_store().load_from_disk()
        except Exception:
            LOG.warning("Failed to load CloudTrail events", exc_info=True)

    def _load_cloudtrail_native(self, api_dir: str) -> None:
        path = os.path.join(api_dir, "cloudtrail_native.state")
        if not os.path.exists(path):
            return
        try:
            with open(path, "rb") as f:
                state = dill.load(f)
            from localemu.services.cloudtrail import provider as ct_provider

            for key, val in state.items():
                if key == "event_data_stores":
                    ct_provider._event_data_stores = val
                    continue
                try:
                    import localemu.services.cloudtrail.native as native_mod

                    setattr(native_mod, key, val)
                except (ImportError, AttributeError):
                    pass
        except Exception:
            LOG.warning("Failed to load CloudTrail native state", exc_info=True)

    # ------------------------------------------------------------------
    # Assets (S3 bodies, DynamoDB snapshot files)
    # ------------------------------------------------------------------
    def _restore_assets(self, assets_dir: str) -> None:
        self._restore_s3_bodies(assets_dir)
        self._restore_ddb_assets(assets_dir)

    _S3_BODY_STREAM_CHUNK = 4 * 1024 * 1024

    def _restore_s3_bodies(self, assets_dir: str) -> None:
        """Restore S3 object bodies from the streaming layout written by
        :meth:`SaveOrchestrator._save_s3_bodies`.

        The legacy single-file ``s3_bodies.state`` layout (a single dill'd
        ``{bucket: {key: bytes}}`` dict) is still loaded for snapshots
        taken before the OOM fix landed; new snapshots use the per-key
        streaming layout under ``assets_dir/s3_bodies/<bucket>/<key>.body``
        with a sibling ``_index.json``.
        """
        streaming_root = os.path.join(assets_dir, "s3_bodies")
        legacy_path = os.path.join(assets_dir, "s3_bodies.state")

        if os.path.isdir(streaming_root) and os.path.exists(
            os.path.join(streaming_root, "_index.json")
        ):
            self._restore_s3_bodies_streaming(streaming_root)
            return
        if os.path.exists(legacy_path):
            self._restore_s3_bodies_legacy(legacy_path)

    def _restore_s3_bodies_streaming(self, streaming_root: str) -> None:
        try:
            from localemu.services.s3.storage.ephemeral import LockedSpooledTemporaryFile

            with open(os.path.join(streaming_root, "_index.json")) as f:
                index: dict[str, list[str]] = json.load(f)

            backend = _get_s3_backend()
            if backend is None:
                LOG.warning(
                    "S3 bodies persisted but EphemeralS3ObjectStore is not available — skipping"
                )
                return

            total = 0
            for bucket_name, key_list in index.items():
                bucket_tmp_dir = os.path.join(backend.root_directory, bucket_name)
                os.makedirs(bucket_tmp_dir, exist_ok=True)
                bucket_assets = os.path.join(streaming_root, _safe_dirname(bucket_name))
                for key_hash in key_list:
                    body_path = os.path.join(
                        bucket_assets, _safe_filename(key_hash) + ".body"
                    )
                    if not os.path.exists(body_path):
                        LOG.warning(
                            "S3 body file missing on restore: %s/%s",
                            bucket_name, key_hash,
                        )
                        continue
                    spooled = LockedSpooledTemporaryFile(
                        dir=bucket_tmp_dir,
                        max_size=512 * 1024,
                    )
                    with open(body_path, "rb") as src:
                        while True:
                            chunk = src.read(self._S3_BODY_STREAM_CHUNK)
                            if not chunk:
                                break
                            spooled.write(chunk)
                    spooled.seek(0)
                    backend._filesystem[bucket_name]["keys"][key_hash] = spooled
                    total += 1
            LOG.info(
                "Restored S3 bodies: %d buckets, %d objects (streamed)",
                len(index), total,
            )
        except Exception:
            LOG.warning("Failed to restore S3 bodies (streaming)", exc_info=True)

    def _restore_s3_bodies_legacy(self, path: str) -> None:
        try:
            from localemu.services.s3.storage.ephemeral import LockedSpooledTemporaryFile

            with open(path, "rb") as f:
                bodies = dill.load(f)

            backend = _get_s3_backend()
            if backend is None:
                LOG.warning(
                    "S3 bodies persisted but EphemeralS3ObjectStore is not available — skipping"
                )
                return

            total = 0
            for bucket_name, key_bodies in bodies.items():
                bucket_tmp_dir = os.path.join(backend.root_directory, bucket_name)
                os.makedirs(bucket_tmp_dir, exist_ok=True)
                for key_hash, data in key_bodies.items():
                    spooled = LockedSpooledTemporaryFile(
                        dir=bucket_tmp_dir,
                        max_size=512 * 1024,
                    )
                    spooled.write(data)
                    spooled.seek(0)
                    backend._filesystem[bucket_name]["keys"][key_hash] = spooled
                    total += 1
            LOG.info(
                "Restored S3 bodies (legacy single-file layout): %d buckets, %d objects",
                len(bodies), total,
            )
        except Exception:
            LOG.warning("Failed to restore S3 bodies (legacy)", exc_info=True)

    def _restore_ddb_assets(self, assets_dir: str) -> None:
        import shutil

        ddb_dir = os.path.join(assets_dir, "dynamodb")
        if not os.path.isdir(ddb_dir):
            return
        try:
            target = os.path.join(config.dirs.data, "dynamodb")
            os.makedirs(target, exist_ok=True)
            for fn in os.listdir(ddb_dir):
                src = os.path.join(ddb_dir, fn)
                dst = os.path.join(target, fn)
                if os.path.isdir(src):
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
        except Exception:
            LOG.warning("Failed to restore DynamoDB assets", exc_info=True)

    # ------------------------------------------------------------------
    # Version compatibility
    # ------------------------------------------------------------------
    def _versions_compatible(self, saved: str, current: str) -> bool:
        """Same major.minor → compatible. Patch and dev tags are tolerated.

        ``0.1.dev133`` and ``0.1.dev102`` both pass. ``1.2.0`` vs ``1.3.0``
        does not — minor bumps may change moto internals, store schemas, or
        add new services whose load order moves.
        """
        if not saved or not current:
            # Accept empty-vs-empty; reject anything else so callers who
            # write garbage get a hard failure during tests.
            return saved == current

        def _major_minor(v: str) -> str:
            parts = v.split(".")
            return ".".join(parts[:2]) if len(parts) >= 2 else v

        return _major_minor(saved) == _major_minor(current)


# ---------------------------------------------------------------------------
# Lifecycle wiring
# ---------------------------------------------------------------------------
def register_persistence() -> None:
    """Called once at startup via the ``_init_persistence`` on_infra_start
    hook. Wires save/load into the runtime lifecycle."""
    if not config.PERSISTENCE:
        return

    _register_pickle_fixes()

    save_strategy = config.SNAPSHOT_SAVE_STRATEGY or "ON_SHUTDOWN"
    load_strategy = config.SNAPSHOT_LOAD_STRATEGY or "ON_STARTUP"

    # LOAD on startup, before any service serves a request.
    if load_strategy == "ON_STARTUP":
        LoadOrchestrator().load(config.dirs.data)

    # SAVE on shutdown — registered on SHUTDOWN_HANDLERS (on_infra_shutdown
    # priority 0), which runs BEFORE services stop (priority -10). This is
    # load-bearing for S3 object bodies: S3Provider.on_before_stop wipes
    # the ephemeral filesystem, so any save that runs later persists S3
    # metadata whose bodies have been cleared.
    if save_strategy == "ON_SHUTDOWN":
        from localemu.runtime.shutdown import SHUTDOWN_HANDLERS

        SHUTDOWN_HANDLERS.register(
            lambda: SaveOrchestrator().save(config.dirs.data)
        )

    # SAVE on schedule.
    if save_strategy == "SCHEDULED":
        interval = config.SNAPSHOT_FLUSH_INTERVAL or 15
        stop_event = threading.Event()

        def _scheduled_loop():
            while not stop_event.wait(interval):
                try:
                    SaveOrchestrator().save(config.dirs.data)
                except Exception:
                    LOG.warning("Scheduled save failed", exc_info=True)

        t = threading.Thread(
            target=_scheduled_loop, daemon=True, name="persistence-scheduler"
        )
        t.start()

        from localemu.runtime.shutdown import SHUTDOWN_HANDLERS

        # Stop the scheduler AND do a final save on shutdown.
        def _stop_and_save():
            stop_event.set()
            try:
                SaveOrchestrator().save(config.dirs.data)
            except Exception:
                LOG.warning("Final scheduled save failed", exc_info=True)

        SHUTDOWN_HANDLERS.register(_stop_and_save)

    LOG.info(
        "Persistence enabled: save=%s, load=%s, dir=%s, version=%s",
        save_strategy, load_strategy, config.dirs.data, _LOCALEMU_VERSION,
    )


def _register_pickle_fixes() -> None:
    """Register custom dill/pickle reducers for types that fail to round-trip
    through dill's default serialization."""
    import copyreg
    import weakref

    import dill

    # Threading primitives. dill ships ``save_lock`` / ``save_rlock`` in
    # ``dill.Pickler.dispatch`` that preserve *lock state*: if a lock is
    # held at save time, the unpickler raises
    # ``UnpicklingError: Cannot acquire lock`` on restore.
    #
    # This hits us in practice because the SaveOrchestrator holds the
    # AccountRegionBundle's own RLock during ``dill.dump`` to prevent
    # concurrent mutation — and that same RLock is an attribute of the
    # bundle we're pickling.
    #
    # dill's dispatch table entries take precedence over ``copyreg``, so
    # overriding here requires patching ``dill.Pickler.dispatch`` directly.
    # We replace the dill entries with reducers that always reconstruct
    # a fresh unlocked instance. This also makes ``threading.Condition``
    # / ``threading.Event`` / ``threading.Semaphore`` safe to round-trip
    # via dill's default reducers: those wrap an internal Lock / RLock
    # that our reducer rebuilds unlocked, while dill preserves object
    # identity so ``queue.mutex`` / ``queue.not_empty._lock`` / etc. keep
    # referring to the same fresh lock.
    _lock_t = type(threading.Lock())
    _rlock_t = type(threading.RLock())

    def _save_fresh_lock(pickler, obj):
        pickler.save_reduce(threading.Lock, (), obj=obj)

    def _save_fresh_rlock(pickler, obj):
        pickler.save_reduce(threading.RLock, (), obj=obj)

    dill.Pickler.dispatch[_lock_t] = _save_fresh_lock
    dill.Pickler.dispatch[_rlock_t] = _save_fresh_rlock

    # NOTE: do NOT override threading.Condition / threading.Event /
    # threading.Semaphore. ``queue.Queue`` constructs Condition objects
    # that SHARE ``queue.mutex`` (``not_empty``, ``not_full``,
    # ``all_tasks_done`` all wrap the same Lock). If we emit fresh
    # standalone Conditions on restore, the sharing invariant is broken:
    # ``Queue.get()`` acquires ``not_empty._lock`` (a new private lock)
    # and then calls ``self.not_full.notify()`` — which tries to check
    # whether ``not_full._lock`` (a different private lock) is held,
    # raises ``RuntimeError: cannot notify on un-acquired lock``, and
    # turns a ReceiveMessage into a 500 ``InternalError``.
    #
    # dill's default handling pickles a Condition via its wrapped Lock
    # reference; because our Lock/RLock reducers above always yield a
    # fresh unlocked instance, the Condition's internal lock is reset too
    # while object identity between ``queue.mutex`` and ``queue.not_empty
    # ._lock`` is preserved.

    # moto.ssm.ParameterDict subclasses dict but its __init__ requires
    # (account_id, region_name). dill's default dict reducer loses those
    # constructor args. Save them explicitly and replay on restore.
    try:
        from moto.ssm.models import ParameterDict

        def _reduce_pd(obj):
            return (_restore_pd, (type(obj), obj.account_id, obj.region_name, dict(obj)))

        def _restore_pd(cls, account_id, region_name, items):
            pd = cls(account_id, region_name)
            pd.update(items)
            return pd

        copyreg.pickle(ParameterDict, _reduce_pd)
    except ImportError:
        pass

    # WeakValueDictionary entries may vanish between save and restore (the
    # referents are gone). Save as empty; owning containers re-populate on
    # access. dill also crashes on populated WVDs containing KeyedRef
    # objects in some moto versions.
    def _reduce_wvd(obj):
        return (weakref.WeakValueDictionary, ())

    copyreg.pickle(weakref.WeakValueDictionary, _reduce_wvd)

    # joserfc.jwk.RSAKey wraps a cryptography.hazmat Rust-backed
    # RSAPrivateKey which has no pickle protocol. moto's CognitoIdpUserPool
    # instantiates one on construction (``self.json_web_key = jwk.RSAKey
    # .import_key(...)``) from a static resource file shipped with moto, so
    # serialize as PEM bytes and re-import on load. Without this, the
    # cognito-idp moto backend save fails entirely and every pool + user
    # is lost across restart.
    try:
        from joserfc import jwk as _jwk

        def _reduce_rsakey(obj):
            return (_restore_rsakey, (obj.as_pem(private=True),))

        def _restore_rsakey(pem: bytes):
            return _jwk.RSAKey.import_key(pem)

        copyreg.pickle(_jwk.RSAKey, _reduce_rsakey)
    except ImportError:
        pass


# NOTE: the REST API for /_localemu/state/{save,load,status} lives in
# ``localemu.dashboard.plugins._register_persistence_endpoints`` because that
# is where the route registration is actually wired into the gateway. Keep
# this module focused on the SaveOrchestrator / LoadOrchestrator engines.
