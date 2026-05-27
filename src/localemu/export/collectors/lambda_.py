"""Lambda collector: enumerate functions (latest version) from LocalEmu.

Code archives are stored in an internal S3 bucket keyed by a sha256
content address. We compute the sha256 ourselves (rather than trust the
one on the config, which in hot-reloading mode is a placeholder), download
the zip bytes into a sidecar, and surface only a descriptor in the IR.

Only ``$LATEST`` is exported in v1. Aliases and numeric versions round-trip
once the snapshot format grows a story for multi-version functions.
"""

from __future__ import annotations

import hashlib
import io
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


@register_collector("lambda")
class LambdaCollector(BaseCollector):
    """Collect Lambda functions (``$LATEST`` only) for a (account, region)."""

    service = "lambda"

    def __init__(self) -> None:
        # Sidecar files produced during ``collect``. The orchestrator reads
        # this after each invocation and merges into ``Snapshot.sidecar_files``.
        # Exposing it as an attribute (rather than returning a tuple) keeps
        # ``BaseCollector.collect`` single-purpose.
        self.sidecar_files: dict[str, bytes] = {}

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        self.sidecar_files = {}
        try:
            from localemu.services.lambda_.invocation.models import lambda_stores
        except Exception:  # pragma: no cover
            LOG.warning("Failed to import lambda_stores; skipping Lambda", exc_info=True)
            return []

        try:
            store = lambda_stores[account_id][region]
        except Exception:
            LOG.warning(
                "No Lambda store for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        resources: list[Resource] = []
        functions = getattr(store, "functions", {}) or {}
        for fn_name, fn in dict(functions).items():
            try:
                resources.append(
                    self._build_function_resource(fn_name, fn, account_id, region)
                )
                # Resource-based policy statements live in ``fn.permissions``
                # (a dict keyed by ``$LATEST`` / version / alias) — NOT in
                # ``fn.policy`` as an earlier version of this collector
                # assumed. Each value is a :class:`FunctionResourcePolicy`
                # wrapping a :class:`ResourcePolicy` whose ``Statement`` is
                # the list of permission statements emitted by
                # ``add_permission``.
                permissions = getattr(fn, "permissions", {}) or {}
                for qualifier, perm in dict(permissions).items():
                    statements = []
                    policy = getattr(perm, "policy", perm)
                    if policy is not None:
                        statements = (
                            getattr(policy, "Statement", None)
                            or getattr(policy, "statements", None)
                            or (policy.get("Statement") if isinstance(policy, dict) else None)
                            or []
                        )
                    for stmt in statements or []:
                        try:
                            resources.append(
                                self._build_permission(stmt, fn_name, account_id, region)
                            )
                        except Exception:
                            LOG.warning("Skipping permission on %s", fn_name, exc_info=True)
                # Aliases — each entry is a :class:`VersionAlias` with
                # ``name`` + ``function_version`` (+ optional description).
                aliases = getattr(fn, "aliases", {}) or {}
                for alias_name, alias in dict(aliases).items():
                    try:
                        resources.append(
                            self._build_alias(alias, alias_name, fn_name, account_id, region)
                        )
                    except Exception:
                        LOG.warning(
                            "Skipping alias %s on %s", alias_name, fn_name, exc_info=True,
                        )
            except Exception:
                LOG.warning(
                    "Failed to serialize Lambda function %r; skipping",
                    fn_name,
                    exc_info=True,
                )

        # Event source mappings (separate from functions in moto)
        try:
            import moto.backends as moto_backends
            moto_lam = moto_backends.get_backend("lambda")[account_id][region]
            esms = getattr(moto_lam, "_event_source_mappings", {}) or {}
            for uuid_key, esm in dict(esms).items():
                try:
                    resources.append(
                        self._build_esm(esm, uuid_key, account_id, region)
                    )
                except Exception:
                    LOG.warning("Skipping ESM %s", uuid_key, exc_info=True)
        except Exception:
            pass  # moto unavailable; ESMs simply not exported

        # Layers
        try:
            import moto.backends as moto_backends
            moto_lam = moto_backends.get_backend("lambda")[account_id][region]
            layer_store = getattr(moto_lam, "_layers", None)
            if layer_store:
                for layer_name in (layer_store.list_layers() or []):
                    name = getattr(layer_name, "name", None) or str(layer_name)
                    versions = layer_store.get_layer_versions(name) or []
                    if versions:
                        latest_ver = versions[-1]
                        try:
                            resources.append(
                                self._build_layer(latest_ver, name, account_id, region)
                            )
                        except Exception:
                            LOG.warning("Skipping layer %s", name, exc_info=True)
        except Exception:
            pass

        return resources

    def _build_permission(
        self, stmt: Any, fn_name: str, account_id: str, region: str
    ) -> Resource:
        """Build a ``lambda.permission`` resource from a policy statement."""
        if isinstance(stmt, dict):
            sid = stmt.get("Sid") or stmt.get("sid") or "AllowInvoke"
            action = stmt.get("Action") or "lambda:InvokeFunction"
            principal = stmt.get("Principal") or {}
            source_arn = stmt.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
        else:
            sid = getattr(stmt, "sid", None) or getattr(stmt, "Sid", "AllowInvoke")
            action = getattr(stmt, "action", "lambda:InvokeFunction")
            principal = getattr(stmt, "principal", {})
            source_arn = getattr(stmt, "source_arn", None)

        if isinstance(principal, dict):
            principal_value = principal.get("Service") or principal.get("AWS") or "*"
        else:
            principal_value = str(principal)

        attrs: dict[str, Any] = {
            "statement_id": sid,
            "action": action,
            "function_name": Ref("lambda", "function", fn_name, attribute="arn"),
            "principal": principal_value,
        }
        if source_arn:
            attrs["source_arn"] = source_arn
        return Resource(
            service="lambda", resource_type="permission",
            resource_id=f"{fn_name}/{sid}",
            account_id=account_id, region=region, attributes=attrs,
        )

    def _build_alias(
        self, alias: Any, alias_name: str, fn_name: str,
        account_id: str, region: str,
    ) -> Resource:
        """Build an ``aws_lambda_alias`` / ``AWS::Lambda::Alias`` resource."""
        name = getattr(alias, "name", None) or alias_name
        attrs: dict[str, Any] = {
            "name": name,
            "function_name": Ref("lambda", "function", fn_name, attribute="arn"),
            "function_version": getattr(alias, "function_version", "$LATEST"),
            "description": getattr(alias, "description", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="lambda", resource_type="alias",
            resource_id=f"{fn_name}/{name}",
            account_id=account_id, region=region, attributes=attrs,
        )

    def _build_esm(
        self, esm: Any, uuid_key: str, account_id: str, region: str
    ) -> Resource:
        """Build a ``lambda.event_source_mapping`` resource."""
        attrs: dict[str, Any] = {
            "uuid": uuid_key,
            "event_source_arn": getattr(esm, "event_source_arn", None),
            "function_name": getattr(esm, "function_arn", None) or getattr(esm, "function_name", None),
            "batch_size": getattr(esm, "batch_size", None),
            "enabled": getattr(esm, "enabled", True),
            "starting_position": getattr(esm, "starting_position", None),
        }
        fn_arn = attrs.get("function_name")
        if isinstance(fn_arn, str) and ":" in fn_arn:
            fn_name = fn_arn.rsplit(":", 1)[-1]
            attrs["function_name"] = Ref("lambda", "function", fn_name, attribute="arn")
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="lambda", resource_type="event_source_mapping",
            resource_id=uuid_key, account_id=account_id,
            region=region, attributes=attrs,
        )

    def _build_layer(
        self, ver: Any, name: str, account_id: str, region: str
    ) -> Resource:
        """Build a ``lambda.layer_version`` resource (latest version only)."""
        runtimes = list(getattr(ver, "compatible_runtimes", []) or [])
        attrs: dict[str, Any] = {
            "layer_name": name,
            "arn": getattr(ver, "arn", None),
            "compatible_runtimes": runtimes,
            "description": getattr(ver, "description", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="lambda", resource_type="layer_version",
            resource_id=name, account_id=account_id,
            region=region, attributes=attrs,
        )

    # ------------------------------------------------------------------

    def _build_function_resource(
        self, fn_name: str, fn: Any, account_id: str, region: str
    ) -> Resource:
        latest = fn.latest()
        config = latest.config

        role_arn = getattr(config, "role", None) or ""
        role_ref = _role_ref_from_arn(role_arn, account_id)

        # ``config.environment`` on moto is a flat ``{var: value}`` map of
        # the user-supplied env vars. Both AWS APIs and downstream
        # writers (Terraform, CloudFormation) expect it nested under the
        # ``variables`` key — emitting the flat dict caused the writer to
        # silently drop every env var (and every secret slot derived from
        # them). Always normalise to ``{"variables": {...}}``.
        raw_env = getattr(config, "environment", None) or {}
        if not isinstance(raw_env, dict):
            raw_env = {}
        env = {"variables": dict(raw_env)}

        # If the function has any aliases or any non-$LATEST published
        # versions on LocalEmu, the user is using Lambda versioning. The
        # exported Terraform must set ``publish = true`` so each apply
        # creates a numbered version — otherwise downstream
        # ``aws_lambda_alias`` resources that point at version ``"1"``
        # fail to create with "Function not found".
        has_aliases = bool(getattr(fn, "aliases", {}) or {})
        versions = getattr(fn, "versions", {}) or {}
        has_published = any(
            v != "$LATEST" for v in versions
        )

        attrs: dict[str, Any] = {
            "function_name": fn_name,
            "runtime": _strify(getattr(config, "runtime", None)),
            "handler": getattr(config, "handler", None),
            "memory_size": getattr(config, "memory_size", None),
            "timeout": getattr(config, "timeout", None),
            "description": getattr(config, "description", None),
            "role": role_ref if role_ref is not None else role_arn,
            "environment": dict(env),
            "architectures": [
                _strify(a) for a in getattr(config, "architectures", []) or []
            ],
            "package_type": _strify(getattr(config, "package_type", None)),
            "publish": True if (has_aliases or has_published) else None,
        }

        vpc_cfg = getattr(config, "vpc_config", None)
        if vpc_cfg is not None:
            attrs["vpc_config"] = {
                "vpc_id": getattr(vpc_cfg, "vpc_id", None),
                "security_group_ids": list(
                    getattr(vpc_cfg, "security_group_ids", []) or []
                ),
                "subnet_ids": list(getattr(vpc_cfg, "subnet_ids", []) or []),
            }

        dla = getattr(config, "dead_letter_arn", None)
        if dla:
            attrs["dead_letter_config"] = {"target_arn": dla}

        tracing_mode = _strify(getattr(config, "tracing_config_mode", None))
        if tracing_mode:
            attrs["tracing_config"] = {"mode": tracing_mode}

        attrs["layers"] = _layers_to_refs(
            getattr(config, "layers", []) or [], account_id
        )

        image = getattr(config, "image", None)
        if image is not None:
            attrs["image"] = {
                "image_uri": getattr(image, "image_uri", None),
                "code_sha256": getattr(image, "code_sha256", None),
                "repository_type": getattr(image, "repository_type", None),
            }

        code_descriptor = self._code_descriptor(
            fn_name, getattr(config, "code", None)
        )
        if code_descriptor is not None:
            attrs["code"] = code_descriptor

        # Tags: in LocalEmu's lambda store, tags are keyed by ARN under
        # ``store.tags``. We don't have easy access to the store here, so
        # tags are currently pulled from the function object if available.
        tags = _extract_tags(fn)

        last_modified = getattr(config, "last_modified", None)

        return Resource(
            service="lambda",
            resource_type="function",
            resource_id=fn_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
            created_at=last_modified if isinstance(last_modified, str) else None,
        )

    def _code_descriptor(self, fn_name: str, code: Any) -> dict[str, Any] | None:
        """Return the descriptor dict for the function's code artifact.

        For S3-backed zip code we download the zip bytes into the sidecar
        map. For hot-reloading code we emit a pointer only — the user's
        host path won't survive on another machine.
        """
        if code is None:
            return None

        cls_name = type(code).__name__

        if cls_name == "HotReloadingCode":
            return {
                "type": "hot_reload",
                "host_path": getattr(code, "host_path", None),
                "sha256": getattr(code, "code_sha256", None),
                "size": getattr(code, "code_size", 0),
            }

        if cls_name == "ImageCode":
            # ImageCode has no zip; ``image`` attribute covers it.
            return {
                "type": "image",
                "image_uri": getattr(code, "image_uri", None),
                "sha256": getattr(code, "code_sha256", None),
            }

        # Default path: S3Code. Download the archive, hash it, stash bytes.
        try:
            zip_bytes = _download_s3_code(code)
        except Exception:
            LOG.warning(
                "Failed to fetch code archive for Lambda %r; emitting descriptor "
                "without bytes",
                fn_name,
                exc_info=True,
            )
            return {
                "type": "zip",
                "sha256": getattr(code, "code_sha256", None),
                "size": getattr(code, "code_size", 0),
                "fetch_failed": True,
            }

        sha256 = hashlib.sha256(zip_bytes).hexdigest()
        sidecar_path = f"lambda/{fn_name}/{sha256}.zip"
        self.sidecar_files[sidecar_path] = zip_bytes
        return {
            "type": "zip",
            "sha256": sha256,
            "size": len(zip_bytes),
            "sidecar_path": sidecar_path,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _role_ref_from_arn(arn: str, account_id: str) -> Ref | None:
    """Produce a Ref for a role ARN *only* if it belongs to this account.

    Cross-account roles are left as raw ARNs — we can't invent a resource
    for them.
    """
    if not arn or ":role/" not in arn:
        return None
    # arn:aws:iam::123456789012:role/name
    parts = arn.split(":")
    if len(parts) < 6:
        return None
    arn_account = parts[4]
    if arn_account and arn_account != account_id:
        return None
    role_name = arn.split(":role/", 1)[1]
    return Ref(service="iam", resource_type="role", resource_id=role_name)


def _layers_to_refs(layers: list[Any], account_id: str) -> list[Any]:
    """Convert ``LayerVersion`` objects to refs (same account) or ARN strings."""
    out: list[Any] = []
    for layer in layers:
        if isinstance(layer, str):
            arn = layer
        else:
            arn = (
                getattr(layer, "layer_version_arn", None)
                or getattr(layer, "arn", None)
                or ""
            )
        if not arn:
            continue
        # arn:aws:lambda:REGION:ACCT:layer:NAME:VERSION
        parts = arn.split(":")
        if len(parts) >= 7 and parts[4] == account_id and parts[5] == "layer":
            layer_name = parts[6]
            out.append(
                Ref(service="lambda", resource_type="layer", resource_id=layer_name)
            )
        else:
            out.append(arn)
    return out


def _download_s3_code(code: Any) -> bytes:
    """Pull the zipped code archive out of LocalEmu's internal S3 bucket.

    We re-use the private ``_download_archive_to_file`` helper that the
    code object itself uses for execution — avoids duplicating the S3
    plumbing and guarantees we read the same bytes the runtime does.
    """
    downloader = getattr(code, "_download_archive_to_file", None)
    if not callable(downloader):
        raise RuntimeError(
            f"Code object {type(code).__name__} has no archive downloader"
        )
    buf = io.BytesIO()
    downloader(buf)
    buf.seek(0)
    return buf.read()


def _extract_tags(fn: Any) -> dict[str, str]:
    tags = getattr(fn, "tags", None)
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {}


def _strify(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    # StrEnum / Enum-ish objects
    inner = getattr(value, "value", None)
    if isinstance(inner, str):
        return inner
    return str(value)
