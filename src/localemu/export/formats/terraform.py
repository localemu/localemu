"""Terraform writer: snapshot → ``main.tf`` + ``providers.tf`` + sidecars.

The writer walks a :class:`~localemu.export.ir.Snapshot`, translates
each resource via :mod:`localemu.export.formats.tf_specs`, and writes
the result as a directory tree (not a single file) so Lambda zips,
README, and provider configuration live next to the HCL:

.. code-block:: text

    <output>/
      main.tf
      providers.tf
      README.md
      lambda/<function>.zip

Name sanitization and collision handling happen up front so that
:class:`~localemu.export.ir.Ref` resolution can target the final,
stable Terraform address for every resource.

Unsupported resource types (no :class:`~localemu.export.formats.tf_specs.TfSpec`
entry) are preserved as a ``# Unsupported resources:`` comment block at
the end of ``main.tf``. Silently dropping them was a v1 footgun — users
could not tell whether an omission was intentional or a bug.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from localemu.export.formats._providers_tf import (
    build_providers_block,
    provider_alias_for_region,
)
from localemu.export.formats.hcl_serializer import HclRaw, HclSerializer
from localemu.export.formats.tf_specs import get_tf_spec, translate
from localemu.export.ir import Ref, Resource, Snapshot

# Allowed Terraform logical name: lowercase identifier. We normalize to
# this stricter charset to make generated names uniform and easy to read.
_SAFE_NAME_CLEAN = re.compile(r"[^a-z0-9_]+")


def safe_tf_name(resource_id: str) -> str:
    """Sanitize ``resource_id`` into a valid lowercase Terraform name.

    * Lowercases the input.
    * Replaces any non-``[a-z0-9_]`` run with a single underscore.
    * Prepends an underscore if the result would start with a digit
      (Terraform requires names to start with a letter or underscore).
    * Falls back to ``"r"`` if sanitization leaves an empty string.

    Collision handling is the caller's responsibility; see
    :meth:`TerraformWriter._assign_logical_names`.
    """
    cleaned = _SAFE_NAME_CLEAN.sub("_", resource_id.lower()).strip("_")
    if not cleaned:
        cleaned = "r"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


class TerraformWriter:
    """Write a :class:`Snapshot` as a Terraform configuration directory."""

    def __init__(self) -> None:
        """Create a writer.

        Stateless — each :meth:`write` call is independent.
        """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, snapshot: Snapshot, output: Path, target: str = "localemu") -> Path:
        """Write ``snapshot`` to the directory ``output``.

        Args:
            snapshot: Resolved snapshot (with :class:`Ref` substitutions
                already applied — the writer does not re-run reference
                resolution).
            output: Destination directory; created if missing.
            target: ``"localemu"`` (default) emits provider endpoints
                pointing at ``localhost:4566`` and test credentials.
                ``"aws"`` emits a minimal provider that resolves
                credentials via the standard AWS credential chain.

        Returns:
            The ``output`` path (for chaining).
        """
        if target not in ("localemu", "aws"):
            raise ValueError(f"unknown target: {target!r}")

        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)

        # 1) Assign a stable, collision-free logical name to every
        #    resource up front so ref resolution can address them.
        logical_names = self._assign_logical_names(snapshot.resources)

        # 2) Pre-compute the default region (first region encountered).
        regions = self._ordered_regions(snapshot.resources)
        default_region = regions[0] if regions else "us-east-1"

        # 3) Build the ref resolver bound to our logical-name table.
        def resolve_ref(ref: Ref) -> str:
            key = (ref.service, ref.resource_type, ref.resource_id)
            entry = logical_names.get(key)
            if entry is None:
                # Unknown target — fall back to a synthesized name.
                # The Terraform plan will fail loudly, which is the
                # right behavior for a genuinely missing reference.
                safe = safe_tf_name(ref.resource_id)
                return f"aws_{ref.service}_{ref.resource_type}.{safe}.{ref.attribute}"
            tf_type, logical = entry
            return f"{tf_type}.{logical}.{ref.attribute}"

        serializer = HclSerializer(ref_resolver=resolve_ref)

        # 4) Translate resources and collect sidecar files.
        supported: dict[str, dict[str, dict[str, Any]]] = {}
        unsupported: list[Resource] = []
        sidecars: dict[str, bytes] = dict(snapshot.sidecar_files)

        for resource in snapshot.resources:
            spec = get_tf_spec(resource.service, resource.resource_type)
            if spec is None:
                unsupported.append(resource)
                continue

            ctx: dict[str, Any] = {}
            if resource.service == "lambda" and resource.resource_type == "function":
                sidecar_path = self._lambda_sidecar_path(resource, sidecars)
                if sidecar_path is not None:
                    ctx["sidecar_zip"] = sidecar_path

            attrs = translate(resource, ctx)
            if attrs is None:
                unsupported.append(resource)
                continue

            # Tag with provider alias for non-default regions. The
            # provider attribute is a bare identifier (``aws.alias``),
            # not a quoted string, so we emit it via ``HclRaw``.
            alias = provider_alias_for_region(resource.region, default_region)
            if alias is not None:
                attrs["provider"] = HclRaw(alias)

            # Emit companion resources (e.g. S3 versioning).
            if spec.extra_resources is not None:
                extras = spec.extra_resources(resource, attrs)
                for (extra_type, extra_name), extra_attrs in extras.items():
                    supported.setdefault(extra_type, {})[safe_tf_name(extra_name)] = extra_attrs

            tf_type, logical = logical_names[
                (resource.service, resource.resource_type, resource.resource_id)
            ]
            supported.setdefault(tf_type, {})[logical] = attrs

        # 5) Serialize and write files.
        main_tf = serializer.serialize(supported)
        if unsupported:
            main_tf += "\n" + self._format_unsupported_block(unsupported)

        (output / "main.tf").write_text(main_tf, encoding="utf-8")
        (output / "providers.tf").write_text(
            build_providers_block(regions, target=target), encoding="utf-8"
        )

        for rel_path, payload in sidecars.items():
            dest = output / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)

        (output / "README.md").write_text(self._readme(target, regions), encoding="utf-8")

        return output

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ordered_regions(resources: list[Resource]) -> list[str]:
        """Return unique regions in first-seen order (empty strings dropped)."""
        seen: dict[str, None] = {}
        for r in resources:
            if r.region and r.region not in seen:
                seen[r.region] = None
        return list(seen)

    @staticmethod
    def _assign_logical_names(
        resources: list[Resource],
    ) -> dict[tuple[str, str, str], tuple[str, str]]:
        """Assign unique Terraform logical names keyed per TF resource type.

        Collisions happen when two resources sanitize to the same name
        (e.g. ``my-bucket`` and ``my_bucket``). We resolve them by
        suffixing ``_1``, ``_2``, ... in the order resources appear.

        Returns:
            Mapping of ``(service, resource_type, resource_id)`` →
            ``(tf_type, logical_name)``. Resources whose type has no
            :class:`~localemu.export.formats.tf_specs.TfSpec` are
            skipped — they end up in the unsupported block.
        """
        out: dict[tuple[str, str, str], tuple[str, str]] = {}
        used_per_type: dict[str, set[str]] = {}

        for r in resources:
            spec = get_tf_spec(r.service, r.resource_type)
            if spec is None:
                continue
            tf_type = spec.resource_type
            base = safe_tf_name(r.resource_id)
            used = used_per_type.setdefault(tf_type, set())

            candidate = base
            suffix = 1
            while candidate in used:
                suffix += 1
                candidate = f"{base}_{suffix}"
            used.add(candidate)

            out[(r.service, r.resource_type, r.resource_id)] = (tf_type, candidate)
        return out

    @staticmethod
    def _lambda_sidecar_path(resource: Resource, sidecars: dict[str, bytes]) -> str | None:
        """Return the sidecar zip path for a Lambda, materializing if needed.

        If the snapshot already includes a zip under ``lambda/<name>.zip``
        we reuse it. Otherwise we look for raw bytes on the resource
        under ``code_zip`` / ``zip_bytes`` and register them. Returns
        ``None`` if we have no payload — the builder will then omit the
        filename argument and the user must edit ``main.tf`` before
        ``terraform apply``.
        """
        safe = safe_tf_name(resource.resource_id)
        expected = f"lambda/{safe}.zip"
        if expected in sidecars:
            return expected

        payload = resource.attributes.get("code_zip") or resource.attributes.get("zip_bytes")
        if isinstance(payload, (bytes, bytearray)):
            sidecars[expected] = bytes(payload)
            return expected
        return None

    @staticmethod
    def _format_unsupported_block(unsupported: list[Resource]) -> str:
        """Render a human-readable comment describing skipped resources."""
        lines = [
            "# Unsupported resources:",
            "# The following resources exist in the exported snapshot but have no",
            "# Terraform spec in LocalEmu's writer. Review and translate manually,",
            "# or open an issue so we can add support.",
        ]
        for r in unsupported:
            lines.append(f"#   - {r.service}.{r.resource_type} {r.resource_id} (region={r.region})")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _readme(target: str, regions: list[str]) -> str:
        """Generate the export's README describing how to apply the config."""
        region_list = ", ".join(regions) if regions else "us-east-1"
        if target == "localemu":
            deploy = (
                "This export targets LocalEmu. Providers are preconfigured with\n"
                "`http://localhost:4566` endpoints and test credentials. Run:\n\n"
                "```\n"
                "terraform init\n"
                "terraform apply\n"
                "```\n\n"
                "Ensure LocalEmu is running locally before applying.\n"
            )
        else:
            deploy = (
                "This export targets real AWS. Providers use the default\n"
                "credential chain (env vars, shared config, instance role).\n"
                "Review `main.tf` for any placeholder values before applying:\n\n"
                "```\n"
                "terraform init\n"
                "terraform plan\n"
                "terraform apply\n"
                "```\n"
            )
        return (
            "# LocalEmu Terraform Export\n\n"
            f"**Target:** `{target}`\n"
            f"**Regions:** {region_list}\n\n"
            "## Files\n\n"
            "- `main.tf` — resource definitions\n"
            "- `providers.tf` — provider configuration\n"
            "- `lambda/*.zip` — Lambda function code bundles\n\n"
            "## Deploying\n\n" + deploy
        )


