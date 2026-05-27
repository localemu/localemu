"""Intermediate representation (IR) for exported infrastructure.

The IR is deliberately format-agnostic: collectors produce :class:`Resource`
objects, the orchestrator assembles a :class:`Snapshot`, and downstream
writers (Terraform/CloudFormation/etc.) consume the snapshot. :class:`Ref`
models a symbolic reference from one resource to another; the reference
resolver (:mod:`localemu.export.references`) substitutes raw ARN / ID
strings with ``Ref`` instances so writers can emit proper inter-resource
links rather than hard-coded strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Ref:
    """Symbolic reference to another resource in the snapshot.

    Attributes:
        service: AWS service name (e.g. ``"iam"``, ``"s3"``).
        resource_type: Type within the service (e.g. ``"role"``, ``"bucket"``).
        resource_id: Logical identifier (name / id) of the target resource.
        attribute: Which attribute of the target to resolve to at render
            time. Defaults to ``"arn"`` because that is by far the most
            common cross-resource reference in AWS.
    """

    service: str
    resource_type: str
    resource_id: str
    attribute: str = "arn"


@dataclass
class Resource:
    """A single exported resource.

    ``attributes`` holds the service-specific properties (for a Lambda
    function: ``handler``, ``runtime``, ``environment``, ...). ``tags`` is
    broken out because nearly every AWS resource has tags and writers want
    uniform access. ``created_at`` is an ISO 8601 string or ``None``.
    """

    service: str
    resource_type: str
    resource_id: str
    account_id: str
    region: str
    attributes: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    created_at: str | None = None


@dataclass
class Snapshot:
    """Top-level export artifact.

    Attributes:
        schema_version: Snapshot schema version (matches package-level
            ``SCHEMA_VERSION``).
        exported_at: ISO 8601 timestamp of when the export ran.
        localemu_version: Version of LocalEmu that produced the snapshot.
        resources: All collected resources.
        redacted_secrets: Dotted paths (``"<logical_id>.attributes.env.X"``)
            that were replaced by the redaction pass. Empty if
            ``include_secrets=True`` was passed to the exporter.
        export_warnings: Human-readable warnings collected during export
            (timeouts, partial failures, detected reference cycles, ...).
        sidecar_files: Logical-path -> bytes map for out-of-band payloads
            (e.g. S3 object bodies, Lambda zips) that should be written
            alongside the main snapshot file.
    """

    schema_version: str
    exported_at: str
    localemu_version: str
    resources: list[Resource] = field(default_factory=list)
    redacted_secrets: list[str] = field(default_factory=list)
    export_warnings: list[str] = field(default_factory=list)
    sidecar_files: dict[str, bytes] = field(default_factory=dict)


_LOGICAL_ID_SANITIZE = re.compile(r"[^A-Za-z0-9]+")


def resource_logical_id(resource: Resource) -> str:
    """Return a stable, writer-friendly logical ID for ``resource``.

    The result is usable as a Terraform local name and a CloudFormation
    logical ID: alphanumeric-plus-underscore, starts with a letter. The
    format is ``<service>_<resource_type>_<sanitized_resource_id>``; e.g.
    an IAM role named ``my-role`` becomes ``iam_role_my_role``.
    """
    sanitized = _LOGICAL_ID_SANITIZE.sub("_", resource.resource_id).strip("_")
    if not sanitized:
        sanitized = "unnamed"
    # CloudFormation logical IDs must start with a letter. ``service`` is
    # always a lowercase AWS service name, so this is safe.
    return f"{resource.service}_{resource.resource_type}_{sanitized}".lower()
