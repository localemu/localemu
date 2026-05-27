"""Real-AWS export pipeline.

This package implements the seven-phase export pipeline that turns running
LocalEmu state into Terraform / CloudFormation that ``terraform apply`` or
``aws cloudformation deploy`` can run successfully against a real AWS
account, with no manual editing.

The pipeline is intentionally separate from the legacy ``localemu`` /
``aws`` writer targets in :mod:`localemu.export.formats`. The legacy
writers are kept for round-trip imports back into LocalEmu; this package
is the path that meets the user's "deploy to real AWS unedited"
requirement.

Phases (each implemented in its own module):

1. Preflight   — :mod:`localemu.export.realaws.preflight`
2. Discovery   — :func:`localemu.export.realaws.exporter.discover`
3. Translation — reuses :mod:`localemu.export.formats.tf_specs` /
                 :mod:`localemu.export.formats.cfn_specs`
4. Rewrite     — :mod:`localemu.export.realaws.rewrite`
5. Lambda code — :mod:`localemu.export.realaws.lambda_code`
6. Secrets     — :mod:`localemu.export.realaws.secrets`
7. Verify      — :mod:`localemu.export.realaws.verify`

The orchestrator that wires them together is
:class:`localemu.export.realaws.exporter.RealAwsExporter`.
"""

from __future__ import annotations

from localemu.export.realaws.exporter import (
    RealAwsExportError,
    RealAwsExporter,
    RealAwsExportResult,
)

__all__ = [
    "RealAwsExportError",
    "RealAwsExporter",
    "RealAwsExportResult",
]
