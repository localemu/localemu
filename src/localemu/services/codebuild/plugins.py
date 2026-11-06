"""Plux hook: applies the CodeBuild ``UpdateProject`` patch at infra start."""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def apply_codebuild_patches() -> None:
    try:
        from localemu.services.codebuild.patches import apply_codebuild_patches

        apply_codebuild_patches()
    except Exception:
        LOG.error("Failed to apply CodeBuild UpdateProject patch", exc_info=True)


__all__ = ["apply_codebuild_patches"]
