"""Plux hook: applies the SageMaker notebook-instance ``OnStart``
lifecycle-script patch at infra start."""

from __future__ import annotations

import logging

from localemu.runtime import hooks

LOG = logging.getLogger(__name__)


@hooks.on_infra_start()
def apply_sagemaker_patches() -> None:
    try:
        from localemu.services.sagemaker.patches import apply_sagemaker_patches

        apply_sagemaker_patches()
    except Exception:
        LOG.error("Failed to apply SageMaker lifecycle-script patch", exc_info=True)


__all__ = ["apply_sagemaker_patches"]
