"""CodeBuild ``UpdateProject`` support.

Moto's CodeBuild backend has no ``update_project`` method at all (not a
stub, absent entirely - confirmed by reading
``moto/codebuild/{models,responses}.py``), so blue-team fixes that
disable ``privilegedMode`` or move secrets to ``SECRETS_MANAGER`` have
nothing to call: real AWS's ``UpdateProject`` accepts the same optional
fields as ``CreateProject``, merged onto the existing project.
"""

from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger(__name__)

_UPDATABLE_FIELDS = (
    "description",
    "source",
    "secondarySources",
    "sourceVersion",
    "secondarySourceVersions",
    "artifacts",
    "secondaryArtifacts",
    "cache",
    "environment",
    "serviceRole",
    "timeoutInMinutes",
    "queuedTimeoutInMinutes",
    "encryptionKey",
    "tags",
    "vpcConfig",
    "badgeEnabled",
    "logsConfig",
    "fileSystemLocations",
    "buildBatchConfig",
    "concurrentBuildLimit",
)


def apply_codebuild_patches() -> None:
    from moto.codebuild.models import CodeBuild, CodeBuildBackend
    from moto.codebuild.responses import CodeBuildResponse
    from moto.utilities.utils import get_partition

    def _update_project(
        self: CodeBuildBackend, project_name: str, **updates: Any
    ) -> dict[str, Any]:
        from moto.codebuild.exceptions import ResourceNotFoundException

        project: CodeBuild | None = self.codebuild_projects.get(project_name)
        if project is None:
            raise ResourceNotFoundException(
                f"Project cannot be found: arn:{get_partition(self.region_name)}:"
                f"codebuild:{self.region_name}:{self.account_id}:project/{project_name}"
            )
        for field in _UPDATABLE_FIELDS:
            value = updates.get(field)
            if value is None:
                continue
            if field == "serviceRole":
                project.service_role = value
                if value.startswith("arn:"):
                    project.project_metadata["serviceRole"] = value
                else:
                    project.project_metadata["serviceRole"] = (
                        f"arn:{get_partition(self.region_name)}:iam::{self.account_id}:"
                        f"role/service-role/{value}"
                    )
            elif field == "tags":
                project.tags = value
                project.project_metadata["tags"] = value
            else:
                project.project_metadata[field] = value
        import time as _time

        project.project_metadata["lastModifiedDate"] = _time.time()
        return project.project_metadata

    def _update_project_response(self: CodeBuildResponse) -> str:
        import json

        kwargs = {
            field: self._get_param(field)
            for field in _UPDATABLE_FIELDS
            if self._get_param(field) is not None
        }
        project_metadata = self.codebuild_backend.update_project(
            self._get_param("name"), **kwargs
        )
        return json.dumps({"project": project_metadata})

    CodeBuildBackend.update_project = _update_project
    CodeBuildResponse.update_project = _update_project_response
    LOG.info("CodeBuild UpdateProject patch applied.")
