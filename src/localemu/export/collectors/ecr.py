"""ECR collector: repositories + lifecycle policies."""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Resource

LOG = logging.getLogger(__name__)


@register_collector("ecr")
class EcrCollector(BaseCollector):
    service = "ecr"

    def collect(self, account_id: str, region: str, include_data: bool) -> list[Resource]:
        try:
            import moto.backends as moto_backends
            backend = moto_backends.get_backend("ecr")[account_id][region]
        except Exception:
            LOG.warning("ECR backend unavailable", exc_info=True)
            return []

        out: list[Resource] = []
        repos = getattr(backend, "repositories", {}) or {}
        for repo_name, repo in dict(repos).items():
            try:
                attrs: dict[str, Any] = {
                    "name": repo_name,
                    "arn": getattr(repo, "arn", None),
                    "image_tag_mutability": getattr(repo, "image_tag_mutability", "MUTABLE"),
                    "image_scanning_configuration": {
                        "scan_on_push": bool(getattr(repo, "image_scan_on_push", False)),
                    },
                }
                encryption = getattr(repo, "encryption_configuration", None)
                if encryption:
                    attrs["encryption_configuration"] = (
                        encryption if isinstance(encryption, dict)
                        else {"encryption_type": "AES256"}
                    )
                policy = getattr(repo, "policy", None)
                if policy:
                    attrs["repository_policy"] = (
                        json.loads(policy) if isinstance(policy, str) else policy
                    )
                lifecycle = getattr(repo, "lifecycle_policy", None)
                if lifecycle:
                    attrs["lifecycle_policy"] = (
                        lifecycle if isinstance(lifecycle, str) else json.dumps(lifecycle)
                    )
                tags = _tags(repo)
                out.append(Resource(
                    service="ecr", resource_type="repository",
                    resource_id=repo_name, account_id=account_id,
                    region=region, attributes=attrs, tags=tags,
                ))
            except Exception:
                LOG.warning("Skipping ECR repo %r", repo_name, exc_info=True)
        return out


def _tags(obj: Any) -> dict[str, str]:
    raw = getattr(obj, "tags", None)
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return {str(t.get("Key", "")): str(t.get("Value", "")) for t in raw if isinstance(t, dict) and "Key" in t}
    return {}
