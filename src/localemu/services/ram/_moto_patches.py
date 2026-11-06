"""Moto patches for RAM gaps.

Moto's RAM backend has ``CreateResourceShare`` (which accepts principals and
resource ARNs inline via ``ResourceShare.add_principals``/``add_resources``)
but no ``AssociateResourceShare``/``DisassociateResourceShare`` operations at
all - not stubs, absent entirely. Confirmed by reading
``moto/ram/{models,responses,urls}.py``: no method, no response handler, no
URL route. Real RAM customers routinely call ``CreateResourceShare`` then
``AssociateResourceShare`` as two separate steps (e.g. adding a principal to
an existing share later), so a feature built only around the inline-at-create
path would break on that real, common flow.

This module adds the missing operations by reusing the model's own
``add_principals``/``add_resources`` (validate-and-append) and the new
``remove_principals``/``remove_resources`` (best-effort removal, since moto
never needed removal before - ``delete()`` only ever marked a whole share
DELETED).

Patches applied (defensive - if moto's shape changes, log and continue):
  1. ``ResourceShare.remove_principals`` / ``remove_resources`` - new.
  2. ``ResourceAccessManagerBackend.associate_resource_share`` /
     ``disassociate_resource_share`` - new, modelled on the existing
     ``get_resource_share_associations`` response shape.
  3. ``ResourceAccessManagerResponse.associate_resource_share`` /
     ``disassociate_resource_share`` - new, modelled on the existing
     ``create_resource_share`` response method.
  4. New URL routes ``/associateresourceshare`` and
     ``/disassociateresourceshare`` registered in ``moto.ram.urls.url_paths``
     - RAM is a ``rest-json`` service (confirmed against the real botocore
     service model), dispatched by URI path, unlike e.g. CodeBuild's
     single-catch-all + X-Amz-Target dispatch - a method alone isn't
     reachable without the route.

The patch module is imported exactly once per process from
``services.ram.__init__``. Re-importing is safe (guarded by a flag).
"""

from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger(__name__)

_applied = False


def apply() -> None:
    """Apply all moto RAM patches. Idempotent."""
    global _applied
    if _applied:
        return
    _applied = True

    try:
        _patch_resource_share_removal()
        _patch_backend_associate_disassociate()
        _patch_response_associate_disassociate()
        _patch_url_routes()
        LOG.info("RAM AssociateResourceShare/DisassociateResourceShare patch applied.")
    except Exception:
        LOG.error("Failed to apply RAM moto patches", exc_info=True)


def _patch_resource_share_removal() -> None:
    from moto.ram.models import ResourceShare

    def _remove_principals(self: ResourceShare, principals: list[str]) -> None:
        for principal in principals:
            if principal in self.principals:
                self.principals.remove(principal)

    def _remove_resources(self: ResourceShare, resource_arns: list[str]) -> None:
        for resource_arn in resource_arns:
            if resource_arn in self.resource_arns:
                self.resource_arns.remove(resource_arn)

    ResourceShare.remove_principals = _remove_principals
    ResourceShare.remove_resources = _remove_resources


def _build_associations(resource: Any, resource_arns: list[str] | None, principals: list[str] | None) -> list[dict]:
    """Mirror the association shape moto's own
    ``get_resource_share_associations`` already returns, for just the
    entities touched by this call - matches the real
    ``AssociateResourceShare``/``DisassociateResourceShare`` response shape
    (``resourceShareAssociations``)."""
    from moto.core.utils import unix_time

    associations = []
    for principal_id in principals or []:
        associations.append({
            "resourceShareArn": resource.arn,
            "resourceShareName": resource.name,
            "associatedEntity": principal_id,
            "associationType": "PRINCIPAL",
            "status": "ASSOCIATED",
            "creationTime": unix_time(resource.creation_time),
            "lastUpdatedTime": unix_time(resource.last_updated_time),
            "external": False,
        })
    for resource_arn in resource_arns or []:
        associations.append({
            "resourceShareArn": resource.arn,
            "resourceShareName": resource.name,
            "associatedEntity": resource_arn,
            "associationType": "RESOURCE",
            "status": "ASSOCIATED",
            "creationTime": unix_time(resource.creation_time),
            "lastUpdatedTime": unix_time(resource.last_updated_time),
            "external": False,
        })
    return associations


def _patch_backend_associate_disassociate() -> None:
    from moto.ram.models import ResourceAccessManagerBackend

    def _find_share(self: ResourceAccessManagerBackend, resource_share_arn: str):
        from moto.ram.exceptions import UnknownResourceException

        resource = next(
            (r for r in self.resource_shares if r.arn == resource_share_arn),
            None,
        )
        if resource is None:
            raise UnknownResourceException(
                f"ResourceShare {resource_share_arn} could not be found."
            )
        return resource

    def _associate_resource_share(
        self: ResourceAccessManagerBackend,
        resource_share_arn: str,
        resource_arns: list[str] | None = None,
        principals: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        resource = self._ram_find_share(resource_share_arn)
        if resource_arns:
            resource.add_resources(resource_arns)
        if principals:
            resource.add_principals(principals)
        resource.last_updated_time = resource.last_updated_time
        return {
            "resourceShareAssociations": _build_associations(resource, resource_arns, principals),
            "clientToken": kwargs.get("client_token") or "",
        }

    def _disassociate_resource_share(
        self: ResourceAccessManagerBackend,
        resource_share_arn: str,
        resource_arns: list[str] | None = None,
        principals: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        resource = self._ram_find_share(resource_share_arn)
        if resource_arns:
            resource.remove_resources(resource_arns)
        if principals:
            resource.remove_principals(principals)
        associations = _build_associations(resource, resource_arns, principals)
        for assoc in associations:
            assoc["status"] = "DISASSOCIATED"
        return {
            "resourceShareAssociations": associations,
            "clientToken": kwargs.get("client_token") or "",
        }

    ResourceAccessManagerBackend._ram_find_share = _find_share
    ResourceAccessManagerBackend.associate_resource_share = _associate_resource_share
    ResourceAccessManagerBackend.disassociate_resource_share = _disassociate_resource_share


def _patch_response_associate_disassociate() -> None:
    import json

    from moto.ram.responses import ResourceAccessManagerResponse

    def _associate_resource_share_response(self: ResourceAccessManagerResponse) -> str:
        params = self.request_params
        result = self.ram_backend.associate_resource_share(
            params.get("resourceShareArn"),
            resource_arns=params.get("resourceArns"),
            principals=params.get("principals"),
            client_token=params.get("clientToken"),
        )
        return json.dumps(result)

    def _disassociate_resource_share_response(self: ResourceAccessManagerResponse) -> str:
        params = self.request_params
        result = self.ram_backend.disassociate_resource_share(
            params.get("resourceShareArn"),
            resource_arns=params.get("resourceArns"),
            principals=params.get("principals"),
            client_token=params.get("clientToken"),
        )
        return json.dumps(result)

    ResourceAccessManagerResponse.associate_resource_share = _associate_resource_share_response
    ResourceAccessManagerResponse.disassociate_resource_share = _disassociate_resource_share_response


def _patch_url_routes() -> None:
    from moto.ram.responses import ResourceAccessManagerResponse
    from moto.ram.urls import url_paths

    url_paths["{0}/associateresourceshare$"] = ResourceAccessManagerResponse.dispatch
    url_paths["{0}/disassociateresourceshare$"] = ResourceAccessManagerResponse.dispatch
