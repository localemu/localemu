"""Bedrock provider - native foundation-model catalog on top of moto's control plane.

Moto's vendored Bedrock backend implements the customization/tagging
control plane (``CreateModelCustomizationJob``, tagging, ...) correctly,
via a URL routing table with no entry at all for ``/foundation-models`` -
a request there fails with ``No moto route for service bedrock on path
/foundation-models found``. This module intercepts just
``ListFoundationModels`` / ``GetFoundationModel`` and backs them with
``catalog`` - a native, curated catalog - not a moto patch. Every other
Bedrock operation stays on the existing (working) moto path.
"""
from __future__ import annotations

from localemu.aws.api import CommonServiceException, RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto
from localemu.services.plugins import Service

from . import catalog


def _handle_list_foundation_models(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    by_provider = request.get("byProvider")
    by_output_modality = request.get("byOutputModality")

    models = catalog.FOUNDATION_MODELS
    if by_provider:
        models = [m for m in models if m.provider_name.lower() == by_provider.lower()]
    if by_output_modality:
        models = [m for m in models if by_output_modality in m.output_modalities]

    return {
        "modelSummaries": [
            catalog.to_wire(m, region=context.region, account_id=context.account_id)
            for m in models
        ]
    }


def _handle_get_foundation_model(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    model_id = request.get("modelIdentifier") or ""
    model = catalog.get_model(model_id)
    if model is None:
        raise CommonServiceException(
            code="ResourceNotFoundException",
            message=(
                f"Could not find model with id {model_id!r}. LocalEmu's foundation-model "
                "catalog is a curated subset (see localemu/services/bedrock/catalog.py), "
                "not the full ~150-model AWS catalog."
            ),
            status_code=404,
            sender_fault=True,
        )
    return {"modelDetails": catalog.to_wire(model, region=context.region, account_id=context.account_id)}


_INTERCEPTED_OPS = {
    "ListFoundationModels": _handle_list_foundation_models,
    "GetFoundationModel": _handle_get_foundation_model,
}


def BedrockDispatcher(service_model) -> DispatchTable:
    table = {}
    for op in service_model.operation_names:
        table[op] = _INTERCEPTED_OPS.get(op, _proxy_moto)
    return table


def create_bedrock_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("bedrock")
    dispatch_table = BedrockDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="bedrock", skeleton=skeleton)
