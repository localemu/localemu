"""GuardDuty provider - native finding generation on top of moto's detector CRUD.

Moto's vendored GuardDuty backend implements the detector/filter control
plane correctly (``CreateDetector``, ``ListDetectors``, ``GetDetector``,
filters, ...) - those stay on the existing moto path via ``_proxy_moto``.
What it has no route for at all is the finding plane: ``CreateSampleFindings``,
``ListFindings``, ``GetFindings``, ``ArchiveFindings``, ``UnarchiveFindings``,
``UpdateFindingsFeedback`` and ``GetFindingsStatistics`` (plus ``ListFilters``).
This module intercepts those and backs them with ``findings_store`` - a native
implementation on a persisted store (``models.guardduty_stores``), not a moto
patch. ``DeleteDetector`` also drops the detector's findings.

``CreateSampleFindings`` also publishes each generated finding to
EventBridge (``source: aws.guardduty``, ``detail-type: GuardDuty Finding``),
matching real AWS: GuardDuty forwards every finding - sample or real - to
the account's default event bus so EventBridge rules can react to it. This
is also what lets a GuardDuty -> EventBridge -> Lambda teaching pipeline
run against the *real* AWS API end to end, with no synthetic
``events put-events`` workaround required.
"""
from __future__ import annotations

import json
import logging

from localemu.aws.api import CommonServiceException, RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto
from localemu.services.plugins import Service, ServiceLifecycleHook

from . import findings_store

LOG = logging.getLogger(__name__)


def _lower_first(key: str) -> str:
    return key[:1].lower() + key[1:] if key else key


def _to_wire_detail(obj):
    """Recursively lowercase-first every dict key.

    GuardDuty's wire/EventBridge convention is uniformly "lowerCamelCase of
    the PascalCase member name" (confirmed against botocore's service
    model: every Finding member carries a ``locationName`` that is exactly
    this transform). Good enough as a generic rule for the whole Finding
    tree - lists and scalars pass through unchanged.
    """
    if isinstance(obj, dict):
        return {_lower_first(k): _to_wire_detail(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_wire_detail(v) for v in obj]
    return obj


def _require_detector(context: RequestContext, detector_id: str) -> None:
    import moto.backends as moto_backends
    from moto.guardduty.exceptions import DetectorNotFoundException

    backend = moto_backends.get_backend("guardduty")[context.account_id][context.region]
    try:
        backend.get_detector(detector_id)
    except DetectorNotFoundException as e:
        raise CommonServiceException(
            code="BadRequestException",
            message=str(getattr(e, "message", e)) or f"The request is rejected because the input detectorId {detector_id} is not owned by the current account.",
            status_code=400,
            sender_fault=True,
        ) from e


def _publish_findings_to_eventbridge(context: RequestContext, findings: list[dict]) -> None:
    from localemu.aws.connect import connect_to

    try:
        events_client = connect_to(
            aws_access_key_id=context.account_id, region_name=context.region,
        ).events
        entries = [
            {
                "Source": "aws.guardduty",
                "DetailType": "GuardDuty Finding",
                "Detail": json.dumps(_to_wire_detail(finding)),
            }
            for finding in findings
        ]
        if entries:
            events_client.put_events(Entries=entries)
    except Exception:
        LOG.debug("GuardDuty->EventBridge forwarding failed", exc_info=True)


def _handle_create_sample_findings(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)

    finding_types = request.get("FindingTypes") or list(findings_store._KNOWN_TYPES.keys())
    created = findings_store.create_sample_findings(
        account_id=context.account_id,
        region=context.region,
        detector_id=detector_id,
        finding_types=finding_types,
    )
    _publish_findings_to_eventbridge(context, created)
    return {}


def _handle_list_findings(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)

    ids, next_token = findings_store.list_findings(
        account_id=context.account_id,
        region=context.region,
        detector_id=detector_id,
        finding_criteria=request.get("FindingCriteria"),
        sort_criteria=request.get("SortCriteria"),
        max_results=request.get("MaxResults"),
        next_token=request.get("NextToken"),
    )
    response: ServiceResponse = {"FindingIds": ids}
    if next_token:
        response["NextToken"] = next_token
    return response


def _handle_get_findings(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)

    findings = findings_store.get_findings(
        account_id=context.account_id,
        region=context.region,
        detector_id=detector_id,
        finding_ids=request.get("FindingIds") or [],
        sort_criteria=request.get("SortCriteria"),
    )
    return {"Findings": findings}


def _handle_archive_findings(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)
    findings_store.set_archived(
        account_id=context.account_id, region=context.region, detector_id=detector_id,
        finding_ids=request.get("FindingIds") or [], archived=True,
    )
    return {}


def _handle_unarchive_findings(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)
    findings_store.set_archived(
        account_id=context.account_id, region=context.region, detector_id=detector_id,
        finding_ids=request.get("FindingIds") or [], archived=False,
    )
    return {}


def _handle_update_findings_feedback(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)
    findings_store.set_feedback(
        account_id=context.account_id, region=context.region, detector_id=detector_id,
        finding_ids=request.get("FindingIds") or [], feedback=request.get("Feedback") or "",
    )
    return {}


def _handle_get_findings_statistics(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)
    stats, next_token = findings_store.get_statistics(
        account_id=context.account_id, region=context.region, detector_id=detector_id,
        finding_criteria=request.get("FindingCriteria"),
        group_by=request.get("GroupBy"), order_by=request.get("OrderBy"),
        max_results=request.get("MaxResults"), next_token=request.get("NextToken"),
        statistic_types=request.get("FindingStatisticTypes"),
    )
    response: ServiceResponse = {"FindingStatistics": stats}
    if next_token:
        response["NextToken"] = next_token
    return response


def _handle_list_filters(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    import moto.backends as moto_backends

    detector_id = request.get("DetectorId") or ""
    _require_detector(context, detector_id)
    backend = moto_backends.get_backend("guardduty")[context.account_id][context.region]
    names = sorted(backend.get_detector(detector_id).filters.keys())
    start = int(request["NextToken"]) if request.get("NextToken") else 0
    page_size = request.get("MaxResults") or 50
    response: ServiceResponse = {"FilterNames": names[start : start + page_size]}
    if start + page_size < len(names):
        response["NextToken"] = str(start + page_size)
    return response


def _handle_delete_detector(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    response = _proxy_moto(context, request)
    findings_store.delete_detector_findings(
        context.account_id, context.region, request.get("DetectorId") or "",
    )
    return response


_INTERCEPTED_OPS = {
    "CreateSampleFindings": _handle_create_sample_findings,
    "ListFindings": _handle_list_findings,
    "GetFindings": _handle_get_findings,
    "ArchiveFindings": _handle_archive_findings,
    "UnarchiveFindings": _handle_unarchive_findings,
    "UpdateFindingsFeedback": _handle_update_findings_feedback,
    "GetFindingsStatistics": _handle_get_findings_statistics,
    "ListFilters": _handle_list_filters,
    "DeleteDetector": _handle_delete_detector,
}


def GuardDutyDispatcher(service_model) -> DispatchTable:
    table = {}
    for op in service_model.operation_names:
        table[op] = _INTERCEPTED_OPS.get(op, _proxy_moto)
    return table


class GuardDutyLifecycle(ServiceLifecycleHook):
    """Clear the native findings store on state reset / load."""

    def on_before_state_reset(self) -> None:
        findings_store.reset()

    def on_before_state_load(self) -> None:
        findings_store.reset()


def create_guardduty_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("guardduty")
    dispatch_table = GuardDutyDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(
        name="guardduty", skeleton=skeleton, lifecycle_hook=GuardDutyLifecycle(),
    )
