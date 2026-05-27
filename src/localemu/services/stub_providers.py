"""Minimal stub providers for the long-tail of AWS services LocalEmu's
moto fork doesn't cover.

Goal: surface AWS-shaped 2xx responses for the most commonly-called
operations (Describe / List / Get) on services like ``translate``,
``mediaconvert``, ``apprunner``, ``amplify``, ``snowball``,
``storagegateway`` — none of which moto-ext implements at all. Real
data plane isn't there, but tooling (CDK / Terraform / boto3 smoke
tests / health probes) that just *describes* state no longer 500s
with ``API for operation X of service Y has not yet been implemented``.

What this is NOT: a real implementation. The state model is in-memory
per process; lists default to empty; specific resource lookups return
404 NotFound. Where it makes sense (``translate:TranslateText``,
``comprehend:DetectDominantLanguage``) we return a hard-coded but
shape-correct payload so demo / smoke tests keep moving.

For services moto DOES implement, we still call moto for ops it covers
and only stub the gaps (see ``_OPS`` per service).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.aws.spec import load_service
from localemu.services.moto import _proxy_moto
from localemu.services.plugins import Service

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-service stub responses. Returning ``{}`` is sufficient when the
# operation's output shape is "everything optional" or "single
# list-typed field" — botocore's serializer then renders the AWS-shaped
# empty payload (``{"Items": []}``, ``{"Servers": []}``, …).
#
# When a richer default makes sense (the ``translate`` echo, etc.) we
# return a dict matching the output-shape field names.
# ---------------------------------------------------------------------------


def _empty(*_args, **_kwargs) -> ServiceResponse:
    return {}


def _translate_text(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    # AWS Translate echoes back the input text unmodified would be
    # surprising; for a smoke-test stub we return the text bracketed
    # by the language codes so callers can see the stub is wired.
    text = request.get("Text") or ""
    src = request.get("SourceLanguageCode") or "auto"
    tgt = request.get("TargetLanguageCode") or "en"
    return {
        "TranslatedText": text,  # AWS keeps original text in the output
        "SourceLanguageCode": "en" if src == "auto" else src,
        "TargetLanguageCode": tgt,
    }


def _detect_dominant_language(_context, request) -> ServiceResponse:
    # Heuristic-free stub: report English with high confidence so smoke
    # tests pass. Real impl would need a language-detection model.
    return {
        "Languages": [
            {"LanguageCode": "en", "Score": 0.99},
        ],
    }


def _detect_sentiment(_context, request) -> ServiceResponse:
    return {
        "Sentiment": "NEUTRAL",
        "SentimentScore": {
            "Positive": 0.25, "Negative": 0.25,
            "Neutral": 0.45, "Mixed": 0.05,
        },
    }


def _macie_session(_context, _request) -> ServiceResponse:
    return {
        "status": "ENABLED",
        "findingPublishingFrequency": "FIFTEEN_MINUTES",
        "serviceRole": "arn:aws:iam::000000000000:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
    }


# ---------------------------------------------------------------------------
# (service, op) -> handler. Handlers MAY take (context, request) and
# return a dict, OR take no args and return a fixed dict via ``_empty``.
# ---------------------------------------------------------------------------

_OPS: dict[str, dict[str, Callable]] = {
    "translate": {
        "TranslateText": _translate_text,
        "ListTerminologies": _empty,
        "ListParallelData": _empty,
        "ListLanguages": lambda _c, _r: {
            "Languages": [
                {"LanguageName": "English", "LanguageCode": "en"},
                {"LanguageName": "French",  "LanguageCode": "fr"},
                {"LanguageName": "Spanish", "LanguageCode": "es"},
                {"LanguageName": "German",  "LanguageCode": "de"},
            ],
            "DisplayLanguageCode": "en",
        },
    },
    "comprehend": {
        "DetectDominantLanguage": _detect_dominant_language,
        "DetectSentiment": _detect_sentiment,
        "DetectEntities":   lambda _c, _r: {"Entities": []},
        "DetectKeyPhrases": lambda _c, _r: {"KeyPhrases": []},
        "DetectPiiEntities": lambda _c, _r: {"Entities": []},
        "DetectSyntax":     lambda _c, _r: {"SyntaxTokens": []},
    },
    "rekognition": {
        "ListCollections": lambda _c, _r: {"CollectionIds": []},
        "DescribeCollection": lambda _c, _r: {
            "FaceCount": 0, "FaceModelVersion": "6.0",
        },
        "ListFaces": lambda _c, _r: {"Faces": []},
        "ListProjects": lambda _c, _r: {"ProjectDescriptions": []},
        "ListStreamProcessors": lambda _c, _r: {"StreamProcessors": []},
        "ListUsers": lambda _c, _r: {"Users": []},
    },
    "transfer": {
        "ListServers": lambda _c, _r: {"Servers": []},
        "ListUsers": lambda _c, _r: {"ServerId": _r.get("ServerId", ""), "Users": []},
        "ListAccesses": lambda _c, _r: {"ServerId": _r.get("ServerId", ""), "Accesses": []},
        "ListAgreements": lambda _c, _r: {"Agreements": []},
        "ListConnectors": lambda _c, _r: {"Connectors": []},
        "ListProfiles": lambda _c, _r: {"Profiles": []},
        "ListCertificates": lambda _c, _r: {"Certificates": []},
        "ListHostKeys": lambda _c, _r: {"ServerId": _r.get("ServerId", ""), "HostKeys": []},
    },
    # personalize, forecast, inspector2 and macie2 are in
    # _HAS_MOTO_BACKEND below. Stub entries here used to shadow real
    # moto state, so ListSchemas / ListDatasets / ListFindings always
    # returned []. Only operations that moto does not implement should
    # be stubbed; bare List* operations are handled by the moto fall-
    # through at the bottom of this file.
    "personalize": {
        "ListCampaigns": lambda _c, _r: {"campaigns": []},
        "ListSolutions": lambda _c, _r: {"solutions": []},
        "ListRecommenders": lambda _c, _r: {"recommenders": []},
        "ListEventTrackers": lambda _c, _r: {"eventTrackers": []},
    },
    "forecast": {
        "ListForecasts": lambda _c, _r: {"Forecasts": []},
        "ListPredictors": lambda _c, _r: {"Predictors": []},
        "ListMonitors": lambda _c, _r: {"Monitors": []},
    },
    "inspector2": {
        # BatchGetAccountStatus is the only op moto does not implement.
        "BatchGetAccountStatus": lambda _c, _r: {"accounts": [], "failedAccounts": []},
    },
    "macie2": {
        # GetMacieSession needs the canned response moto does not provide.
        "GetMacieSession": _macie_session,
    },
    "mediaconvert": {
        "ListJobs": lambda _c, _r: {"Jobs": []},
        "ListQueues": lambda _c, _r: {"Queues": [
            {"Name": "Default", "Status": "ACTIVE", "Type": "SYSTEM",
             "Arn": "arn:aws:mediaconvert:us-east-1:000000000000:queues/Default"},
        ]},
        "ListPresets": lambda _c, _r: {"Presets": []},
        "ListJobTemplates": lambda _c, _r: {"JobTemplates": []},
        "DescribeEndpoints": lambda _c, _r: {"Endpoints": [{
            "Url": "https://mediaconvert.us-east-1.amazonaws.com",
        }]},
    },
    "storagegateway": {
        "ListGateways": lambda _c, _r: {"Gateways": []},
        "ListTagsForResource": lambda _c, _r: {"Tags": []},
        "ListFileShares": lambda _c, _r: {"FileShareInfoList": []},
        "ListVolumes": lambda _c, _r: {"VolumeInfos": []},
    },
    "apprunner": {
        "ListServices": lambda _c, _r: {"ServiceSummaryList": []},
        "ListConnections": lambda _c, _r: {"ConnectionSummaryList": []},
        "ListAutoScalingConfigurations": lambda _c, _r: {"AutoScalingConfigurationSummaryList": []},
        "ListObservabilityConfigurations": lambda _c, _r: {"ObservabilityConfigurationSummaryList": []},
        "ListVpcConnectors": lambda _c, _r: {"VpcConnectors": []},
    },
    "amplify": {
        "ListApps": lambda _c, _r: {"apps": []},
        "ListBranches": lambda _c, _r: {"branches": []},
        "ListBackendEnvironments": lambda _c, _r: {"backendEnvironments": []},
        "ListDomainAssociations": lambda _c, _r: {"domainAssociations": []},
    },
    "waf": {
        "ListWebACLs": lambda _c, _r: {"WebACLs": []},
        "ListByteMatchSets": lambda _c, _r: {"ByteMatchSets": []},
        "ListIPSets": lambda _c, _r: {"IPSets": []},
        "ListRules": lambda _c, _r: {"Rules": []},
        "ListRateBasedRules": lambda _c, _r: {"Rules": []},
    },
    "snowball": {
        "ListJobs": lambda _c, _r: {"JobListEntries": []},
        "ListClusters": lambda _c, _r: {"ClusterListEntries": []},
        "ListServiceVersions": lambda _c, _r: {"ServiceVersions": []},
        "ListCompatibleImages": lambda _c, _r: {"CompatibleImages": []},
    },
}


# Services moto-ext implements but where specific ops are missing.
# For these we proxy to moto for unknown ops and only stub the gaps.
_HAS_MOTO_BACKEND = {
    "comprehend", "rekognition", "transfer", "personalize", "forecast",
    "inspector2", "macie2",
}


def _make_dispatch(service_name: str, service_model) -> DispatchTable:
    stub_ops = _OPS.get(service_name, {})
    has_moto = service_name in _HAS_MOTO_BACKEND
    table: DispatchTable = {}
    for op in service_model.operation_names:
        if op in stub_ops:
            handler = stub_ops[op]
            def make(h):
                def _dispatch(context, request):
                    return h(context, request)
                return _dispatch
            table[op] = make(handler)
        elif has_moto:
            table[op] = _proxy_moto
        else:
            # No moto, no stub — return an AWS-shaped 501 NotImplemented
            def _not_impl(context, _request, _op=op, _svc=service_name):
                from localemu.aws.api import CommonServiceException
                raise CommonServiceException(
                    code="NotImplementedException",
                    message=(
                        f"LocalEmu stub for {_svc}:{_op} not provided. Add an "
                        f"entry under services.stub_providers._OPS[{_svc!r}] to "
                        "register a response."
                    ),
                    status_code=501,
                    sender_fault=True,
                )
            table[op] = _not_impl
    return table


def create_stub_service(service_name: str) -> Service:
    """Build a Service whose dispatch table is the per-op stub map.

    Used by ``services/providers.py`` for the 14 services listed in
    LocalEmu's long-tail audit (translate, mediaconvert, snowball, …).
    """
    service_model = load_service(service_name)
    dispatch_table = _make_dispatch(service_name, service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name=service_name, skeleton=skeleton)
