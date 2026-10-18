"""Unit tests for the native Bedrock foundation-model catalog.

Moto's vendored Bedrock backend has no route for ListFoundationModels /
GetFoundationModel at all. These tests cover the native replacement
directly, without needing a running server.
"""
from __future__ import annotations

import pytest

from localemu.services.bedrock import catalog
from localemu.services.bedrock.provider import (
    _handle_get_foundation_model,
    _handle_list_foundation_models,
)


def _ctx():
    from types import SimpleNamespace

    return SimpleNamespace(account_id="000000000000", region="us-east-1")


def test_catalog_is_non_empty_and_ids_are_unique():
    ids = [m.model_id for m in catalog.FOUNDATION_MODELS]
    assert len(ids) > 0
    assert len(ids) == len(set(ids))


def test_get_model_known_and_unknown():
    assert catalog.get_model("anthropic.claude-3-haiku-20240307-v1:0") is not None
    assert catalog.get_model("not-a-real-model") is None


def test_to_wire_shape():
    model = catalog.get_model("amazon.titan-embed-text-v1")
    wire = catalog.to_wire(model, region="us-east-1", account_id="000000000000")
    assert wire["modelId"] == "amazon.titan-embed-text-v1"
    assert wire["modelArn"].endswith("foundation-model/amazon.titan-embed-text-v1")
    assert wire["outputModalities"] == ["EMBEDDING"]
    assert wire["modelLifecycle"] == {"status": "ACTIVE"}


def test_list_foundation_models_returns_full_catalog():
    result = _handle_list_foundation_models(_ctx(), {})
    assert len(result["modelSummaries"]) == len(catalog.FOUNDATION_MODELS)


def test_list_foundation_models_filters_by_provider():
    result = _handle_list_foundation_models(_ctx(), {"byProvider": "Meta"})
    assert len(result["modelSummaries"]) > 0
    assert all(m["providerName"] == "Meta" for m in result["modelSummaries"])


def test_list_foundation_models_filters_by_output_modality():
    result = _handle_list_foundation_models(_ctx(), {"byOutputModality": "EMBEDDING"})
    assert len(result["modelSummaries"]) > 0
    assert all("EMBEDDING" in m["outputModalities"] for m in result["modelSummaries"])


def test_get_foundation_model_known_id():
    result = _handle_get_foundation_model(_ctx(), {"modelIdentifier": "meta.llama3-8b-instruct-v1:0"})
    assert result["modelDetails"]["modelId"] == "meta.llama3-8b-instruct-v1:0"


def test_get_foundation_model_unknown_id_raises():
    from localemu.aws.api import CommonServiceException

    with pytest.raises(CommonServiceException) as exc_info:
        _handle_get_foundation_model(_ctx(), {"modelIdentifier": "no-such-model"})
    assert exc_info.value.code == "ResourceNotFoundException"
