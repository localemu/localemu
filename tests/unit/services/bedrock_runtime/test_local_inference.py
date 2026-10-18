"""Unit tests for the model-id -> Ollama-tag mapping table."""
from __future__ import annotations

from localemu.services.bedrock_runtime import local_inference


def test_same_family_models_have_matching_fidelity():
    spec = local_inference.get_spec("meta.llama3-1-8b-instruct-v1:0")
    assert spec.ollama_tag == "llama3.1:8b"
    assert spec.fidelity == local_inference.FIDELITY_SAME_FAMILY


def test_closed_weight_models_marked_different_family():
    spec = local_inference.get_spec("anthropic.claude-3-haiku-20240307-v1:0")
    assert spec.fidelity == local_inference.FIDELITY_DIFFERENT_FAMILY
    assert spec.ollama_tag is not None


def test_oversized_models_have_no_ollama_tag():
    spec = local_inference.get_spec("meta.llama3-1-405b-instruct-v1:0")
    assert spec.ollama_tag is None
    assert spec.min_total_ram_gb is None
    assert spec.fidelity == local_inference.FIDELITY_UNAVAILABLE
    assert spec.note  # must explain why, not just silently say no


def test_closed_weight_with_no_open_equivalent_is_unavailable():
    spec = local_inference.get_spec("mistral.mistral-large-2402-v1:0")
    assert spec.ollama_tag is None
    assert spec.fidelity == local_inference.FIDELITY_UNAVAILABLE


def test_unmapped_model_returns_none():
    assert local_inference.get_spec("totally.unknown-model") is None


def test_every_mapped_entry_with_a_tag_has_a_ram_requirement():
    for model_id, spec in local_inference.LOCAL_INFERENCE_MAP.items():
        if spec.ollama_tag is not None:
            assert spec.min_total_ram_gb is not None, model_id
            assert spec.min_total_ram_gb > 0, model_id


def test_embedding_models_are_tagged_embedding_modality():
    spec = local_inference.get_spec("amazon.titan-embed-text-v1")
    assert spec.modality == "EMBEDDING"
