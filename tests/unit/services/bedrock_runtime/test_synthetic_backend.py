"""Unit tests for the zero-dependency default InvokeModel backend.

Covers: each model family gets a response shaped like its real API (so
application code written against real Bedrock doesn't need to change),
and responses are deterministic per input but distinct across inputs.
"""
from __future__ import annotations

from localemu.services.bedrock_runtime import synthetic_backend


def test_anthropic_shape():
    body = synthetic_backend.invoke(
        "anthropic.claude-3-haiku-20240307-v1:0",
        {"messages": [{"role": "user", "content": "hi"}]},
    )
    assert body["type"] == "message"
    assert body["role"] == "assistant"
    assert body["content"][0]["type"] == "text"
    assert isinstance(body["content"][0]["text"], str)
    assert "usage" in body


def test_amazon_titan_embed_shape():
    body = synthetic_backend.invoke("amazon.titan-embed-text-v1", {"inputText": "hello world"})
    assert len(body["embedding"]) == 1536
    assert body["inputTextTokenCount"] == 2


def test_amazon_titan_embed_v2_uses_1024_dims():
    body = synthetic_backend.invoke("amazon.titan-embed-text-v2:0", {"inputText": "hi"})
    assert len(body["embedding"]) == 1024


def test_amazon_titan_text_shape():
    body = synthetic_backend.invoke("amazon.titan-text-express-v1", {"inputText": "hello"})
    assert body["results"][0]["completionReason"] == "FINISH"
    assert isinstance(body["results"][0]["outputText"], str)


def test_meta_llama_shape():
    body = synthetic_backend.invoke("meta.llama3-1-8b-instruct-v1:0", {"prompt": "hi there"})
    assert "generation" in body
    assert body["prompt_token_count"] == 2
    assert body["stop_reason"] == "stop"


def test_mistral_shape():
    body = synthetic_backend.invoke("mistral.mistral-7b-instruct-v0:2", {"prompt": "hi"})
    assert body["outputs"][0]["stop_reason"] == "stop"


def test_cohere_embed_shape():
    body = synthetic_backend.invoke("cohere.embed-english-v3", {"texts": ["a", "b"]})
    assert body["response_type"] == "embeddings_floats"
    assert len(body["embeddings"]) == 2
    assert len(body["embeddings"][0]) == 1024


def test_cohere_generate_shape():
    body = synthetic_backend.invoke("cohere.command-r-v1:0", {"prompt": "hi"})
    assert body["generations"][0]["id"] == "0"


def test_ai21_shape():
    body = synthetic_backend.invoke("ai21.jamba-1-5-large-v1:0", {"messages": [{"role": "user", "content": "hi"}]})
    assert body["choices"][0]["message"]["role"] == "assistant"


def test_unknown_family_falls_back_gracefully():
    body = synthetic_backend.invoke("someprovider.some-model-v1:0", {"anything": "goes"})
    assert "output" in body


def test_deterministic_same_input_same_output():
    a = synthetic_backend.invoke("mistral.mistral-7b-instruct-v0:2", {"prompt": "same"})
    b = synthetic_backend.invoke("mistral.mistral-7b-instruct-v0:2", {"prompt": "same"})
    assert a == b


def test_distinct_inputs_produce_distinct_outputs():
    a = synthetic_backend.invoke("mistral.mistral-7b-instruct-v0:2", {"prompt": "prompt A"})
    b = synthetic_backend.invoke("mistral.mistral-7b-instruct-v0:2", {"prompt": "prompt B"})
    assert a["outputs"][0]["text"] != b["outputs"][0]["text"]


def test_responses_are_labeled_synthetic():
    """Anyone reading a response should immediately see it's not a real model."""
    body = synthetic_backend.invoke("meta.llama3-1-8b-instruct-v1:0", {"prompt": "hi"})
    assert "synthetic" in body["generation"].lower()
