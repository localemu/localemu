"""Prompt extraction for BEDROCK_BACKEND=ollama.

Each model family's real InvokeModel body has its own shape; the local
model must receive the user's actual text (and system prompt), not raw JSON
or an empty string.
"""
from __future__ import annotations

import io
import json

from localemu.services.bedrock_runtime import local_inference, ollama_backend
from localemu.services.bedrock_runtime import provider as rt


def test_anthropic_string_content_and_system():
    body = {"system": "Be brief.", "messages": [{"role": "user", "content": "hi"}]}
    assert rt._extract_prompt(body) == ("hi", "Be brief.")


def test_anthropic_content_blocks_become_plain_text_not_json():
    body = {"messages": [{"role": "user", "content": [
        {"type": "text", "text": "hello"}, {"type": "text", "text": "world"},
    ]}]}
    prompt, system = rt._extract_prompt(body)
    assert prompt == "hello\nworld"
    assert "type" not in prompt and system is None


def test_anthropic_system_as_blocks():
    body = {"system": [{"type": "text", "text": "A"}, {"type": "text", "text": "B"}],
            "messages": [{"role": "user", "content": "x"}]}
    assert rt._extract_prompt(body)[1] == "A\nB"


def test_non_text_blocks_are_skipped():
    body = {"messages": [{"role": "user", "content": [
        {"type": "image", "source": {"data": "AAAA"}}, {"type": "text", "text": "what is this"},
    ]}]}
    assert rt._extract_prompt(body)[0] == "what is this"


def test_multi_turn_keeps_roles():
    body = {"messages": [
        {"role": "user", "content": "q1"}, {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q2"},
    ]}
    assert rt._extract_prompt(body)[0] == "user: q1\nassistant: a1\nuser: q2"


def test_cohere_command_r_message_is_not_dropped():
    assert rt._extract_prompt({"message": "hello"}) == ("hello", None)


def test_cohere_chat_history_and_preamble():
    body = {"message": "and now?", "preamble": "You are terse.",
            "chat_history": [{"role": "USER", "message": "hi"}, {"role": "CHATBOT", "message": "yo"}]}
    prompt, system = rt._extract_prompt(body)
    assert prompt == "user: hi\nchatbot: yo\nuser: and now?"
    assert system == "You are terse."


def test_single_prompt_families():
    assert rt._extract_prompt({"prompt": "p"}) == ("p", None)          # Llama, Mistral
    assert rt._extract_prompt({"inputText": "t"}) == ("t", None)       # Titan
    assert rt._extract_prompt({}) == ("", None)


def test_every_text_model_in_the_map_gets_its_prompt_through():
    """For each text model, the body shape its family really sends must
    yield a non-empty prompt."""
    shape = {
        "anthropic": {"messages": [{"role": "user", "content": "X"}]},
        "ai21": {"messages": [{"role": "user", "content": "X"}]},
        "amazon": {"inputText": "X"},
        "meta": {"prompt": "X"},
        "mistral": {"prompt": "X"},
        "cohere": {"message": "X"},
    }
    for model_id, spec in local_inference.LOCAL_INFERENCE_MAP.items():
        if spec.ollama_tag is None or spec.modality != "TEXT":
            continue
        assert rt._extract_prompt(shape[model_id.split(".")[0]])[0] == "X", model_id


def test_generate_sends_system_only_when_given(monkeypatch):
    sent = []

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"response": "ok"}

    import requests
    monkeypatch.setattr(requests, "post", lambda url, json=None, **kw: sent.append(json) or _Resp())
    monkeypatch.setattr(ollama_backend, "ensure_model_pulled", lambda tag: None)
    monkeypatch.setattr(ollama_backend, "_ensure_container", lambda: 1234)

    ollama_backend.generate("m", "p")
    ollama_backend.generate("m", "p", system="S")
    assert "system" not in sent[0]
    assert sent[1]["system"] == "S"


def test_invoke_ollama_end_to_end_wiring(monkeypatch):
    """InvokeModel (ollama) for Command R reaches generate() with the
    caller's text, and the reply comes back in Cohere's response shape."""
    from localemu.services.bedrock_runtime import memory_gate
    monkeypatch.setenv("BEDROCK_BACKEND", "ollama")
    monkeypatch.setattr(memory_gate, "check_memory", lambda *a: None)
    seen = {}
    monkeypatch.setattr(ollama_backend, "generate",
                        lambda tag, prompt, system=None: seen.update(tag=tag, prompt=prompt) or "REPLY")
    out = rt._handle_invoke_model(None, {
        "modelId": "cohere.command-r-v1:0",
        "body": io.BytesIO(json.dumps({"message": "ping"}).encode()),
    })
    assert seen == {"tag": "mistral:7b", "prompt": "ping"}
    assert json.loads(out["body"])["generations"][0]["text"] == "REPLY"


# --- request validation (applies to both backends) ---------------------------

import pytest  # noqa: E402

from localemu.aws.api import CommonServiceException  # noqa: E402


def _invoke(model_id, body):
    return rt._handle_invoke_model(None, {"modelId": model_id, "body": io.BytesIO(body)})


@pytest.mark.parametrize("model_id", [
    "meta.llama3-1-8b-instruct-v1:0",
    "arn:aws:bedrock:us-east-1::foundation-model/meta.llama3-1-8b-instruct-v1:0",
    "us.meta.llama3-1-8b-instruct-v1:0",
])
def test_known_model_ids_are_accepted_in_every_form(model_id):
    assert json.loads(_invoke(model_id, b'{"prompt":"x"}')["body"])["generation"]


@pytest.mark.parametrize("model_id", [
    "anthropic.claude-sonnet-4-6-v1:0",
    "us.anthropic.claude-sonnet-4-6-v1:0",
    "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-pro-v1:0",
])
def test_well_formed_ids_outside_the_catalog_are_accepted(model_id):
    out = json.loads(_invoke(model_id, b'{"messages":[{"role":"user","content":"x"}]}')["body"])
    assert out


@pytest.mark.parametrize("model_id", ["", "foo.bar-v1", "us.foo.bar-v1", "not-a-model", "anthropic", "arn:aws:bedrock:us-east-1::foundation-model/nope"])
def test_unknown_model_ids_raise_validation_exception(model_id):
    with pytest.raises(CommonServiceException) as exc:
        _invoke(model_id, b'{"prompt":"x"}')
    assert exc.value.code == "ValidationException"
    assert exc.value.message == "The provided model identifier is invalid."


@pytest.mark.parametrize("body", [b"", b"not json", b"[1,2]", b'"text"', b"null"])
def test_malformed_bodies_raise_validation_exception(body):
    with pytest.raises(CommonServiceException) as exc:
        _invoke("meta.llama3-1-8b-instruct-v1:0", body)
    assert exc.value.code == "ValidationException"
