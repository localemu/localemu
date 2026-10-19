"""bedrock-runtime provider - InvokeModel, with a synthetic default and an
opt-in real-local-inference backend.

There is no moto backend for bedrock-runtime at all (real Bedrock
inference is a hosted model service, not a CRUD-able API surface), so
every operation this module doesn't explicitly handle gets the router's
501 "no handler for operation '<name>' on service 'bedrock-runtime'"
response. Only ``InvokeModel`` is intercepted.

``BEDROCK_BACKEND`` picks the implementation:
  synthetic (default) - deterministic, zero dependencies, always works.
  ollama               - real local inference via a Docker sidecar, gated
                          by memory_gate.check_memory() so an under-resourced
                          dev machine gets a clear error instead of a stall.
"""
from __future__ import annotations

import json
import logging
import os
import re

from localemu.aws.api import CommonServiceException, RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.plugins import Service

from localemu.services.bedrock import catalog

from . import local_inference, memory_gate, synthetic_backend

LOG = logging.getLogger(__name__)


def _backend() -> str:
    return os.environ.get("BEDROCK_BACKEND", "synthetic").strip().lower()


def _invoke_ollama(model_id: str, body: dict) -> dict:
    spec = local_inference.get_spec(model_id)
    if spec is None:
        raise CommonServiceException(
            code="ValidationException",
            message=(
                f"No local-inference mapping curated for model id {model_id!r}. "
                "See localemu/services/bedrock_runtime/local_inference.py for the "
                "models BEDROCK_BACKEND=ollama supports, or use "
                "BEDROCK_BACKEND=synthetic for any model id."
            ),
            status_code=400, sender_fault=True,
        )
    if spec.ollama_tag is None:
        raise CommonServiceException(
            code="ValidationException",
            message=(
                f"{model_id!r} has no runnable local equivalent: {spec.note} "
                "Use BEDROCK_BACKEND=synthetic for this model id."
            ),
            status_code=400, sender_fault=True,
        )

    memory_gate.check_memory(model_id, spec.min_total_ram_gb)

    from . import ollama_backend

    if spec.modality == "EMBEDDING":
        text = body.get("inputText") or (body.get("texts") or [""])[0]
        embedding = ollama_backend.embed(spec.ollama_tag, text)
        if "embed" in model_id and model_id.startswith("amazon"):
            return {"embedding": embedding, "inputTextTokenCount": len(text.split())}
        return {
            "id": "ollama", "texts": body.get("texts", [text]),
            "embeddings": [embedding], "response_type": "embeddings_floats",
        }

    # TEXT generation: build a prompt (and optional system prompt) from
    # whichever shape the caller's model family uses, then route the real
    # text back into that same family's response shape so client code
    # doesn't change between BEDROCK_BACKEND=synthetic and =ollama.
    prompt, system = _extract_prompt(body)
    text = ollama_backend.generate(spec.ollama_tag, prompt, system=system)
    return _wrap_text_response(model_id, prompt, text)


def _text_of(content) -> str:
    """Plain text of a message ``content``: a string, or a list of blocks
    (Anthropic Messages, AI21 Jamba) of which only ``text`` blocks count."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
            if not isinstance(block, dict) or block.get("type", "text") == "text"
        )
    return "" if content is None else str(content)


def _extract_prompt(body: dict) -> tuple[str, str | None]:
    """Return ``(prompt, system)`` for a text InvokeModel request body.

    Covers every request shape in the local-inference map: Anthropic
    Messages and AI21 Jamba (``messages`` plus optional ``system``), Cohere
    Command R (``message`` plus optional ``chat_history``), and the single
    prompt families (``prompt`` for Llama/Mistral, ``inputText`` for Titan).
    """
    system = _text_of(body.get("system")) or None

    if "messages" in body:
        messages = body.get("messages") or []
        turns = [(m.get("role", "user"), _text_of(m.get("content"))) for m in messages]
        if len(turns) == 1:
            return turns[0][1], system
        # A bare concatenation would lose who said what; label the turns.
        return "\n".join(f"{role}: {text}" for role, text in turns), system

    if "message" in body:
        history = body.get("chat_history") or []
        lines = [
            f"{str(h.get('role', 'USER')).lower()}: {h.get('message', '')}" for h in history
        ]
        if not lines:
            return body.get("message") or "", system or (body.get("preamble") or None)
        lines.append(f"user: {body.get('message') or ''}")
        return "\n".join(lines), system or (body.get("preamble") or None)

    return body.get("prompt") or body.get("inputText") or "", system


def _wrap_text_response(model_id: str, prompt: str, text: str) -> dict:
    family = model_id.split(".", 1)[0]
    if family == "anthropic":
        return {
            "id": "ollama", "type": "message", "role": "assistant", "model": model_id,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": len(prompt.split()), "output_tokens": len(text.split())},
        }
    if family == "amazon":
        return {
            "inputTextTokenCount": len(prompt.split()),
            "results": [{"tokenCount": len(text.split()), "outputText": text, "completionReason": "FINISH"}],
        }
    if family == "meta":
        return {
            "generation": text, "prompt_token_count": len(prompt.split()),
            "generation_token_count": len(text.split()), "stop_reason": "stop",
        }
    if family == "mistral":
        return {"outputs": [{"text": text, "stop_reason": "stop"}]}
    if family == "cohere":
        return {"id": "ollama", "generations": [{"id": "0", "text": text}], "prompt": prompt}
    if family == "ai21":
        return {"id": "ollama", "choices": [{"message": {"role": "assistant", "content": text}}]}
    return {"output": text}


_FOUNDATION_MODEL_ARN = re.compile(r"^arn:aws[a-z-]*:bedrock:[a-z0-9-]*::foundation-model/(?P<id>.+)$")
_INFERENCE_PROFILE_PREFIXES = ("us.", "eu.", "apac.", "us-gov.", "global.")


# Providers that publish models on Bedrock. The catalog only lists models whose
# ids were verified, so a well-formed id from one of these providers is accepted
# even when it is not in the catalog (newer Claude, Nova, ...): rejecting it
# would break applications that use a real, valid model.
_BEDROCK_PROVIDERS = (
    "anthropic", "amazon", "meta", "mistral", "cohere", "ai21", "deepseek",
    "qwen", "openai", "writer", "stability", "twelvelabs", "luma", "google",
    "minimax", "moonshot", "nvidia", "zai",
)
_MODEL_ID_SHAPE = re.compile(
    r"^(?:" + "|".join(_BEDROCK_PROVIDERS) + r")\.[a-z0-9][a-z0-9._-]*(?::\d+)?$"
)


def _validate_model_id(model_id: str) -> str:
    """Return the bare foundation-model id, or raise the ValidationException
    real Bedrock raises for a malformed identifier. Accepts a plain id, a
    foundation-model ARN and a cross-region inference-profile id
    (``us.<model id>``). Ids of models outside the catalog are accepted when
    they have the shape of a Bedrock id from a known provider."""
    candidate = model_id
    if match := _FOUNDATION_MODEL_ARN.match(candidate):
        candidate = match.group("id")
    for prefix in _INFERENCE_PROFILE_PREFIXES:
        if candidate.startswith(prefix) and _MODEL_ID_SHAPE.match(candidate[len(prefix):]):
            candidate = candidate[len(prefix):]
            break
    if not catalog.get_model(candidate) and not _MODEL_ID_SHAPE.match(candidate):
        raise CommonServiceException(
            code="ValidationException",
            message="The provided model identifier is invalid.",
            status_code=400, sender_fault=True,
        )
    return candidate


def _handle_invoke_model(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    model_id = request.get("modelId") or ""
    raw_body = request.get("body") or b""
    # The "body" blob arrives as a file-like WSGI input stream, not raw
    # bytes - it's the sole REST payload for InvokeModel, same as S3's
    # PutObject "Body". Read it fully; the request is already buffered by
    # the time it reaches a provider, so this isn't a streaming concern.
    if hasattr(raw_body, "read"):
        raw_body = raw_body.read()
    model_id = _validate_model_id(model_id)
    try:
        body = json.loads(raw_body)
    except Exception:
        body = None
    if not isinstance(body, dict):
        raise CommonServiceException(
            code="ValidationException",
            message="Malformed input request, please reformat your input and try again.",
            status_code=400, sender_fault=True,
        )

    backend = _backend()
    if backend == "ollama":
        result_body = _invoke_ollama(model_id, body)
    elif backend == "synthetic":
        result_body = synthetic_backend.invoke(model_id, body)
    else:
        raise CommonServiceException(
            code="ValidationException",
            message=f"Unknown BEDROCK_BACKEND={backend!r} (expected 'synthetic' or 'ollama').",
            status_code=400, sender_fault=True,
        )

    return {
        "body": json.dumps(result_body).encode(),
        "contentType": "application/json",
    }


_INTERCEPTED_OPS = {
    "InvokeModel": _handle_invoke_model,
}


def BedrockRuntimeDispatcher(service_model) -> DispatchTable:
    # Only register what we actually implement. Every other operation
    # (Converse, InvokeModelWithResponseStream, ...) is deliberately left
    # out of the table so the router answers 501 "no handler for operation"
    # - we're not claiming coverage we don't have.
    return dict(_INTERCEPTED_OPS)


def create_bedrock_runtime_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("bedrock-runtime")
    dispatch_table = BedrockRuntimeDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="bedrock-runtime", skeleton=skeleton)
