"""The zero-dependency default InvokeModel backend: no Docker, no Ollama,
no download, works the instant LocalEmu starts. Deterministic per input
(same prompt -> same output), so tests built on top of it stay stable.

Each model family's real InvokeModel response has its own JSON body shape
(Anthropic's Messages format, Titan's, Llama's, Mistral's, Cohere's, ...).
This mirrors each shape closely enough that application code written
against the real Bedrock API (such as 08-llm-gateway's BedrockLLMClient)
parses it without changes - the values are synthetic, the shape is real.
"""
from __future__ import annotations

import hashlib
import json


def _seed(text: str) -> int:
    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)


def _synthetic_text(prompt: str) -> str:
    digest = hashlib.sha256(prompt.encode()).hexdigest()[:12]
    return (
        f"[synthetic LocalEmu response, BEDROCK_BACKEND=synthetic, "
        f"prompt-digest={digest}] This is a deterministic placeholder, not "
        f"a real model output. Set BEDROCK_BACKEND=ollama for real local "
        f"inference."
    )


def _synthetic_embedding(text: str, dim: int) -> list[float]:
    seed = _seed(text)
    return [((seed * (i + 1)) % 1000) / 1000.0 for i in range(dim)]


def _family(model_id: str) -> str:
    return model_id.split(".", 1)[0] if "." in model_id else model_id


def invoke(model_id: str, body: dict) -> dict:
    """Return a synthetic response body shaped like the real model family's."""
    family = _family(model_id)

    if family == "anthropic":
        prompt = json.dumps(body.get("messages", body.get("prompt", "")))
        return {
            "id": f"msg_synthetic_{_seed(prompt):08x}",
            "type": "message",
            "role": "assistant",
            "model": model_id,
            "content": [{"type": "text", "text": _synthetic_text(prompt)}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": len(prompt.split()), "output_tokens": 32},
        }

    if family == "amazon" and "embed" in model_id:
        text = body.get("inputText", "")
        dim = 1024 if "v2" in model_id else 1536
        return {"embedding": _synthetic_embedding(text, dim), "inputTextTokenCount": len(text.split())}

    if family == "amazon":
        prompt = body.get("inputText", "")
        return {
            "inputTextTokenCount": len(prompt.split()),
            "results": [{
                "tokenCount": 32,
                "outputText": _synthetic_text(prompt),
                "completionReason": "FINISH",
            }],
        }

    if family == "meta":
        prompt = body.get("prompt", "")
        return {
            "generation": _synthetic_text(prompt),
            "prompt_token_count": len(prompt.split()),
            "generation_token_count": 32,
            "stop_reason": "stop",
        }

    if family == "mistral":
        prompt = body.get("prompt", "")
        return {"outputs": [{"text": _synthetic_text(prompt), "stop_reason": "stop"}]}

    if family == "cohere" and "embed" in model_id:
        texts = body.get("texts", [])
        dim = 1024
        return {
            "id": f"embed_synthetic_{_seed(str(texts)):08x}",
            "texts": texts,
            "embeddings": [_synthetic_embedding(t, dim) for t in texts] or [_synthetic_embedding("", dim)],
            "response_type": "embeddings_floats",
        }

    if family == "cohere":
        prompt = body.get("prompt", body.get("message", ""))
        return {
            "id": f"gen_synthetic_{_seed(prompt):08x}",
            "generations": [{"id": "0", "text": _synthetic_text(prompt)}],
            "prompt": prompt,
        }

    if family == "ai21":
        prompt = body.get("messages", body.get("prompt", ""))
        prompt_str = json.dumps(prompt)
        return {
            "id": f"ai21_synthetic_{_seed(prompt_str):08x}",
            "choices": [{"message": {"role": "assistant", "content": _synthetic_text(prompt_str)}}],
        }

    # Unknown family: a generic-but-honest fallback rather than a crash.
    return {"output": _synthetic_text(json.dumps(body))}
