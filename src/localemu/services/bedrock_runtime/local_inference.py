"""Model-id -> local-Ollama-model mapping, with an honest fidelity label and
a minimum machine RAM *tier* per entry.

Every entry answers three questions for ``BEDROCK_BACKEND=ollama``:

  1. What local model actually runs this request?
  2. How faithful is that substitution to the real Bedrock model
     ("same_family" - it's genuinely the same model weights family;
     "distilled" - a distillation of the real model, not the real thing;
     "different_family" - a different model entirely, e.g. standing in
     for a closed-weight model like Claude)?
  3. What machine RAM tier (16 / 32 / 64GB total) does this model belong
     to? See ``memory_gate.py`` - this is a one-time check against the
     machine's total physical RAM, not a live/available-memory probe.

Models whose *real* weights are too large to run on a 16-64GB dev machine
at any reasonable quantization (Llama 3.1 405B, Mistral Large, etc.) are
listed with ``ollama_tag=None`` so the error path is explicit and
informative rather than a confusing failure three layers down.
"""
from __future__ import annotations

from dataclasses import dataclass

FIDELITY_SAME_FAMILY = "same_family"
FIDELITY_DISTILLED = "distilled"
FIDELITY_DIFFERENT_FAMILY = "different_family"
FIDELITY_UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class LocalInferenceSpec:
    ollama_tag: str | None
    min_total_ram_gb: int | None
    fidelity: str
    modality: str  # "TEXT" | "EMBEDDING"
    note: str = ""


LOCAL_INFERENCE_MAP: dict[str, LocalInferenceSpec] = {
    # --------------------------- Anthropic (closed-weight: no real local
    # equivalent exists at all - these are an explicitly different model
    # family standing in so InvokeModel has something real to call). ---
    "anthropic.claude-3-haiku-20240307-v1:0": LocalInferenceSpec(
        "llama3.1:8b", 16, FIDELITY_DIFFERENT_FAMILY, "TEXT",
        note="Claude has no open weights. This runs Llama 3.1 8B instead - "
             "a real model, not the real Claude.",
    ),
    "anthropic.claude-3-5-sonnet-20240620-v1:0": LocalInferenceSpec(
        "llama3.1:8b", 16, FIDELITY_DIFFERENT_FAMILY, "TEXT",
        note="Claude has no open weights. This runs Llama 3.1 8B instead - "
             "a real model, not the real Claude.",
    ),

    # --------------------------- Amazon Titan (closed-weight) ---------
    "amazon.titan-embed-text-v1": LocalInferenceSpec(
        "nomic-embed-text", 16, FIDELITY_DIFFERENT_FAMILY, "EMBEDDING",
    ),
    "amazon.titan-embed-text-v2:0": LocalInferenceSpec(
        "nomic-embed-text", 16, FIDELITY_DIFFERENT_FAMILY, "EMBEDDING",
    ),
    "amazon.titan-text-express-v1": LocalInferenceSpec(
        "llama3.1:8b", 16, FIDELITY_DIFFERENT_FAMILY, "TEXT",
    ),

    # --------------------------- Meta Llama (open-weight: genuinely the
    # same model family, just a specific size/quantization). ------------
    "meta.llama3-8b-instruct-v1:0": LocalInferenceSpec("llama3:8b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-1-8b-instruct-v1:0": LocalInferenceSpec("llama3.1:8b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-2-1b-instruct-v1:0": LocalInferenceSpec("llama3.2:1b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-2-3b-instruct-v1:0": LocalInferenceSpec("llama3.2:3b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-2-11b-instruct-v1:0": LocalInferenceSpec("llama3.2-vision:11b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-70b-instruct-v1:0": LocalInferenceSpec("llama3:70b", 64, FIDELITY_SAME_FAMILY, "TEXT"),
    "meta.llama3-1-70b-instruct-v1:0": LocalInferenceSpec("llama3.1:70b", 64, FIDELITY_SAME_FAMILY, "TEXT"),
    # Real weights: ~405B params. No quantization gets this under 64GB.
    "meta.llama3-1-405b-instruct-v1:0": LocalInferenceSpec(
        None, None, FIDELITY_UNAVAILABLE, "TEXT",
        note="Llama 3.1 405B needs ~230GB+ RAM even at 4-bit quantization - "
             "not realistic on a dev machine. Use BEDROCK_BACKEND=synthetic "
             "for this model id.",
    ),
    "meta.llama3-2-90b-instruct-v1:0": LocalInferenceSpec(
        None, None, FIDELITY_UNAVAILABLE, "TEXT",
        note="Llama 3.2 90B needs more RAM than a 64GB dev machine "
             "reasonably has. Use BEDROCK_BACKEND=synthetic for this model id.",
    ),

    # --------------------------- Mistral AI (open-weight) ---------------
    "mistral.mistral-7b-instruct-v0:2": LocalInferenceSpec("mistral:7b", 16, FIDELITY_SAME_FAMILY, "TEXT"),
    "mistral.mixtral-8x7b-instruct-v0:1": LocalInferenceSpec(
        "mixtral:8x7b", 32, FIDELITY_SAME_FAMILY, "TEXT",
        note="Mixtral 8x7B's total weight footprint (~47B params, all "
             "loaded regardless of per-token routing) needs 32GB+ RAM.",
    ),
    # Mistral Large is closed-weight (proprietary) despite the "Mistral AI"
    # brand - there is no open-weight equivalent to run locally at all.
    "mistral.mistral-large-2402-v1:0": LocalInferenceSpec(
        None, None, FIDELITY_UNAVAILABLE, "TEXT",
        note="Mistral Large is closed-weight - no local equivalent exists. "
             "Use BEDROCK_BACKEND=synthetic for this model id.",
    ),

    # --------------------------- Cohere (closed-weight) -----------------
    "cohere.command-r-v1:0": LocalInferenceSpec(
        "mistral:7b", 16, FIDELITY_DIFFERENT_FAMILY, "TEXT",
        note="Command R has no open weights. This runs Mistral 7B instead.",
    ),
    "cohere.embed-english-v3": LocalInferenceSpec("nomic-embed-text", 16, FIDELITY_DIFFERENT_FAMILY, "EMBEDDING"),
    "cohere.embed-multilingual-v3": LocalInferenceSpec("nomic-embed-text", 16, FIDELITY_DIFFERENT_FAMILY, "EMBEDDING"),

    # --------------------------- AI21 Labs (closed-weight) --------------
    "ai21.jamba-1-5-large-v1:0": LocalInferenceSpec(
        None, None, FIDELITY_UNAVAILABLE, "TEXT",
        note="Jamba 1.5 Large is closed-weight at this size - no local "
             "equivalent curated. Use BEDROCK_BACKEND=synthetic for this model id.",
    ),
}


def get_spec(model_id: str) -> LocalInferenceSpec | None:
    return LOCAL_INFERENCE_MAP.get(model_id)
