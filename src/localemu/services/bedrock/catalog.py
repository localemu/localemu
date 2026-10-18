"""Foundation model catalog backing ListFoundationModels / GetFoundationModel.

Moto's vendored Bedrock backend has no route for either call at all - see
``provider.py``. This is NOT the full ~150-model Bedrock catalog: it's a
curated, verified subset covering the long-established model families
(Anthropic Claude 3.x, Amazon Titan, Meta Llama 3/3.1/3.2, Mistral/Mixtral,
Cohere, AI21 Jamba) whose exact ``modelId`` strings are well documented and
stable.

Several newer (2025/2026) provider families now listed on
https://docs.aws.amazon.com/bedrock/latest/userguide/model-cards.html -
DeepSeek, Qwen, Z.AI (GLM), Moonshot (Kimi), OpenAI gpt-oss, NVIDIA
Nemotron, Google Gemma 4 - are deliberately NOT included here: their exact
Bedrock ``modelId`` strings weren't confirmed at the time this catalog was
written, and a wrong invented ID would be worse than an honest gap. Adding
them (with verified IDs) is a good follow-up contribution - see
``local_inference.py`` for the matching local-inference side of the same
gap.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FoundationModel:
    model_id: str
    provider_name: str
    model_name: str
    input_modalities: list[str]
    output_modalities: list[str]
    response_streaming_supported: bool = True
    customizations_supported: list[str] = field(default_factory=list)
    inference_types_supported: list[str] = field(default_factory=lambda: ["ON_DEMAND"])
    lifecycle_status: str = "ACTIVE"


FOUNDATION_MODELS: list[FoundationModel] = [
    # --------------------------- Anthropic ---------------------------
    FoundationModel(
        model_id="anthropic.claude-3-haiku-20240307-v1:0",
        provider_name="Anthropic", model_name="Claude 3 Haiku",
        input_modalities=["TEXT", "IMAGE"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        provider_name="Anthropic", model_name="Claude 3.5 Sonnet",
        input_modalities=["TEXT", "IMAGE"], output_modalities=["TEXT"],
    ),
    # --------------------------- Amazon ---------------------------
    FoundationModel(
        model_id="amazon.titan-text-express-v1",
        provider_name="Amazon", model_name="Titan Text Express",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="amazon.titan-embed-text-v1",
        provider_name="Amazon", model_name="Titan Embeddings G1 - Text",
        input_modalities=["TEXT"], output_modalities=["EMBEDDING"],
        response_streaming_supported=False,
    ),
    FoundationModel(
        model_id="amazon.titan-embed-text-v2:0",
        provider_name="Amazon", model_name="Titan Text Embeddings V2",
        input_modalities=["TEXT"], output_modalities=["EMBEDDING"],
        response_streaming_supported=False,
    ),
    # --------------------------- Meta ---------------------------
    FoundationModel(
        model_id="meta.llama3-8b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3 8B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-70b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3 70B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-1-8b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.1 8B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-1-70b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.1 70B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-1-405b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.1 405B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-2-1b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.2 1B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-2-3b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.2 3B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-2-11b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.2 11B Instruct",
        input_modalities=["TEXT", "IMAGE"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="meta.llama3-2-90b-instruct-v1:0",
        provider_name="Meta", model_name="Llama 3.2 90B Instruct",
        input_modalities=["TEXT", "IMAGE"], output_modalities=["TEXT"],
    ),
    # --------------------------- Mistral AI ---------------------------
    FoundationModel(
        model_id="mistral.mistral-7b-instruct-v0:2",
        provider_name="Mistral AI", model_name="Mistral 7B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="mistral.mixtral-8x7b-instruct-v0:1",
        provider_name="Mistral AI", model_name="Mixtral 8x7B Instruct",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="mistral.mistral-large-2402-v1:0",
        provider_name="Mistral AI", model_name="Mistral Large",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    # --------------------------- Cohere ---------------------------
    FoundationModel(
        model_id="cohere.command-r-v1:0",
        provider_name="Cohere", model_name="Command R",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
    FoundationModel(
        model_id="cohere.embed-english-v3",
        provider_name="Cohere", model_name="Embed English",
        input_modalities=["TEXT"], output_modalities=["EMBEDDING"],
        response_streaming_supported=False,
    ),
    FoundationModel(
        model_id="cohere.embed-multilingual-v3",
        provider_name="Cohere", model_name="Embed Multilingual",
        input_modalities=["TEXT"], output_modalities=["EMBEDDING"],
        response_streaming_supported=False,
    ),
    # --------------------------- AI21 Labs ---------------------------
    FoundationModel(
        model_id="ai21.jamba-1-5-large-v1:0",
        provider_name="AI21 Labs", model_name="Jamba 1.5 Large",
        input_modalities=["TEXT"], output_modalities=["TEXT"],
    ),
]

_BY_ID = {m.model_id: m for m in FOUNDATION_MODELS}


def get_model(model_id: str) -> FoundationModel | None:
    return _BY_ID.get(model_id)


def to_wire(model: FoundationModel, *, region: str, account_id: str) -> dict:
    """Shape a FoundationModel as the ListFoundationModels/GetFoundationModel wire dict."""
    return {
        "modelArn": f"arn:aws:bedrock:{region}:{account_id}:foundation-model/{model.model_id}",
        "modelId": model.model_id,
        "modelName": model.model_name,
        "providerName": model.provider_name,
        "inputModalities": model.input_modalities,
        "outputModalities": model.output_modalities,
        "responseStreamingSupported": model.response_streaming_supported,
        "customizationsSupported": model.customizations_supported,
        "inferenceTypesSupported": model.inference_types_supported,
        "modelLifecycle": {"status": model.lifecycle_status},
    }
