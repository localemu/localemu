"""Docker-backed Ollama sidecar for BEDROCK_BACKEND=ollama.

One shared container for the whole LocalEmu instance (unlike OpenSearch's
one-container-per-domain: Bedrock models aren't a per-resource concept,
they're a shared inference endpoint), running the official ``ollama/ollama``
image. Model weights are pulled into it lazily, on the first InvokeModel
call that needs them - not at startup - so enabling this backend doesn't
mean downloading anything until a model is actually requested.
"""
from __future__ import annotations

import logging
import threading

from localemu.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localemu.utils.docker_utils import DOCKER_CLIENT
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)

CONTAINER_NAME = "localemu-bedrock-ollama"
IMAGE = "ollama/ollama:latest"
CONTAINER_LABEL = "localemu.service=bedrock-ollama"

_lock = threading.Lock()
_host_port: int | None = None
_pulled_tags: set[str] = set()


def _ensure_container() -> int:
    """Start the shared Ollama container if it isn't already running.

    Returns the host port it's reachable on. Thread-safe and idempotent -
    safe to call before every InvokeModel.
    """
    global _host_port
    with _lock:
        if _host_port is not None:
            return _host_port

        try:
            info = DOCKER_CLIENT.inspect_container(CONTAINER_NAME)
            running = (info.get("State") or {}).get("Running")
            if not running:
                DOCKER_CLIENT.start_container(CONTAINER_NAME)
            port_bindings = (
                info.get("HostConfig", {}).get("PortBindings", {})
                or info.get("NetworkSettings", {}).get("Ports", {})
            )
            for bindings in port_bindings.values():
                if bindings:
                    _host_port = int(bindings[0]["HostPort"])
                    break
            if _host_port:
                LOG.info("Reusing existing Ollama container on port %s", _host_port)
                return _host_port
        except Exception:
            pass  # No existing container - create one below.

        try:
            DOCKER_CLIENT.inspect_image(IMAGE)
        except Exception:
            LOG.info("Pulling Ollama image %s (one-time)...", IMAGE)
            DOCKER_CLIENT.pull_image(IMAGE)

        host_port = get_free_tcp_port()
        ports = PortMappings()
        ports.add(host_port, 11434)
        volumes = VolumeMappings()
        volumes.add(("localemu-bedrock-ollama-data", "/root/.ollama"))

        config = ContainerConfiguration(
            image_name=IMAGE,
            name=CONTAINER_NAME,
            ports=ports,
            volumes=volumes,
            detach=True,
            labels={"localemu.service": "bedrock-ollama"},
        )
        DOCKER_CLIENT.create_container_from_config(config)
        DOCKER_CLIENT.start_container(CONTAINER_NAME)

        _wait_for_ready(host_port)
        _host_port = host_port
        LOG.info("Ollama sidecar ready on port %s", host_port)
        return _host_port


def _wait_for_ready(port: int, timeout: int = 60) -> None:
    import time

    import requests

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"http://localhost:{port}/api/tags", timeout=3).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(f"Ollama sidecar did not become ready within {timeout}s")


def ensure_model_pulled(tag: str) -> None:
    """Pull a model into the shared container, if not already present.

    Blocks until the pull finishes (or fails) - this is the slow part
    (multi-GB downloads), by design: a caller awaiting InvokeModel should
    know up front, not get a confusing empty response mid-pull.
    """
    if tag in _pulled_tags:
        return
    port = _ensure_container()

    import requests

    LOG.info("Pulling Ollama model %s (this can take a while on first use)...", tag)
    with requests.post(
        f"http://localhost:{port}/api/pull", json={"name": tag}, stream=True, timeout=None,
    ) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            import json as _json

            try:
                status = _json.loads(line).get("status", "")
            except Exception:
                continue
            if status == "success":
                break
    _pulled_tags.add(tag)
    LOG.info("Ollama model %s ready", tag)


def generate(tag: str, prompt: str, system: str | None = None) -> str:
    ensure_model_pulled(tag)
    port = _ensure_container()

    import requests

    payload = {"model": tag, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system
    resp = requests.post(
        f"http://localhost:{port}/api/generate", json=payload, timeout=300,
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def embed(tag: str, text: str) -> list[float]:
    ensure_model_pulled(tag)
    port = _ensure_container()

    import requests

    resp = requests.post(
        f"http://localhost:{port}/api/embeddings",
        json={"model": tag, "prompt": text},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("embedding", [])
