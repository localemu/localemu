"""Instance health for the console's overview band.

Everything here is read from the running process and the Docker daemon
it talks to; nothing is configured for display purposes:

* version / start time / uptime from the package and process,
* IAM enforcement mode from ``IAM_ENFORCEMENT`` (read the way the
  enforcer reads it),
* Docker: a real ``ping`` + ``version`` against the daemon LocalEmu's
  container client is configured for, and a count of the containers
  LocalEmu manages, classified per service by the labels / names the
  service implementations stamp on them,
* the Bedrock Ollama sidecar (only when ``BEDROCK_BACKEND=ollama``):
  whether the container exists and whether its HTTP API answers.

Docker and Ollama probes are cached for a few seconds so a dashboard
polling the endpoint cannot hammer the daemon.
"""
from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from typing import Any

LOG = logging.getLogger(__name__)

PROBE_TTL_SECONDS = 5.0

# Value of the ``localemu.service`` container label -> console service id.
# Collected from the service implementations (``services/*/docker``,
# ``services/bedrock_runtime/ollama_backend.py``): EC2 instances and their
# networking sidecars, RDS, ECS tasks, OpenSearch, Redshift, MSK, the
# Bedrock Ollama sidecar.
_LABEL_TO_SERVICE = {
    "ec2": "ec2",
    "imds-sidecar": "ec2",
    "flow-log-sidecar": "ec2",
    "eip-proxy": "ec2",
    "nat-gateway": "vpc",
    "vpc-endpoint": "vpc",
    "rds": "rds",
    "ecs": "ecs",
    "opensearch": "opensearch",
    "redshift": "redshift",
    "msk": "kafka",
    "bedrock-ollama": "bedrock",
}
_MQ_LABEL = "localemu.mq.broker-id"
_MQ_NAME_PREFIX = "localemu-mq-"
_EKS_NAME_PREFIX = "k3d-localemu-eks"
_LAMBDA_NAME_MARKER = "-lambda-"


def classify_container(container: dict[str, Any]) -> str | None:
    """Console service id for a container from ``list_containers``, or
    ``None`` if LocalEmu does not manage it."""
    labels = container.get("labels") or {}
    name = (container.get("name") or "").lstrip("/")
    svc_label = labels.get("localemu.service")
    if svc_label:
        return _LABEL_TO_SERVICE.get(svc_label, svc_label)
    if _MQ_LABEL in labels or name.startswith(_MQ_NAME_PREFIX):
        return "mq"
    if name.startswith(_EKS_NAME_PREFIX):
        return "eks"
    if _LAMBDA_NAME_MARKER in name and name.split(_LAMBDA_NAME_MARKER, 1)[0] in _main_container_names():
        return "lambda"
    return None


def _main_container_names() -> set[str]:
    # Lambda's Docker executor names containers
    # ``<main-container-name>-lambda-<function>-<executor-id>``.
    names = {"localemu"}
    try:
        from localemu.utils.container_networking import get_main_container_name

        n = get_main_container_name()  # lru_cached
        if n:
            names.add(n)
    except Exception:
        pass
    try:
        from localemu import config

        n = getattr(config, "MAIN_CONTAINER_NAME", None)
        if n:
            names.add(n)
    except Exception:
        pass
    return names


def _env(name: str) -> str:
    return os.environ.get(name, "").strip().lower()


def docker_backends() -> dict[str, dict[str, Any]]:
    """Services whose resources can run as Docker containers, with the
    switch that controls it and whether it is on in this process's
    environment. Mirrors the checks in each provider."""
    from localemu import config

    lambda_exec = (getattr(config, "LAMBDA_RUNTIME_EXECUTOR", "") or "").strip().lower()
    return {
        "ec2": {"enabled": _env("EC2_VM_MANAGER") in ("", "docker"),
                "switch": "EC2_VM_MANAGER (default docker; none disables)"},
        "ecs": {"enabled": _env("ECS_DOCKER_BACKEND") != "0",
                "switch": "ECS_DOCKER_BACKEND (default on; 0 disables)"},
        "eks": {"enabled": _env("EKS_K8S_PROVIDER") not in ("off", "none", "metadata", "moto", "disabled")
                and shutil.which("k3d") is not None,
                "switch": "EKS_K8S_PROVIDER + k3d on PATH"},
        "opensearch": {"enabled": True, "switch": "on whenever Docker is reachable"},
        "rds": {"enabled": _env("RDS_DOCKER_BACKEND") == "1", "switch": "RDS_DOCKER_BACKEND=1"},
        "redshift": {"enabled": _env("REDSHIFT_DOCKER_BACKEND") == "1", "switch": "REDSHIFT_DOCKER_BACKEND=1"},
        "kafka": {"enabled": _env("MSK_DOCKER_BACKEND") in ("1", "true"), "switch": "MSK_DOCKER_BACKEND=1"},
        "mq": {"enabled": _env("MQ_DOCKER_BACKEND") in ("1", "true"), "switch": "MQ_DOCKER_BACKEND=1"},
        "lambda": {"enabled": lambda_exec == "docker",
                   "switch": "LAMBDA_RUNTIME_EXECUTOR (default docker)"},
        "bedrock": {"enabled": _env("BEDROCK_BACKEND") == "ollama", "switch": "BEDROCK_BACKEND=ollama"},
    }


_cache_lock = threading.Lock()
_docker_cache: tuple[float, dict] | None = None
_ollama_cache: tuple[float, dict] | None = None


def docker_status(force: bool = False) -> dict[str, Any]:
    global _docker_cache
    now = time.time()
    with _cache_lock:
        if not force and _docker_cache and now - _docker_cache[0] < PROBE_TTL_SECONDS:
            return _docker_cache[1]
    result: dict[str, Any] = {
        "available": False,
        "server_version": None,
        "error": None,
        "containers": {"managed": 0, "running": 0, "by_service": {}},
        "checked_at": now,
    }
    try:
        from localemu.utils.docker_utils import DOCKER_CLIENT

        if not DOCKER_CLIENT.has_docker():
            result["error"] = "Docker daemon not reachable from LocalEmu"
        else:
            result["available"] = True
            try:
                info = DOCKER_CLIENT.get_system_info() or {}
                result["server_version"] = info.get("ServerVersion")
                result["operating_system"] = info.get("OperatingSystem")
            except Exception as e:
                LOG.debug("docker system info failed", exc_info=True)
                result["error"] = f"docker info failed: {e}"
            try:
                by_service: dict[str, dict[str, int]] = {}
                managed = running = 0
                for c in DOCKER_CLIENT.list_containers(all=True):
                    svc = classify_container(c)
                    if not svc:
                        continue
                    managed += 1
                    is_running = str(c.get("status") or "").lower() == "running"
                    running += 1 if is_running else 0
                    slot = by_service.setdefault(svc, {"total": 0, "running": 0})
                    slot["total"] += 1
                    slot["running"] += 1 if is_running else 0
                result["containers"] = {
                    "managed": managed, "running": running, "by_service": by_service,
                }
            except Exception as e:
                LOG.debug("docker list_containers failed", exc_info=True)
                result["error"] = f"listing containers failed: {e}"
    except Exception as e:
        LOG.debug("docker probe failed", exc_info=True)
        result["error"] = f"docker client unavailable: {e}"
    with _cache_lock:
        _docker_cache = (now, result)
    return result


def ollama_status(force: bool = False) -> dict[str, Any]:
    global _ollama_cache
    backend = _env("BEDROCK_BACKEND") or "synthetic"
    if backend != "ollama":
        return {"backend": backend, "configured": False}
    now = time.time()
    with _cache_lock:
        if not force and _ollama_cache and now - _ollama_cache[0] < PROBE_TTL_SECONDS:
            return _ollama_cache[1]
    result: dict[str, Any] = {
        "backend": "ollama", "configured": True, "container": None, "running": False,
        "port": None, "reachable": False, "models": [], "detail": None,
    }
    try:
        from localemu.services.bedrock_runtime import ollama_backend

        name = getattr(ollama_backend, "CONTAINER_NAME", "localemu-bedrock-ollama")
        result["container"] = name
        port = getattr(ollama_backend, "_host_port", None)
        try:
            from localemu.utils.docker_utils import DOCKER_CLIENT

            info = DOCKER_CLIENT.inspect_container(name)
            result["running"] = bool((info.get("State") or {}).get("Running"))
            if not port:
                bindings = (info.get("HostConfig") or {}).get("PortBindings") or {}
                for b in bindings.values():
                    if b:
                        port = int(b[0].get("HostPort") or 0) or None
                        break
        except Exception:
            result["detail"] = (
                "sidecar container not created yet; LocalEmu starts it on the "
                "first InvokeModel / Converse call"
            )
        result["port"] = port
        if port and result["running"]:
            import requests

            try:
                resp = requests.get(f"http://localhost:{port}/api/tags", timeout=2)
                result["reachable"] = resp.status_code == 200
                if resp.ok:
                    result["models"] = [
                        m.get("name") for m in (resp.json() or {}).get("models", []) if m.get("name")
                    ]
            except Exception as e:
                result["detail"] = f"container running but API not answering: {e}"
    except Exception as e:
        result["detail"] = f"ollama backend module unavailable: {e}"
    with _cache_lock:
        _ollama_cache = (now, result)
    return result


def system_snapshot(request_host_url: str | None = None) -> dict[str, Any]:
    from localemu import config, constants

    from .api import _start_time, iam_enforcement_mode

    endpoint = None
    if request_host_url:
        endpoint = request_host_url.rstrip("/")
    if not endpoint:
        try:
            endpoint = config.external_service_url()
        except Exception:
            endpoint = f"http://localhost:{config.GATEWAY_LISTEN[0].port}"
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("DEFAULT_REGION") or "us-east-1"
    return {
        "version": constants.VERSION,
        "endpoint": endpoint,
        "port": config.GATEWAY_LISTEN[0].port,
        "default_region": region,
        "started_at": _start_time,
        "uptime_seconds": int(time.time() - _start_time),
        "iam_enforcement": iam_enforcement_mode(),
        "persistence": bool(getattr(config, "PERSISTENCE", False)),
        "docker": docker_status(),
        "docker_backends": docker_backends(),
        "bedrock": ollama_status(),
    }
