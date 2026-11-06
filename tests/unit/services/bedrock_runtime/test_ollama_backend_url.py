"""The Ollama sidecar must be reached at an address that works from where
LocalEmu runs. Inside the LocalEmu container, ``localhost:<published port>``
is that container itself, so the sidecar's own address comes first."""
from types import SimpleNamespace

import pytest

from localemu.services.bedrock_runtime import ollama_backend


class _FakeDocker:
    def __init__(self, ip=None, error=None):
        self.ip, self.error = ip, error

    def get_container_ip(self, name):
        if self.error:
            raise self.error
        return self.ip


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(ollama_backend, "_base_url", None)
    monkeypatch.setattr(ollama_backend, "_host_port", None)


def test_container_address_is_tried_before_localhost(monkeypatch):
    monkeypatch.setattr(ollama_backend, "DOCKER_CLIENT", _FakeDocker(ip="172.17.0.7"))
    assert ollama_backend._candidate_urls(51357) == [
        "http://172.17.0.7:11434",
        "http://localhost:51357",
    ]


def test_localhost_is_the_fallback_when_the_container_has_no_address(monkeypatch):
    monkeypatch.setattr(ollama_backend, "DOCKER_CLIENT", _FakeDocker(ip=None))
    assert ollama_backend._candidate_urls(51357) == ["http://localhost:51357"]


def test_localhost_is_the_fallback_when_the_lookup_fails(monkeypatch):
    monkeypatch.setattr(ollama_backend, "DOCKER_CLIENT", _FakeDocker(error=RuntimeError("no docker")))
    assert ollama_backend._candidate_urls(51357) == ["http://localhost:51357"]


def _fake_get(reachable):
    def get(url, timeout):
        if not any(url.startswith(r) for r in reachable):
            raise ConnectionError(url)
        return SimpleNamespace(status_code=200)

    return get


def test_ready_check_returns_the_address_that_answers(monkeypatch):
    import requests

    monkeypatch.setattr(ollama_backend, "DOCKER_CLIENT", _FakeDocker(ip="172.17.0.7"))
    # LocalEmu in a container: only the container address answers
    monkeypatch.setattr(requests, "get", _fake_get(["http://172.17.0.7:11434"]))
    assert ollama_backend._wait_for_ready(51357, timeout=5) == "http://172.17.0.7:11434"
    # LocalEmu on the host (Docker Desktop): only the published port answers
    monkeypatch.setattr(requests, "get", _fake_get(["http://localhost:51357"]))
    assert ollama_backend._wait_for_ready(51357, timeout=5) == "http://localhost:51357"


def test_ready_check_raises_when_nothing_answers(monkeypatch):
    import requests

    monkeypatch.setattr(ollama_backend, "DOCKER_CLIENT", _FakeDocker(ip=None))
    monkeypatch.setattr(requests, "get", _fake_get([]))
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(RuntimeError, match="did not become ready"):
        ollama_backend._wait_for_ready(51357, timeout=0)
