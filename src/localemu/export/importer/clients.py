"""boto3 client construction and caching for the importer.

A single import run creates many clients across many (service, region)
pairs. Constructing a boto3 client is non-trivial — it parses credentials,
loads service models, and compiles endpoint rules — so we cache by
``(service, region)``. All clients share a single :class:`botocore.Session`
so credential resolution happens once.

Credential policy (a direct fix for a v1 bug where ``test/test`` was
baked in even for real-AWS targets):

* ``endpoint_url`` is ``None`` **and** ``access_key`` is ``None`` →
  real AWS target: defer entirely to boto3's default credential chain
  (env vars, shared config, IMDS, SSO, ...).
* ``endpoint_url`` provided → LocalEmu/LocalStack-style target: use the
  explicit credentials if given, otherwise fall back to ``test/test``
  (harmless placeholder that every local emulator accepts).
"""

from __future__ import annotations

import threading
from typing import Any

import boto3
from botocore.config import Config


class ClientFactory:
    """Thread-safe factory that caches boto3 clients by (service, region)."""

    def __init__(
        self,
        endpoint_url: str | None,
        access_key: str | None,
        secret_key: str | None,
        region: str,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._default_region = region
        self._cache: dict[tuple[str, str], Any] = {}
        self._lock = threading.Lock()

        if endpoint_url is None and access_key is None:
            # Real AWS target — rely on default credential chain.
            self._access_key: str | None = None
            self._secret_key: str | None = None
            self._use_default_chain = True
        else:
            # Local emulator or explicit creds. Only default to test/test
            # when talking to a non-AWS endpoint; never for real AWS.
            if access_key is None:
                self._access_key = "test"
                self._secret_key = "test"
            else:
                self._access_key = access_key
                self._secret_key = secret_key if secret_key is not None else "test"
            self._use_default_chain = False

        # Adaptive retries with generous max_attempts: imports hit APIs
        # hard (parallel waves, bursty) and both LocalEmu and real AWS
        # occasionally throttle under load. Adaptive mode honors retry
        # metadata from the service and backs off intelligently.
        self._botocore_config = Config(retries={"max_attempts": 10, "mode": "adaptive"})

    def get_client(self, service: str, region: str | None = None):  # type: ignore[no-untyped-def]
        """Return a cached boto3 client for ``(service, region)``.

        ``region`` defaults to the factory's default region. The returned
        client is safe to share across threads (boto3 clients are
        thread-safe for API calls, though not for client construction —
        hence the lock around the cache).
        """
        resolved_region = region or self._default_region
        key = (service, resolved_region)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
            kwargs: dict[str, object] = {
                "service_name": service,
                "region_name": resolved_region,
                "config": self._botocore_config,
            }
            if self._endpoint_url is not None:
                kwargs["endpoint_url"] = self._endpoint_url
            if not self._use_default_chain:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            client = boto3.client(**kwargs)  # type: ignore[arg-type]
            self._cache[key] = client
            return client
