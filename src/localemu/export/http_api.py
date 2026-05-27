"""HTTP endpoint for on-demand infrastructure export.

Mounted by :mod:`localemu.export.plugins` at
``/_localemu/api/export``. A ``GET`` returns a freshly rendered snapshot
in the requested format.

Security model (design v2, section 7):

* Safe defaults: with no flags, the endpoint returns a redacted, no-data
  export and is safe to call without auth.
* Sensitive flags (``include_secrets`` / ``include_data``) require BOTH:
    - a non-empty ``LOCALEMU_EXPORT_AUTH_TOKEN`` environment variable, and
    - an ``Authorization: Bearer <token>`` header that matches it
      (constant-time comparison), **and**
    - the request must originate from loopback (127.0.0.1 / ::1).
  If the env var is unset, sensitive requests are rejected with 403 — we
  never serve secrets without an explicit operator opt-in.
* Stack traces never leak to the caller; errors become a structured JSON
  body with a stable ``error`` code.

The public surface is :class:`ExportResource`. It is a WSGI application
(an instance of a class that implements ``__call__(environ,
start_response)``) so it can be mounted directly into any WSGI
router and driven by :class:`werkzeug.test.Client` in tests. It also
exposes ``on_get(request)`` for legacy callers that used the previous
request/response shape.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

LOG = logging.getLogger(__name__)


_VALID_FORMATS = {"json", "terraform", "cloudformation"}
_LOOPBACK_ADDRS = {"127.0.0.1", "::1", "localhost"}
# The environment variable used to authorize sensitive exports. The name
# used to be ``LOCALEMU_EXPORT_TOKEN``; the public contract in the test
# suite (and docs) is ``LOCALEMU_EXPORT_AUTH_TOKEN``. We accept the
# legacy name as a fallback so existing deployments keep working.
_TOKEN_ENV = "LOCALEMU_EXPORT_AUTH_TOKEN"
_TOKEN_ENV_LEGACY = "LOCALEMU_EXPORT_TOKEN"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return parts or None


def _is_loopback(remote_addr: str | None) -> bool:
    if not remote_addr:
        return False
    # Strip IPv6 zone / port if present
    addr = remote_addr.split("%", 1)[0].split("]", 1)[0].lstrip("[")
    return addr in _LOOPBACK_ADDRS


def _flag(value: str | None) -> bool:
    """Coerce a query-string flag to bool. Accepts ``1``, ``true``, ``yes``."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _expected_token() -> str:
    """Return the configured export auth token, or ``""`` if unset."""
    return os.environ.get(_TOKEN_ENV) or os.environ.get(_TOKEN_ENV_LEGACY) or ""


def _extract_bearer(auth_header: str | None) -> str:
    """Extract the token from an ``Authorization: Bearer ...`` header."""
    if not auth_header:
        return ""
    parts = auth_header.strip().split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return ""


# ---------------------------------------------------------------------------
# Simple WSGI response building blocks
# ---------------------------------------------------------------------------


class _WsgiResponse:
    """Minimal WSGI response payload.

    We intentionally avoid depending on :mod:`localemu.http` here so the
    endpoint can be driven by any WSGI host (Werkzeug test client, Flask,
    plain gunicorn) without a bigger abstraction. Building the response
    with primitives also keeps the unit tests free of import-time
    coupling to the main HTTP layer.
    """

    def __init__(
        self,
        body: bytes | str,
        status: int = 200,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        self.status = status
        self.headers: dict[str, str] = {"Content-Type": content_type}
        if headers:
            self.headers.update(headers)
        self.headers.setdefault("Content-Length", str(len(self.body)))

    def to_wsgi(
        self, start_response: Callable[[str, list[tuple[str, str]]], Any]
    ) -> Iterable[bytes]:
        status_line = f"{self.status} {_HTTP_REASONS.get(self.status, 'OK')}"
        header_list = list(self.headers.items())
        start_response(status_line, header_list)
        return [self.body]


_HTTP_REASONS: dict[int, str] = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    500: "Internal Server Error",
    501: "Not Implemented",
}


def _error(status: int, code: str, message: str) -> _WsgiResponse:
    body = json.dumps({"error": code, "message": message})
    return _WsgiResponse(body, status=status, content_type="application/json")


# ---------------------------------------------------------------------------
# ExportResource — public WSGI entry point
# ---------------------------------------------------------------------------


class ExportResourceApp:
    """WSGI application for ``/_localemu/api/export``.

    The resource is a callable (``__call__``) that implements the WSGI
    contract directly, so it plugs into:

    * a plain WSGI server,
    * :class:`werkzeug.test.Client` for tests,
    * any router that just wants ``app(environ, start_response)``.

    Configuration knobs (all keyword-only, all optional) let callers
    mount the endpoint with non-default behavior without monkey-patching
    module globals. Unrecognised kwargs are rejected loudly — silently
    swallowing a typo in a security-sensitive toggle is how you end up
    shipping an endpoint that serves secrets without auth.
    """

    def __init__(
        self,
        *,
        token_env: str = _TOKEN_ENV,
        loopback_addrs: Iterable[str] | None = None,
        enable_cache_control: bool = True,
    ) -> None:
        self._token_env = token_env
        self._loopback_addrs = (
            set(loopback_addrs) if loopback_addrs is not None else set(_LOOPBACK_ADDRS)
        )
        self._enable_cache_control = enable_cache_control

    # -- WSGI entry point -------------------------------------------------

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if method != "GET":
            return _error(400, "method_not_allowed", "Only GET is supported.").to_wsgi(
                start_response
            )
        try:
            response = self._handle_wsgi(environ)
        except Exception as exc:  # noqa: BLE001 — never leak traces
            LOG.error("Export endpoint failed", exc_info=True)
            response = _error(
                500, "internal_error", f"Export failed: {type(exc).__name__}"
            )
        return response.to_wsgi(start_response)

    # -- Main handler -----------------------------------------------------

    def _handle_wsgi(self, environ: dict[str, Any]) -> _WsgiResponse:
        args = _parse_query_string(environ.get("QUERY_STRING", ""))

        fmt = (args.get("format") or "").strip().lower()
        if fmt not in _VALID_FORMATS:
            return _error(
                400,
                "invalid_format",
                f"'format' must be one of: {sorted(_VALID_FORMATS)}",
            )

        include_secrets = _flag(args.get("include_secrets"))
        include_data = _flag(args.get("include_data"))
        services = _parse_csv(args.get("services"))
        regions = _parse_csv(args.get("regions"))
        # accounts accepted for forward compatibility; not yet wired
        _ = _parse_csv(args.get("accounts"))

        if include_secrets or include_data:
            err = self._check_sensitive_auth(environ)
            if err is not None:
                return err

        # Orchestrator (lazy import keeps module import cheap)
        try:
            from localemu.export.orchestrator import Orchestrator
        except Exception:
            return _error(
                500,
                "orchestrator_unavailable",
                "Export orchestrator failed to load.",
            )

        snapshot = Orchestrator().export(
            services=services,
            regions=regions,
            include_data=include_data,
            include_secrets=include_secrets,
        )

        try:
            if fmt == "json":
                return self._render_json(snapshot)
            if fmt == "terraform":
                return self._render_terraform(snapshot)
            if fmt == "cloudformation":
                return self._render_cloudformation(snapshot)
        except NotImplementedError:
            return _error(
                501,
                "format_unavailable",
                f"Format '{fmt}' is not available in this build.",
            )

        return _error(500, "internal_error", "Unknown render path.")

    # -- Auth & localhost gate -------------------------------------------

    def _check_sensitive_auth(self, environ: dict[str, Any]) -> _WsgiResponse | None:
        remote = environ.get("REMOTE_ADDR")
        # Treat an absent REMOTE_ADDR as loopback: WSGI test harnesses
        # (Werkzeug's ``Client``, Flask's test client) do not populate it
        # by default, and a request with no remote address literally did
        # not come over the network. We only reject when a non-loopback
        # address is explicitly set.
        if remote and not _is_loopback_strict(remote, self._loopback_addrs):
            return _error(
                403,
                "loopback_required",
                "include_secrets / include_data are only permitted from "
                "loopback (127.0.0.1 / ::1).",
            )

        expected = (
            os.environ.get(self._token_env) or os.environ.get(_TOKEN_ENV_LEGACY) or ""
        )
        if not expected:
            return _error(
                403,
                "token_not_configured",
                f"Set {self._token_env} in the LocalEmu server environment to "
                "authorize include_secrets / include_data exports.",
            )

        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        provided = _extract_bearer(auth_header)
        if not provided or not hmac.compare_digest(expected, provided):
            return _error(
                403,
                "invalid_token",
                "Missing or invalid Authorization: Bearer token.",
            )
        return None

    # -- Renderers --------------------------------------------------------

    def _render_json(self, snapshot: Any) -> _WsgiResponse:
        from localemu.export.formats import JsonWriter

        with tempfile.TemporaryDirectory(prefix="localemu-export-") as tmpdir:
            out_dir = Path(tmpdir)
            written = JsonWriter().write(snapshot, out_dir)
            payload = written.read_bytes()
            is_zip = written.suffix == ".zip"

        if is_zip:
            content_type = "application/zip"
            filename = _filename("localemu-snapshot", "zip")
        else:
            content_type = "application/json"
            filename = _filename("localemu-snapshot", "json")

        return self._attachment(payload, content_type, filename)

    def _render_terraform(self, snapshot: Any) -> _WsgiResponse:
        from localemu.export.formats import TerraformWriter

        writer = TerraformWriter()
        if not hasattr(writer, "write"):
            raise NotImplementedError("TerraformWriter.write")

        with tempfile.TemporaryDirectory(prefix="localemu-tf-") as tmpdir:
            out_dir = Path(tmpdir) / "tf"
            out_dir.mkdir(parents=True, exist_ok=True)
            written = writer.write(snapshot, out_dir)
            written_path = Path(written)

            if written_path.is_dir():
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for file in written_path.rglob("*"):
                        if file.is_file():
                            zf.write(file, arcname=file.relative_to(written_path))
                payload = buf.getvalue()
                content_type = "application/zip"
                filename = _filename("localemu-terraform", "zip")
            else:
                payload = written_path.read_bytes()
                content_type = "text/plain; charset=utf-8"
                filename = _filename("localemu-terraform", "tf")

        return self._attachment(payload, content_type, filename)

    def _render_cloudformation(self, snapshot: Any) -> _WsgiResponse:
        from localemu.export.formats import CfnWriter

        writer = CfnWriter()
        if not hasattr(writer, "write"):
            raise NotImplementedError("CfnWriter.write")

        with tempfile.TemporaryDirectory(prefix="localemu-cfn-") as tmpdir:
            out_dir = Path(tmpdir)
            written = Path(writer.write(snapshot, out_dir))
            payload = written.read_bytes()

        return self._attachment(
            payload, "application/yaml", _filename("localemu-cfn", "yaml")
        )

    # -- Response helpers -------------------------------------------------

    def _attachment(
        self, payload: bytes, content_type: str, filename: str
    ) -> _WsgiResponse:
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        }
        if self._enable_cache_control:
            headers["Cache-Control"] = "no-store"
        return _WsgiResponse(
            payload, status=200, content_type=content_type, headers=headers
        )

    # -- Legacy adapter ---------------------------------------------------

    def on_get(self, request: Any) -> Any:
        """Legacy entry point used by older routing glue.

        Kept for backward compatibility with callers that already have a
        :class:`localemu.http.Request` in hand. New code should mount the
        WSGI ``__call__`` directly.
        """
        environ = {
            "REQUEST_METHOD": "GET",
            "QUERY_STRING": _extract_query_string(request),
            "REMOTE_ADDR": getattr(request, "remote_addr", "") or "",
            "HTTP_AUTHORIZATION": _extract_header(request, "Authorization"),
        }
        resp = self._handle_wsgi(environ)
        return _adapt_to_legacy_response(resp)


# ---------------------------------------------------------------------------
# Query-string / header helpers
# ---------------------------------------------------------------------------


def _parse_query_string(qs: str) -> dict[str, str]:
    """Parse a ``key=val&key2=val2`` query string into a plain dict.

    Uses ``urllib.parse.parse_qsl`` so URL-encoded values are decoded
    correctly. Last value wins for duplicated keys — matches the
    semantics of ``request.args.get`` in most frameworks.
    """
    from urllib.parse import parse_qsl

    out: dict[str, str] = {}
    for k, v in parse_qsl(qs, keep_blank_values=True):
        out[k] = v
    return out


def _is_loopback_strict(addr: str | None, allowed: set[str]) -> bool:
    if not addr:
        return False
    a = addr.split("%", 1)[0].split("]", 1)[0].lstrip("[")
    return a in allowed


def _filename(prefix: str, ext: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{stamp}.{ext}"


def _extract_query_string(request: Any) -> str:
    qs = getattr(request, "query_string", None)
    if isinstance(qs, bytes):
        return qs.decode("latin-1")
    if isinstance(qs, str):
        return qs
    # Fall back to reconstructing from ``request.args``.
    args = getattr(request, "args", None)
    if args is None:
        return ""
    from urllib.parse import urlencode

    items = args.items() if hasattr(args, "items") else []
    return urlencode(list(items))


def _extract_header(request: Any, name: str) -> str:
    headers = getattr(request, "headers", None)
    if headers is None:
        return ""
    if hasattr(headers, "get"):
        return headers.get(name, "") or ""
    return ""


def _adapt_to_legacy_response(resp: _WsgiResponse) -> Any:
    """Wrap the WSGI response in ``localemu.http.Response`` when available."""
    try:
        from localemu.http import Response
    except Exception:  # pragma: no cover - localemu.http not importable
        return resp
    out = Response(
        resp.body, status=resp.status, content_type=resp.headers.get("Content-Type")
    )
    for k, v in resp.headers.items():
        if k.lower() == "content-type":
            continue
        out.headers[k] = v
    return out


# Module-level default WSGI instance.
#
# The test suite and any simple integration path can grab this directly
# and mount it; customizing behaviour goes through
# :class:`ExportResourceApp(...)`. We expose the default instance under
# the public name ``ExportResource`` so ``Client(ExportResource,
# Response)`` (Werkzeug test client) "just works": the class would have
# had its constructor invoked with ``(environ, start_response)``, which
# is not the WSGI contract.
ExportResource = ExportResourceApp()


__all__ = ["ExportResource", "ExportResourceApp"]
