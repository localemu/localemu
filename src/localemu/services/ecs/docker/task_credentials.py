"""ECS task role credentials endpoint (fix #79).

Serves the ECS v2 container-credentials response shape on a host-bound
HTTP port. ECS task containers fetch creds via the
``AWS_CONTAINER_CREDENTIALS_FULL_URI`` env var the task manager injects,
which points at ``http://host.docker.internal:<port>/v2/credentials/<task_id>``.

We do NOT set ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` — that variant
forces the SDK to resolve the URI against the hard-coded
``http://169.254.170.2`` link-local IP, which requires a dedicated
sidecar or iptables DNAT to be routable inside Docker's network modes.
Using FULL_URI avoids the whole problem: the SDK hits our host port
directly over ``host.docker.internal`` (resolved via the
``--add-host host.docker.internal:host-gateway`` flag already applied
to every task container).

RELATIVE_URI takes priority over FULL_URI when both are set, so we
keep RELATIVE_URI unset.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

LOG = logging.getLogger(__name__)


class TaskCredentialStore:
    """Thread-safe in-memory store of ECS task-role credentials keyed by task_id."""

    def __init__(self) -> None:
        self._by_task: dict[str, dict] = {}
        self._lock = threading.Lock()

    def put(self, task_id: str, creds: dict) -> None:
        with self._lock:
            self._by_task[task_id] = dict(creds)

    def get(self, task_id: str) -> Optional[dict]:
        with self._lock:
            creds = self._by_task.get(task_id)
            return dict(creds) if creds else None

    def revoke(self, task_id: str) -> None:
        with self._lock:
            self._by_task.pop(task_id, None)

    def all_task_ids(self) -> list[str]:
        with self._lock:
            return list(self._by_task.keys())


class _TaskCredentialsHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        server: TaskCredentialsServer = self.server  # type: ignore[assignment]
        path = self.path.split("?", 1)[0].rstrip("/")

        # /v2/credentials/<task_id>
        if path.startswith("/v2/credentials/"):
            task_id = path[len("/v2/credentials/"):]
            creds = server.store.get(task_id)
            if not creds:
                self.send_error(404, "Credentials not found for this task")
                return
            body = json.dumps(creds).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # /v3/<task_id>[/task] and /v4/<task_id>[/task] — minimal stubs so
        # customer code calling ``curl $ECS_CONTAINER_METADATA_URI`` does not
        # get a connection reset. We do NOT implement the full metadata shape.
        if path.startswith("/v3/") or path.startswith("/v4/"):
            body = json.dumps({
                "Cluster": "default",
                "TaskARN": "",
                "Family": "",
                "Revision": "1",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404, "Not found")

    def log_message(self, format, *args):  # noqa: A002
        LOG.debug("TaskCreds %s %s", self.client_address[0], format % args)


class TaskCredentialsServer:
    """HTTP server bound to 127.0.0.1:<ephemeral> that serves ECS task creds."""

    def __init__(self) -> None:
        self.store = TaskCredentialStore()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._port: Optional[int] = None
        self._lock = threading.Lock()

    def start(self) -> int:
        """Start the server on a free port (idempotent). Returns the port."""
        with self._lock:
            if self._httpd is not None and self._port is not None:
                return self._port
            # Bind 0.0.0.0 (not just 127.0.0.1) so Docker containers
            # reaching host.docker.internal can connect. Docker Desktop
            # routes host.docker.internal to the host's real interface,
            # not loopback, so a 127.0.0.1-only bind would be unreachable.
            self._httpd = ThreadingHTTPServer(("0.0.0.0", 0), _TaskCredentialsHandler)
            self._httpd.store = self.store  # type: ignore[attr-defined]
            self._port = self._httpd.server_address[1]
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True,
                name="ecs-task-creds-server",
            )
            self._thread.start()
            LOG.info("ECS task credentials server listening on port %d", self._port)
            return self._port

    def stop(self) -> None:
        with self._lock:
            if self._httpd is not None:
                try:
                    self._httpd.shutdown()
                    self._httpd.server_close()
                except Exception:
                    LOG.debug("Failed to stop task creds server", exc_info=True)
                self._httpd = None
                self._port = None

    @property
    def port(self) -> Optional[int]:
        return self._port


_instance_lock = threading.Lock()
_instance: Optional[TaskCredentialsServer] = None


def get_task_credentials_server() -> TaskCredentialsServer:
    """Return the process-wide singleton task-credentials server, starting it."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = TaskCredentialsServer()
            _instance.start()
        return _instance
