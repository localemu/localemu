"""Periodically scan an EC2 container for newly-listening TCP ports.

So a user can run ``nginx`` on :80 or a custom app on :12345 inside
the instance without telling LocalEmu anything in advance — the
watcher discovers what's bound via ``ss -ltn`` and emits a port set
to a subscriber callback. Diffs (added / removed) drive the userspace
proxy's listener registry.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Callable

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


# Match `ss -H -ltn` lines:
#   LISTEN 0  4096  0.0.0.0:80    0.0.0.0:*
#   LISTEN 0  511   *:443         *:*
#   LISTEN 0  128   [::]:22       [::]:*
_LISTEN_RE = re.compile(
    r"^LISTEN\s+\S+\s+\S+\s+(?P<addr>\S+):(?P<port>\d+)\s",
    re.MULTILINE,
)


def parse_ss_output(text: str) -> set[int]:
    """Return the set of ports the container has bound for incoming
    TCP. Skips loopback-only binds (``127.x``, ``::1``) because those
    aren't user-facing services."""
    out: set[int] = set()
    for m in _LISTEN_RE.finditer(text):
        addr = m.group("addr")
        port = int(m.group("port"))
        # ignore loopback-only services (postgres binds on
        # 127.0.0.1 before user enables network; we don't expose
        # those by default)
        if addr.startswith("127.") or addr == "::1":
            continue
        out.add(port)
    return out


def scan_listening_ports(container_name: str) -> set[int]:
    """Run ``ss -H -ltn`` inside ``container_name`` and parse the
    listening TCP ports. Returns an empty set when the container
    doesn't have ``ss`` or the exec fails."""
    cmds = [
        ["ss", "-H", "-ltn"],
        # Alpine's `ss` from `iproute2` works the same. Some minimal
        # images ship `netstat` only.
        ["netstat", "-tln"],
    ]
    for cmd in cmds:
        try:
            stdout, _ = DOCKER_CLIENT.exec_in_container(container_name, cmd)
            text = (stdout or b"").decode(errors="replace")
            if not text.strip():
                continue
            if cmd[0] == "netstat":
                # Convert netstat -tln output rows to the ss shape
                # (just the address column matters)
                ports: set[int] = set()
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) < 4 or parts[0] != "tcp" and not parts[0].startswith("tcp"):
                        continue
                    addr = parts[3]
                    if ":" not in addr:
                        continue
                    addr_h, port_s = addr.rsplit(":", 1)
                    if addr_h.strip("[]").startswith("127.") or addr_h in ("::1", "[::1]"):
                        continue
                    try:
                        ports.add(int(port_s))
                    except ValueError:
                        pass
                return ports
            return parse_ss_output(text)
        except Exception:
            LOG.debug(
                "port watcher: %s failed in %s; trying next probe",
                cmd[0], container_name, exc_info=True,
            )
    return set()


class ContainerPortWatcher:
    """One thread per watched container. Polls every ``interval``
    seconds and calls ``on_change(added, removed)`` whenever the bound
    port set changes."""

    def __init__(
        self,
        container_name: str,
        on_change: Callable[[set[int], set[int]], None],
        interval: float = 3.0,
    ) -> None:
        self.container_name = container_name
        self.on_change = on_change
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._known: set[int] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"eip-watch-{self.container_name}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                current = scan_listening_ports(self.container_name)
            except Exception:
                LOG.debug("port watcher loop error", exc_info=True)
                current = self._known  # don't fire spurious diffs
            added = current - self._known
            removed = self._known - current
            if added or removed:
                try:
                    self.on_change(added, removed)
                except Exception:
                    LOG.warning(
                        "port watcher on_change for %s raised",
                        self.container_name, exc_info=True,
                    )
                self._known = current
            self._stop.wait(self.interval)
