"""Host-side asyncio TCP proxy for the EIP data plane.

Binds a listener on ``127.0.0.1:<host_port>`` in the LocalEmu process
itself, so the accepted socket's ``peername`` carries the real source
IP of the caller (the Mac / Linux host that ran ``curl``). On every
accept:

  1. Read ``src_ip`` from the socket.
  2. Evaluate the EC2 instance's Security Groups against
     ``(src_ip, tcp, container_port)``. Mutations to SG rules take
     effect on the next connection because the evaluator reads moto
     state live.
  3. Emit a ``FlowLogEntry`` with the real ``src_ip`` so flow logs
     are honest about who hit the EIP.
  4. On ACCEPT: tunnel the bytes through
     ``docker exec -i <ec2> socat - TCP:127.0.0.1:<container_port>``.
     ``docker exec`` enters the container's netns directly, so we
     don't go through the bridge gateway and the source IP is never
     rewritten anywhere we care about.
  5. On REJECT: close the socket.

The ``socat`` binary must exist inside the EC2 container; the data
plane installs it on first attach (``apk add --no-cache socat``).
"""
from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

from localemu.services.ec2.docker.sg_evaluator import (
    ConnectionAttempt, SecurityGroupEvaluator,
)
from localemu.utils.net import get_free_tcp_port

LOG = logging.getLogger(__name__)


@dataclass
class ProxyListener:
    host_port: int
    container_port: int
    server: asyncio.AbstractServer


@dataclass
class _ProxyRoute:
    public_ip: str
    container_name: str
    account_id: str
    region: str
    instance_id: str
    sg_ids: list[str]
    eni_id: Optional[str]
    listeners: dict[int, ProxyListener] = field(default_factory=dict)


class EipHostProxy:
    """Process-wide singleton that owns:
      * a background event loop running on its own thread
      * a per-(EIP) route table
      * per-(EIP, container_port) asyncio TCP listeners bound on
        the host's loopback
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._routes: dict[str, _ProxyRoute] = {}
        self._lock = threading.RLock()

    # -- event loop lifecycle ----------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is not None:
            return self._loop
        with self._lock:
            if self._loop is not None:
                return self._loop
            self._ready.clear()

            def _runner() -> None:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._loop = loop
                self._ready.set()
                try:
                    loop.run_forever()
                except Exception:
                    LOG.warning("EIP proxy loop crashed", exc_info=True)
                finally:
                    loop.close()

            self._thread = threading.Thread(
                target=_runner, name="eip-host-proxy", daemon=True,
            )
            self._thread.start()
            self._ready.wait(timeout=5)
            assert self._loop is not None
            return self._loop

    # -- route registry ----------------------------------------------

    def attach(
        self, public_ip: str, container_name: str,
        sg_ids: list[str], account_id: str, region: str,
        instance_id: str, eni_id: Optional[str] = None,
    ) -> None:
        """Register an EIP route. Per-port listeners get added later
        via :meth:`open_port` as the port watcher discovers the
        container's listening ports."""
        self._ensure_loop()
        with self._lock:
            if public_ip in self._routes:
                # Idempotent re-attach — drop the old listeners first.
                self._detach_locked(public_ip)
            self._routes[public_ip] = _ProxyRoute(
                public_ip=public_ip, container_name=container_name,
                account_id=account_id, region=region,
                instance_id=instance_id, sg_ids=list(sg_ids),
                eni_id=eni_id,
            )
        LOG.info(
            "EIP host proxy: route %s -> %s (sgs=%s)",
            public_ip, container_name, sg_ids,
        )

    def detach(self, public_ip: str) -> dict[int, int]:
        with self._lock:
            return self._detach_locked(public_ip)

    def _detach_locked(self, public_ip: str) -> dict[int, int]:
        route = self._routes.pop(public_ip, None)
        if route is None:
            return {}
        out = {cp: ls.host_port for cp, ls in route.listeners.items()}
        for ls in list(route.listeners.values()):
            self._close_server(ls.server)
        return out

    def update_sg_ids(self, public_ip: str, sg_ids: list[str]) -> None:
        with self._lock:
            route = self._routes.get(public_ip)
            if route is not None:
                route.sg_ids = list(sg_ids)

    # -- per-port listeners ------------------------------------------

    def open_port(self, public_ip: str, container_port: int) -> int | None:
        """Bind ``127.0.0.1:<host_port>`` for ``container_port``.
        Returns the host port we bound on (idempotent: returns the
        existing port if already bound)."""
        loop = self._ensure_loop()
        with self._lock:
            route = self._routes.get(public_ip)
            if route is None:
                return None
            existing = route.listeners.get(container_port)
            if existing is not None:
                return existing.host_port

        host_port = get_free_tcp_port()
        fut = asyncio.run_coroutine_threadsafe(
            self._start_server(public_ip, container_port, host_port), loop,
        )
        try:
            server = fut.result(timeout=5)
        except Exception:
            LOG.warning(
                "EIP host proxy: bind 127.0.0.1:%s failed for %s:%s",
                host_port, public_ip, container_port, exc_info=True,
            )
            return None

        with self._lock:
            route = self._routes.get(public_ip)
            if route is None:
                # Detached during bind — tear down.
                self._close_server(server)
                return None
            route.listeners[container_port] = ProxyListener(
                host_port=host_port, container_port=container_port,
                server=server,
            )
        LOG.info(
            "EIP host proxy: listening 127.0.0.1:%s for %s container_port=%s",
            host_port, public_ip, container_port,
        )
        return host_port

    def close_port(self, public_ip: str, container_port: int) -> None:
        with self._lock:
            route = self._routes.get(public_ip)
            if route is None:
                return
            ls = route.listeners.pop(container_port, None)
        if ls is not None:
            self._close_server(ls.server)
            LOG.info(
                "EIP host proxy: closed 127.0.0.1:%s for %s container_port=%s",
                ls.host_port, public_ip, container_port,
            )

    def host_port_for(
        self, public_ip: str, container_port: int,
    ) -> int | None:
        with self._lock:
            route = self._routes.get(public_ip)
            if route is None:
                return None
            ls = route.listeners.get(container_port)
            return ls.host_port if ls else None

    def snapshot_routes(self) -> dict[str, dict[int, int]]:
        with self._lock:
            return {
                ip: {cp: ls.host_port for cp, ls in route.listeners.items()}
                for ip, route in self._routes.items()
            }

    # -- internals ---------------------------------------------------

    def _close_server(self, server: asyncio.AbstractServer) -> None:
        loop = self._loop
        if loop is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._aclose_server(server), loop,
            )
            fut.result(timeout=2)
        except Exception:
            LOG.debug("EIP host proxy: close_server failed", exc_info=True)

    async def _aclose_server(self, server: asyncio.AbstractServer) -> None:
        try:
            server.close()
            await server.wait_closed()
        except Exception:
            pass

    async def _start_server(
        self, public_ip: str, container_port: int, host_port: int,
    ) -> asyncio.AbstractServer:
        async def _handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        ) -> None:
            await self._serve(public_ip, container_port, reader, writer)

        return await asyncio.start_server(
            _handler, host="127.0.0.1", port=host_port,
            reuse_address=True,
        )

    async def _serve(
        self, public_ip: str, container_port: int,
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip = peer[0] if isinstance(peer, tuple) else "0.0.0.0"
        src_port = peer[1] if isinstance(peer, tuple) and len(peer) >= 2 else 0

        with self._lock:
            route = self._routes.get(public_ip)
        if route is None:
            _safe_close(writer)
            return

        # Step 1: SG enforcement against the REAL caller IP
        try:
            allowed = SecurityGroupEvaluator(
                route.account_id, route.region,
            ).is_ingress_allowed(
                route.sg_ids,
                ConnectionAttempt(
                    source_ip=src_ip, protocol="tcp",
                    dest_port=container_port,
                ),
            )
        except Exception:
            LOG.warning(
                "EIP host proxy: SG eval error for %s:%s from %s; denying",
                public_ip, container_port, src_ip, exc_info=True,
            )
            allowed = False

        # Step 2: emit flow log entry — carries the real source IP
        _emit_flow_log(
            route, src_ip, src_port, container_port,
            "ACCEPT" if allowed else "REJECT",
        )

        if not allowed:
            LOG.debug(
                "EIP host proxy: SG DENY %s:%s from %s",
                public_ip, container_port, src_ip,
            )
            _safe_close(writer)
            return

        # Step 3: tunnel via docker exec into the container's netns
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", "-i", route.container_name,
                "socat", "-", f"TCP:127.0.0.1:{container_port}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception as exc:
            LOG.warning(
                "EIP host proxy: docker exec spawn failed: %s", exc,
            )
            _safe_close(writer)
            return

        try:
            await asyncio.gather(
                _pipe(reader, proc.stdin),
                _pipe_reader_to_writer(proc.stdout, writer),
                return_exceptions=True,
            )
        finally:
            try:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2)
                    except asyncio.TimeoutError:
                        proc.kill()
            except Exception:
                pass
            _safe_close(writer)


def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


async def _pipe(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter | None,
) -> None:
    if dst is None:
        return
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        return
    except Exception:
        LOG.debug("EIP pipe ended with exception", exc_info=True)
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def _pipe_reader_to_writer(
    src: asyncio.StreamReader | None, dst: asyncio.StreamWriter,
) -> None:
    if src is None:
        return
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        return
    except Exception:
        LOG.debug("EIP pipe ended with exception", exc_info=True)
    finally:
        try:
            dst.close()
        except Exception:
            pass


def _emit_flow_log(
    route: _ProxyRoute, src_ip: str, src_port: int,
    dst_port: int, action: str,
) -> None:
    """Best-effort flow log emission. The recorder routes by ENI to
    the user's configured destination (CWL group from CreateFlowLogs).
    Failures here are silent — the data path must not block on
    observability."""
    try:
        from localemu.services.ec2.docker.flow_log_recorder import (
            FlowLogEntry, get_flow_log_recorder,
        )
        entry = FlowLogEntry(
            account_id=route.account_id,
            interface_id=route.eni_id or "eni-eip",
            srcaddr=src_ip,
            dstaddr=route.public_ip,
            srcport=src_port,
            dstport=dst_port,
            protocol=6,  # TCP
            action=action,
        )
        get_flow_log_recorder().record(entry)
    except Exception:
        LOG.debug("EIP host proxy: flow log emit failed", exc_info=True)


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_proxy: EipHostProxy | None = None
_lock = threading.Lock()


def get_eip_host_proxy() -> EipHostProxy:
    global _proxy
    if _proxy is None:
        with _lock:
            if _proxy is None:
                _proxy = EipHostProxy()
    return _proxy


def reset_for_tests() -> None:
    global _proxy
    with _lock:
        if _proxy is not None:
            for ip in list(_proxy._routes.keys()):
                _proxy.detach(ip)
        _proxy = None
