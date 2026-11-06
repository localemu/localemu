import logging
import os
import threading
import time
from typing import Any

from rolo.gateway import Gateway
from rolo.serving.twisted import TwistedGateway
from twisted.internet import endpoints, reactor, ssl

from localemu import config
from localemu.aws.serving.twisted import (
    HARD_SHUTDOWN_DEADLINE_S,
    TLSMultiplexerFactory,
    stop_thread_pool,
)
from localemu.utils import patch

from .core import RuntimeServer

LOG = logging.getLogger(__name__)


class TwistedRuntimeServer(RuntimeServer):
    def __init__(self):
        self.thread_pool = None
        self._protocol_factory = None
        self._dynamic_ports: dict[int, Any] = {}
        self._dynamic_ports_lock = threading.Lock()

    def register(
        self,
        gateway: Gateway,
        listen: list[config.HostAndPort],
        ssl_creds: tuple[str, str] | None = None,
    ):
        # setup twisted webserver Site
        site = TwistedGateway(gateway)

        # configure ssl
        if ssl_creds:
            cert_file_name, key_file_name = ssl_creds
            context_factory = ssl.DefaultOpenSSLContextFactory(key_file_name, cert_file_name)
            context_factory.getContext().use_certificate_chain_file(cert_file_name)
            protocol_factory = TLSMultiplexerFactory(context_factory, False, site)
        else:
            protocol_factory = site

        # Stashed so ``add_dynamic_listener`` can register additional
        # listeners (one per VPC Interface endpoint) that share this exact
        # Site/gateway, after the reactor is already running.
        self._protocol_factory = protocol_factory

        # add endpoint for each host/port combination
        for host_and_port in listen:
            if config.is_ipv6_address(host_and_port.host):
                endpoint = endpoints.TCP6ServerEndpoint(
                    reactor, host_and_port.port, interface=host_and_port.host
                )
            else:
                # TODO: interface = host?
                endpoint = endpoints.TCP4ServerEndpoint(reactor, host_and_port.port)
            endpoint.listen(protocol_factory)

    def add_dynamic_listener(self, host: str = "0.0.0.0", timeout: float = 5.0) -> int:
        """Bind an additional listener (OS-assigned port) onto the same
        gateway Site used by ``register()``, and return the bound port.

        Used for VPC Interface endpoint attribution: each endpoint's proxy
        forwards to its own dedicated host port instead of everyone sharing
        the main gateway port, so the request handler chain can tell which
        endpoint a request arrived through by reading ``SERVER_PORT`` -
        source-IP attribution was tried and found to never work on Docker
        Desktop, where container->host traffic is NATed to 127.0.0.1.

        Must be safe to call from any thread: the reactor is not
        thread-safe, so the actual ``listen()`` call is scheduled onto the
        reactor thread via ``callFromThread`` and this method blocks (with
        a timeout) for the result.

        Raises RuntimeError if ``register()`` hasn't run yet (e.g. this
        server backend isn't the one actually in use) or if binding fails.
        """
        if self._protocol_factory is None:
            raise RuntimeError(
                "add_dynamic_listener called before register() - no gateway Site to attach to"
            )

        result: dict = {}
        done = threading.Event()

        def _do_listen():
            try:
                if config.is_ipv6_address(host):
                    endpoint = endpoints.TCP6ServerEndpoint(reactor, 0, interface=host)
                else:
                    endpoint = endpoints.TCP4ServerEndpoint(reactor, 0, interface=host)
                deferred = endpoint.listen(self._protocol_factory)

                def _ok(listening_port):
                    result["port"] = listening_port
                    done.set()

                def _err(failure):
                    result["error"] = failure
                    done.set()

                deferred.addCallbacks(_ok, _err)
            except Exception as e:  # noqa: BLE001 - surfaced to the caller below
                result["error"] = e
                done.set()

        reactor.callFromThread(_do_listen)
        if not done.wait(timeout=timeout):
            raise RuntimeError("Timed out registering dynamic VPC endpoint listener")
        if "error" in result:
            raise RuntimeError(f"Failed to register dynamic listener: {result['error']}")

        listening_port = result["port"]
        bound_port = listening_port.getHost().port
        with self._dynamic_ports_lock:
            self._dynamic_ports[bound_port] = listening_port
        return bound_port

    def remove_dynamic_listener(self, bound_port: int, timeout: float = 5.0) -> None:
        """Tear down a listener previously created by ``add_dynamic_listener``."""
        with self._dynamic_ports_lock:
            listening_port = self._dynamic_ports.pop(bound_port, None)
        if listening_port is None:
            return

        done = threading.Event()

        def _do_stop():
            try:
                listening_port.stopListening()
            except Exception:
                LOG.debug("Error stopping dynamic listener on port %s", bound_port, exc_info=True)
            finally:
                done.set()

        reactor.callFromThread(_do_stop)
        done.wait(timeout=timeout)

    def run(self):
        reactor.suggestThreadPoolSize(config.GATEWAY_WORKER_COUNT)
        self.thread_pool = reactor.getThreadPool()
        patch.patch(self.thread_pool.stop)(stop_thread_pool)

        # we don't need signal handlers, since all they do is call ``reactor`` stop, which we expect the
        # caller to do via ``shutdown``.
        return reactor.run(installSignalHandlers=False)

    def shutdown(self):
        # Wake any long-poll consumers (dashboard SSE) so their serving
        # threads exit cleanly before we try to join the thread pool.
        # Without this, the pool's 10s join timeout always fires when a
        # dashboard tab is open at shutdown time.
        try:
            from localemu.dashboard.bus import get_bus

            get_bus().shutdown()
        except Exception:
            LOG.debug("Bus shutdown signaling failed", exc_info=True)

        if self.thread_pool:
            self.thread_pool.stop(timeout=10)

        # reactor.stop() is not thread-safe: it must run on the reactor
        # thread itself. shutdown() is called from whichever thread owns
        # the runtime's lifecycle (a pytest sessionfinish hook, or the
        # SIGTERM/SIGINT handler in runtime/main.py), not the thread
        # running reactor.run() (see .run() above), so calling it
        # directly here races Twisted's internal reactor state and the
        # stop request can be silently dropped, hanging the process
        # forever. Route it through callFromThread instead - the same
        # fix already applied for this exact failure mode in
        # aws/serving/twisted.py's _shutdown_reactor(). The cross-thread
        # hazard is also already handled correctly elsewhere in this
        # class via callFromThread (see add_dynamic_listener /
        # remove_dynamic_listener below).
        try:
            reactor.callFromThread(reactor.stop)
        except Exception:
            # Reactor already torn down; fall through to the deadline below.
            LOG.debug("reactor.callFromThread(reactor.stop) failed", exc_info=True)

        # Hard deadline: if a dashboard SSE stream is still attached to a
        # half-closed socket, its worker thread can stay parked inside
        # the Twisted writer indefinitely even after the steps above.
        # Escalate to os._exit so callers (localemu stop, Ctrl+C, a
        # pytest session) are never left hanging forever.
        thread_pool = self.thread_pool

        def _force_exit_if_still_running():
            time.sleep(HARD_SHUTDOWN_DEADLINE_S)
            if thread_pool and any(t.is_alive() for t in thread_pool.threads):
                LOG.warning(
                    "[shutdown] Twisted worker thread(s) still alive after "
                    "graceful timeout + %.1fs grace, forcing process exit",
                    HARD_SHUTDOWN_DEADLINE_S,
                )
                os._exit(0)

        threading.Thread(
            target=_force_exit_if_still_running,
            name="localemu-shutdown-watchdog",
            daemon=True,
        ).start()
