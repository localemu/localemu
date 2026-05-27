"""High-level EIP data plane facade.

One uniform path on every host (Mac, Linux, WSL2): a host-side
asyncio TCP proxy bound on ``127.0.0.1:<host_port>`` that tunnels
into the EC2 container via ``docker exec`` + ``socat``.

What the facade orchestrates on ``AssociateAddress``:

  1. Make sure ``socat`` exists inside the EC2 container — we install
     it once via ``apk add`` so the tunnel command has its binary.
  2. Register the route with the host proxy.
  3. Spin up a :class:`ContainerPortWatcher` that polls the container
     for newly-listening TCP ports.
  4. On every port-set change, intersect with the SG-allowed port set
     and open / close host listeners accordingly.

On SG mutation (``AuthorizeSecurityGroupIngress`` /
``RevokeSecurityGroupIngress``), :meth:`refresh_sg` reconciles every
EIP whose instance carries that SG so revoking a rule tears down
the listener within seconds.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

from localemu.services.ec2.docker.sg_evaluator import (
    ConnectionAttempt, SecurityGroupEvaluator,
)
from localemu.services.ec2.eip.port_watcher import ContainerPortWatcher
from localemu.services.ec2.eip.proxy import get_eip_host_proxy
from localemu.services.ec2.eip.store import (
    EipAssociation, all_stores, get_eip_store,
)
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


@dataclass
class _Active:
    public_ip: str
    container_name: str
    account_id: str
    region: str
    sg_ids: list[str]
    watcher: Optional[ContainerPortWatcher] = None
    listening: set[int] = field(default_factory=set)


class EipDataPlane:
    """One per process. Hides the proxy + watcher orchestration."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: dict[str, _Active] = {}

    # -- attach / detach ---------------------------------------------

    def attach(
        self, *, public_ip: str, instance_id: str,
        container_name: str, sg_ids: list[str],
        account_id: str, region: str,
        eni_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            if public_ip in self._active:
                self._detach_locked(public_ip)

            # Ensure socat exists inside the container so the docker-
            # exec tunnel has its binary. Idempotent + best-effort.
            _ensure_socat(container_name)

            proxy = get_eip_host_proxy()
            proxy.attach(
                public_ip=public_ip, container_name=container_name,
                sg_ids=list(sg_ids), account_id=account_id,
                region=region, instance_id=instance_id, eni_id=eni_id,
            )

            active = _Active(
                public_ip=public_ip, container_name=container_name,
                account_id=account_id, region=region,
                sg_ids=list(sg_ids),
            )

            def _on_change(added: set[int], removed: set[int]) -> None:
                active.listening = (active.listening | added) - removed
                self._reconcile_listeners(public_ip)

            watcher = ContainerPortWatcher(container_name, _on_change)
            active.watcher = watcher
            self._active[public_ip] = active
            watcher.start()

        LOG.info(
            "EIP data plane: attached %s -> %s (sgs=%s)",
            public_ip, container_name, sg_ids,
        )

    def detach(self, public_ip: str) -> None:
        with self._lock:
            self._detach_locked(public_ip)

    def _detach_locked(self, public_ip: str) -> None:
        active = self._active.pop(public_ip, None)
        if active is None:
            return
        if active.watcher is not None:
            active.watcher.stop()
        get_eip_host_proxy().detach(public_ip)
        LOG.info("EIP data plane: detached %s", public_ip)

    # -- SG-driven reconciliation ------------------------------------

    def _reconcile_listeners(self, public_ip: str) -> None:
        """Intersect (ports the container is listening on) with
        (ports any SG rule admits) and open / close host listeners
        to match. Called from the port watcher on diff and from
        :meth:`refresh_sg` on SG mutation."""
        with self._lock:
            active = self._active.get(public_ip)
            if active is None:
                return
            proxy = get_eip_host_proxy()
            evaluator = SecurityGroupEvaluator(
                active.account_id, active.region,
            )
            allow_set: set[int] = set()
            for port in active.listening:
                if _sg_allows_any_for_port(
                    evaluator, active.sg_ids, port,
                ):
                    allow_set.add(port)

            current = set(proxy.snapshot_routes().get(public_ip, {}).keys())
            to_open = allow_set - current
            to_close = current - allow_set

            store = get_eip_store(active.account_id, active.region)
            assoc = store.by_ip(public_ip)
            for p in sorted(to_open):
                host_port = proxy.open_port(public_ip, p)
                if host_port is not None and assoc is not None:
                    assoc.proxies[p] = host_port
            for p in sorted(to_close):
                proxy.close_port(public_ip, p)
                if assoc is not None:
                    assoc.proxies.pop(p, None)

    def refresh_sg(
        self, account_id: str, region: str, sg_id: str,
    ) -> None:
        """Triggered by AuthorizeSecurityGroupIngress / Revoke. Re-
        evaluates every EIP whose instance carries the mutated SG.

        ``sg_ids`` is captured at attach time; a future hook from
        ``ModifyNetworkInterfaceAttribute`` would update it. For 1.0
        SG ID set per instance is stable post-launch in moto, so
        we don't refresh the ID list here — only the rule-set."""
        with self._lock:
            targets = [
                ip for ip, a in self._active.items()
                if a.account_id == account_id
                and a.region == region
                and sg_id in a.sg_ids
            ]
        for ip in targets:
            self._reconcile_listeners(ip)


def _ensure_socat(container_name: str) -> None:
    """Install ``socat`` inside ``container_name`` if missing. The
    docker-exec tunnel needs it as the upstream stream relay. Cheap
    no-op when already installed (``apk add --no-cache`` skips)."""
    try:
        # First probe: is socat already there?
        _, _ = DOCKER_CLIENT.exec_in_container(
            container_name, ["sh", "-c", "command -v socat >/dev/null"],
        )
        return
    except Exception:
        pass
    # Try apk (alpine) first, then apt-get (debian/ubuntu)
    try:
        DOCKER_CLIENT.exec_in_container(
            container_name,
            ["sh", "-c",
             "apk add --no-cache socat >/dev/null 2>&1 "
             "|| (apt-get update -qq && apt-get install -y -qq socat) "
             ">/dev/null 2>&1 || true"],
        )
    except Exception:
        LOG.warning(
            "EIP data plane: failed to install socat in %s; the tunnel "
            "will not work until it's present", container_name,
        )


def _sg_allows_any_for_port(
    evaluator: SecurityGroupEvaluator, sg_ids: list[str], port: int,
) -> bool:
    """True if at least one ingress rule across ``sg_ids`` admits
    SOME caller IP on this TCP port. We probe a few diverse IPs
    (covers ``0.0.0.0/0`` rules, loopback rules, common-LAN rules).
    If any matches, we open the listener — per-connection eval
    (in the proxy) then narrows to the actual caller."""
    for probe in ("0.0.0.0", "127.0.0.1", "10.0.0.1", "192.168.0.1"):
        if evaluator.is_ingress_allowed(
            sg_ids,
            ConnectionAttempt(
                source_ip=probe, protocol="tcp", dest_port=port,
            ),
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_plane: EipDataPlane | None = None
_lock = threading.Lock()


def get_eip_data_plane() -> EipDataPlane:
    global _plane
    if _plane is None:
        with _lock:
            if _plane is None:
                _plane = EipDataPlane()
    return _plane


def reset_for_tests() -> None:
    global _plane
    with _lock:
        if _plane is not None:
            for ip in list(_plane._active.keys()):
                _plane.detach(ip)
        _plane = None
    from localemu.services.ec2.eip import proxy as _p
    _p.reset_for_tests()
    from localemu.services.ec2.eip import store as _s
    _s.reset_for_tests()


# ---------------------------------------------------------------------------
# v1 sidecar cleanup — remove leftover ``localemu-eip-*`` containers
# from the discarded sidecar-based design.
# ---------------------------------------------------------------------------

def cleanup_v1_sidecars() -> None:
    """Best-effort removal of ``localemu-eip-*`` sidecar containers
    that the previous (sidecar-based) implementation might have left
    behind. Called once at startup."""
    try:
        containers = DOCKER_CLIENT.list_containers(
            filter=["label=localemu.service=eip-proxy"], all=True,
        )
    except Exception:
        return
    for c in containers:
        name = c.get("name") or ""
        try:
            DOCKER_CLIENT.remove_container(name, force=True)
            LOG.debug("EIP data plane: removed v1 sidecar %s", name)
        except Exception:
            pass
