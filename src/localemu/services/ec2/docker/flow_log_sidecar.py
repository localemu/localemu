"""Per-EC2-container flow-log sidecar (NFLOG-based).

The original ``FlowLogPoller`` reads ``dmesg`` inside the EC2 container
to scrape iptables ``LOG`` lines. On macOS Docker Desktop the kernel
ring buffer is shared across all containers in the LinuxKit VM, so
per-container ``dmesg`` reads return empty even with ``CAP_SYSLOG`` —
the ``-j LOG`` directive fires (counters increment, proven) but the
output never reaches the container's view of the ring buffer.

This module replaces the ``LOG`` → dmesg path with ``NFLOG`` → sidecar.

How it works
------------

  1. ``sg_iptables`` emits ``-j NFLOG --nflog-group N --nflog-prefix "LE-FL:..."``
     rules. NFLOG delivers matched packets over a *netlink socket* — a
     per-network-namespace primitive that works identically on Linux
     and macOS Docker Desktop (no shared ring buffer).

  2. We spawn ONE tiny sidecar container per EC2 instance, using
     ``--network=container:<ec2-container>`` so it lives inside the
     EC2 container's network namespace. The sidecar runs ``ulogd2``
     which binds NFLOG group N and appends each packet as a single
     iptables-``LOG``-compatible text line to
     ``/var/log/localemu-flow/flow.log`` inside the sidecar.

  3. ``SidecarFlowLogPoller`` ``docker exec``s the sidecar to read the
     growing log file incrementally. Each line is parsed by the same
     ``parse_iptables_log_line`` that handled dmesg lines before.

Why a sidecar (vs. running ulogd2 inside the EC2 container itself)
------------------------------------------------------------------

  - Keeps the EC2 base image unchanged — adding ``ulogd2`` + its
    config there would rebuild a multi-hundred-MB cached image.
  - Separates the flow-log plane from the user workload so an OOM /
    ulogd2 crash can't take the EC2 container down.
  - Cleanup on ``terminate_instance`` is a single ``docker rm``;
    the EC2 filesystem is never touched.

Lifecycle
---------

- ``ensure_sidecar(instance_id, container_name, nflog_group)`` is
  idempotent and called from ``DockerVmManager.create_instance`` after
  the EC2 container is running and after ``apply_sg_to_container``.
- ``cleanup_sidecar(instance_id)`` is called from
  ``DockerVmManager.terminate_instance``.
- ``cleanup_all()`` tears down every sidecar on LocalEmu shutdown
  when persistence is off.
"""

from __future__ import annotations

import logging
import os
import tempfile
import textwrap
import threading
import time

from localemu.utils.container_utils.container_client import ContainerConfiguration
from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)


# NFLOG group used by every LocalEmu SG/NACL rule. The prefix carries
# the instance id + direction + action so one shared group number works
# for all containers (each sidecar lives in its own netns so groups
# don't collide across instances anyway).
DEFAULT_NFLOG_GROUP = 42


# LocalEmu-built sidecar image tag. We bake ulogd2 + iptables into the
# image at LocalEmu startup (see ``_ensure_sidecar_image``) so the
# sidecar can run in the EC2 container's network namespace WITHOUT
# internet access — real AWS VPCs without an IGW have the same
# constraint and the EC2 netns is --internal=true.
_SIDECAR_IMAGE = "localemu/flow-log-sidecar:latest"


_SIDECAR_DOCKERFILE = """\
FROM alpine:3.19
RUN apk add --no-cache ulogd iptables \\
    && mkdir -p /var/log/localemu-flow /etc/ulogd
LABEL org.localemu.image-role="flow-log-sidecar"
LABEL org.opencontainers.image.source="https://github.com/localemu/localemu"
LABEL org.opencontainers.image.description="LocalEmu per-EC2 NFLOG→ulogd2 relay sidecar"
"""


# Entrypoint script run inside the sidecar container. Writes a minimal
# ulogd2 config that binds NFLOG group G and appends one line per
# packet to ``/var/log/localemu-flow/flow.log``, then execs ulogd2 in
# foreground so Docker tracks the process.
#
# The ``LOGEMU`` output plugin emits exactly the iptables ``LOG``
# format we already parse in
# ``flow_log_recorder.parse_iptables_log_line``, preserving the
# ``LE-FL:<iid>:<I|O>:<A|D>:`` prefix. We intentionally do NOT tweak
# the format — the less transformation, the fewer bugs.
#
# No ``apk add`` at runtime: the sidecar image is built at LocalEmu
# startup with ulogd2 pre-installed. This matters because the sidecar
# shares the EC2 container's net namespace, which for VPC-internal
# subnets has NO route to the internet.
_SIDECAR_ENTRYPOINT = textwrap.dedent(r"""
    set -e

    mkdir -p /var/log/localemu-flow /etc/ulogd
    : > /var/log/localemu-flow/flow.log

    NFLOG_GROUP="${NFLOG_GROUP:-42}"

    cat > /etc/ulogd/ulogd.conf <<EOF
[global]
logfile="/var/log/localemu-flow/ulogd.log"
loglevel=3
plugin="/usr/lib/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/ulogd/ulogd_raw2packet_BASE.so"
plugin="/usr/lib/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/ulogd/ulogd_filter_PRINTPKT.so"
plugin="/usr/lib/ulogd/ulogd_output_LOGEMU.so"

stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=${NFLOG_GROUP}

[emu1]
file="/var/log/localemu-flow/flow.log"
sync=1
EOF

    echo "[localemu-flow-sidecar] starting ulogd on NFLOG group ${NFLOG_GROUP}"
    # -v: log to stderr so ``docker logs`` is useful when debugging.
    exec ulogd -v -c /etc/ulogd/ulogd.conf
""").strip() + "\n"


def _sidecar_name(instance_id: str) -> str:
    # Short suffix matches the EC2 container naming scheme.
    return f"localemu-flowlog-{instance_id}"


_lock = threading.Lock()
# instance_id -> sidecar container name (for book-keeping only; Docker
# is always the source of truth via labels).
_sidecars: dict[str, str] = {}


def _image_available() -> bool:
    try:
        DOCKER_CLIENT.inspect_image(_SIDECAR_IMAGE)
        return True
    except Exception:
        return False


_image_build_lock = threading.Lock()


def _ensure_image() -> bool:
    """Ensure the sidecar image is built. Idempotent and thread-safe.

    Why build vs. pull:
    -------------------
    The sidecar lives in the EC2 container's network namespace, which
    for VPC-internal subnets has no route to the internet. That means
    ``apk add ulogd`` at runtime fails. We build ``localemu/flow-log-sidecar``
    ONCE on the LocalEmu host (where internet works) with ulogd2 +
    iptables baked in. All per-instance sidecars then reuse the image —
    no network access required at container start.
    """
    if _image_available():
        return True
    with _image_build_lock:
        if _image_available():
            return True
        try:
            LOG.info(
                "Building %s for flow-log sidecars (one-time)…",
                _SIDECAR_IMAGE,
            )
            with tempfile.TemporaryDirectory(
                prefix="localemu-flow-sidecar-",
            ) as ctx:
                dockerfile_path = os.path.join(ctx, "Dockerfile")
                with open(dockerfile_path, "w") as f:
                    f.write(_SIDECAR_DOCKERFILE)
                DOCKER_CLIENT.build_image(
                    dockerfile_path=dockerfile_path,
                    image_name=_SIDECAR_IMAGE,
                    context_path=ctx,
                )
            LOG.info("Built %s successfully", _SIDECAR_IMAGE)
            return True
        except Exception:
            LOG.warning(
                "Flow-log sidecar: build of %s failed, feature disabled",
                _SIDECAR_IMAGE, exc_info=True,
            )
            return False


def _sidecar_running(name: str) -> bool:
    try:
        inspect = DOCKER_CLIENT.inspect_container(name)
    except Exception:
        return False
    return bool((inspect.get("State") or {}).get("Running"))


def _wait_for_ready(
    name: str, timeout: int = 10,
) -> bool:
    """Wait for the sidecar to write its log file (confirms ulogd started)."""
    deadline = time.time() + timeout
    backoff = 0.2
    probe_cmd = [
        "sh", "-c",
        "test -f /var/log/localemu-flow/flow.log && echo READY || echo WAIT",
    ]
    while time.time() < deadline:
        try:
            out, _ = DOCKER_CLIENT.exec_in_container(name, probe_cmd)
            if b"READY" in (out or b""):
                return True
        except Exception:
            pass
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 1.0)
    return False


def ensure_sidecar(
    instance_id: str,
    ec2_container_name: str,
    nflog_group: int = DEFAULT_NFLOG_GROUP,
) -> str | None:
    """Create + start the flow-log sidecar for one EC2 instance.

    Idempotent: when a sidecar is already running for this instance the
    call is a cheap lookup. Returns the sidecar container name on
    success, ``None`` on any failure — in that case flow-log capture is
    simply off for this instance, it does NOT affect the EC2 container.
    """
    with _lock:
        if instance_id in _sidecars:
            name = _sidecars[instance_id]
            if _sidecar_running(name):
                return name
            # Stale entry — fall through to recreate.
            _sidecars.pop(instance_id, None)

    if not _ensure_image():
        return None

    name = _sidecar_name(instance_id)

    # Re-use an already-running sidecar from a previous LocalEmu run.
    try:
        existing = DOCKER_CLIENT.list_containers(
            filter=[f"name={name}"], all=True,
        )
    except Exception:
        existing = []
    for c in existing:
        cname = c.get("name") or ""
        if cname == name:
            try:
                DOCKER_CLIENT.start_container(name)
            except Exception:
                pass
            if _sidecar_running(name):
                with _lock:
                    _sidecars[instance_id] = name
                return name
            # Broken — remove and re-create.
            try:
                DOCKER_CLIENT.remove_container(name, force=True)
            except Exception:
                pass
            break

    # ``--network=container:<ec2>`` puts the sidecar in the EC2
    # container's netns so ``NFLOG`` messages emitted by iptables in
    # that netns arrive on the sidecar's netlink socket. The sidecar
    # keeps its OWN mount and PID namespaces so its filesystem is
    # separate from the EC2 container — clean teardown, no risk of
    # polluting the user's rootfs.
    try:
        cfg = ContainerConfiguration(
            image_name=_SIDECAR_IMAGE,
            name=name,
            command=["sh", "-c", _SIDECAR_ENTRYPOINT],
            env_vars={"NFLOG_GROUP": str(nflog_group)},
            # NET_ADMIN: required to open NFNETLINK sockets.
            # NET_RAW:   required for libnetfilter_log packet parsing.
            cap_add=["NET_ADMIN", "NET_RAW"],
            additional_flags=f"--network=container:{ec2_container_name}",
            detach=True,
            labels={
                "localemu.service": "flow-log-sidecar",
                "localemu.instance-id": instance_id,
            },
        )
        DOCKER_CLIENT.create_container_from_config(cfg)
        DOCKER_CLIENT.start_container(name)
    except Exception:
        LOG.warning(
            "Flow-log sidecar: failed to start for %s",
            instance_id, exc_info=True,
        )
        try:
            DOCKER_CLIENT.remove_container(name, force=True)
        except Exception:
            pass
        return None

    if not _wait_for_ready(name, timeout=20):
        LOG.warning(
            "Flow-log sidecar %s did not become ready within 20s; "
            "flow-log capture may be partial",
            name,
        )

    with _lock:
        _sidecars[instance_id] = name
    LOG.info(
        "Flow-log sidecar %s running for EC2 instance %s (NFLOG group %d)",
        name, instance_id, nflog_group,
    )
    return name


def get_sidecar_name(instance_id: str) -> str | None:
    """Return the cached sidecar container name or probe Docker for it.

    Used by ``SidecarFlowLogPoller`` so it can issue ``docker exec``
    against the sidecar (not the EC2 container).
    """
    with _lock:
        cached = _sidecars.get(instance_id)
    if cached and _sidecar_running(cached):
        return cached
    # Fallback: derive from naming convention and verify it's live.
    name = _sidecar_name(instance_id)
    if _sidecar_running(name):
        with _lock:
            _sidecars[instance_id] = name
        return name
    return None


def cleanup_sidecar(instance_id: str) -> None:
    """Stop + remove the sidecar. Called on ``terminate_instance``."""
    with _lock:
        _sidecars.pop(instance_id, None)
    name = _sidecar_name(instance_id)
    try:
        DOCKER_CLIENT.remove_container(name, force=True)
    except Exception:
        pass


def cleanup_all() -> None:
    """Best-effort teardown of every sidecar. Called on LocalEmu
    shutdown when persistence is OFF."""
    with _lock:
        ids = list(_sidecars.keys())
        _sidecars.clear()
    for instance_id in ids:
        try:
            DOCKER_CLIENT.remove_container(
                _sidecar_name(instance_id), force=True,
            )
        except Exception:
            pass
