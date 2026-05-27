"""LocalEmu-managed EC2 base image.

Builds a single Docker image (default tag ``localemu/ec2-base:latest``)
that has everything an EC2 container needs at runtime baked in:

  - openssh-server  (so the container can serve SSH from the entrypoint)
  - iptables        (so SG / NACL enforcement actually works)
  - curl, ca-certs  (so the container can reach IMDS and the LocalEmu gateway)
  - iproute2 / iputils-ping / netcat / dnsutils  (intra-VPC connectivity testing)
  - postgresql-client / mysql-client  (so the EC2 instance can reach RDS)

Why we need this
----------------
LocalEmu's VPC networks are created with ``--internal=True`` (matches
AWS VPC isolation: no internet without an IGW). A bare ``ubuntu:22.04``
container on such a network cannot ``apt-get install`` anything at
runtime — the package mirrors are unreachable. The previous startup
script tried to install openssh + iptables on every boot, hit the
no-internet wall, exited, and the container died. Every SG / NACL /
IMDS / Flow-Log feature that depends on a running container then
silently failed.

Lifecycle
---------
``ensure_base_image`` is called from ``DockerVmManager`` before any
``run_instances`` work. It is idempotent and serialised through a
process-wide lock so concurrent ``RunInstances`` calls only build the
image once. The build runs ON the LocalEmu host (which DOES have
internet), so the inability of VPC-attached containers to reach the
public internet is irrelevant — the image is fetched once, baked once,
and reused for every EC2 instance container thereafter.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

BASE_IMAGE_TAG = "localemu/ec2-base:v3"

# NOTE on awscli: Ubuntu 22.04's ``apt install awscli`` ships v1.22.34
# with botocore 1.23 (2021). That version predates the AWS_ENDPOINT_URL
# environment-variable support (added in botocore 1.28 / awscli 1.29.72,
# May 2023). Without it, ``aws s3 ls`` from inside an EC2 container
# still talks to the real ``s3.amazonaws.com`` — defeating the whole
# point of LocalEmu. We therefore install awscli via pip so we get a
# recent version that honours AWS_ENDPOINT_URL.
_DOCKERFILE = """\
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \\
    && apt-get install -y -qq --no-install-recommends \\
        openssh-server \\
        iptables \\
        iproute2 \\
        iputils-ping \\
        curl \\
        ca-certificates \\
        netcat-openbsd \\
        procps \\
        net-tools \\
        dnsutils \\
        bind9-host \\
        postgresql-client \\
        mysql-client \\
        python3-pip \\
    && pip3 install --no-cache-dir 'awscli>=1.32' \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/* ~/.cache/pip \\
    && mkdir -p /run/sshd /root/.ssh \\
    && chmod 700 /root/.ssh \\
    && ssh-keygen -A
LABEL org.localemu.image-role="ec2-base"
LABEL org.opencontainers.image.source="https://github.com/localemu/localemu"
LABEL org.opencontainers.image.description="LocalEmu-managed EC2 base image (ubuntu+sshd+iptables+net tooling+awscli v1.32+)"
"""

_build_lock = threading.Lock()
_built_in_this_process: bool = False


def _image_present() -> bool:
    """Return True if Docker already has the base image locally."""
    try:
        DOCKER_CLIENT.inspect_image(BASE_IMAGE_TAG)
        return True
    except Exception:
        return False


def ensure_base_image(force_rebuild: bool = False) -> str:
    """Make sure ``localemu/ec2-base:latest`` exists; build it if not.

    Returns the image tag (always ``BASE_IMAGE_TAG``). Idempotent.

    The first call after process start will block on the build (~30-90s
    depending on apt mirror speed). Subsequent calls are no-ops because
    the in-process flag short-circuits and Docker's image cache makes
    even cold-process re-checks instant.

    Build failures are NOT silently swallowed: the exception propagates
    so the caller (``DockerVmManager.create_instance``) can decide to
    fall back to ``ubuntu:22.04`` or refuse to launch. We log loudly
    either way.
    """
    global _built_in_this_process

    if _built_in_this_process and not force_rebuild:
        return BASE_IMAGE_TAG

    with _build_lock:
        if _built_in_this_process and not force_rebuild:
            return BASE_IMAGE_TAG

        if not force_rebuild and _image_present():
            LOG.debug("Base image %s already present, skipping build", BASE_IMAGE_TAG)
            _built_in_this_process = True
            return BASE_IMAGE_TAG

        LOG.info(
            "Building LocalEmu EC2 base image %s (one-time, ~30-90s)…",
            BASE_IMAGE_TAG,
        )
        with tempfile.TemporaryDirectory(prefix="localemu-ec2-base-") as ctx:
            dockerfile_path = os.path.join(ctx, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(_DOCKERFILE)

            DOCKER_CLIENT.build_image(
                dockerfile_path=dockerfile_path,
                image_name=BASE_IMAGE_TAG,
                context_path=ctx,
            )

        LOG.info("Built %s successfully", BASE_IMAGE_TAG)
        _built_in_this_process = True
        return BASE_IMAGE_TAG
