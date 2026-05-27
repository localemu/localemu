#
# base: Stage which installs necessary runtime dependencies (OS packages, etc.)
#
FROM python:3.13.12-slim-trixie@sha256:8bc60ca09afaa8ea0d6d1220bde073bacfedd66a4bf8129cbdc8ef0e16c8a952 AS base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        apt-get install -y --no-install-recommends \
            ca-certificates curl gnupg git make openssl tar pixz zip unzip \
            groff-base iputils-ping nss-passwords procps iproute2 xz-utils \
            libatomic1 binutils && \
        apt-get install --only-upgrade libexpat1

# Install k3d + kubectl — required for EKS (``EKS_K8S_PROVIDER=k3d``) to
# spin real k3s clusters on the host Docker daemon via the mounted socket.
# k3d is a Go binary; pinned so a future upstream release can't break us.
ARG K3D_VERSION=v5.8.3
ARG KUBECTL_VERSION=v1.33.6
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) K3D_ARCH=amd64; KUBECTL_ARCH=amd64 ;; \
      arm64) K3D_ARCH=arm64; KUBECTL_ARCH=arm64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/k3d \
      "https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}/k3d-linux-${K3D_ARCH}" && \
    chmod +x /usr/local/bin/k3d && \
    curl -fsSL -o /usr/local/bin/kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${KUBECTL_ARCH}/kubectl" && \
    chmod +x /usr/local/bin/kubectl; \
    # Smoke-test the binaries we just dropped. ``curl -f`` already
    # guarantees the download was a valid 200 response from the right
    # URL, so a failure here is almost certainly QEMU-emulation noise
    # when building amd64 images on arm64 hosts (Go binaries occasionally
    # trip on syscalls that user-mode emulation does not translate).
    # Run as best-effort: log the outcome but do not fail the build.
    if /usr/local/bin/k3d version >/dev/null 2>&1; then \
      echo "k3d sanity-check: OK"; \
    else \
      echo "k3d sanity-check: skipped (likely cross-arch emulation)"; \
    fi; \
    if /usr/local/bin/kubectl version --client=true >/dev/null 2>&1; then \
      echo "kubectl sanity-check: OK"; \
    else \
      echo "kubectl sanity-check: skipped (likely cross-arch emulation)"; \
    fi

SHELL [ "/bin/bash", "-c" ]
ENV LANG=C.UTF-8

# set workdir
RUN mkdir -p /opt/code/localemu/src
WORKDIR /opt/code/localemu/

# create localemu user and filesystem hierarchy
RUN useradd -ms /bin/bash localemu && \
    mkdir -p /var/lib/localemu && \
    chown -R localemu:localemu /var/lib/localemu && \
    chmod -R 755 /var/lib/localemu && \
    mkdir -p /usr/lib/localemu && \
    chown -R localemu:localemu /usr/lib/localemu && \
    mkdir -p /tmp/localemu && \
    chown -R localemu:localemu /tmp/localemu && \
    chmod -R 755 /tmp/localemu && \
    touch /tmp/localemu/.marker && \
    chmod 755 /root

# install the entrypoint script
COPY bin/docker-entrypoint.sh /usr/local/bin/
COPY bin/hosts /etc/hosts

# expose default environment
ENV USER=localemu
ENV PYTHONUNBUFFERED=1


#
# builder: Stage which pre-installs Python dependencies for layer caching
#
FROM base AS builder
ARG TARGETARCH

# Install build dependencies (gcc/g++ needed for native extensions)
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        apt-get install -y --no-install-recommends gcc g++

# Create virtualenv and upgrade build tools
RUN --mount=type=cache,target=/root/.cache \
    python -m venv .venv && . .venv/bin/activate && \
    pip3 install --upgrade pip wheel setuptools setuptools_scm

# Copy only pyproject.toml first (for dependency layer caching)
COPY pyproject.toml plux.ini ./

# Pre-install runtime dependencies (cached unless pyproject.toml changes).
# setuptools-scm needs a version hint because .git is not available in Docker.
ARG LOCALEMU_BUILD_VERSION=0.1.dev0
RUN --mount=type=cache,target=/root/.cache \
    . .venv/bin/activate && \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALEMU=${LOCALEMU_BUILD_VERSION} \
    pip3 install --dry-run .[runtime] 2>/dev/null; \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALEMU=${LOCALEMU_BUILD_VERSION} \
    pip3 install .[runtime]


#
# final: Builds upon base, copies venv from builder, installs LocalEmu
#
FROM base
COPY --chown=localemu:localemu --from=builder /opt/code/localemu/.venv /opt/code/localemu/.venv

# The build version is set by CI or defaults to dev
ARG LOCALEMU_BUILD_VERSION=0.1.dev0

# Copy project files
COPY --chown=localemu:localemu pyproject.toml plux.ini Makefile ./

# Copy source code
COPY --chown=localemu:localemu src/ /opt/code/localemu/src

# Install LocalEmu from source (single source of truth: pyproject.toml)
RUN --mount=type=cache,target=/root/.cache \
    . .venv/bin/activate && \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALEMU=${LOCALEMU_BUILD_VERSION} \
    pip install -e .[runtime]

# Generate service catalog cache
RUN . .venv/bin/activate && python3 -m localemu.aws.spec

# Ensure static lib and config directories exist
RUN mkdir -p /usr/lib/localemu /etc/localemu/conf.d /etc/localemu/init && \
    chown -R localemu:localemu /usr/lib/localemu /etc/localemu && \
    chmod -R 755 /usr/lib/localemu /etc/localemu

# Link package installer virtual environments into the localemu venv
RUN echo /var/lib/localemu/lib/python-packages/lib/python3.13/site-packages > localemu-var-python-packages-venv.pth && \
    mv localemu-var-python-packages-venv.pth .venv/lib/python*/site-packages/
RUN echo /usr/lib/localemu/python-packages/lib/python3.13/site-packages > localemu-static-python-packages-venv.pth && \
    mv localemu-static-python-packages-venv.pth .venv/lib/python*/site-packages/

# Expose: gateway (4566), external service ports (4510-4559), debugpy (5678)
EXPOSE 4566 4510-4559 5678

HEALTHCHECK --interval=10s --start-period=15s --retries=5 --timeout=10s \
    CMD curl -sf http://localhost:4566/_localemu/health || exit 1

# Default volume for persistent state.
# When PERSISTENCE=1 is set, state is saved here on shutdown and
# restored on startup. Mount a named volume or host directory to
# keep data across container recreations:
#   docker run -v localemu-data:/var/lib/localemu -e PERSISTENCE=1 ...
VOLUME /var/lib/localemu

# Mark as community edition
RUN touch /usr/lib/localemu/.community-version

LABEL authors="LocalEmu Contributors"
LABEL maintainer="LocalEmu Team (info@localemu.cloud)"
LABEL description="LocalEmu - Free, open-source AWS cloud emulator"

# Build metadata (set by CI, changes every build)
ARG LOCALEMU_BUILD_DATE
ARG LOCALEMU_BUILD_GIT_HASH
ENV LOCALEMU_BUILD_DATE=${LOCALEMU_BUILD_DATE}
ENV LOCALEMU_BUILD_GIT_HASH=${LOCALEMU_BUILD_GIT_HASH}
ENV LOCALEMU_BUILD_VERSION=${LOCALEMU_BUILD_VERSION}

# Application files are owned by the localemu user via the COPY --chown
# steps above, so no recursive chown is needed here. A trailing
# ``chown -R /opt/code/localemu`` would rewrite metadata on the whole
# virtualenv and force the overlay filesystem to copy every file into a
# new layer, roughly doubling the image size. The runtime only reads
# this tree; everything it writes lives under /usr/lib/localemu,
# /var/lib/localemu, or $HOME. The container still starts as root so the
# entrypoint can align the GID of a bind-mounted Docker socket with the
# localemu user; the entrypoint then drops privileges to localemu via
# setpriv before exec'ing the Python runtime. Callers wanting hard-locked
# non-root behavior can still pass ``--user localemu`` (or any UID/GID)
# on docker run, in which case the socket-fixup branch is skipped and the
# entrypoint runs directly as that user.

# Start LocalEmu
ENTRYPOINT ["docker-entrypoint.sh"]
