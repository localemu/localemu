#!/bin/bash

set -eo pipefail
shopt -s nullglob

# Strip `LOCALEMU_` prefix in environment variables name; except LOCALEMU_HOST and LOCALEMU_HOSTNAME (deprecated)
source <(
  env |
  grep -v -e '^LOCALEMU_HOSTNAME' |
  grep -v -e '^LOCALEMU_HOST' |
  grep -v -e '^LOCALEMU_[[:digit:]]' |
  sed -ne 's/^LOCALEMU_\([^=]\+\)=.*/export \1=${LOCALEMU_\1}/p'
)

LOG_DIR=/var/lib/localemu/logs
test -d ${LOG_DIR} || mkdir -p ${LOG_DIR}

# When the host's Docker socket is bind-mounted, its GID inside the
# container will not match the localemu user's group. If we are root
# we make sure the localemu user can talk to it; otherwise the caller
# is responsible for getting the GIDs right themselves.
if [ "$(id -u)" = "0" ] && [ -S /var/run/docker.sock ]; then
    SOCK_GID=$(stat -c '%g' /var/run/docker.sock)
    if ! getent group "$SOCK_GID" >/dev/null 2>&1; then
        groupadd -g "$SOCK_GID" hostdocker >/dev/null 2>&1 || true
    fi
    SOCK_GROUP=$(getent group "$SOCK_GID" | cut -d: -f1)
    if [ -n "$SOCK_GROUP" ]; then
        usermod -aG "$SOCK_GROUP" localemu >/dev/null 2>&1 || true
    fi
fi

# activate the virtual environment
source /opt/code/localemu/.venv/bin/activate

# run runtime init hooks BOOT stage before starting localemu
test -d /etc/localemu/init/boot.d && python3 -m localemu.runtime.init BOOT

# start localemu directly — exec ensures signals are handled correctly.
# If we started as root (the default since the image needs to fix the
# Docker socket group on boot), drop privileges to the localemu user
# via setpriv. setpriv preserves the environment, so the activated
# virtualenv and the de-prefixed LOCALEMU_* exports above survive the
# exec.
if [ "$(id -u)" = "0" ]; then
    LOCALEMU_UID=$(id -u localemu)
    LOCALEMU_GID=$(id -g localemu)
    SUPPL_GIDS=$(id -G localemu | tr ' ' ',')
    # ``HOME`` stays pointing at /root by default after setpriv — fix it
    # explicitly so packages that write under ``$HOME/.cache`` (plux, pip
    # at runtime, etc.) land somewhere the localemu user can write.
    export HOME=$(getent passwd localemu | cut -d: -f6)
    export USER=localemu
    export LOGNAME=localemu
    exec setpriv \
        --reuid="$LOCALEMU_UID" \
        --regid="$LOCALEMU_GID" \
        --groups="$SUPPL_GIDS" \
        --inh-caps=-all \
        python3 -m localemu.runtime.main
fi
exec python3 -m localemu.runtime.main
