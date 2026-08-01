#!/usr/bin/env bash
# ``aws ssm start-session --document-name
# AWS-StartPortForwardingSession end-to-end.
#
# Real AWS's port-forwarding model :
#   * ``aws ssm start-session`` with ``AWS-StartPortForwardingSession``
#     spawns ``session-manager-plugin`` locally.
#   * The plugin listens on ``localPortNumber`` on the caller's box.
#   * When the caller connects to that port, the plugin frames the raw
#     TCP bytes into SMUX v1 (xtaci/smux wire) and multiplexes them
#     onto the WebSocket data channel. amazon-ssm-agent on the target
#     side splices the demuxed bytes to ``127.0.0.1:portNumber``.
#
# LocalEmu mirrors this shape :
#   * ``StartSession`` on the SSM control plane parses the document +
#     Parameters and returns a WebSocket URL under
#     ``/ssm/portal/session/<id>``.
#   * The port bridge (``services/ssm/port_mux_bridge.py``) speaks
#     SMUX v1 : one ``docker exec -i <container> nc 127.0.0.1 <port>``
#     per accepted SMUX stream, framed with the xtaci/smux wire
#     ``| ver(1) | cmd(1) | length(u16 LE) | sid(u32 LE) | payload |``.
#
# The in-container responder is a tiny Python HTTP server. ``nc -l``
# with ``-q`` semantics tears the listener down aggressively and races
# the tunnel handshake ; a socket server that stays up for the full
# request/response cycle is what real AWS-SSM users see.
#
# Success criterion : ``curl http://localhost:<localPort>/`` returns
# a non-empty body containing the marker. Bytes have crossed the
# SMUX tunnel in both directions.
set -euo pipefail

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

BOOT_KEY_NAME="portfwd-boot-$$"
LOCAL_PORT="${LOCAL_PORT:-18012}"
TARGET_PORT="${TARGET_PORT:-8012}"
BODY_MARKER="HELLO-FROM-LOCALEMU-F5C-$$"
PLUGIN_PID=""
IID=""

cleanup() {
    # Kill the AWS CLI (parent) then the plugin (child). ``aws ssm``
    # forks the plugin as a subprocess, and a kill on the parent
    # does not reap the child on macOS ; a stray plugin still
    # holding :$LOCAL_PORT wedges the next re-run.
    [ -n "$PLUGIN_PID" ] && kill "$PLUGIN_PID" 2>/dev/null || true
    pkill -P "$PLUGIN_PID" -f session-manager-plugin 2>/dev/null || true
    pkill -f "session-manager-plugin.*localPortNumber=${LOCAL_PORT}" 2>/dev/null || true
    [ -n "$IID" ] && aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true
    aws ec2 delete-key-pair --key-name "$BOOT_KEY_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Boot an instance.
aws ec2 create-key-pair --key-name "$BOOT_KEY_NAME" \
    --query 'KeyMaterial' --output text > /dev/null

IID=$(aws ec2 run-instances --image-id ami-ubuntu-22.04 \
    --instance-type t2.micro --key-name "$BOOT_KEY_NAME" --count 1 \
    --query 'Instances[0].InstanceId' --output text)
for _ in $(seq 1 30); do
    s=$(aws ec2 describe-instances --instance-ids "$IID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$s" = running ] && break
    sleep 1
done

CONTAINER="localemu-ec2-$IID"

# 2. Serve a stable HTTP body from inside the container. A short
# Python server stays up for the full session ; nc -l -q 1 races
# the tunnel setup.
echo ">>> step 1: HTTP responder listening in container on :$TARGET_PORT"
docker exec -d "$CONTAINER" sh -c "cat > /tmp/portfwd_srv.py <<PYEOF
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', ${TARGET_PORT}))
s.listen(5)
while True:
    conn, _ = s.accept()
    try:
        req = b''
        while b'\r\n\r\n' not in req:
            chunk = conn.recv(4096)
            if not chunk: break
            req += chunk
        body = b'${BODY_MARKER}'
        resp = b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % (len(body), body)
        conn.sendall(resp)
    finally:
        conn.close()
PYEOF
python3 /tmp/portfwd_srv.py"

# Wait for the listener to be bound.
for _ in $(seq 1 15); do
    if docker exec "$CONTAINER" ss -tlnp 2>/dev/null | grep -q ":${TARGET_PORT}"; then
        break
    fi
    sleep 0.3
done
docker exec "$CONTAINER" ss -tlnp 2>/dev/null | grep ":${TARGET_PORT}" | head -1 \
    || { echo "FAIL: python responder never bound :${TARGET_PORT}"; exit 2; }

# 3. Start the SSM port-forwarding session.
echo ">>> step 2: aws ssm start-session (AWS-StartPortForwardingSession)"
aws ssm start-session --target "$IID" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "portNumber=${TARGET_PORT},localPortNumber=${LOCAL_PORT}" \
    > /tmp/portfwd-plugin.log 2>&1 &
PLUGIN_PID=$!

for _ in $(seq 1 20); do
    if lsof -iTCP:${LOCAL_PORT} -sTCP:LISTEN -Pn 2>/dev/null | grep -q LISTEN; then
        break
    fi
    sleep 0.3
done
if ! lsof -iTCP:${LOCAL_PORT} -sTCP:LISTEN -Pn 2>/dev/null | grep -q LISTEN; then
    echo "FAIL: plugin never opened local :${LOCAL_PORT}"
    cat /tmp/portfwd-plugin.log
    exit 2
fi

# 4. Curl through the tunnel : the body must contain the marker.
echo ">>> step 3: curl through the tunnel returns the marker body"
BODY=$(curl -s --max-time 10 "http://127.0.0.1:${LOCAL_PORT}/" || true)
if ! printf '%s' "$BODY" | grep -q "$BODY_MARKER"; then
    echo "FAIL: tunnel body did not contain marker."
    echo "  expected substring : $BODY_MARKER"
    echo "  got                : $(printf '%s' "$BODY" | head -c 200)"
    echo "--- plugin log ---"
    cat /tmp/portfwd-plugin.log
    exit 3
fi

echo "PASS: SSM port-forwarding tunnel returns end-to-end body via SMUX v1"
