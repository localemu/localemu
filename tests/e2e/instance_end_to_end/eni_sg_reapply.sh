#!/usr/bin/env bash
# ENI-level SG changes reflect in iptables live.
#
# Real AWS lets you :
#   * attach a fresh ENI with its own SGs to a running instance
#   * modify the ``Groups`` attribute on an ENI already attached to
#     a running instance
#   * detach an ENI ; its SGs stop applying
#
# On real EC2, each of those flips the effective network policy
# without an instance restart. Historically LocalEmu updated moto but
# never touched the running container's iptables - you had to stop
# and re-launch the instance for a ``ModifyNetworkInterfaceAttribute
# --groups`` to bite. This E2E covers the three transitions.
#
# The test uses a stable Python HTTP server inside the container on
# TWO ports (8010 = "primary-only", 8020 = "secondary-only") and
# probes them via the container's private IP from a sibling probe
# container on the same VPC network - so ingress on those ports
# actually gets enforced by SG_IN.
set -euo pipefail

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

STAMP="$$"
KEY_NAME="sgreapply-boot-$STAMP"
VPC_ID=""
SUBNET_ID=""
SG_A_ID=""      # primary : allows 8010
SG_B_ID=""      # attached via secondary ENI later : allows 8020
IID=""
ENI_ID=""
ATTACH_ID=""
PROBE_CONTAINER="localemu-sgreapply-probe-$STAMP"

cleanup() {
    [ -n "$IID" ] && aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true
    [ -n "$ATTACH_ID" ] && aws ec2 detach-network-interface --attachment-id "$ATTACH_ID" --force >/dev/null 2>&1 || true
    [ -n "$ENI_ID" ] && aws ec2 delete-network-interface --network-interface-id "$ENI_ID" >/dev/null 2>&1 || true
    [ -n "$SG_A_ID" ] && aws ec2 delete-security-group --group-id "$SG_A_ID" >/dev/null 2>&1 || true
    [ -n "$SG_B_ID" ] && aws ec2 delete-security-group --group-id "$SG_B_ID" >/dev/null 2>&1 || true
    [ -n "$SUBNET_ID" ] && aws ec2 delete-subnet --subnet-id "$SUBNET_ID" >/dev/null 2>&1 || true
    [ -n "$VPC_ID" ] && aws ec2 delete-vpc --vpc-id "$VPC_ID" >/dev/null 2>&1 || true
    aws ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || true
    docker rm -f "$PROBE_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. VPC + subnet + two SGs -------------------------------------
echo ">>> step 1: VPC + subnet + two SGs"
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.13.0.0/16 \
    --query 'Vpc.VpcId' --output text)
SUBNET_ID=$(aws ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block 10.13.1.0/24 \
    --availability-zone us-east-1a --query 'Subnet.SubnetId' --output text)

SG_A_ID=$(aws ec2 create-security-group --group-name "sgreapply-A-$STAMP" \
    --description "primary SG allows 8010 only" --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
SG_B_ID=$(aws ec2 create-security-group --group-name "sgreapply-B-$STAMP" \
    --description "attached-later SG allows 8020 only" --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id "$SG_A_ID" \
    --protocol tcp --port 8010 --cidr 0.0.0.0/0 >/dev/null
aws ec2 authorize-security-group-ingress --group-id "$SG_B_ID" \
    --protocol tcp --port 8020 --cidr 0.0.0.0/0 >/dev/null

# --- 2. Boot instance with SG-A only -------------------------------
echo ">>> step 2: RunInstances with SG-A only"
aws ec2 create-key-pair --key-name "$KEY_NAME" --query 'KeyMaterial' --output text > /dev/null
IID=$(aws ec2 run-instances --image-id ami-ubuntu-22.04 \
    --instance-type t2.micro --key-name "$KEY_NAME" --count 1 \
    --subnet-id "$SUBNET_ID" --security-group-ids "$SG_A_ID" \
    --query 'Instances[0].InstanceId' --output text)
for _ in $(seq 1 30); do
    s=$(aws ec2 describe-instances --instance-ids "$IID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$s" = running ] && break
    sleep 1
done

CONTAINER="localemu-ec2-$IID"
INSTANCE_IP=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
VPC_NET="localemu-vpc-${VPC_ID}"

# --- 3. Serve two ports inside the container -----------------------
echo ">>> step 3: python listeners on :8010 (SG-A) and :8020 (SG-B)"
docker exec -d "$CONTAINER" sh -c "cat > /tmp/sgreapply_srv.py <<PYEOF
import socket, threading
def serve(port, tag):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port)); s.listen(5)
    while True:
        c, _ = s.accept()
        try:
            c.recv(2048)
            body = tag.encode()
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' % (len(body), body))
        finally:
            c.close()
for p, t in ((8010, 'PORT-8010-SG-A'), (8020, 'PORT-8020-SG-B')):
    threading.Thread(target=serve, args=(p, t), daemon=True).start()
threading.Event().wait()
PYEOF
python3 /tmp/sgreapply_srv.py"

for _ in $(seq 1 15); do
    if docker exec "$CONTAINER" ss -tlnp 2>/dev/null | grep -qE ":(8010|8020) "; then break; fi
    sleep 0.3
done

# --- 4. Probe container on same VPC network ------------------------
docker run -d --rm --name "$PROBE_CONTAINER" --network "$VPC_NET" \
    --entrypoint sh curlimages/curl:8.4.0 -c 'sleep 3600' >/dev/null

probe() {
    local port="$1" expect_ok="$2"
    local out rc
    out=$(docker exec "$PROBE_CONTAINER" curl -s --max-time 3 \
        "http://${INSTANCE_IP}:${port}/" 2>&1 || true)
    if [ "$expect_ok" = "yes" ]; then
        printf '%s' "$out" | grep -q "PORT-${port}" \
            && echo "  probe :$port  OPEN  ✓" \
            || { echo "  probe :$port  EXPECTED-OPEN but got empty/blocked"; return 1; }
    else
        if printf '%s' "$out" | grep -q "PORT-${port}"; then
            echo "  probe :$port  EXPECTED-CLOSED but got response"; return 1
        else
            echo "  probe :$port  CLOSED ✓"
        fi
    fi
}

echo ">>> step 4: primary ENI only, SG-A only : :8010 OPEN, :8020 CLOSED"
probe 8010 yes
probe 8020 no

# --- 5. Create + attach a secondary ENI carrying SG-B --------------
echo ">>> step 5: attach a second ENI with SG-B - :8020 must OPEN"
ENI_ID=$(aws ec2 create-network-interface --subnet-id "$SUBNET_ID" \
    --groups "$SG_B_ID" --description "sgreapply secondary ENI" \
    --query 'NetworkInterface.NetworkInterfaceId' --output text)
ATTACH_ID=$(aws ec2 attach-network-interface \
    --network-interface-id "$ENI_ID" --instance-id "$IID" --device-index 1 \
    --query 'AttachmentId' --output text)
sleep 1
probe 8010 yes
probe 8020 yes

# --- 6. ModifyNetworkInterfaceAttribute --groups on the SECOND ENI -
echo ">>> step 6: swap secondary ENI groups from SG-B to SG-A - :8020 must CLOSE"
aws ec2 modify-network-interface-attribute \
    --network-interface-id "$ENI_ID" --groups "$SG_A_ID" >/dev/null
sleep 1
probe 8010 yes
probe 8020 no

# --- 7. Restore SG-B on the secondary ENI to open again ------------
echo ">>> step 7: put SG-B back on secondary ENI - :8020 must OPEN again"
aws ec2 modify-network-interface-attribute \
    --network-interface-id "$ENI_ID" --groups "$SG_B_ID" >/dev/null
sleep 1
probe 8020 yes

# --- 8. Detach the secondary ENI ; :8020 must close again ----------
echo ">>> step 8: detach secondary ENI - :8020 must CLOSE"
aws ec2 detach-network-interface --attachment-id "$ATTACH_ID" --force >/dev/null
ATTACH_ID=""
sleep 1
probe 8010 yes
probe 8020 no

echo "PASS: ENI attach / modify-groups / detach reflected in live iptables"
