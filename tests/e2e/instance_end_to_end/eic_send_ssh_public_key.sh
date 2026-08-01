#!/usr/bin/env bash
# ``aws ec2-instance-connect send-ssh-public-key`` end-to-end.
#
# Real AWS's ephemeral-key model :
#   * Push a public key with SendSSHPublicKey.
#   * Instance accepts SSH with that key for 60 seconds.
#   * Instance rejects SSH with that key after 60 seconds.
#
# LocalEmu mirrors this exactly, minus the AuthorizedKeysCommand + IMDS
# indirection (see services/ec2_instance_connect/provider.py).
set -euo pipefail

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

BOOT_KEY_NAME="eic-boot-$$"
EIC_KEY_PATH="/tmp/eic-key-$$"
CLIENT="localemu-eic-client-$$"
IID=""

trap '[ -n "$IID" ] && aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true; \
      aws ec2 delete-key-pair --key-name "$BOOT_KEY_NAME" >/dev/null 2>&1 || true; \
      docker rm -f "$CLIENT" >/dev/null 2>&1 || true; \
      rm -f "$EIC_KEY_PATH" "${EIC_KEY_PATH}.pub"' EXIT

# Boot key just so sshd starts (see SSHD_ENTRYPOINT_SCRIPT vs
# NO_SSH_ENTRYPOINT_SCRIPT in vm_manager.py).
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

# Generate the ephemeral EIC keypair (client-side, real AWS pattern).
ssh-keygen -t ed25519 -f "$EIC_KEY_PATH" -N "" -q

echo ">>> step 1: send-ssh-public-key returns Success=true"
RESP=$(aws ec2-instance-connect send-ssh-public-key \
    --instance-id "$IID" --instance-os-user ubuntu \
    --ssh-public-key "file://${EIC_KEY_PATH}.pub" 2>&1)
echo "$RESP" | grep -q '"Success": true' \
    || { echo "FAIL: response missing Success=true : $RESP"; exit 2; }

echo ">>> step 2: authorized_keys has the localemu-eic marker block"
docker exec "localemu-ec2-$IID" grep -q "localemu-eic BEGIN " \
    /home/ubuntu/.ssh/authorized_keys \
    || { echo "FAIL: EIC marker missing from authorized_keys"; exit 3; }

echo ">>> step 3: ssh -i <eic-key> ubuntu@<PrivateIpAddress> succeeds within TTL"
PRIVATE_IP=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
VPC_NET=$(docker inspect --format \
    '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
    "localemu-ec2-$IID" | grep localemu-vpc | head -1)

docker run -d --name "$CLIENT" --network "$VPC_NET" \
    --entrypoint sh localemu/ec2-base:v4 \
    -c 'while true; do sleep 3600; done' > /dev/null
docker cp "$EIC_KEY_PATH" "$CLIENT:/tmp/id_ed25519"
docker exec "$CLIENT" sh -c "chmod 600 /tmp/id_ed25519"

SSH_OPTS="-i /tmp/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8"

WITHIN_HOST=$(docker exec "$CLIENT" sh -c \
    "ssh $SSH_OPTS ubuntu@$PRIVATE_IP hostname" 2>/dev/null | tr -d '\r')
[ -n "$WITHIN_HOST" ] \
    || { echo "FAIL: ssh within TTL returned no hostname"; exit 4; }

echo ">>> step 4: wait 65s for TTL expiry"
sleep 65

echo ">>> step 5: authorized_keys no longer carries the marker"
if docker exec "localemu-ec2-$IID" \
    grep -q 'localemu-eic' /home/ubuntu/.ssh/authorized_keys 2>/dev/null; then
    echo "FAIL: EIC marker still present after TTL"
    exit 5
fi

echo ">>> step 6: ssh with expired EIC key must fail with Permission denied"
if docker exec "$CLIENT" sh -c \
    "ssh $SSH_OPTS ubuntu@$PRIVATE_IP hostname" 2>/dev/null; then
    echo "FAIL: SSH succeeded after TTL - cleanup did not work"
    exit 6
fi

echo ""
echo ">>> PASS: EIC key valid within 60s TTL, rejected after."
