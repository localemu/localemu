#!/usr/bin/env bash
# SSH via the AMI's canonical user.
#
# Proves that ``ssh ubuntu@<PrivateIpAddress>`` works from an in-VPC
# client after ``run-instances --key-name <name>``, matching every real
# AWS Ubuntu-AMI tutorial. Also proves ``root`` still works
# (back-compat with LocalEmu 1.1.x scripts).
#
# The client is a container attached to the same VPC network as the
# target instance. On the user's laptop this is the "bastion pattern":
# LocalEmu does not open host-to-VPC-private-IP reachability on
# macOS by design (LocalEmu is not a Docker port mapper). ``aws ssm
# start-session --target <i-...>`` is the AWS-native path from the
# user's own shell.
set -euo pipefail

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

KEY_NAME="sshkp-$$"
KEY_PATH="/tmp/${KEY_NAME}.pem"
CLIENT_NAME="localemu-sshkp-client-$$"

trap 'aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true; \
      aws ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || true; \
      docker rm -f "$CLIENT_NAME" >/dev/null 2>&1 || true; \
      rm -f "$KEY_PATH"' EXIT

echo ">>> step 1: create key pair"
aws ec2 create-key-pair --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$KEY_PATH"
chmod 600 "$KEY_PATH"

echo ">>> step 2: launch Ubuntu instance"
IID=$(aws ec2 run-instances --image-id ami-ubuntu-22.04 \
    --instance-type t2.micro --key-name "$KEY_NAME" --count 1 \
    --query 'Instances[0].InstanceId' --output text)
for _ in $(seq 1 30); do
    s=$(aws ec2 describe-instances --instance-ids "$IID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$s" = running ] && break
    sleep 1
done
[ "$s" = running ] || { echo "FAIL: instance never went running"; exit 2; }

echo ">>> step 3: discover PrivateIpAddress + VPC Docker network"
PRIVATE_IP=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
VPC_NET=$(docker inspect --format \
    '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
    "localemu-ec2-$IID" | grep localemu-vpc | head -1)

echo ">>> step 4: spawn in-VPC SSH client"
docker run -d --name "$CLIENT_NAME" --network "$VPC_NET" \
    --entrypoint sh localemu/ec2-base:v4 \
    -c 'while true; do sleep 3600; done' > /dev/null
docker cp "$KEY_PATH" "$CLIENT_NAME:/tmp/id_rsa"
docker exec "$CLIENT_NAME" sh -c "chmod 600 /tmp/id_rsa"

SSH_OPTS="-i /tmp/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=8"

echo ">>> step 5: ssh ubuntu@$PRIVATE_IP hostname"
HN=$(docker exec "$CLIENT_NAME" sh -c \
    "ssh $SSH_OPTS ubuntu@$PRIVATE_IP hostname" | tr -d '\r')
[ -n "$HN" ] || { echo "FAIL: hostname empty"; exit 3; }
echo "     hostname=$HN"

echo ">>> step 6: ssh ubuntu@$PRIVATE_IP id (uid=1000)"
UID_LINE=$(docker exec "$CLIENT_NAME" sh -c \
    "ssh $SSH_OPTS ubuntu@$PRIVATE_IP id" | tr -d '\r')
echo "     id=$UID_LINE"
echo "$UID_LINE" | grep -q "uid=1000" \
    || { echo "FAIL: uid not 1000"; exit 4; }

echo ">>> step 7: ssh ubuntu@$PRIVATE_IP sudo -n whoami (NOPASSWD)"
WHO=$(docker exec "$CLIENT_NAME" sh -c \
    "ssh $SSH_OPTS ubuntu@$PRIVATE_IP 'sudo -n whoami'" | tr -d '\r')
[ "$WHO" = root ] || { echo "FAIL: sudo whoami=$WHO"; exit 5; }

echo ">>> step 8: ssh root@$PRIVATE_IP hostname (1.1.x back-compat)"
HN2=$(docker exec "$CLIENT_NAME" sh -c \
    "ssh $SSH_OPTS root@$PRIVATE_IP hostname" | tr -d '\r')
[ "$HN2" = "$HN" ] || { echo "FAIL: root hostname mismatch"; exit 6; }

echo ""
echo ">>> PASS: ssh ubuntu@<PrivateIpAddress> works and matches AWS."
