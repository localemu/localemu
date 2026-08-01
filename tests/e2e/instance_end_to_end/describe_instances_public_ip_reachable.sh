#!/usr/bin/env bash
# DescribeInstances returns a truthful PublicIpAddress.
#
# LocalEmu returned either moto's fabricated ``54.214.x.x``
# (unreachable from anywhere) or the fake ``127.0.0.1`` fallback (also
# not connectable to anything meaningful). Users who followed real-AWS
# tutorials: ``curl http://<PublicIpAddress>`` from another instance,
# ``ssh <user>@<PublicIpAddress>`` - all hit dead ends.
#
# LocalEmu returns the container's real IP on the shared
# public-plane Docker network (``localemu-pubport-br``). That IP is
# reachable from every other container attached to that bridge -
# the same behaviour real AWS ships. Instances with no public IP get
# the field omitted entirely, matching real AWS's contract.
#
# Also verifies :
#  * The legacy ``localemu:ssh-port`` tag is no longer emitted - port 22
#    is on port 22 of the instance's real IP inside LocalEmu's networks.
#  * ``PublicDnsName`` matches AWS shape
#    ``ec2-<ip-dashed>.compute-1.amazonaws.com``.
#  * IMDS ``public-ipv4`` and ``public-hostname`` agree with the API.
set -euo pipefail

export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

KEY_NAME="pubip-key-$$"
trap 'aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true; \
      aws ec2 delete-key-pair --key-name "$KEY_NAME" >/dev/null 2>&1 || true' EXIT

# Key-pair keeps sshd running (see NO_SSH_ENTRYPOINT_SCRIPT vs SSHD_ENTRYPOINT_SCRIPT
# in vm_manager.py - the "no key" path sleeps forever without sshd).
aws ec2 create-key-pair --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > /dev/null

IID=$(aws ec2 run-instances --image-id ami-ubuntu-22.04 \
    --instance-type t2.micro --key-name "$KEY_NAME" --count 1 \
    --query 'Instances[0].InstanceId' --output text)

for _ in $(seq 1 30); do
    s=$(aws ec2 describe-instances --instance-ids "$IID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text)
    [ "$s" = running ] && break
    sleep 1
done
[ "$s" = running ] || { echo "FAIL: never went running"; exit 2; }

echo ">>> step 1: no localemu:ssh-port tag"
TAGS=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].Tags' --output json)
if echo "$TAGS" | grep -q "localemu:ssh-port"; then
    echo "FAIL: legacy ssh-port tag still present: $TAGS"
    exit 3
fi

echo ">>> step 2: PublicIpAddress is neither 127.0.0.1 nor a moto 54.x.x.x"
PUB=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
if [ "$PUB" = "127.0.0.1" ] || [ -z "$PUB" ]; then
    echo "FAIL: PublicIpAddress=$PUB (regression)"
    exit 4
fi
if echo "$PUB" | grep -q "^54\."; then
    echo "FAIL: moto 54.x.x.x fabrication leaking: $PUB"
    exit 5
fi

echo ">>> step 3: PublicIpAddress must be reachable inside LocalEmu"
VPC_NET=$(docker inspect --format \
    '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
    "localemu-ec2-$IID" | grep -v localemu-vpc | head -1)
[ -n "$VPC_NET" ] || { echo "FAIL: no public-plane network found"; exit 6; }

CLIENT="localemu-pubip-client-$$"
docker rm -f "$CLIENT" >/dev/null 2>&1 || true
docker run -d --name "$CLIENT" --network "$VPC_NET" \
    --entrypoint sh localemu/ec2-base:v4 \
    -c 'while true; do sleep 3600; done' > /dev/null
trap 'docker rm -f "$CLIENT" >/dev/null 2>&1 || true; \
      aws ec2 terminate-instances --instance-ids "$IID" >/dev/null 2>&1 || true' EXIT

# From another container on the same public-plane bridge, TCP-connect to
# port 22 of the returned PublicIpAddress. If this hangs / refuses,
# LocalEmu returned an unreachable address (the ENGIE-demo failure).
if ! docker exec "$CLIENT" sh -c \
    "nc -z -w 5 $PUB 22 2>/dev/null" ; then
    echo "FAIL: PublicIpAddress $PUB not reachable on port 22"
    exit 7
fi

echo ">>> step 4: PublicDnsName matches AWS-shape ec2-<ip>.compute-1.amazonaws.com"
DNS=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].PublicDnsName' --output text)
EXPECTED_DNS="ec2-${PUB//./-}.compute-1.amazonaws.com"
[ "$DNS" = "$EXPECTED_DNS" ] || {
    echo "FAIL: PublicDnsName=$DNS, expected $EXPECTED_DNS"
    exit 8
}

echo ">>> step 5: IMDS agrees with the API"
IMDS_PUB=$(docker exec "localemu-ec2-$IID" \
    curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
IMDS_HOST=$(docker exec "localemu-ec2-$IID" \
    curl -s http://169.254.169.254/latest/meta-data/public-hostname)
[ "$IMDS_PUB" = "$PUB" ] || {
    echo "FAIL: IMDS public-ipv4=$IMDS_PUB, API=$PUB"
    exit 9
}
[ "$IMDS_HOST" = "$DNS" ] || {
    echo "FAIL: IMDS public-hostname=$IMDS_HOST, API=$DNS"
    exit 10
}

echo ""
echo ">>> PASS: PublicIpAddress reachable and IMDS consistent."
echo "    PublicIpAddress=$PUB"
echo "    PublicDnsName=$DNS"
echo "    Tags: (no legacy ssh-port entry)"
