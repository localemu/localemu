#!/usr/bin/env python3
"""E2E — VPC peering API validation (P2).

Proves the handler-layer guards LocalEmu adds on top of moto:
  - self-peer rejected
  - overlapping CIDR rejected
  - duplicate active/pending peering returns existing (not new id)
  - modify-options on non-active rejected
  - delete-twice returns NotFound on second call
  - cross-region accept rejected (with opt-in escape hatch)

Uses only aws CLI / boto3 — no ``docker`` commands.
"""
from __future__ import annotations

import os
import sys
import time
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
PEER_REGION = "us-west-2"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)
KW_PEER = dict(KW, region_name=PEER_REGION)
ec2 = boto3.client("ec2", **KW)
ec2_peer = boto3.client("ec2", **KW_PEER)

PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []
state: dict = {}


def step(name: str):
    def deco(fn):
        def wrap():
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn()
                dt = time.time() - t0
                print(f"  PASS [{dt:.1f}s]", flush=True)
                PASS.append((name, dt))
            except AssertionError as e:
                dt = time.time() - t0
                print(f"  FAIL [{dt:.1f}s] {e}", flush=True)
                FAIL.append((name, str(e)))
            except Exception as e:
                dt = time.time() - t0
                print(f"  ERROR [{dt:.1f}s] {type(e).__name__}: {e}", flush=True)
                FAIL.append((name, f"{type(e).__name__}: {e}"))
        return wrap
    return deco


def _err_code(exc: Exception) -> str:
    try:
        return exc.response["Error"]["Code"]  # type: ignore[attr-defined]
    except Exception:
        return ""


@step("01-self-peering-rejected")
def self_peering():
    v = ec2.create_vpc(CidrBlock="10.220.0.0/16")["Vpc"]["VpcId"]
    state["self_v"] = v
    try:
        ec2.create_vpc_peering_connection(VpcId=v, PeerVpcId=v)
    except Exception as e:
        assert _err_code(e) == "InvalidVpcPeeringConnectionId.Malformed", \
            f"expected Malformed, got {_err_code(e)}: {e}"
        return
    raise AssertionError("self-peer should have been rejected")


@step("02-overlapping-cidr-rejected")
def overlapping_cidr():
    va = ec2.create_vpc(CidrBlock="10.221.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.221.128.0/17")["Vpc"]["VpcId"]
    state["ov_a"] = va; state["ov_b"] = vb
    try:
        ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)
    except Exception as e:
        assert _err_code(e) == "InvalidVpcPeeringConnectionRequest.OverlappingCidr", \
            f"expected OverlappingCidr, got {_err_code(e)}: {e}"
        return
    raise AssertionError("overlapping-cidr peer should have been rejected")


@step("03-duplicate-create-returns-existing")
def duplicate_returns_existing():
    va = ec2.create_vpc(CidrBlock="10.222.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.223.0.0/16")["Vpc"]["VpcId"]
    state["du_a"] = va; state["du_b"] = vb
    p1 = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)[
        "VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=p1)
    # Second create on the SAME pair must not produce a new pcx id.
    r2 = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)
    p2 = r2["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    assert p1 == p2, f"expected duplicate to return {p1}, got new {p2}"
    state["du_p"] = p1


@step("04-modify-options-on-pending-rejected")
def modify_pending():
    va = ec2.create_vpc(CidrBlock="10.224.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.225.0.0/16")["Vpc"]["VpcId"]
    state["mp_a"] = va; state["mp_b"] = vb
    p = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)[
        "VpcPeeringConnection"]["VpcPeeringConnectionId"]
    state["mp_p"] = p
    try:
        ec2.modify_vpc_peering_connection_options(
            VpcPeeringConnectionId=p,
            RequesterPeeringConnectionOptions={
                "AllowDnsResolutionFromRemoteVpc": True,
            },
        )
    except Exception as e:
        assert _err_code(e) == "InvalidStateTransition", \
            f"expected InvalidStateTransition, got {_err_code(e)}: {e}"
        return
    raise AssertionError("modify on pending should have been rejected")


@step("05-delete-twice-returns-NotFound-on-second")
def delete_twice():
    va = ec2.create_vpc(CidrBlock="10.226.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.227.0.0/16")["Vpc"]["VpcId"]
    state["d2_a"] = va; state["d2_b"] = vb
    p = ec2.create_vpc_peering_connection(VpcId=va, PeerVpcId=vb)[
        "VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=p)
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=p)
    try:
        ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=p)
    except Exception as e:
        assert _err_code(e) == "InvalidVpcPeeringConnectionID.NotFound", \
            f"expected NotFound, got {_err_code(e)}: {e}"
        return
    raise AssertionError("second delete should have been rejected")


@step("06-cross-region-accept-rejected")
def cross_region_reject():
    va = ec2.create_vpc(CidrBlock="10.228.0.0/16")["Vpc"]["VpcId"]
    vb = ec2_peer.create_vpc(CidrBlock="10.229.0.0/16")["Vpc"]["VpcId"]
    state["cr_a"] = va; state["cr_b"] = vb
    p = ec2.create_vpc_peering_connection(
        VpcId=va, PeerVpcId=vb, PeerRegion=PEER_REGION,
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    state["cr_p"] = p
    try:
        # Accept can be issued from either side; try the requester side.
        ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=p)
    except Exception as e:
        assert _err_code(e) == "OperationNotPermitted", \
            f"expected OperationNotPermitted, got {_err_code(e)}: {e}"
        return
    raise AssertionError("cross-region accept should have been rejected")


def cleanup():
    print("\n=== CLEANUP ===")
    # Best-effort delete of everything we created.
    for k in ("du_p", "mp_p", "cr_p"):
        pid = state.get(k)
        if not pid:
            continue
        try:
            ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pid)
        except Exception:
            pass
    for key in (
        "self_v", "ov_a", "ov_b", "du_a", "du_b", "mp_a", "mp_b",
        "d2_a", "d2_b", "cr_a",
    ):
        v = state.get(key)
        if not v:
            continue
        try:
            ec2.delete_vpc(VpcId=v)
        except Exception:
            pass
    if state.get("cr_b"):
        try:
            ec2_peer.delete_vpc(VpcId=state["cr_b"])
        except Exception:
            pass


def main() -> int:
    steps = [
        self_peering, overlapping_cidr, duplicate_returns_existing,
        modify_pending, delete_twice, cross_region_reject,
    ]
    for s in steps:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
