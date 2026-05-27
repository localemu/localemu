#!/usr/bin/env python3
"""E2E — TGW lifecycle semantics (T3).

AWS's CreateTransitGateway API shape does not expose ``ClientToken``
(unlike CreateTransitGatewayPeeringAttachment), so retry idempotency
at that call site is handled by callers via tagging or pre-check.

What we do cover here are the cross-account Accept / Reject handlers
moto ships as ``NotImplementedError``:

  01 AcceptTransitGatewayVpcAttachment on a missing id raises
     InvalidTransitGatewayAttachmentID.NotFound.
  02 RejectTransitGatewayVpcAttachment on a missing id raises
     InvalidTransitGatewayAttachmentID.NotFound.
  03 AcceptTransitGatewayVpcAttachment on an already-available
     attachment raises IncorrectState — only pendingAcceptance is
     acceptable input to Accept, per AWS.
  04 RejectTransitGatewayVpcAttachment on an already-available
     attachment raises IncorrectState.

Happy-path Accept (pending → available) requires a cross-account
attachment; LocalEmu's single-account happy path autocompletes to
``available`` at CreateTransitGatewayVpcAttachment so there is
nothing to Accept.
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
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)
ec2 = boto3.client("ec2", **KW)

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


def _err_code(e: Exception) -> str:
    try:
        return e.response["Error"]["Code"]  # type: ignore[attr-defined]
    except Exception:
        return ""


@step("01-Accept-on-missing-attachment-rejected")
def accept_missing():
    try:
        ec2.accept_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId="tgw-attach-deadbeefdeadbeef1",
        )
    except Exception as e:
        assert _err_code(e) == "InvalidTransitGatewayAttachmentID.NotFound", \
            f"expected NotFound, got {_err_code(e)}: {e}"
        return
    raise AssertionError("Accept on missing attachment should have raised")


@step("02-Reject-on-missing-attachment-rejected")
def reject_missing():
    try:
        ec2.reject_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId="tgw-attach-deadbeefdeadbeef2",
        )
    except Exception as e:
        assert _err_code(e) == "InvalidTransitGatewayAttachmentID.NotFound", \
            f"expected NotFound, got {_err_code(e)}: {e}"
        return
    raise AssertionError("Reject on missing attachment should have raised")


@step("03-Accept-on-already-available-attachment-rejected")
def accept_wrong_state():
    tgw = ec2.create_transit_gateway(Description=f"t3-wrong-{TAG}")
    tgw_id = tgw["TransitGateway"]["TransitGatewayId"]
    state["tgw"] = tgw_id
    vpc = ec2.create_vpc(CidrBlock="10.170.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.170.1.0/24",
        AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    state["vpc"] = vpc; state["sub"] = sub
    att = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc, SubnetIds=[sub],
    )["TransitGatewayVpcAttachment"]
    state["att"] = att["TransitGatewayAttachmentId"]
    assert att["State"] == "available", f"expected available, got {att['State']}"
    try:
        ec2.accept_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId=att["TransitGatewayAttachmentId"],
        )
    except Exception as e:
        assert _err_code(e) == "IncorrectState", \
            f"expected IncorrectState, got {_err_code(e)}: {e}"
        return
    raise AssertionError("Accept on available should have been rejected")


@step("04-Reject-on-already-available-attachment-rejected")
def reject_wrong_state():
    try:
        ec2.reject_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId=state["att"],
        )
    except Exception as e:
        assert _err_code(e) == "IncorrectState", \
            f"expected IncorrectState, got {_err_code(e)}: {e}"
        return
    raise AssertionError("Reject on available should have been rejected")


def cleanup():
    print("\n=== CLEANUP ===")
    if state.get("att"):
        try: ec2.delete_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId=state["att"])
        except Exception: pass
        time.sleep(1)
    if state.get("sub"):
        try: ec2.delete_subnet(SubnetId=state["sub"])
        except Exception: pass
    if state.get("vpc"):
        try: ec2.delete_vpc(VpcId=state["vpc"])
        except Exception: pass
    if state.get("tgw"):
        try: ec2.delete_transit_gateway(TransitGatewayId=state["tgw"])
        except Exception: pass


def main() -> int:
    for s in [accept_missing, reject_missing,
              accept_wrong_state, reject_wrong_state]:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
