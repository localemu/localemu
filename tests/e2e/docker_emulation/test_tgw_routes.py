#!/usr/bin/env python3
"""E2E — TGW route-table semantics (T2).

Covers:
  01 CreateTransitGatewayRoute response carries non-empty
     TransitGatewayAttachments (moto silently drops this field).
  02 SearchTransitGatewayRoutes returns routes with non-empty
     TransitGatewayAttachments.
  03 EnableTransitGatewayRouteTablePropagation materialises the
     attached VPC's CIDR as a propagated route.
  04 DisableTransitGatewayRouteTablePropagation removes it.
  05 AssociateTransitGatewayRouteTable twice to different RTs
     returns Resource.AlreadyAssociated.
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


@step("00-setup-tgw-vpcs-attachments-and-rt")
def setup_all():
    tgw = ec2.create_transit_gateway(
        Description=f"t2-{TAG}",
        Options={"DefaultRouteTableAssociation": "disable",
                 "DefaultRouteTablePropagation": "disable"},
    )["TransitGateway"]["TransitGatewayId"]
    state["tgw"] = tgw
    va = ec2.create_vpc(CidrBlock="10.160.0.0/16")["Vpc"]["VpcId"]
    vb = ec2.create_vpc(CidrBlock="10.161.0.0/16")["Vpc"]["VpcId"]
    sa = ec2.create_subnet(VpcId=va, CidrBlock="10.160.1.0/24",
                           AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    sb = ec2.create_subnet(VpcId=vb, CidrBlock="10.161.1.0/24",
                           AvailabilityZone=f"{REGION}a")["Subnet"]["SubnetId"]
    state.update(dict(va=va, vb=vb, sa=sa, sb=sb))
    atta = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw, VpcId=va, SubnetIds=[sa],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    attb = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw, VpcId=vb, SubnetIds=[sb],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    state["atta"] = atta; state["attb"] = attb
    rt = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw,
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    state["rt"] = rt


@step("01-CreateTransitGatewayRoute-returns-attachment")
def static_route_shape():
    r = ec2.create_transit_gateway_route(
        DestinationCidrBlock="10.200.0.0/16",
        TransitGatewayRouteTableId=state["rt"],
        TransitGatewayAttachmentId=state["atta"],
    )
    route = r.get("Route") or {}
    atts = route.get("TransitGatewayAttachments") or []
    assert atts, f"TransitGatewayAttachments empty: {route}"
    assert atts[0].get("TransitGatewayAttachmentId") == state["atta"], atts


@step("02-SearchTransitGatewayRoutes-returns-attachment")
def search_shape():
    r = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=state["rt"],
        Filters=[{"Name": "type", "Values": ["static"]}],
    )
    routes = r.get("Routes") or []
    assert routes, "no routes returned"
    hit = next(
        (x for x in routes if x.get("DestinationCidrBlock") == "10.200.0.0/16"),
        None,
    )
    assert hit, f"static route missing from search: {routes}"
    atts = hit.get("TransitGatewayAttachments") or []
    assert atts and atts[0].get("TransitGatewayAttachmentId") == state["atta"], atts


@step("03-EnablePropagation-materialises-vpc-cidr")
def propagate_in():
    ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayRouteTableId=state["rt"],
        TransitGatewayAttachmentId=state["attb"],
    )
    r = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=state["rt"],
        Filters=[{"Name": "type", "Values": ["propagated"]}],
    )
    routes = r.get("Routes") or []
    hit = next(
        (x for x in routes if x.get("DestinationCidrBlock") == "10.161.0.0/16"),
        None,
    )
    assert hit, f"propagated route for VPC B CIDR missing: {routes}"
    atts = hit.get("TransitGatewayAttachments") or []
    assert atts and atts[0].get("TransitGatewayAttachmentId") == state["attb"], atts


@step("04-DisablePropagation-removes-the-route")
def propagate_out():
    ec2.disable_transit_gateway_route_table_propagation(
        TransitGatewayRouteTableId=state["rt"],
        TransitGatewayAttachmentId=state["attb"],
    )
    r = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=state["rt"],
        Filters=[{"Name": "type", "Values": ["propagated"]}],
    )
    routes = r.get("Routes") or []
    hit = next(
        (x for x in routes if x.get("DestinationCidrBlock") == "10.161.0.0/16"),
        None,
    )
    assert hit is None, f"propagated route still present: {routes}"


@step("05-AssociateRouteTable-twice-to-different-RTs-rejected")
def assoc_twice():
    ec2.associate_transit_gateway_route_table(
        TransitGatewayRouteTableId=state["rt"],
        TransitGatewayAttachmentId=state["atta"],
    )
    # A second RT on the same TGW, associated to the SAME attachment
    rt2 = ec2.create_transit_gateway_route_table(
        TransitGatewayId=state["tgw"],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    state["rt2"] = rt2
    try:
        ec2.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=rt2,
            TransitGatewayAttachmentId=state["atta"],
        )
    except Exception as e:
        assert _err_code(e) == "Resource.AlreadyAssociated", \
            f"expected Resource.AlreadyAssociated, got {_err_code(e)}: {e}"
        return
    raise AssertionError("second Associate should have been rejected")


def cleanup():
    print("\n=== CLEANUP ===")
    for rt in (state.get("rt"), state.get("rt2")):
        if rt:
            try: ec2.delete_transit_gateway_route_table(
                TransitGatewayRouteTableId=rt)
            except Exception: pass
    for att in (state.get("atta"), state.get("attb")):
        if att:
            try: ec2.delete_transit_gateway_vpc_attachment(
                TransitGatewayAttachmentId=att)
            except Exception: pass
    if state.get("tgw"):
        try: ec2.delete_transit_gateway(TransitGatewayId=state["tgw"])
        except Exception: pass
    for s in (state.get("sa"), state.get("sb")):
        if s:
            try: ec2.delete_subnet(SubnetId=s)
            except Exception: pass
    for v in (state.get("va"), state.get("vb")):
        if v:
            try: ec2.delete_vpc(VpcId=v)
            except Exception: pass


def main() -> int:
    for s in [setup_all, static_route_shape, search_shape,
              propagate_in, propagate_out, assoc_twice]:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
