"""Exhaustive empirical sweep: probe every operation with no required
input parameters across all 123 services, record what really works,
and emit a coverage.empirical.json that mirrors the website's schema
but reflects observed behaviour.

For ops that require input args (most CreateX / GetY ops), we cannot
probe them cheaply without provisioning real resources, so we record
them as ``unverified``. The website's static coverage already tells
the user moto/custom, so we keep that classification for unverified
ops and ONLY flip an op's status when empirical observation proves
moto's "implemented" claim was wrong (i.e. it returns 501).
"""

import json
import os
import pathlib
import sys
from datetime import datetime, timezone

import boto3
import botocore.exceptions

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
session = boto3.Session()


# Path to the dashboard/website coverage.json source of truth. Default
# assumes the localemu-cloud-website checkout sits next to this repo, the
# layout most contributors use; override with LOCALEMU_COVERAGE_JSON for
# any other arrangement.
COVERAGE_PATH = os.environ.get(
    "LOCALEMU_COVERAGE_JSON",
    str(pathlib.Path(__file__).resolve().parents[3].parent
        / "localemu-cloud-website" / "src" / "data" / "coverage.json"),
)
COVERAGE_FRESH = "/tmp/coverage.new.json"  # post-generator-fix
OUT_PATH = "/tmp/coverage.empirical.json"
RESULTS_PATH = "/tmp/sweep_all_ops_results.json"


def boto_op_to_py(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if i > 0 and ch.isupper() and not name[i-1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def probe_service(svc_name: str):
    try:
        client = session.client(svc_name, **KW)
    except Exception as e:
        return None, f"client error: {e}"
    sm = client.meta.service_model
    results = {}
    for op_name in sm.operation_names:
        op = sm.operation_model(op_name)
        ishape = op.input_shape
        required = list(ishape.required_members) if ishape else []
        if required:
            results[op_name] = {"probed": False, "reason": "has required args"}
            continue
        py = boto_op_to_py(op_name)
        method = getattr(client, py, None)
        if method is None:
            results[op_name] = {"probed": False, "reason": "no client method"}
            continue
        try:
            method()
            results[op_name] = {"probed": True, "outcome": "2xx",
                                "alive": True}
        except botocore.exceptions.ClientError as e:
            http = e.response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode", 0,
            )
            code = e.response.get("Error", {}).get("Code", "")
            msg = str(e)
            broken = False
            if http >= 500 or "not been implemented" in msg.lower():
                broken = True
            if "must start with a slash" in msg.lower():
                broken = True
            results[op_name] = {
                "probed": True, "outcome": f"{http} {code}",
                "alive": not broken,
                "message": msg[:120] if broken else None,
            }
        except botocore.exceptions.ParamValidationError:
            # Client-side rejection of our empty call — service IS wired.
            results[op_name] = {"probed": True, "outcome": "ParamValidationError",
                                "alive": True}
        except Exception as e:
            results[op_name] = {"probed": True, "outcome": str(type(e).__name__),
                                "alive": False, "message": str(e)[:120]}
    return results, None


def main():
    with open(COVERAGE_FRESH) as f:
        coverage = json.load(f)

    all_results = {}
    empirical_corrections = {}  # svc -> {op: "not_implemented"}
    for svc in sorted(coverage["services"].keys()):
        print(f"probing {svc}…", flush=True)
        results, err = probe_service(svc)
        if err:
            all_results[svc] = {"error": err}
            continue
        all_results[svc] = results
        broken_ops = [op for op, r in results.items()
                      if r.get("probed") and r.get("alive") is False]
        if broken_ops:
            empirical_corrections[svc] = broken_ops

    # Apply corrections to the coverage data.
    new_services = {}
    for svc, svc_data in coverage["services"].items():
        ops = list(svc_data["operations"])
        broken = set(empirical_corrections.get(svc, []))
        if broken:
            for op in ops:
                if op["name"] in broken and op["status"] != "custom":
                    op["status"] = "not_implemented"
        custom = sum(1 for op in ops if op["status"] == "custom")
        moto = sum(1 for op in ops if op["status"] == "moto")
        not_impl = sum(1 for op in ops if op["status"] == "not_implemented")
        new_services[svc] = {
            "display_name": svc_data["display_name"],
            "total": svc_data["total"],
            "custom": custom,
            "moto": moto,
            "not_implemented": not_impl,
            "operations": ops,
        }

    total_ops = sum(v["total"] for v in new_services.values())
    total_impl = sum(v["custom"] + v["moto"] for v in new_services.values())
    out = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_services": len(new_services),
        "total_operations": total_ops,
        "total_implemented": total_impl,
        "services": new_services,
    }
    with open(OUT_PATH, "w") as f:
        json.dump(out, f, indent=2)
    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nempirical corrections in {len(empirical_corrections)} services")
    for svc in sorted(empirical_corrections):
        print(f"  {svc:30s} {len(empirical_corrections[svc])} ops flipped → not_implemented")
    print(f"\nold total_implemented: {coverage['total_implemented']}")
    print(f"new total_implemented: {total_impl}")
    print(f"delta: {coverage['total_implemented'] - total_impl} ops downgraded")
    print(f"\nwrote {OUT_PATH}")


if __name__ == "__main__":
    main()
