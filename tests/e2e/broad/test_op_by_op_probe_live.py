"""For each service marked broken by the smoke sweep, probe every
no-required-args List*/Describe*/Get* operation and record which
return 500 vs work.

Output: per-op pass/fail table that lets us amend coverage.json so
the website tells the truth.
"""

import json
import sys

import boto3
import botocore.exceptions

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

BROKEN_SERVICES = [
    "appconfig", "bedrock", "codecommit", "personalize", "rekognition",
    "service-quotas", "textract", "timestream-write", "transfer",
]

session = boto3.Session()


def is_alive_response(e: botocore.exceptions.ClientError) -> bool:
    """4xx = API alive (just needs args). 5xx = broken."""
    code = e.response.get("Error", {}).get("Code", "")
    http = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    if http and 400 <= http < 500:
        return True
    # Some "not implemented" come through as InternalFailure 501
    msg = str(e).lower()
    if "not been implemented" in msg or "no moto route" in msg:
        return False
    if "must start with a slash" in msg:
        return False
    return False


def probe_service(svc_name: str) -> dict:
    try:
        client = session.client(svc_name, **KW)
    except Exception as e:
        return {"error": f"cannot create client: {e}"}
    service_model = client.meta.service_model
    op_names = service_model.operation_names

    results: dict[str, dict] = {}
    for op_name in op_names:
        op = service_model.operation_model(op_name)
        # Find required input params; skip ops that need args we don't have.
        input_shape = op.input_shape
        required = list(input_shape.required_members) if input_shape else []
        # Only call ops with NO required input (cheap to probe).
        if required:
            results[op_name] = {"probed": False, "skipped": "has required args"}
            continue
        # Convert "GetSomeThing" → "get_some_thing"
        py_name = boto_op_to_py(op_name)
        method = getattr(client, py_name, None)
        if method is None:
            results[op_name] = {"probed": False, "skipped": "no client method"}
            continue
        try:
            method()
            results[op_name] = {"probed": True, "outcome": "2xx",
                                "verdict": "implemented"}
        except botocore.exceptions.ClientError as e:
            http = e.response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode", 0,
            )
            code = e.response.get("Error", {}).get("Code", "?")
            verdict = "implemented" if is_alive_response(e) else "broken"
            results[op_name] = {
                "probed": True, "outcome": f"{http} {code}", "verdict": verdict,
            }
        except botocore.exceptions.ParamValidationError as e:
            results[op_name] = {"probed": True, "outcome": "ParamValidationError",
                                "verdict": "implemented"}
        except Exception as e:
            results[op_name] = {"probed": True,
                                "outcome": f"{type(e).__name__}",
                                "verdict": "broken"}
    return results


def boto_op_to_py(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if i > 0 and ch.isupper() and not name[i-1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


all_results = {}
for svc in BROKEN_SERVICES:
    print(f"=== {svc} ===")
    r = probe_service(svc)
    all_results[svc] = r
    probed = sum(1 for v in r.values() if v.get("probed"))
    skipped = sum(1 for v in r.values() if not v.get("probed"))
    broken = sum(1 for v in r.values()
                 if v.get("verdict") == "broken")
    implemented = sum(1 for v in r.values()
                      if v.get("verdict") == "implemented")
    print(f"  {len(r)} ops, {probed} probed (no required args), "
          f"{skipped} skipped (needed args)")
    print(f"  implemented={implemented}  broken={broken}")
    if broken:
        print("  broken ops:")
        for op, v in sorted(r.items()):
            if v.get("verdict") == "broken":
                print(f"    {op:40s} {v.get('outcome')}")

with open("/tmp/sweep_op_by_op_results.json", "w") as f:
    json.dump(all_results, f, indent=2)
print(f"\nJSON: /tmp/sweep_op_by_op_results.json")
