#!/usr/bin/env python3
"""End-to-end container-image Lambda test (fix #85).

Proves LocalEmu can run a Lambda function packaged as a container
image (PackageType=Image) — the modern AWS Lambda deployment format
used by ML workloads, custom dependencies, and >250 MB payloads —
not just the classic Zip format.

The test:
  01 Build a real Docker image locally from AWS's official Lambda
     base (``public.ecr.aws/lambda/python:3.12``) with a trivial
     handler, giving it a local tag.
  02 Create an IAM role acceptable as a Lambda execution role.
  03 CreateFunction with PackageType=Image and ImageUri pointing
     at the freshly built local image.
  04 The function record reports PackageType=Image and carries the
     ImageUri we supplied.
  05 Wait for function state to become Active (image inspection +
     runtime resolution is async).
  06 Invoke with a specific payload; the handler response must
     include data that proves OUR code ran — not a generic runtime
     fallback.
  07 Confirm that the Docker container LocalEmu spawned is
     derived from OUR image (not any runtime default), so we
     don't accept a cosmetic PASS from the wrong executor.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
TAG = uuid.uuid4().hex[:6]
CFG = Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=60)
KW = dict(endpoint_url=ENDPOINT, region_name=REGION,
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          config=CFG)

iam = boto3.client("iam", **KW)
lam = boto3.client("lambda", **KW)

FN_NAME = f"img-fn-{TAG}"
ROLE_NAME = f"img-lambda-role-{TAG}"
IMAGE_TAG = f"localemu-lambda-test:{TAG}"
SENTINEL = f"ran-container-image-handler-{TAG}"

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


HANDLER_PY = f"""\
import json
import os

def lambda_handler(event, context):
    return {{
        "statusCode": 200,
        "sentinel": "{SENTINEL}",
        "received": event,
        "function_name": getattr(context, "function_name", None),
        "env": {{"LOCALEMU": os.environ.get("AWS_LAMBDA_RUNTIME_API", "unset")}},
    }}
"""

DOCKERFILE = """\
FROM public.ecr.aws/lambda/python:3.12
COPY handler.py ${LAMBDA_TASK_ROOT}
CMD ["handler.lambda_handler"]
"""


@step("01-build-local-lambda-container-image")
def build_image():
    build_dir = tempfile.mkdtemp(prefix="localemu-lambda-img-")
    state["build_dir"] = build_dir
    with open(os.path.join(build_dir, "Dockerfile"), "w") as f:
        f.write(DOCKERFILE)
    with open(os.path.join(build_dir, "handler.py"), "w") as f:
        f.write(HANDLER_PY)
    # Build for linux/amd64 explicitly: Lambda's executor maps the
    # function's Architectures[0] to a Docker platform flag, and the
    # default is x86_64. On Apple Silicon hosts ``docker build`` without
    # --platform yields arm64 which doesn't satisfy the amd64 flag Lambda
    # passes to ``docker create`` → NoSuchImage. Match what Lambda asks
    # for.
    r = subprocess.run(
        ["docker", "build", "--platform", "linux/amd64",
         "-t", IMAGE_TAG, build_dir],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, \
        f"docker build failed: rc={r.returncode}\nstdout:{r.stdout}\nstderr:{r.stderr}"
    # Capture the image's ID so we can check Lambda's spawned container
    # is derived from it.
    inspect = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_TAG],
        capture_output=True, text=True, timeout=10,
    )
    assert inspect.returncode == 0 and inspect.stdout.strip(), \
        "could not inspect freshly built image"
    state["image_id"] = inspect.stdout.strip()


@step("02-create-iam-execution-role")
def create_role():
    iam.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
    state["role_arn"] = f"arn:aws:iam::000000000000:role/{ROLE_NAME}"


@step("03-create-function-with-package-type-image")
def create_fn():
    r = lam.create_function(
        FunctionName=FN_NAME,
        Role=state["role_arn"],
        PackageType="Image",
        Code={"ImageUri": IMAGE_TAG},
        Timeout=30,
        MemorySize=512,
    )
    assert r.get("PackageType") == "Image", \
        f"PackageType should be Image, got: {r.get('PackageType')}"
    assert r.get("FunctionName") == FN_NAME
    state["fn_arn"] = r.get("FunctionArn")


@step("04-get-function-reports-image-uri-and-package-type")
def inspect_fn():
    r = lam.get_function(FunctionName=FN_NAME)
    cfg = r.get("Configuration", {})
    code = r.get("Code", {})
    assert cfg.get("PackageType") == "Image", cfg
    # ImageUri lives under ``Code`` in GetFunction's response.
    assert code.get("ImageUri") == IMAGE_TAG, f"ImageUri mismatch: {code}"
    # ResolvedImageUri should carry a digest (sha256:...) — proves
    # LocalEmu inspected the image rather than storing the tag blind.
    resolved = code.get("ResolvedImageUri", "")
    assert "sha256:" in resolved, \
        f"ResolvedImageUri should carry image digest, got: {resolved!r}"


@step("05-wait-for-function-to-become-active")
def wait_active():
    deadline = time.time() + 60
    last = None
    while time.time() < deadline:
        cfg = lam.get_function_configuration(FunctionName=FN_NAME)
        last = cfg.get("State")
        if last == "Active":
            return
        if last == "Failed":
            raise AssertionError(
                f"function went to Failed state: reason={cfg.get('StateReason')!r}"
            )
        time.sleep(1)
    raise AssertionError(f"function not Active within 60s, last state: {last!r}")


@step("06-invoke-function-and-verify-handler-ran")
def invoke():
    payload = {"who": "tarek", "tag": TAG}
    r = lam.invoke(
        FunctionName=FN_NAME,
        Payload=json.dumps(payload).encode(),
        InvocationType="RequestResponse",
    )
    status = r.get("StatusCode")
    body = r["Payload"].read().decode()
    fn_err = r.get("FunctionError")
    print(f"  statusCode={status} functionError={fn_err!r}")
    print(f"  body={body[:500]}")
    assert status == 200, f"invoke status wrong: {status}"
    assert not fn_err, f"function error: {fn_err}; body={body}"
    parsed = json.loads(body)
    # The sentinel string is baked into our handler.py — if we see
    # it, OUR code ran in OUR image. Anything else means LocalEmu
    # fell back to a default runtime (which would be a scam).
    assert parsed.get("sentinel") == SENTINEL, \
        f"sentinel missing — handler did not run: {parsed}"
    assert parsed.get("received") == payload, \
        f"payload round-trip mismatch: {parsed.get('received')}"
    assert parsed.get("function_name") == FN_NAME, \
        f"function_name in context wrong: {parsed.get('function_name')}"


@step("07-spawned-container-is-derived-from-our-image")
def spawned_from_our_image():
    # LocalEmu spawns lambda containers with predictable names. Walk
    # the current containers, find one whose Image matches our tag
    # OR whose parent image (from inspect) matches our tagged image
    # id. If none match, LocalEmu ran the function in something else
    # — a silent fallback that would pass the invoke test but miss
    # the architectural point of ``PackageType=Image``.
    r = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label=io.localemu/main=1",
         "--format", "{{.Names}}\t{{.Image}}"],
        capture_output=True, text=True, timeout=10,
    )
    # Fallback filter: just list all containers whose name contains
    # our sanitized function name (pattern ``localemu-lambda-<fn>-*``).
    r = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}"],
        capture_output=True, text=True, timeout=10,
    )
    matched = [
        line for line in r.stdout.splitlines()
        if FN_NAME.lower() in line.lower()
        or "lambda" in line.lower() and IMAGE_TAG in line
    ]
    # Primary proof: at least one container whose ``Image`` column
    # matches our tag.
    our_image_containers = [
        line for line in r.stdout.splitlines() if IMAGE_TAG in line
    ]
    assert our_image_containers, (
        f"no container spawned from our image tag {IMAGE_TAG}; "
        f"all containers:\n{r.stdout}"
    )


def cleanup():
    print("\n=== CLEANUP ===")
    try:
        lam.delete_function(FunctionName=FN_NAME)
    except Exception:
        pass
    try:
        iam.delete_role(RoleName=ROLE_NAME)
    except Exception:
        pass
    # Remove the test image. Lambda's executor containers are torn
    # down automatically when the function is deleted.
    try:
        subprocess.run(["docker", "rmi", "-f", IMAGE_TAG],
                       capture_output=True, timeout=30)
    except Exception:
        pass
    if state.get("build_dir") and os.path.exists(state["build_dir"]):
        subprocess.run(["rm", "-rf", state["build_dir"]], timeout=10)


def main() -> int:
    steps = [
        build_image,
        create_role,
        create_fn,
        inspect_fn,
        wait_active,
        invoke,
        spawned_from_our_image,
    ]
    for s in steps:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS:
        print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL:
        print(f"  FAIL  {n}  -- {err[:200]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
