#!/usr/bin/env python3
"""E2E — service-to-service calls must pass under ``IAM_ENFORCEMENT=1``.

Regression guard for the bug documented in
``LocalEmu_Bugs_2.md``: every cross-service hop that runs through
``connect_to(...)`` (plus the Lambda code-storage path that uses
``config.INTERNAL_RESOURCE_ACCOUNT`` directly) was denied by the IAM
enforcer because the caller key was not in the known-caller set.

This test pins the fix: the enforcer now recognises either the
``x-localemu-data`` internal-request-parameters header or the two
LocalEmu-internal access-key sentinels, and bypasses evaluation.

Two independent scenarios:

  01  ``lambda:CreateFunction`` with a correct Lambda trust policy.
      The bug's primary repro. Lambda internally calls ``sts:AssumeRole``
      (via ``connect_to(...).sts.request_metadata(service_principal=
      "lambda")``) and ``s3:CreateBucket``/``s3:PutObject`` (via
      ``connect_to(aws_access_key_id=INTERNAL_RESOURCE_ACCOUNT).s3``).
      Both internal hops must succeed for the function to reach state
      ``Active``.

  02  ``sns:Publish`` -> ``sqs:SendMessage`` fanout. SNS delivery to a
      subscribed SQS queue hops via the same internal-client factory.
      The message must arrive in the queue.

Required to run:
    LocalEmu started with ``IAM_ENFORCEMENT=1`` (the rest of the env
    follows the other e2e tests). Do NOT set ``ROOT_ACCESS_KEYS`` —
    the whole point is that the operator-facing config doesn't need
    any LocalEmu-internal knowledge.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
import zipfile
from io import BytesIO

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
iam = boto3.client("iam", **KW)
lam = boto3.client("lambda", **KW)
sns = boto3.client("sns", **KW)
sqs = boto3.client("sqs", **KW)

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


def _wait_lambda_active(fn_name: str, timeout: int = 30) -> str:
    """Block until the function reaches state ``Active`` (or fail)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        cfg = lam.get_function(FunctionName=fn_name)["Configuration"]
        s = cfg.get("State", "")
        if s == "Active":
            return s
        if s == "Failed":
            raise AssertionError(f"lambda entered Failed state: {cfg}")
        time.sleep(1)
    raise AssertionError(f"lambda never reached Active (last state={s!r})")


@step("01-lambda-create-function-under-IAM_ENFORCEMENT")
def lambda_create_function():
    # Trust policy must be exactly what the enforcer would demand for
    # lambda.amazonaws.com — otherwise we'd be testing the wrong thing
    # (a genuine AccessDenied, not the internal-caller regression).
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = f"bugfix-role-{TAG}"
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
    )
    role_arn = iam.get_role(RoleName=role)["Role"]["Arn"]
    state["role_name"] = role; state["role_arn"] = role_arn

    # Zip up a trivial handler in memory.
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "handler.py",
            "def h(e, c):\n    return {'ok': True}\n",
        )
    buf.seek(0)

    fn = f"bugfix-fn-{TAG}"
    # Before the fix: fails with
    #   InvalidParameterValueException: The role defined for the
    #   function cannot be assumed by Lambda
    # because `can_assume_role` can't call `sts:AssumeRole` internally.
    result = lam.create_function(
        FunctionName=fn,
        Runtime="python3.11",
        Handler="handler.h",
        Role=role_arn,
        Code={"ZipFile": buf.read()},
    )
    state["fn"] = fn
    assert result["FunctionArn"].endswith(f":function:{fn}"), result
    _wait_lambda_active(fn)


@step("02-sns-to-sqs-fanout-under-IAM_ENFORCEMENT")
def sns_to_sqs():
    # SNS delivery to SQS crosses LocalEmu's internal boundary the same
    # way Lambda does: the SNS provider builds an internal client via
    # ``connect_to(...)`` to drop the message into the target queue.
    qname = f"bugfix-q-{TAG}"
    q = sqs.create_queue(QueueName=qname)
    q_url = q["QueueUrl"]
    q_arn = sqs.get_queue_attributes(
        QueueUrl=q_url, AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]
    state["q_url"] = q_url

    topic = sns.create_topic(Name=f"bugfix-t-{TAG}")["TopicArn"]
    state["topic_arn"] = topic

    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn)

    payload = f"bugfix-msg-{TAG}"
    sns.publish(TopicArn=topic, Message=payload)

    deadline = time.time() + 15
    seen = False
    while time.time() < deadline:
        resp = sqs.receive_message(
            QueueUrl=q_url, MaxNumberOfMessages=1, WaitTimeSeconds=1,
        )
        for msg in resp.get("Messages", []) or []:
            # SNS wraps the body in its own envelope. We only care that
            # the payload reached the queue — anything else is an SNS
            # encoding detail unrelated to the enforcer regression.
            if payload in (msg.get("Body") or ""):
                seen = True
                break
        if seen:
            break
    assert seen, (
        "SNS→SQS delivery did not reach the queue. Under IAM_ENFORCEMENT=1 "
        "this failure mode is the same unknown-caller rejection that blocks "
        "lambda:CreateFunction, just on a different S2S path."
    )


def cleanup():
    print("\n=== CLEANUP ===")
    if state.get("fn"):
        try: lam.delete_function(FunctionName=state["fn"])
        except Exception: pass
    if state.get("role_name"):
        try: iam.delete_role(RoleName=state["role_name"])
        except Exception: pass
    if state.get("topic_arn"):
        try: sns.delete_topic(TopicArn=state["topic_arn"])
        except Exception: pass
    if state.get("q_url"):
        try: sqs.delete_queue(QueueUrl=state["q_url"])
        except Exception: pass


def main() -> int:
    for s in [lambda_create_function, sns_to_sqs]:
        s()
    print("\n" + "=" * 60)
    print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
    for n, dt in PASS: print(f"  PASS  {n}  ({dt:.1f}s)")
    for n, err in FAIL: print(f"  FAIL  {n}  -- {err[:300]}")
    cleanup()
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
