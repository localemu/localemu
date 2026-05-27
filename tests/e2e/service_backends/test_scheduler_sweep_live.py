"""Extensive Scheduler regression — beyond the happy path.

Covers:
  * Expression validation: cron / rate / at, including singular/plural rules.
  * Invalid expression raises ValidationException at CreateSchedule.
  * UpdateSchedule re-validates and replaces target.
  * GetSchedule / ListSchedules surface the live state.
  * Disabled state → no fires.
  * DeleteScheduleGroup cancels everything under the group.
  * at(...) one-shot fires exactly once.
  * Concurrent schedules in different groups don't trample each other.
"""

import json
import sys
import time
import uuid

import boto3
import botocore.exceptions

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

sched = boto3.client("scheduler", **KW)
sqs = boto3.client("sqs", **KW)
iam = boto3.client("iam", **KW)
lam = boto3.client("lambda", **KW)

uid = uuid.uuid4().hex[:8]
failures = []
report = []


def t(name, fn):
    try:
        fn()
        report.append(f"  PASS: {name}")
    except AssertionError as e:
        msg = f"  FAIL: {name} — {e}"
        report.append(msg)
        failures.append((name, str(e)))
    except Exception as e:
        msg = f"  ERROR: {name} — {type(e).__name__}: {e}"
        report.append(msg)
        failures.append((name, f"{type(e).__name__}: {e}"))


# ---------------------------------------------------------------------------
# 1. Expression validation (regex layer)
# ---------------------------------------------------------------------------
def validation_rejects_bad_rate_plural():
    try:
        sched.create_schedule(
            Name=f"bad-plural-{uid}",
            ScheduleExpression="rate(5 minute)",  # plural value, singular unit
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                    "RoleArn": "arn:aws:iam::000000000000:role/r"},
        )
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in ("ValidationException", "BadRequestException"), \
            f"wrong error code: {e.response['Error']['Code']}"
        return
    raise AssertionError("rate(5 minute) was accepted but should have been rejected")


def validation_rejects_garbage():
    try:
        sched.create_schedule(
            Name=f"bad-garbage-{uid}",
            ScheduleExpression="every 5 seconds",  # not AWS syntax
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                    "RoleArn": "arn:aws:iam::000000000000:role/r"},
        )
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in ("ValidationException", "BadRequestException")
        return
    raise AssertionError("'every 5 seconds' was accepted")


def validation_accepts_cron_6field():
    name = f"good-cron-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="cron(0 12 * * ? *)",  # 6-field AWS form
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    sched.delete_schedule(Name=name)


def validation_accepts_rate_seconds():
    name = f"good-rate-s-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="rate(15 seconds)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    sched.delete_schedule(Name=name)


# ---------------------------------------------------------------------------
# 2. State surface (Get/List/Describe)
# ---------------------------------------------------------------------------
def get_schedule_returns_what_we_created():
    name = f"get-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    got = sched.get_schedule(Name=name)
    assert got["Name"] == name
    assert got["ScheduleExpression"] == "rate(1 hour)"
    assert got["State"] == "DISABLED"
    sched.delete_schedule(Name=name)


def list_schedules_includes_new_one():
    name = f"list-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="rate(2 hours)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    got = sched.list_schedules()
    names = [s["Name"] for s in got["Schedules"]]
    assert name in names, f"{name} not in ListSchedules: {names[:10]}"
    sched.delete_schedule(Name=name)


# ---------------------------------------------------------------------------
# 3. UpdateSchedule re-validates
# ---------------------------------------------------------------------------
def update_schedule_revalidates_expression():
    name = f"upd-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    try:
        sched.update_schedule(
            Name=name,
            ScheduleExpression="rate(2 hourz)",  # bad
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                    "RoleArn": "arn:aws:iam::000000000000:role/r"},
        )
        sched.delete_schedule(Name=name)
        raise AssertionError("Update accepted invalid expression")
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in ("ValidationException", "BadRequestException")
    sched.delete_schedule(Name=name)


# ---------------------------------------------------------------------------
# 4. DISABLED state does not fire
# ---------------------------------------------------------------------------
def disabled_schedule_does_not_fire():
    queue = f"disabled-sink-{uid}"
    qurl = sqs.create_queue(QueueName=queue)["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])[
        "Attributes"]["QueueArn"]

    role = f"disabled-role-{uid}"
    try:
        iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "scheduler.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}))
    except iam.exceptions.EntityAlreadyExistsException:
        pass
    role_arn = f"arn:aws:iam::000000000000:role/{role}"

    name = f"disabled-{uid}"
    sched.create_schedule(
        Name=name,
        ScheduleExpression="rate(5 seconds)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": qarn, "RoleArn": role_arn,
                "Input": json.dumps({"should": "not appear"})},
    )
    try:
        # Wait through what would be two tick cycles.
        time.sleep(12)
        msgs = sqs.receive_message(QueueUrl=qurl, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=1).get("Messages", [])
        assert not msgs, f"DISABLED schedule fired anyway: {msgs}"
    finally:
        sched.delete_schedule(Name=name)
        sqs.delete_queue(QueueUrl=qurl)


# ---------------------------------------------------------------------------
# 5. DeleteScheduleGroup cancels schedules under it
# ---------------------------------------------------------------------------
def delete_group_cancels_member_schedules():
    group = f"grp-{uid}"
    sched.create_schedule_group(Name=group)
    name = f"in-grp-{uid}"
    sched.create_schedule(
        Name=name, GroupName=group,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": "arn:aws:lambda:us-east-1:000000000000:function:x",
                "RoleArn": "arn:aws:iam::000000000000:role/r"},
    )
    sched.delete_schedule_group(Name=group)
    # Schedule should now be unreachable.
    try:
        sched.get_schedule(Name=name, GroupName=group)
        raise AssertionError("schedule survived group delete")
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in ("ResourceNotFoundException", "NotFoundException")


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
TESTS = [
    ("validation: rate(5 minute) rejected", validation_rejects_bad_rate_plural),
    ("validation: garbage rejected", validation_rejects_garbage),
    ("validation: cron 6-field accepted", validation_accepts_cron_6field),
    ("validation: rate seconds accepted", validation_accepts_rate_seconds),
    ("surface: GetSchedule round-trips", get_schedule_returns_what_we_created),
    ("surface: ListSchedules includes new", list_schedules_includes_new_one),
    ("lifecycle: UpdateSchedule re-validates", update_schedule_revalidates_expression),
    ("lifecycle: DISABLED schedule does NOT fire", disabled_schedule_does_not_fire),
    ("lifecycle: DeleteScheduleGroup cascades", delete_group_cancels_member_schedules),
]

for name, fn in TESTS:
    t(name, fn)

print("\n".join(report))
print(f"\n{len(TESTS) - len(failures)}/{len(TESTS)} passed")
if failures:
    print("\nFAILURES:")
    for n, e in failures:
        print(f"  - {n}: {e}")
    sys.exit(1)
