"""E2E: SQS / SNS resource-policy enforcement under IAM_ENFORCEMENT=1.

Companion to the S3 enforcement test. Proves an explicit Deny in a queue or
topic policy overrides an identity Allow (the resource policy is read from
LocalEmu's native SQS/SNS stores, not moto's empty backends).

Self-skips when enforcement is off. Run with:
    pytest tests/e2e/test_sqs_sns_iam_enforcement_e2e.py -v
"""

import json
import uuid

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"
CFG = Config(retries={"max_attempts": 0})
ROOT_KEY = "AKIAIOSFODNN7EXAMPLE"


def _client(service, access_key, secret="x"):
    return boto3.client(
        service, endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id=access_key, aws_secret_access_key=secret, config=CFG,
    )


@pytest.fixture(scope="module")
def root():
    return {s: _client(s, ROOT_KEY) for s in ("iam", "sqs", "sns")}


@pytest.fixture(scope="module", autouse=True)
def _require_enforcement(root):
    iam = root["iam"]
    uname = f"probe-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=uname)
    key = iam.create_access_key(UserName=uname)["AccessKey"]
    try:
        _client("sqs", key["AccessKeyId"], key["SecretAccessKey"]).list_queues()
        enforced = False
    except ClientError as e:
        enforced = e.response["Error"]["Code"] == "AccessDenied"
    finally:
        try:
            iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
            iam.delete_user(UserName=uname)
        except Exception:
            pass
    if not enforced:
        pytest.skip("IAM_ENFORCEMENT not active; start LocalEmu with IAM_ENFORCEMENT=1")


def _user(iam, action, resource):
    uname = f"u-{uuid.uuid4().hex[:8]}"
    iam.create_user(UserName=uname)
    iam.put_user_policy(
        UserName=uname, PolicyName="p",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": resource}],
        }),
    )
    key = iam.create_access_key(UserName=uname)["AccessKey"]
    return key["AccessKeyId"], key["SecretAccessKey"]


def test_sqs_queue_policy_deny_overrides_identity_allow(root):
    qname = f"enf-{uuid.uuid4().hex[:8]}"
    q_url = root["sqs"].create_queue(QueueName=qname)["QueueUrl"]
    q_arn = root["sqs"].get_queue_attributes(
        QueueUrl=q_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    akid, secret = _user(root["iam"], "sqs:SendMessage", q_arn)
    user_sqs = _client("sqs", akid, secret)

    # identity policy allows SendMessage -> works
    user_sqs.send_message(QueueUrl=q_url, MessageBody="before")

    # queue policy explicitly denies SendMessage for everyone
    deny = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny", "Principal": "*",
            "Action": "sqs:SendMessage", "Resource": q_arn,
        }],
    }
    root["sqs"].set_queue_attributes(QueueUrl=q_url, Attributes={"Policy": json.dumps(deny)})

    with pytest.raises(ClientError) as exc:
        user_sqs.send_message(QueueUrl=q_url, MessageBody="after")
    assert exc.value.response["Error"]["Code"] == "AccessDenied"

    root["sqs"].delete_queue(QueueUrl=q_url)


def test_sns_topic_policy_deny_overrides_identity_allow(root):
    topic_arn = root["sns"].create_topic(Name=f"enf-{uuid.uuid4().hex[:8]}")["TopicArn"]

    akid, secret = _user(root["iam"], "sns:Publish", topic_arn)
    user_sns = _client("sns", akid, secret)

    # identity policy allows Publish -> works
    user_sns.publish(TopicArn=topic_arn, Message="before")

    deny = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny", "Principal": "*",
            "Action": "sns:Publish", "Resource": topic_arn,
        }],
    }
    root["sns"].set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(deny)
    )

    with pytest.raises(ClientError) as exc:
        user_sns.publish(TopicArn=topic_arn, Message="after")
    assert exc.value.response["Error"]["Code"] == "AccessDenied"

    root["sns"].delete_topic(TopicArn=topic_arn)
