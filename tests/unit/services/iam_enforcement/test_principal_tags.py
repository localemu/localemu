"""IAM user and role tags feed ``aws:PrincipalTag`` condition keys."""
import boto3
import pytest
from moto import mock_aws

from localemu.services.iam_enforcement.identity import _principal_tags, resolve_caller


def test_principal_tags_reads_tagger_and_list_shapes():
    class Tagger:
        def get_tag_dict_for_resource(self, arn):
            return {"team": "sec"}

    class Backend:
        tagger = Tagger()

    assert _principal_tags(Backend(), "arn", [{"Key": "env", "Value": "prod"}]) == {"team": "sec", "env": "prod"}
    assert _principal_tags(Backend(), "arn", {"a": {"Key": "env", "Value": "prod"}}) == {"team": "sec", "env": "prod"}
    assert _principal_tags(object(), "arn", None) == {}


@mock_aws
def test_iam_user_tags_resolve_to_principal_tags():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev", Tags=[{"Key": "team", "Value": "dev"}])
    key = iam.create_access_key(UserName="dev")["AccessKey"]["AccessKeyId"]
    assert resolve_caller(key, "123456789012", "us-east-1").tags == {"aws:PrincipalTag/team": "dev"}
    iam.tag_user(UserName="dev", Tags=[{"Key": "team", "Value": "sec"}])
    assert resolve_caller(key, "123456789012", "us-east-1").tags == {"aws:PrincipalTag/team": "sec"}
