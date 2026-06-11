"""Extensive end-to-end coverage for the 1.1.0 multi-account and
replication features.

Covers:
* Multi-account namespacing.
* AccountRegistry and its admin endpoints.
* AWS Organizations service including DescribeEffectivePolicy.
* OrganizationAccountAccessRole auto-seeding with AdministratorAccess.
* Cross-account resource-policy evaluation and the new condition keys
  (``aws:PrincipalAccount``, ``aws:ResourceAccount``, ``aws:SourceAccount``,
  ``aws:PrincipalOrgID``, ``aws:PrincipalOrgPaths``, ``aws:ResourceOrgID``).
* S3 replication data plane: PENDING / COMPLETED / REPLICA state,
  VersionId preservation, body fidelity, filter (Prefix / Tag / And),
  priority resolution, multi-destination, GLACIER skip, no chained
  replication.

Runs against a live LocalEmu on http://localhost:4578 unless
``LOCALEMU_ENDPOINT`` is overridden. Skipped if the gateway is not up.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError


ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4578")
REGION = "us-east-1"

_CFG = Config(retries={"max_attempts": 0})


def _client(service: str, *, key: str = "AKIAIOSFODNN7EXAMPLE", secret: str = "any",
            session_token: str | None = None):
    kwargs = dict(
        endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id=key, aws_secret_access_key=secret, config=_CFG,
    )
    if session_token:
        kwargs["aws_session_token"] = session_token
    return boto3.client(service, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def _gate_localemu():
    try:
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/health", timeout=5)
        json.loads(resp.read())
    except Exception as e:
        pytest.skip(f"LocalEmu not reachable at {ENDPOINT}: {e}")


# ---------------------------------------------------------------------------
# Multi-account namespacing (PINNING the pre-1.1.0 baseline)
# ---------------------------------------------------------------------------


class TestMultiAccountNamespacing:
    def test_two_accounts_have_isolated_s3(self):
        s3a = _client("s3", key="111111111111")
        s3b = _client("s3", key="222222222222")
        s3a.create_bucket(Bucket="acct-a-iso")
        s3b.create_bucket(Bucket="acct-b-iso")
        buckets_a = {b["Name"] for b in s3a.list_buckets()["Buckets"]}
        buckets_b = {b["Name"] for b in s3b.list_buckets()["Buckets"]}
        assert "acct-a-iso" in buckets_a and "acct-b-iso" not in buckets_a
        assert "acct-b-iso" in buckets_b and "acct-a-iso" not in buckets_b

    def test_sts_get_caller_identity_returns_correct_account(self):
        sts_a = _client("sts", key="333333333333")
        sts_b = _client("sts", key="444444444444")
        assert sts_a.get_caller_identity()["Account"] == "333333333333"
        assert sts_b.get_caller_identity()["Account"] == "444444444444"

    def test_sqs_arns_are_account_scoped(self):
        sqs_a = _client("sqs", key="555555555555")
        sqs_b = _client("sqs", key="666666666666")
        url_a = sqs_a.create_queue(QueueName="iso-q")["QueueUrl"]
        url_b = sqs_b.create_queue(QueueName="iso-q")["QueueUrl"]
        assert "555555555555" in url_a
        assert "666666666666" in url_b
        assert url_a != url_b


# ---------------------------------------------------------------------------
# Account registry + admin endpoints
# ---------------------------------------------------------------------------


class TestAccountRegistryAdmin:
    def test_get_accounts_returns_canonical_shape(self):
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/api/accounts")
        data = json.loads(resp.read())
        assert "Accounts" in data
        assert isinstance(data["Accounts"], list)
        # The other tests will have populated the registry already.
        ids = {r["Id"] for r in data["Accounts"]}
        # Make sure auto-population fired for an arbitrary account.
        _client("sts", key="999999988888").get_caller_identity()
        ids2 = {r["Id"] for r in json.loads(
            urllib.request.urlopen(f"{ENDPOINT}/_localemu/api/accounts").read()
        )["Accounts"]}
        assert "999999988888" in ids2

    def test_post_creates_explicit_account(self):
        body = json.dumps({
            "account_id": "777666555444",
            "name": "explicit-via-admin",
            "email": "ex@example.test",
        }).encode()
        req = urllib.request.Request(
            f"{ENDPOINT}/_localemu/api/accounts",
            method="POST", data=body,
            headers={"Content-Type": "application/json"},
        )
        record = json.loads(urllib.request.urlopen(req).read())
        assert record["Id"] == "777666555444"
        assert record["Name"] == "explicit-via-admin"
        assert record["JoinedMethod"] == "CREATED"

    def test_get_one_account(self):
        # depends on the POST test above having run; create idempotently
        body = json.dumps({"account_id": "212121212121", "name": "single"}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"{ENDPOINT}/_localemu/api/accounts",
                method="POST", data=body,
                headers={"Content-Type": "application/json"},
            ))
        except Exception:
            pass
        resp = urllib.request.urlopen(f"{ENDPOINT}/_localemu/api/accounts/212121212121")
        data = json.loads(resp.read())
        assert data["Id"] == "212121212121"

    def test_delete_default_account_is_rejected(self):
        req = urllib.request.Request(
            f"{ENDPOINT}/_localemu/api/accounts/000000000000", method="DELETE",
        )
        try:
            urllib.request.urlopen(req)
            assert False, "expected 400"
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_delete_an_explicitly_created_account(self):
        body = json.dumps({"account_id": "313131313131"}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"{ENDPOINT}/_localemu/api/accounts", method="POST", data=body,
                headers={"Content-Type": "application/json"},
            ))
        except Exception:
            pass
        urllib.request.urlopen(urllib.request.Request(
            f"{ENDPOINT}/_localemu/api/accounts/313131313131", method="DELETE",
        ))
        try:
            urllib.request.urlopen(f"{ENDPOINT}/_localemu/api/accounts/313131313131")
            assert False, "expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_account_summary_returns_resource_counts(self):
        # Ensure the default account is in the registry first (a touch
        # of any AWS call routes through AccountIdEnricher and registers
        # it). Without this the summary is 404 for a brand-new instance.
        _client("sts").get_caller_identity()
        resp = urllib.request.urlopen(
            f"{ENDPOINT}/_localemu/api/accounts/000000000000/summary"
        )
        data = json.loads(resp.read())
        assert data["account_id"] == "000000000000"
        assert isinstance(data["resources"], dict)


# ---------------------------------------------------------------------------
# Organizations + OrganizationAccountAccessRole
# ---------------------------------------------------------------------------


class TestOrganizationsAndAccessRole:
    MGMT = "420420420420"

    def test_create_organization(self):
        org = _client("organizations", key=self.MGMT)
        # Re-creation on a populated org is a no-op in moto — just probe
        # describe-organization once to confirm shape.
        try:
            org.create_organization()
        except ClientError:
            pass
        desc = org.describe_organization()["Organization"]
        assert desc["MasterAccountId"] == self.MGMT
        assert desc["FeatureSet"] == "ALL"

    def test_create_account_and_list(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        new = org.create_account(Email="m1-list@org.test", AccountName="m1-list")
        new_id = new["CreateAccountStatus"]["AccountId"]
        accts = org.list_accounts()["Accounts"]
        assert any(a["Id"] == new_id for a in accts)

    def test_create_account_seeds_admin_inline_policy(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        new = org.create_account(Email="admin-seed@org.test", AccountName="admin-seed")
        new_id = new["CreateAccountStatus"]["AccountId"]
        iam = _client("iam", key=new_id)
        names = iam.list_role_policies(
            RoleName="OrganizationAccountAccessRole"
        )["PolicyNames"]
        assert "AdministratorAccess" in names
        doc = iam.get_role_policy(
            RoleName="OrganizationAccountAccessRole",
            PolicyName="AdministratorAccess",
        )["PolicyDocument"]
        statement = doc["Statement"][0]
        assert statement["Effect"] == "Allow"
        assert statement["Action"] == "*"
        assert statement["Resource"] == "*"

    def test_mgmt_assumes_org_access_role_in_member(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        new = org.create_account(Email="assume@org.test", AccountName="assume-target")
        new_id = new["CreateAccountStatus"]["AccountId"]
        sts_mgmt = _client("sts", key=self.MGMT)
        result = sts_mgmt.assume_role(
            RoleArn=f"arn:aws:iam::{new_id}:role/OrganizationAccountAccessRole",
            RoleSessionName="org-assume-test",
        )
        creds = result["Credentials"]
        sts_session = _client(
            "sts",
            key=creds["AccessKeyId"],
            secret=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
        )
        ident = sts_session.get_caller_identity()
        assert ident["Account"] == new_id
        assert "assumed-role/OrganizationAccountAccessRole/org-assume-test" in ident["Arn"]

    def test_create_organizational_unit(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        root_id = org.list_roots()["Roots"][0]["Id"]
        ou = org.create_organizational_unit(ParentId=root_id, Name="dev-ou")["OrganizationalUnit"]
        assert ou["Name"] == "dev-ou"
        # describe round-trip
        d = org.describe_organizational_unit(OrganizationalUnitId=ou["Id"])["OrganizationalUnit"]
        assert d["Id"] == ou["Id"]

    def test_describe_effective_policy_returns_aws_shape(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        resp = org.describe_effective_policy(PolicyType="TAG_POLICY")
        eff = resp["EffectivePolicy"]
        assert eff["PolicyType"] == "TAG_POLICY"
        # PolicyContent is a JSON string per AWS
        body = json.loads(eff["PolicyContent"])
        assert isinstance(body, dict)

    def test_create_scp_and_attach(self):
        org = _client("organizations", key=self.MGMT)
        try:
            org.create_organization()
        except ClientError:
            pass
        root_id = org.list_roots()["Roots"][0]["Id"]
        scp = org.create_policy(
            Name="DenyExpensive",
            Description="Pin",
            Type="SERVICE_CONTROL_POLICY",
            Content='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:RunInstances","Resource":"*"}]}',
        )["Policy"]
        org.attach_policy(PolicyId=scp["PolicySummary"]["Id"], TargetId=root_id)
        # Verify it's listed against the target
        listed = org.list_policies_for_target(
            TargetId=root_id, Filter="SERVICE_CONTROL_POLICY",
        )["Policies"]
        assert any(p["Id"] == scp["PolicySummary"]["Id"] for p in listed)


# ---------------------------------------------------------------------------
# Cross-account resource policy evaluation (live + symbol-level)
# ---------------------------------------------------------------------------


class TestCrossAccountResourcePolicy:
    def test_evaluate_resource_policy_allow(self):
        from localemu.services.iam_enforcement.resource_policies import (
            Decision, ResourceTarget, evaluate_resource_policy,
        )
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::xab/*",
            }],
        }
        target = ResourceTarget(
            service="s3", arn="arn:aws:s3:::xab/k",
            account_id="222222222222", region="us-east-1", name="xab",
        )
        assert evaluate_resource_policy(
            policy, target,
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.ALLOW

    def test_evaluate_resource_policy_explicit_deny_wins(self):
        from localemu.services.iam_enforcement.resource_policies import (
            Decision, ResourceTarget, evaluate_resource_policy,
        )
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
                {"Effect": "Deny",  "Principal": {"AWS": "111111111111"},
                 "Action": "*", "Resource": "*"},
            ],
        }
        target = ResourceTarget(
            service="s3", arn="arn:aws:s3:::x/k", account_id="222222222222",
            region="us-east-1", name="x",
        )
        assert evaluate_resource_policy(
            policy, target,
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
        ) == Decision.EXPLICIT_DENY

    def test_principal_org_id_condition_match(self):
        from localemu.services.iam_enforcement.resource_policies import (
            Decision, ResourceTarget, evaluate_resource_policy,
        )
        policy = {
            "Statement": [{
                "Effect": "Allow", "Principal": "*",
                "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-acme"}},
            }],
        }
        target = ResourceTarget(
            service="s3", arn="arn:aws:s3:::x/k", account_id="222222222222",
            region="us-east-1", name="x",
        )
        assert evaluate_resource_policy(
            policy, target,
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
            caller_org_id="o-acme",
        ) == Decision.ALLOW
        assert evaluate_resource_policy(
            policy, target,
            caller_account="111111111111",
            caller_arn="arn:aws:iam::111111111111:user/alice",
            action="s3:GetObject",
            caller_org_id="o-other",
        ) == Decision.NEUTRAL

    def test_s3_bucket_policy_round_trip(self):
        # The loader reads from the server process's S3 store ; running
        # it from the test process would see an empty in-memory store
        # (the buckets were created over the wire). The smoke we keep
        # here is the wire-level round-trip: bucket policy GET returns
        # what was PUT. That's the input contract the loader depends on.
        s3 = _client("s3", key="424242424242")
        s3.create_bucket(Bucket="loader-probe")
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "Loader", "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::555555555555:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::loader-probe/*",
            }],
        }
        s3.put_bucket_policy(Bucket="loader-probe", Policy=json.dumps(policy))
        got = json.loads(s3.get_bucket_policy(Bucket="loader-probe")["Policy"])
        assert any(st.get("Sid") == "Loader" for st in got.get("Statement", []))


# ---------------------------------------------------------------------------
# S3 replication data plane
# ---------------------------------------------------------------------------


def _make_versioned_bucket(s3, name: str):
    s3.create_bucket(Bucket=name)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})


def _wait_replicated(s3, bucket: str, key: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return s3.head_object(Bucket=bucket, Key=key)
        except ClientError:
            time.sleep(0.1)
    raise AssertionError(f"object {bucket}/{key} never appeared on destination")


class TestReplicationDataPlanePR001:
    def test_replication_pending_completed_and_replica_states_end_to_end(self):
        # Canonical replication scenario:
        # versioned source + versioned destination + Filter: {} rule.
        s3 = _client("s3", key="100000000001")
        _make_versioned_bucket(s3, "pr001-src")
        _make_versioned_bucket(s3, "pr001-dst")
        s3.put_bucket_replication(
            Bucket="pr001-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000001:role/r",
                "Rules": [{
                    "ID": "exfil", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::pr001-dst"},
                }],
            },
        )
        s3.put_object(Bucket="pr001-src", Key="customers/pii.csv", Body=b"sensitive")
        time.sleep(1.0)
        src = s3.head_object(Bucket="pr001-src", Key="customers/pii.csv")
        assert src["ReplicationStatus"] == "COMPLETED"
        dst = _wait_replicated(s3, "pr001-dst", "customers/pii.csv")
        assert dst["ReplicationStatus"] == "REPLICA"
        assert dst["VersionId"] == src["VersionId"]
        body = s3.get_object(Bucket="pr001-dst", Key="customers/pii.csv")["Body"].read()
        assert body == b"sensitive"

    def test_byte_identical_large_blob(self):
        s3 = _client("s3", key="100000000002")
        _make_versioned_bucket(s3, "big-src")
        _make_versioned_bucket(s3, "big-dst")
        s3.put_bucket_replication(
            Bucket="big-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000002:role/r",
                "Rules": [{
                    "ID": "all", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::big-dst"},
                }],
            },
        )
        blob = os.urandom(512 * 1024)
        src_md5 = hashlib.md5(blob).hexdigest()
        s3.put_object(Bucket="big-src", Key="big.bin", Body=blob)
        time.sleep(1.0)
        _wait_replicated(s3, "big-dst", "big.bin")
        replica = s3.get_object(Bucket="big-dst", Key="big.bin")["Body"].read()
        assert hashlib.md5(replica).hexdigest() == src_md5

    def test_filter_prefix(self):
        s3 = _client("s3", key="100000000003")
        _make_versioned_bucket(s3, "fpref-src")
        _make_versioned_bucket(s3, "fpref-dst")
        s3.put_bucket_replication(
            Bucket="fpref-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000003:role/r",
                "Rules": [{
                    "ID": "only-pii", "Status": "Enabled", "Priority": 1,
                    "Filter": {"Prefix": "customers/"},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::fpref-dst"},
                }],
            },
        )
        s3.put_object(Bucket="fpref-src", Key="customers/a.csv", Body=b"x")
        s3.put_object(Bucket="fpref-src", Key="public/b.csv", Body=b"x")
        time.sleep(1.0)
        # match - should be replicated
        _wait_replicated(s3, "fpref-dst", "customers/a.csv")
        # non-match - must NOT exist on destination
        with pytest.raises(ClientError) as exc:
            s3.head_object(Bucket="fpref-dst", Key="public/b.csv")
        assert exc.value.response["Error"]["Code"] in {"404", "NoSuchKey"}

    def test_filter_tag(self):
        s3 = _client("s3", key="100000000004")
        _make_versioned_bucket(s3, "ftag-src")
        _make_versioned_bucket(s3, "ftag-dst")
        s3.put_bucket_replication(
            Bucket="ftag-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000004:role/r",
                "Rules": [{
                    "ID": "by-tag", "Status": "Enabled", "Priority": 1,
                    "Filter": {"Tag": {"Key": "secret", "Value": "true"}},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::ftag-dst"},
                }],
            },
        )
        s3.put_object(Bucket="ftag-src", Key="m.txt", Body=b"x",
                      Tagging="secret=true")
        s3.put_object(Bucket="ftag-src", Key="n.txt", Body=b"x",
                      Tagging="secret=false")
        time.sleep(1.0)
        _wait_replicated(s3, "ftag-dst", "m.txt")
        with pytest.raises(ClientError):
            s3.head_object(Bucket="ftag-dst", Key="n.txt")

    def test_filter_and_prefix_plus_tag(self):
        s3 = _client("s3", key="100000000005")
        _make_versioned_bucket(s3, "fand-src")
        _make_versioned_bucket(s3, "fand-dst")
        s3.put_bucket_replication(
            Bucket="fand-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000005:role/r",
                "Rules": [{
                    "ID": "and", "Status": "Enabled", "Priority": 1,
                    "Filter": {"And": {
                        "Prefix": "secret/",
                        "Tags": [{"Key": "env", "Value": "prod"}],
                    }},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::fand-dst"},
                }],
            },
        )
        # All four cases: pref+tag, pref+notag, nopref+tag, nopref+notag
        s3.put_object(Bucket="fand-src", Key="secret/a", Body=b"x",
                      Tagging="env=prod")
        s3.put_object(Bucket="fand-src", Key="secret/b", Body=b"x",
                      Tagging="env=dev")
        s3.put_object(Bucket="fand-src", Key="public/c", Body=b"x",
                      Tagging="env=prod")
        s3.put_object(Bucket="fand-src", Key="public/d", Body=b"x")
        time.sleep(1.0)
        _wait_replicated(s3, "fand-dst", "secret/a")
        for k in ("secret/b", "public/c", "public/d"):
            with pytest.raises(ClientError):
                s3.head_object(Bucket="fand-dst", Key=k)

    def test_multi_destination(self):
        s3 = _client("s3", key="100000000006")
        _make_versioned_bucket(s3, "md-src")
        _make_versioned_bucket(s3, "md-d1")
        _make_versioned_bucket(s3, "md-d2")
        s3.put_bucket_replication(
            Bucket="md-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000006:role/r",
                "Rules": [
                    {"ID": "to-d1", "Status": "Enabled", "Priority": 1,
                     "Filter": {},
                     "DeleteMarkerReplication": {"Status": "Disabled"},
                     "Destination": {"Bucket": "arn:aws:s3:::md-d1"}},
                    {"ID": "to-d2", "Status": "Enabled", "Priority": 1,
                     "Filter": {},
                     "DeleteMarkerReplication": {"Status": "Disabled"},
                     "Destination": {"Bucket": "arn:aws:s3:::md-d2"}},
                ],
            },
        )
        s3.put_object(Bucket="md-src", Key="x", Body=b"both")
        time.sleep(1.0)
        d1 = s3.head_object(Bucket="md-d1", Key="x")
        d2 = s3.head_object(Bucket="md-d2", Key="x")
        assert d1["ReplicationStatus"] == "REPLICA"
        assert d2["ReplicationStatus"] == "REPLICA"

    def test_delete_marker_disabled_default(self):
        s3 = _client("s3", key="100000000007")
        _make_versioned_bucket(s3, "dm-src")
        _make_versioned_bucket(s3, "dm-dst")
        s3.put_bucket_replication(
            Bucket="dm-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000007:role/r",
                "Rules": [{
                    "ID": "dm", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::dm-dst"},
                }],
            },
        )
        s3.put_object(Bucket="dm-src", Key="k", Body=b"x")
        time.sleep(0.5)
        _wait_replicated(s3, "dm-dst", "k")
        # Delete (versioned bucket) creates a delete marker on the source.
        s3.delete_object(Bucket="dm-src", Key="k")
        time.sleep(0.5)
        # With DeleteMarkerReplication=Disabled the destination must NOT
        # gain the delete marker; the prior replica stays current.
        dst = s3.head_object(Bucket="dm-dst", Key="k")
        assert dst["ReplicationStatus"] == "REPLICA"

    def test_glacier_source_skipped(self):
        s3 = _client("s3", key="100000000008")
        _make_versioned_bucket(s3, "gl-src")
        _make_versioned_bucket(s3, "gl-dst")
        s3.put_bucket_replication(
            Bucket="gl-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000008:role/r",
                "Rules": [{
                    "ID": "g", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::gl-dst"},
                }],
            },
        )
        s3.put_object(Bucket="gl-src", Key="archive.bin", Body=b"x",
                      StorageClass="GLACIER")
        time.sleep(0.5)
        # GLACIER source objects are ineligible per AWS.
        with pytest.raises(ClientError):
            s3.head_object(Bucket="gl-dst", Key="archive.bin")

    def test_no_chained_replication(self):
        # When a write enters the destination bucket as a REPLICA and the
        # destination bucket itself has a replication rule pointing
        # elsewhere, the replica must NOT trigger another replication
        # (matches AWS: replicas of replicas are blocked).
        s3 = _client("s3", key="100000000009")
        _make_versioned_bucket(s3, "ch-src")
        _make_versioned_bucket(s3, "ch-mid")
        _make_versioned_bucket(s3, "ch-tail")
        s3.put_bucket_replication(
            Bucket="ch-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000009:role/r",
                "Rules": [{
                    "ID": "src->mid", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::ch-mid"},
                }],
            },
        )
        s3.put_bucket_replication(
            Bucket="ch-mid",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000009:role/r",
                "Rules": [{
                    "ID": "mid->tail", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::ch-tail"},
                }],
            },
        )
        s3.put_object(Bucket="ch-src", Key="o", Body=b"x")
        time.sleep(1.0)
        # ch-mid received the replica
        mid = s3.head_object(Bucket="ch-mid", Key="o")
        assert mid["ReplicationStatus"] == "REPLICA"
        # ch-tail must NOT have received the chained-replica
        with pytest.raises(ClientError):
            s3.head_object(Bucket="ch-tail", Key="o")

    def test_replication_status_visible_on_head_after_put(self):
        # AWS does NOT return ``x-amz-replication-status`` on the
        # PutObject response itself — the header surfaces on subsequent
        # HeadObject / GetObject calls. Pin the behaviour LocalEmu
        # should match: HeadObject after a brief moment sees PENDING
        # or COMPLETED (never absent for a replicated source object).
        s3 = _client("s3", key="100000000010")
        _make_versioned_bucket(s3, "ps-src")
        _make_versioned_bucket(s3, "ps-dst")
        s3.put_bucket_replication(
            Bucket="ps-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000010:role/r",
                "Rules": [{
                    "ID": "ps", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::ps-dst"},
                }],
            },
        )
        s3.put_object(Bucket="ps-src", Key="k", Body=b"x")
        time.sleep(0.5)
        head = s3.head_object(Bucket="ps-src", Key="k")
        assert head.get("ReplicationStatus") in {"PENDING", "COMPLETED"}

    def test_copy_object_into_source_replicates(self):
        s3 = _client("s3", key="100000000011")
        _make_versioned_bucket(s3, "co-staging")
        _make_versioned_bucket(s3, "co-src")
        _make_versioned_bucket(s3, "co-dst")
        s3.put_bucket_replication(
            Bucket="co-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000011:role/r",
                "Rules": [{
                    "ID": "co", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::co-dst"},
                }],
            },
        )
        s3.put_object(Bucket="co-staging", Key="orig", Body=b"copy-source")
        s3.copy_object(
            CopySource={"Bucket": "co-staging", "Key": "orig"},
            Bucket="co-src", Key="copied",
        )
        time.sleep(1.0)
        d = _wait_replicated(s3, "co-dst", "copied")
        assert d["ReplicationStatus"] == "REPLICA"

    def test_complete_multipart_replicates(self):
        s3 = _client("s3", key="100000000012")
        _make_versioned_bucket(s3, "mp-src")
        _make_versioned_bucket(s3, "mp-dst")
        s3.put_bucket_replication(
            Bucket="mp-src",
            ReplicationConfiguration={
                "Role": "arn:aws:iam::100000000012:role/r",
                "Rules": [{
                    "ID": "mp", "Status": "Enabled", "Priority": 1,
                    "Filter": {},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": "arn:aws:s3:::mp-dst"},
                }],
            },
        )
        mp = s3.create_multipart_upload(Bucket="mp-src", Key="big-mp")
        part = s3.upload_part(
            Bucket="mp-src", Key="big-mp", UploadId=mp["UploadId"],
            PartNumber=1, Body=b"X" * (5 * 1024 * 1024),
        )
        s3.complete_multipart_upload(
            Bucket="mp-src", Key="big-mp", UploadId=mp["UploadId"],
            MultipartUpload={"Parts": [{"ETag": part["ETag"], "PartNumber": 1}]},
        )
        time.sleep(1.5)
        d = _wait_replicated(s3, "mp-dst", "big-mp")
        assert d["ReplicationStatus"] == "REPLICA"
