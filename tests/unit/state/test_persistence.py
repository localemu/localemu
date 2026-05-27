"""
Complete test suite for LocalEmu's persistence engine.

Tests cover:
- Round-trip save/load for 8 services (S3, DynamoDB, SQS, SNS, EventBridge, KMS, Logs, SecretsManager)
- Serialization fixes (SSM ParameterDict, WeakValueDictionary)
- Edge cases (corrupt state, version mismatch, cold start, atomic writes, manifest)
- Infrastructure (load order tiers, save/load symmetry)

Each test is self-contained: create state -> save -> reset -> load -> verify.
"""

from __future__ import annotations

import json
import os
import weakref

import dill
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACCOUNT = "000000000000"
REGION = "us-east-1"


@pytest.fixture
def data_dir(tmp_path):
    """Provide a clean temporary directory for each test."""
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _register_pickle_fixes():
    """Ensure custom dill reducers are registered before every test."""
    from localemu.state.persistence import _register_pickle_fixes

    _register_pickle_fixes()


# ===========================================================================
# Round-trip tests: create -> save -> reset -> load -> verify
# ===========================================================================


class TestS3RoundTrip:
    """S3 bucket + object survives save/load cycle."""

    def test_s3_round_trip(self, data_dir):
        from localemu.services.s3.models import s3_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        # Create state
        store = s3_stores[ACCOUNT][REGION]
        store.buckets["test-bucket"] = type(
            "FakeBucket", (), {"name": "test-bucket", "objects": {"key1": b"data1"}}
        )()

        # Save
        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "s3" in manifest["services"]
        assert os.path.exists(os.path.join(data_dir, "state", "api_states", "s3.state"))

        # Reset
        s3_stores[ACCOUNT][REGION].buckets.clear()
        assert "test-bucket" not in s3_stores[ACCOUNT][REGION].buckets

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        # Verify restored
        restored = s3_stores[ACCOUNT][REGION]
        assert "test-bucket" in restored.buckets
        assert restored.buckets["test-bucket"].name == "test-bucket"
        assert restored.buckets["test-bucket"].objects["key1"] == b"data1"


class TestDynamoDBRoundTrip:
    """DynamoDB table + item survives save/load cycle."""

    def test_dynamodb_round_trip(self, data_dir):
        from localemu.services.dynamodb.models import dynamodb_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        store = dynamodb_stores[ACCOUNT][REGION]
        store.table_definitions["test-table"] = {
            "TableName": "test-table",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "Items": [{"pk": {"S": "item1"}, "data": {"S": "value1"}}],
        }

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "dynamodb" in manifest["services"]

        # Reset
        store.table_definitions.clear()
        assert "test-table" not in dynamodb_stores[ACCOUNT][REGION].table_definitions

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = dynamodb_stores[ACCOUNT][REGION]
        assert "test-table" in restored.table_definitions
        assert restored.table_definitions["test-table"]["TableName"] == "test-table"
        assert restored.table_definitions["test-table"]["Items"][0]["pk"]["S"] == "item1"


class TestSQSRoundTrip:
    """SQS queue survives save/load cycle."""

    def test_sqs_round_trip(self, data_dir):
        from localemu.services.sqs.models import StandardQueue, sqs_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        store = sqs_stores[ACCOUNT][REGION]
        queue = StandardQueue(name="test-queue", region=REGION, account_id=ACCOUNT)
        store.queues["test-queue"] = queue

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "sqs" in manifest["services"]

        # Reset
        store.queues.clear()
        assert "test-queue" not in sqs_stores[ACCOUNT][REGION].queues

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = sqs_stores[ACCOUNT][REGION]
        assert "test-queue" in restored.queues
        assert restored.queues["test-queue"].name == "test-queue"


class TestSNSRoundTrip:
    """SNS topic survives save/load cycle."""

    def test_sns_round_trip(self, data_dir):
        from localemu.services.sns.models import sns_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        store = sns_stores[ACCOUNT][REGION]
        topic_arn = f"arn:aws:sns:{REGION}:{ACCOUNT}:test-topic"
        store.topics[topic_arn] = {
            "arn": topic_arn,
            "name": "test-topic",
            "attributes": {},
            "data_protection_policy": None,
            "subscriptions": [],
        }

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "sns" in manifest["services"]

        # Reset
        store.topics.clear()
        assert topic_arn not in sns_stores[ACCOUNT][REGION].topics

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = sns_stores[ACCOUNT][REGION]
        assert topic_arn in restored.topics
        assert restored.topics[topic_arn]["name"] == "test-topic"


class TestEventsRoundTrip:
    """EventBridge event bus + rule survives save/load cycle."""

    def test_events_round_trip(self, data_dir):
        from localemu.services.events.models import EventBus, Rule, events_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        store = events_stores[ACCOUNT][REGION]
        bus = EventBus(name="test-bus", region=REGION, account_id=ACCOUNT)
        rule = Rule(
            name="test-rule",
            region=REGION,
            account_id=ACCOUNT,
            event_bus_name="test-bus",
            event_pattern='{"source": ["test"]}',
        )
        bus.rules["test-rule"] = rule
        store.event_buses["test-bus"] = bus

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "events" in manifest["services"]

        # Reset
        store.event_buses.clear()
        assert "test-bus" not in events_stores[ACCOUNT][REGION].event_buses

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = events_stores[ACCOUNT][REGION]
        assert "test-bus" in restored.event_buses
        assert "test-rule" in restored.event_buses["test-bus"].rules
        assert restored.event_buses["test-bus"].rules["test-rule"].name == "test-rule"


class TestKMSRoundTrip:
    """KMS key survives save/load cycle."""

    def test_kms_round_trip(self, data_dir):
        from localemu.services.kms.models import kms_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        store = kms_stores[ACCOUNT][REGION]
        fake_key = type(
            "FakeKmsKey",
            (),
            {
                "metadata": type(
                    "FakeMeta", (), {"key_id": "key-1234", "key_state": "Enabled"}
                )(),
                "crypto_key": None,
                "policy": "{}",
            },
        )()
        store.keys["key-1234"] = fake_key

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "kms" in manifest["services"]

        # Reset
        store.keys.clear()
        assert "key-1234" not in kms_stores[ACCOUNT][REGION].keys

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = kms_stores[ACCOUNT][REGION]
        assert "key-1234" in restored.keys
        assert restored.keys["key-1234"].metadata.key_id == "key-1234"


class TestLogsRoundTrip:
    """CloudWatch Logs log group survives save/load cycle (moto backend)."""

    def test_logs_round_trip(self, data_dir):
        import moto.backends as mb

        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        be = mb.get_backend("logs")[ACCOUNT][REGION]
        be.create_log_group("test-log-group", tags={})
        assert "test-log-group" in be.groups

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "logs.moto" in manifest["services"]

        # Reset
        be.delete_log_group("test-log-group")
        assert "test-log-group" not in be.groups

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        be_after = mb.get_backend("logs")[ACCOUNT][REGION]
        assert "test-log-group" in be_after.groups


class TestSecretsManagerMotoRoundTrip:
    """Secrets Manager secret + value survives save/load cycle via moto backend."""

    def test_secretsmanager_moto_round_trip(self, data_dir):
        import moto.backends as mb

        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        be = mb.get_backend("secretsmanager")[ACCOUNT][REGION]
        be.create_secret(
            name="test-secret",
            secret_string="s3cr3t-value",
            secret_binary=None,
            description="test secret",
            tags=[],
            kms_key_id=None,
            client_request_token=None,
            replica_regions=[],
            force_overwrite=False,
        )
        assert "test-secret" in be.secrets

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "secretsmanager.moto" in manifest["services"]

        # Reset
        del be.secrets["test-secret"]
        assert "test-secret" not in be.secrets

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        be_after = mb.get_backend("secretsmanager")[ACCOUNT][REGION]
        assert "test-secret" in be_after.secrets


# ===========================================================================
# Serialization fix tests
# ===========================================================================


class TestSSMParameterDictRoundTrip:
    """SSM ParameterDict serializes and deserializes correctly with custom reducer."""

    def test_ssm_parameter_dict_round_trip(self):
        from moto.ssm.models import ParameterDict

        pd = ParameterDict(ACCOUNT, REGION)
        pd["/test/param"] = ["value-version-1"]

        # Serialize + deserialize via dill
        data = dill.dumps(pd)
        restored = dill.loads(data)

        assert isinstance(restored, ParameterDict)
        assert restored.account_id == ACCOUNT
        assert restored.region_name == REGION
        assert "/test/param" in restored
        assert restored["/test/param"] == ["value-version-1"]


class TestWeakValueDictionaryRoundTrip:
    """WeakValueDictionary serializes without crash and restores as empty WVD."""

    def test_weakvaluedictionary_round_trip(self):
        class Holder:
            pass

        wvd = weakref.WeakValueDictionary()
        obj = Holder()
        wvd["key1"] = obj

        # Serialize + deserialize -- must not crash
        data = dill.dumps(wvd)
        restored = dill.loads(data)

        assert isinstance(restored, weakref.WeakValueDictionary)
        # WVD restores empty by design -- owning containers re-populate


# ===========================================================================
# Edge case tests
# ===========================================================================


class TestCorruptStateFileSkipsService:
    """Garbage in one .state file does not prevent other services from loading."""

    def test_corrupt_state_file_skips_service(self, data_dir):
        from localemu.services.sqs.models import StandardQueue, sqs_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        # Create valid SQS state
        store = sqs_stores[ACCOUNT][REGION]
        store.queues["survive-queue"] = StandardQueue(
            name="survive-queue", region=REGION, account_id=ACCOUNT
        )

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)

        # Corrupt the S3 state file
        api_dir = os.path.join(data_dir, "state", "api_states")
        corrupt_path = os.path.join(api_dir, "s3.state")
        with open(corrupt_path, "wb") as f:
            f.write(b"THIS IS GARBAGE DATA NOT VALID DILL \x00\xff\xfe")

        # Ensure s3 is in the manifest so the loader tries it
        manifest_path = os.path.join(data_dir, "state", "_manifest.json")
        with open(manifest_path) as f:
            m = json.load(f)
        if "s3" not in m["services"]:
            m["services"].append("s3")
        with open(manifest_path, "w") as f:
            json.dump(m, f)

        # Reset SQS
        store.queues.clear()

        # Load -- s3 should fail gracefully, sqs should still load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        restored = sqs_stores[ACCOUNT][REGION]
        assert "survive-queue" in restored.queues


class TestVersionMismatchSkipsLoad:
    """Incompatible version in manifest returns False."""

    def test_version_mismatch_skips_load(self, data_dir):
        from localemu.state.persistence import LoadOrchestrator

        # Write manifest with incompatible major.minor version
        state_dir = os.path.join(data_dir, "state")
        os.makedirs(state_dir, exist_ok=True)
        manifest = {
            "version": "99.99.0",
            "timestamp": "2099-01-01T00:00:00+00:00",
            "services": ["s3"],
            "errors": [],
            "format": "dill",
        }
        with open(os.path.join(state_dir, "_manifest.json"), "w") as f:
            json.dump(manifest, f)

        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is False


class TestEmptyDataDirColdStart:
    """No manifest file results in cold start (returns False)."""

    def test_empty_data_dir_cold_start(self, data_dir):
        from localemu.state.persistence import LoadOrchestrator

        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is False


class TestAtomicWriteNoPartialFile:
    """After successful save, no .tmp files should remain."""

    def test_atomic_write_no_partial_file(self, data_dir):
        from localemu.services.sqs.models import StandardQueue, sqs_stores
        from localemu.state.persistence import SaveOrchestrator

        store = sqs_stores[ACCOUNT][REGION]
        store.queues["atomic-test"] = StandardQueue(
            name="atomic-test", region=REGION, account_id=ACCOUNT
        )

        saver = SaveOrchestrator()
        saver.save(data_dir)

        # Walk the entire state directory -- no .tmp files should exist
        state_dir = os.path.join(data_dir, "state")
        for root, dirs, files in os.walk(state_dir):
            for fn in files:
                assert not fn.endswith(".tmp"), f"Partial file left behind: {fn}"


class TestManifestRecordsAllServices:
    """Manifest lists all saved services."""

    def test_manifest_records_all_services(self, data_dir):
        from localemu.services.sns.models import sns_stores
        from localemu.services.sqs.models import StandardQueue, sqs_stores
        from localemu.state.persistence import SaveOrchestrator

        # Create state in multiple services
        sqs_stores[ACCOUNT][REGION].queues["q1"] = StandardQueue(
            name="q1", region=REGION, account_id=ACCOUNT
        )
        topic_arn = f"arn:aws:sns:{REGION}:{ACCOUNT}:t1"
        sns_stores[ACCOUNT][REGION].topics[topic_arn] = {
            "arn": topic_arn,
            "name": "t1",
            "attributes": {},
            "data_protection_policy": None,
            "subscriptions": [],
        }

        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)

        assert "sqs" in manifest["services"]
        assert "sns" in manifest["services"]

        # Verify manifest file on disk matches
        manifest_path = os.path.join(data_dir, "state", "_manifest.json")
        assert os.path.exists(manifest_path)
        with open(manifest_path) as f:
            disk_manifest = json.load(f)
        assert disk_manifest["services"] == manifest["services"]
        assert disk_manifest["format"] == "dill"
        assert "timestamp" in disk_manifest


# ===========================================================================
# Infrastructure tests
# ===========================================================================


class TestLoadOrderTiersAreOrdered:
    """Verify Tier 0 < Tier 1 < ... < Tier 4."""

    def test_load_order_tiers_are_ordered(self):
        from localemu.state.registry import LOAD_ORDER

        assert len(LOAD_ORDER) == 5, f"Expected 5 tiers, got {len(LOAD_ORDER)}"

        # Build tier index map
        tier_of = {}
        for idx, tier in enumerate(LOAD_ORDER):
            for svc in tier:
                tier_of[svc] = idx

        # Tier 0: foundational
        assert "iam" in LOAD_ORDER[0]
        assert "sts" in LOAD_ORDER[0]
        assert "kms" in LOAD_ORDER[0]

        # Tier 1: core data
        assert "s3" in LOAD_ORDER[1]
        assert "sqs" in LOAD_ORDER[1]
        assert "dynamodb" in LOAD_ORDER[1]

        # Tier 2: Lambda depends on S3
        assert "lambda_" in LOAD_ORDER[2]
        assert tier_of["lambda_"] > tier_of["s3"]

        # Tier 3: depends on Lambda + messaging
        assert "events" in LOAD_ORDER[3]

        # Tier 4: CloudFormation depends on everything
        assert "cloudformation" in LOAD_ORDER[4]
        cf_tier = tier_of["cloudformation"]
        for svc, t in tier_of.items():
            if svc != "cloudformation":
                assert t < cf_tier, f"{svc} (tier {t}) must load before cloudformation"

        # Verify no tier is empty
        for idx, tier in enumerate(LOAD_ORDER):
            assert len(tier) > 0, f"Tier {idx} should not be empty"


class TestSaveAndLoadAreSymmetric:
    """Save then load restores exact state -- full symmetry check."""

    def test_save_and_load_are_symmetric(self, data_dir):
        from localemu.services.events.models import EventBus, events_stores
        from localemu.services.sqs.models import StandardQueue, sqs_stores
        from localemu.state.persistence import LoadOrchestrator, SaveOrchestrator

        # Create multi-service state
        sqs_store = sqs_stores[ACCOUNT][REGION]
        sqs_store.queues["sym-queue"] = StandardQueue(
            name="sym-queue", region=REGION, account_id=ACCOUNT
        )

        events_store = events_stores[ACCOUNT][REGION]
        events_store.event_buses["sym-bus"] = EventBus(
            name="sym-bus", region=REGION, account_id=ACCOUNT
        )

        # Save
        saver = SaveOrchestrator()
        manifest = saver.save(data_dir)
        assert "sqs" in manifest["services"]
        assert "events" in manifest["services"]

        # Record pre-reset state
        original_queue_name = sqs_store.queues["sym-queue"].name
        original_bus_name = events_store.event_buses["sym-bus"].name

        # Reset both
        sqs_store.queues.clear()
        events_store.event_buses.clear()
        assert "sym-queue" not in sqs_stores[ACCOUNT][REGION].queues
        assert "sym-bus" not in events_stores[ACCOUNT][REGION].event_buses

        # Load
        loader = LoadOrchestrator()
        result = loader.load(data_dir, trigger_post_load_hooks=False)
        assert result is True

        # Verify exact restoration
        assert sqs_stores[ACCOUNT][REGION].queues["sym-queue"].name == original_queue_name
        assert events_stores[ACCOUNT][REGION].event_buses["sym-bus"].name == original_bus_name
