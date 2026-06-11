"""Unit tests for the S3 replication engine.

Covers the symbol-level pieces ``s3.replication`` exports : the filter
matcher, eligibility predicate, rule resolution (priority per
destination, multi-destination), delete-marker gating, and the engine
dispatch path in sync mode.

These tests do NOT exercise the live S3 provider or any moto backend ;
they build minimal stand-in objects with just the attributes the engine
reads. Live E2E for the engine lives in
``tests/e2e/test_1_1_0_multi_account_and_replication.py``.
"""

from __future__ import annotations

import types

import pytest

from localemu.services.s3 import replication as repl


# --------------------------------------------------------------------------
# Helpers : minimal stand-ins for S3Bucket / S3Object that the engine reads.
# --------------------------------------------------------------------------


def _bucket(*, name: str = "src",
            versioning: str = "Enabled",
            config: dict | None = None):
    """Build a minimal source-bucket stand-in.

    The engine reads `.replication`, `.versioning_status`, `.name`. Anything
    else stays absent and the engine treats it as the default.
    """
    return types.SimpleNamespace(
        name=name, versioning_status=versioning, replication=config,
    )


def _obj(*, key: str = "k",
         version_id: str = "v1",
         storage_class: str = "STANDARD",
         replication_status: str | None = None):
    """Build a minimal S3Object stand-in."""
    return types.SimpleNamespace(
        key=key, version_id=version_id, storage_class=storage_class,
        replication_status=replication_status,
        etag="etag", size=0, user_metadata={}, system_metadata={},
        checksum_algorithm=None, checksum_value=None, checksum_type=None,
        is_current=True,
    )


def _config(rules: list[dict]) -> dict:
    return {"Role": "arn:aws:iam::000000000000:role/r", "Rules": rules}


def _rule(**kwargs):
    """Build a rule with sensible defaults the engine + AWS shape expect."""
    base = {
        "ID": kwargs.pop("ID", "rule"),
        "Status": kwargs.pop("Status", "Enabled"),
        "Priority": kwargs.pop("Priority", 1),
        "Filter": kwargs.pop("Filter", {}),
        "DeleteMarkerReplication": kwargs.pop(
            "DeleteMarkerReplication", {"Status": "Disabled"},
        ),
        "Destination": kwargs.pop(
            "Destination", {"Bucket": "arn:aws:s3:::dst"},
        ),
    }
    base.update(kwargs)
    return base


# --------------------------------------------------------------------------
# Filter matching
# --------------------------------------------------------------------------


class TestFilterMatching:
    def test_empty_filter_matches_every_key(self):
        rule = _rule(Filter={})
        assert repl._filter_matches(rule, "anything/at/all", {})

    def test_prefix_match(self):
        rule = _rule(Filter={"Prefix": "customers/"})
        assert repl._filter_matches(rule, "customers/pii.csv", {})

    def test_prefix_mismatch(self):
        rule = _rule(Filter={"Prefix": "customers/"})
        assert not repl._filter_matches(rule, "public/x", {})

    def test_single_tag_match(self):
        rule = _rule(Filter={"Tag": {"Key": "env", "Value": "prod"}})
        assert repl._filter_matches(rule, "k", {"env": "prod"})

    def test_single_tag_value_mismatch(self):
        rule = _rule(Filter={"Tag": {"Key": "env", "Value": "prod"}})
        assert not repl._filter_matches(rule, "k", {"env": "dev"})

    def test_single_tag_key_missing(self):
        rule = _rule(Filter={"Tag": {"Key": "env", "Value": "prod"}})
        assert not repl._filter_matches(rule, "k", {})

    def test_and_prefix_plus_tag_match(self):
        rule = _rule(Filter={"And": {
            "Prefix": "secret/",
            "Tags": [{"Key": "env", "Value": "prod"}],
        }})
        assert repl._filter_matches(rule, "secret/a", {"env": "prod"})

    def test_and_prefix_match_tag_mismatch(self):
        rule = _rule(Filter={"And": {
            "Prefix": "secret/",
            "Tags": [{"Key": "env", "Value": "prod"}],
        }})
        assert not repl._filter_matches(rule, "secret/a", {"env": "dev"})

    def test_and_prefix_mismatch(self):
        rule = _rule(Filter={"And": {
            "Prefix": "secret/",
            "Tags": [{"Key": "env", "Value": "prod"}],
        }})
        assert not repl._filter_matches(rule, "public/a", {"env": "prod"})

    def test_and_multiple_tags_all_required(self):
        rule = _rule(Filter={"And": {
            "Tags": [
                {"Key": "env", "Value": "prod"},
                {"Key": "team", "Value": "core"},
            ],
        }})
        assert repl._filter_matches(rule, "k", {"env": "prod", "team": "core"})
        assert not repl._filter_matches(rule, "k", {"env": "prod"})


class TestTagBasedRuleDetector:
    def test_empty_filter_is_not_tag_based(self):
        assert not repl._is_tag_based_rule(_rule(Filter={}))

    def test_prefix_only_is_not_tag_based(self):
        assert not repl._is_tag_based_rule(_rule(Filter={"Prefix": "p/"}))

    def test_single_tag_is_tag_based(self):
        assert repl._is_tag_based_rule(
            _rule(Filter={"Tag": {"Key": "k", "Value": "v"}})
        )

    def test_and_with_tags_is_tag_based(self):
        assert repl._is_tag_based_rule(_rule(Filter={"And": {
            "Prefix": "p/",
            "Tags": [{"Key": "k", "Value": "v"}],
        }}))

    def test_and_with_only_prefix_is_not_tag_based(self):
        assert not repl._is_tag_based_rule(
            _rule(Filter={"And": {"Prefix": "p/"}})
        )


# --------------------------------------------------------------------------
# Eligibility
# --------------------------------------------------------------------------


class TestEligibility:
    def test_no_replication_config_not_eligible(self):
        b = _bucket(config=None)
        assert not repl._eligible(b, _obj(), is_delete_marker=False)

    def test_versioning_not_enabled_not_eligible(self):
        b = _bucket(versioning="Suspended", config=_config([_rule()]))
        assert not repl._eligible(b, _obj(), is_delete_marker=False)

    def test_versioning_unset_not_eligible(self):
        b = _bucket(versioning="", config=_config([_rule()]))
        assert not repl._eligible(b, _obj(), is_delete_marker=False)

    def test_already_replica_source_not_eligible(self):
        b = _bucket(config=_config([_rule()]))
        o = _obj(replication_status="REPLICA")
        assert not repl._eligible(b, o, is_delete_marker=False)

    @pytest.mark.parametrize("cls", [
        "GLACIER", "DEEP_ARCHIVE",
        "INTELLIGENT_TIERING_ARCHIVE_ACCESS",
        "INTELLIGENT_TIERING_DEEP_ARCHIVE_ACCESS",
        # Dash variant (AWS uses both spellings interchangeably in the SDKs)
        "INTELLIGENT-TIERING-ARCHIVE-ACCESS",
    ])
    def test_glacier_class_source_not_eligible(self, cls):
        b = _bucket(config=_config([_rule()]))
        o = _obj(storage_class=cls)
        assert not repl._eligible(b, o, is_delete_marker=False)

    def test_glacier_class_irrelevant_for_delete_markers(self):
        # Delete markers carry no storage class ; eligibility skips the
        # class check for them.
        b = _bucket(config=_config([_rule()]))
        marker = _obj(storage_class="GLACIER")  # actually a delete marker
        assert repl._eligible(b, marker, is_delete_marker=True)

    def test_happy_path_eligible(self):
        b = _bucket(config=_config([_rule()]))
        assert repl._eligible(b, _obj(), is_delete_marker=False)


# --------------------------------------------------------------------------
# Rule resolution
# --------------------------------------------------------------------------


class TestRuleResolution:
    def test_disabled_rule_skipped(self):
        b = _bucket(config=_config([_rule(Status="Disabled")]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="000000000000",
        )
        assert result == []

    def test_single_matching_rule_returns_destination(self):
        b = _bucket(config=_config([
            _rule(Destination={"Bucket": "arn:aws:s3:::dst1"})
        ]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="000000000000",
        )
        assert len(result) == 1
        rule, dest_bucket, dest_account = result[0]
        assert dest_bucket == "dst1"
        assert dest_account == "000000000000"

    def test_priority_resolution_per_destination_higher_wins(self):
        rules = [
            _rule(ID="low",  Priority=1, Filter={"Prefix": "k"},
                  Destination={"Bucket": "arn:aws:s3:::shared"}),
            _rule(ID="high", Priority=10, Filter={"Prefix": "k"},
                  Destination={"Bucket": "arn:aws:s3:::shared"}),
        ]
        b = _bucket(config=_config(rules))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="000000000000",
        )
        assert len(result) == 1
        winning_rule, dest_bucket, _ = result[0]
        assert winning_rule["ID"] == "high"
        assert dest_bucket == "shared"

    def test_two_destinations_both_fire(self):
        rules = [
            _rule(ID="to-d1", Destination={"Bucket": "arn:aws:s3:::d1"}),
            _rule(ID="to-d2", Destination={"Bucket": "arn:aws:s3:::d2"}),
        ]
        b = _bucket(config=_config(rules))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="000000000000",
        )
        dests = sorted(r[1] for r in result)
        assert dests == ["d1", "d2"]

    def test_filter_drops_non_matching_rule(self):
        rules = [
            _rule(ID="prefix-only-pii", Filter={"Prefix": "pii/"},
                  Destination={"Bucket": "arn:aws:s3:::pii-dst"}),
            _rule(ID="catch-all", Filter={},
                  Destination={"Bucket": "arn:aws:s3:::all-dst"}),
        ]
        b = _bucket(config=_config(rules))
        # public/ key matches only the second rule
        result = repl.resolve_rules_for_object(
            b, "public/x", {}, is_delete_marker=False,
            src_account="000000000000",
        )
        assert len(result) == 1
        assert result[0][1] == "all-dst"

    def test_src_account_passed_through_as_default_dest_account(self):
        b = _bucket(config=_config([_rule()]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="111122223333",
        )
        assert len(result) == 1
        assert result[0][2] == "111122223333"

    def test_explicit_destination_account_overrides_src_account(self):
        b = _bucket(config=_config([_rule(Destination={
            "Bucket": "arn:aws:s3:::xacct",
            "Account": "444455556666",
        })]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=False, src_account="111122223333",
        )
        assert result[0][2] == "444455556666"


# --------------------------------------------------------------------------
# Delete-marker gating
# --------------------------------------------------------------------------


class TestDeleteMarkerGating:
    def test_delete_marker_disabled_rule_drops_marker(self):
        b = _bucket(config=_config([_rule(
            DeleteMarkerReplication={"Status": "Disabled"},
        )]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=True, src_account="000000000000",
        )
        assert result == []

    def test_delete_marker_enabled_rule_keeps_marker(self):
        b = _bucket(config=_config([_rule(
            DeleteMarkerReplication={"Status": "Enabled"},
        )]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=True, src_account="000000000000",
        )
        assert len(result) == 1

    def test_tag_based_rule_never_replicates_delete_markers(self):
        # Real AWS forbids delete-marker replication for tag-based rules,
        # regardless of DeleteMarkerReplication.Status.
        b = _bucket(config=_config([_rule(
            Filter={"Tag": {"Key": "env", "Value": "prod"}},
            DeleteMarkerReplication={"Status": "Enabled"},
        )]))
        result = repl.resolve_rules_for_object(
            b, "k", {"env": "prod"}, is_delete_marker=True,
            src_account="000000000000",
        )
        assert result == []

    def test_lifecycle_delete_markers_never_replicate(self):
        # Lifecycle-induced delete markers never replicate, even with
        # DeleteMarkerReplication enabled.
        b = _bucket(config=_config([_rule(
            DeleteMarkerReplication={"Status": "Enabled"},
        )]))
        result = repl.resolve_rules_for_object(
            b, "k", {}, is_delete_marker=True, lifecycle=True,
            src_account="000000000000",
        )
        assert result == []


# --------------------------------------------------------------------------
# Engine sync-mode dispatch (no real storage backend)
# --------------------------------------------------------------------------


class TestEngineSyncDispatch:
    def test_no_config_does_nothing(self):
        engine = repl.ReplicationEngine()
        engine.run_synchronously = True
        b = _bucket(config=None)
        o = _obj()
        engine.dispatch(src_account="000000000000", src_bucket=b,
                        s3_object=o)
        # No status set because eligibility short-circuited.
        assert o.replication_status is None

    def test_no_eligible_rules_does_nothing(self):
        engine = repl.ReplicationEngine()
        engine.run_synchronously = True
        # Prefix filter that doesn't match the key
        b = _bucket(config=_config([_rule(Filter={"Prefix": "secret/"})]))
        o = _obj(key="public/x")
        engine.dispatch(src_account="000000000000", src_bucket=b,
                        s3_object=o)
        assert o.replication_status is None

    def test_eligible_but_dest_missing_marks_failed(self):
        engine = repl.ReplicationEngine()
        engine.run_synchronously = True
        # Rule points at a destination bucket that doesn't exist in
        # the S3 store ; the engine must mark the source FAILED.
        b = _bucket(config=_config([_rule(
            Destination={"Bucket": "arn:aws:s3:::nope-bucket"},
        )]))
        o = _obj()
        engine.dispatch(src_account="000000000000", src_bucket=b,
                        s3_object=o)
        assert o.replication_status == repl.STATUS_FAILED

    def test_engine_singleton_returns_same_instance(self):
        a = repl.get_engine()
        b = repl.get_engine()
        assert a is b
        repl.reset_engine_for_tests()
        c = repl.get_engine()
        assert c is not a
