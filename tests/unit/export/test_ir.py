"""Unit tests for the export IR dataclasses (:mod:`localemu.export.ir`)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from localemu.export.ir import Ref, Resource, Snapshot, resource_logical_id


class TestRef:
    def test_default_attribute_is_arn(self) -> None:
        ref = Ref(service="iam", resource_type="role", resource_id="r")
        assert ref.attribute == "arn"

    def test_is_frozen(self) -> None:
        ref = Ref(service="iam", resource_type="role", resource_id="r")
        with pytest.raises(FrozenInstanceError):
            ref.service = "s3"  # type: ignore[misc]

    def test_is_hashable(self) -> None:
        ref = Ref(service="iam", resource_type="role", resource_id="r")
        # Frozen dataclasses are hashable by default.
        assert {ref, ref} == {ref}

    def test_equality_by_value(self) -> None:
        a = Ref("iam", "role", "r")
        b = Ref("iam", "role", "r")
        c = Ref("iam", "role", "other")
        assert a == b
        assert a != c


class TestResource:
    def test_defaults(self) -> None:
        r = Resource(
            service="s3",
            resource_type="bucket",
            resource_id="b",
            account_id="000000000000",
            region="us-east-1",
        )
        assert r.attributes == {}
        assert r.tags == {}
        assert r.created_at is None

    def test_independent_default_dicts(self) -> None:
        """Default-factory dicts must not be shared across instances."""
        a = Resource("s3", "bucket", "a", "000000000000", "us-east-1")
        b = Resource("s3", "bucket", "b", "000000000000", "us-east-1")
        a.attributes["foo"] = 1
        assert "foo" not in b.attributes


class TestSnapshot:
    def test_defaults(self) -> None:
        s = Snapshot(
            schema_version="2.0",
            exported_at="2026-01-01T00:00:00Z",
            localemu_version="test",
        )
        assert s.resources == []
        assert s.redacted_secrets == []
        assert s.export_warnings == []
        assert s.sidecar_files == {}

    def test_holds_resources(self) -> None:
        r = Resource("s3", "bucket", "b", "000000000000", "us-east-1")
        s = Snapshot(
            schema_version="2.0",
            exported_at="2026-01-01T00:00:00Z",
            localemu_version="test",
            resources=[r],
        )
        assert s.resources[0] is r


class TestResourceLogicalId:
    def test_basic(self) -> None:
        r = Resource("iam", "role", "my-role", "000000000000", "us-east-1")
        assert resource_logical_id(r) == "iam_role_my_role"

    def test_sanitizes_non_alphanum(self) -> None:
        r = Resource("s3", "bucket", "bucket.with.dots/and/slashes", "000000000000", "us-east-1")
        lid = resource_logical_id(r)
        assert lid == "s3_bucket_bucket_with_dots_and_slashes"

    def test_empty_id_gets_unnamed(self) -> None:
        r = Resource("s3", "bucket", "!!!", "000000000000", "us-east-1")
        assert resource_logical_id(r) == "s3_bucket_unnamed"

    def test_lowercase(self) -> None:
        r = Resource("iam", "role", "UpperName", "000000000000", "us-east-1")
        assert resource_logical_id(r).islower()
