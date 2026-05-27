"""Unit tests for :mod:`localemu.export.references`."""

from __future__ import annotations

from localemu.export.ir import Ref, Resource, Snapshot
from localemu.export.references import resolve_references


def _snap(resources: list[Resource]) -> Snapshot:
    return Snapshot(
        schema_version="2.0",
        exported_at="2026-01-01T00:00:00Z",
        localemu_version="test",
        resources=resources,
    )


def test_resolves_arn_reference() -> None:
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="my-role",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:iam::000000000000:role/my-role"},
    )
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"role": "arn:aws:iam::000000000000:role/my-role"},
    )
    out = resolve_references(_snap([role, fn]))
    new_fn = next(r for r in out.resources if r.resource_id == "fn")
    assert isinstance(new_fn.attributes["role"], Ref)
    ref: Ref = new_fn.attributes["role"]
    assert ref.service == "iam"
    assert ref.resource_type == "role"
    assert ref.resource_id == "my-role"
    assert ref.attribute == "arn"


def test_unresolvable_arn_left_as_string() -> None:
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"role": "arn:aws:iam::000000000000:role/missing"},
    )
    out = resolve_references(_snap([fn]))
    new_fn = out.resources[0]
    assert new_fn.attributes["role"] == "arn:aws:iam::000000000000:role/missing"


def test_self_reference_stays_literal() -> None:
    """A resource's own ARN in its own attributes must not become a Ref."""
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="my-role",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:iam::000000000000:role/my-role"},
    )
    out = resolve_references(_snap([role]))
    new_role = out.resources[0]
    assert new_role.attributes["arn"] == role.attributes["arn"]


def test_non_arn_name_reference_resolves_when_unambiguous() -> None:
    bucket = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="data-lake",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::data-lake"},
    )
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"bucket": "data-lake"},
    )
    out = resolve_references(_snap([bucket, fn]))
    new_fn = next(r for r in out.resources if r.resource_id == "fn")
    # Name refs use attribute='id' per the resolver contract.
    val = new_fn.attributes["bucket"]
    assert isinstance(val, Ref)
    assert val.resource_id == "data-lake"


def test_cycle_detection_warns_not_crashes() -> None:
    a = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="a",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::a", "peer": "arn:aws:s3:::b"},
    )
    b = Resource(
        service="s3",
        resource_type="bucket",
        resource_id="b",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:s3:::b", "peer": "arn:aws:s3:::a"},
    )
    out = resolve_references(_snap([a, b]))
    # Cross-refs still resolve
    a_new = next(r for r in out.resources if r.resource_id == "a")
    assert isinstance(a_new.attributes["peer"], Ref)


def test_multi_region_refs() -> None:
    role_east = Resource(
        service="iam",
        resource_type="role",
        resource_id="shared-role",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:iam::000000000000:role/shared-role"},
    )
    fn_west = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn-west",
        account_id="000000000000",
        region="us-west-2",
        attributes={"role": "arn:aws:iam::000000000000:role/shared-role"},
    )
    out = resolve_references(_snap([role_east, fn_west]))
    fn_out = next(r for r in out.resources if r.resource_id == "fn-west")
    assert isinstance(fn_out.attributes["role"], Ref)
    assert fn_out.attributes["role"].resource_id == "shared-role"


def test_input_snapshot_not_mutated() -> None:
    role = Resource(
        service="iam",
        resource_type="role",
        resource_id="r",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:iam::000000000000:role/r"},
    )
    fn = Resource(
        service="lambda",
        resource_type="function",
        resource_id="fn",
        account_id="000000000000",
        region="us-east-1",
        attributes={"role": "arn:aws:iam::000000000000:role/r"},
    )
    snap = _snap([role, fn])
    original_role_attr = fn.attributes["role"]
    resolve_references(snap)
    # Original resource's attribute must remain a plain string.
    assert fn.attributes["role"] == original_role_attr


def test_non_string_values_passed_through() -> None:
    r = Resource(
        service="dynamodb",
        resource_type="table",
        resource_id="t",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:dynamodb:us-east-1:000000000000:table/t", "rcu": 5, "enabled": True},
    )
    out = resolve_references(_snap([r]))
    new_r = out.resources[0]
    assert new_r.attributes["rcu"] == 5
    assert new_r.attributes["enabled"] is True


def test_refs_inside_nested_containers() -> None:
    topic = Resource(
        service="sns",
        resource_type="topic",
        resource_id="t",
        account_id="000000000000",
        region="us-east-1",
        attributes={"arn": "arn:aws:sns:us-east-1:000000000000:t"},
    )
    queue = Resource(
        service="sqs",
        resource_type="queue",
        resource_id="q",
        account_id="000000000000",
        region="us-east-1",
        attributes={
            "arn": "arn:aws:sqs:us-east-1:000000000000:q",
            "subscriptions": [{"endpoint": "arn:aws:sns:us-east-1:000000000000:t"}],
        },
    )
    out = resolve_references(_snap([topic, queue]))
    q_new = next(r for r in out.resources if r.resource_id == "q")
    sub0 = q_new.attributes["subscriptions"][0]
    assert isinstance(sub0["endpoint"], Ref)
