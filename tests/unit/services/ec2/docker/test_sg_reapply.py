"""Unit tests for SG re-apply on running containers .

Previously AuthorizeSecurityGroupIngress / Revoke / ModifyInstance only
wrote to moto state; the iptables chains inside running EC2 containers
were never refreshed. SG changes were invisible until the instance was
re-created.

The fix is an event-driven re-apply:
  - Labels on every EC2 container record the attached SG IDs,
    account_id and region.
  - An in-memory mapping is kept current; on cold start it is
    rebuilt from the container labels.
  - Provider handlers for authorize/revoke/modify call into
    sg_reapply to find every instance that has the changed SG and
    re-run apply_sg_to_container for it.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import sg_reapply


@pytest.fixture(autouse=True)
def clean_mapping():
    """Reset the module-level mapping between tests."""
    with sg_reapply._sg_mapping_lock:
        sg_reapply._sg_mapping.clear()
    yield
    with sg_reapply._sg_mapping_lock:
        sg_reapply._sg_mapping.clear()


class TestRecordAndLookup:
    def test_record_instance_sgs_stores_tuple_key(self):
        sg_reapply.record_instance_sgs("000000000000", "us-east-1", "i-aaa", ["sg-1", "sg-2"])
        with sg_reapply._sg_mapping_lock:
            assert sg_reapply._sg_mapping[("000000000000", "us-east-1", "i-aaa")] == ["sg-1", "sg-2"]

    def test_record_overwrites_previous(self):
        sg_reapply.record_instance_sgs("000000000000", "us-east-1", "i-aaa", ["sg-1"])
        sg_reapply.record_instance_sgs("000000000000", "us-east-1", "i-aaa", ["sg-2"])
        with sg_reapply._sg_mapping_lock:
            assert sg_reapply._sg_mapping[("000000000000", "us-east-1", "i-aaa")] == ["sg-2"]


class TestRebuildFromDocker:
    def test_rebuild_populates_from_labels(self):
        fake_containers = [
            {
                "name": "localemu-ec2-i-111",
                "labels": {
                    "localemu.service": "ec2",
                    "localemu.instance-id": "i-111",
                    "localemu.account-id": "000000000000",
                    "localemu.region": "us-east-1",
                    "localemu.sg-ids": "sg-a,sg-b",
                },
            },
            {
                "name": "localemu-ec2-i-222",
                "labels": {
                    "localemu.service": "ec2",
                    "localemu.instance-id": "i-222",
                    "localemu.account-id": "000000000000",
                    "localemu.region": "us-west-2",
                    "localemu.sg-ids": "sg-a",
                },
            },
        ]
        dc = mock.MagicMock()
        dc.list_containers.return_value = fake_containers
        with mock.patch.object(sg_reapply, "DOCKER_CLIENT", dc):
            sg_reapply.rebuild_mapping_from_docker()
        with sg_reapply._sg_mapping_lock:
            assert sg_reapply._sg_mapping[("000000000000", "us-east-1", "i-111")] == ["sg-a", "sg-b"]
            assert sg_reapply._sg_mapping[("000000000000", "us-west-2", "i-222")] == ["sg-a"]

    def test_rebuild_skips_containers_missing_required_labels(self):
        fake_containers = [
            {"name": "localemu-ec2-i-999", "labels": {"localemu.service": "ec2"}},  # no instance id
        ]
        dc = mock.MagicMock()
        dc.list_containers.return_value = fake_containers
        with mock.patch.object(sg_reapply, "DOCKER_CLIENT", dc):
            sg_reapply.rebuild_mapping_from_docker()
        with sg_reapply._sg_mapping_lock:
            assert sg_reapply._sg_mapping == {}


class TestReapplySgForSgId:
    def test_hits_only_instances_with_the_sg(self):
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-1", ["sg-x", "sg-y"])
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-2", ["sg-y"])
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-3", ["sg-x"])

        calls: list[str] = []
        def _apply(container, sgs, acct, rgn):
            calls.append(container)
            return True

        with mock.patch.object(
            sg_reapply, "apply_sg_to_container", side_effect=_apply,
        ):
            count = sg_reapply.reapply_sg_for_sg_id("sg-x", "a1", "us-east-1")

        assert count == 2
        assert sorted(calls) == ["localemu-ec2-i-1", "localemu-ec2-i-3"]

    def test_account_and_region_isolation(self):
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-1", ["sg-x"])
        sg_reapply.record_instance_sgs("a2", "us-east-1", "i-2", ["sg-x"])
        sg_reapply.record_instance_sgs("a1", "us-west-2", "i-3", ["sg-x"])

        calls: list[str] = []
        def _apply(container, sgs, acct, rgn):
            calls.append(container)
            return True

        with mock.patch.object(
            sg_reapply, "apply_sg_to_container", side_effect=_apply,
        ):
            count = sg_reapply.reapply_sg_for_sg_id("sg-x", "a1", "us-east-1")

        assert count == 1
        assert calls == ["localemu-ec2-i-1"]

    def test_apply_failure_not_counted_as_success(self):
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-1", ["sg-x"])
        with mock.patch.object(
            sg_reapply, "apply_sg_to_container", return_value=False,
        ):
            count = sg_reapply.reapply_sg_for_sg_id("sg-x", "a1", "us-east-1")
        assert count == 0

    def test_empty_sg_returns_zero(self):
        count = sg_reapply.reapply_sg_for_sg_id("sg-nonexistent", "a1", "us-east-1")
        assert count == 0


class TestReapplySgForInstance:
    def test_updates_mapping_and_reapplies(self):
        sg_reapply.record_instance_sgs("a1", "us-east-1", "i-7", ["sg-old"])
        with mock.patch.object(
            sg_reapply, "apply_sg_to_container", return_value=True,
        ) as applier:
            ok = sg_reapply.reapply_sg_for_instance(
                "i-7", "a1", "us-east-1", ["sg-new-1", "sg-new-2"],
            )
        assert ok is True
        applier.assert_called_once_with(
            "localemu-ec2-i-7", ["sg-new-1", "sg-new-2"], "a1", "us-east-1",
        )
        # mapping must reflect the new set
        with sg_reapply._sg_mapping_lock:
            assert sg_reapply._sg_mapping[("a1", "us-east-1", "i-7")] == ["sg-new-1", "sg-new-2"]

    def test_returns_false_when_apply_fails(self):
        with mock.patch.object(
            sg_reapply, "apply_sg_to_container", return_value=False,
        ):
            ok = sg_reapply.reapply_sg_for_instance(
                "i-7", "a1", "us-east-1", ["sg-1"],
            )
        assert ok is False
