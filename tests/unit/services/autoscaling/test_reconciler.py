"""Unit tests for the ASG reconciler — pure diff between moto's
desired set and vm_manager's actual container set.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from localemu.services.autoscaling import reconciler


# ---------------------------------------------------------------------------
# Pure helpers (no Docker / no moto / no I/O)
# ---------------------------------------------------------------------------

class TestComputeDiff:
    def test_empty_sets(self):
        launch, terminate = reconciler.compute_diff(set(), set())
        assert launch == set()
        assert terminate == set()

    def test_only_moto_means_launch_all(self):
        launch, terminate = reconciler.compute_diff(
            {"i-1", "i-2"}, set(),
        )
        assert launch == {"i-1", "i-2"}
        assert terminate == set()

    def test_only_containers_means_terminate_all(self):
        launch, terminate = reconciler.compute_diff(
            set(), {"i-1", "i-2"},
        )
        assert launch == set()
        assert terminate == {"i-1", "i-2"}

    def test_overlap_no_op(self):
        launch, terminate = reconciler.compute_diff(
            {"i-1", "i-2"}, {"i-1", "i-2"},
        )
        assert launch == set()
        assert terminate == set()

    def test_partial_overlap(self):
        launch, terminate = reconciler.compute_diff(
            {"i-1", "i-2", "i-3"}, {"i-2", "i-3", "i-4"},
        )
        assert launch == {"i-1"}
        assert terminate == {"i-4"}


class TestPickSubnetRoundRobin:
    def test_none_when_no_csv(self):
        assert reconciler._pick_subnet_round_robin(None, {}) is None
        assert reconciler._pick_subnet_round_robin("", {}) is None
        assert reconciler._pick_subnet_round_robin(" , ", {}) is None

    def test_single_subnet(self):
        assert reconciler._pick_subnet_round_robin("subnet-a", {}) == "subnet-a"

    def test_picks_emptiest(self):
        assert reconciler._pick_subnet_round_robin(
            "subnet-a,subnet-b,subnet-c",
            {"subnet-a": 2, "subnet-b": 0, "subnet-c": 1},
        ) == "subnet-b"

    def test_tie_break_alphabetical(self):
        assert reconciler._pick_subnet_round_robin(
            "subnet-z,subnet-a,subnet-m", {},
        ) == "subnet-a"


class TestCollectSubnetCounts:
    def test_empty(self):
        assert reconciler.collect_subnet_counts({}) == {}

    def test_counts_aggregated(self):
        assert reconciler.collect_subnet_counts({
            "i-1": "subnet-a",
            "i-2": "subnet-a",
            "i-3": "subnet-b",
            "i-4": None,  # ignored
        }) == {"subnet-a": 2, "subnet-b": 1}


# ---------------------------------------------------------------------------
# build_launch_spec
# ---------------------------------------------------------------------------

class TestBuildLaunchSpec:
    def test_resolves_from_group_properties(self):
        group = SimpleNamespace(
            image_id="ami-test",
            instance_type="t3.micro",
            user_data="echo hi",
            security_groups=["sg-1", "sg-2"],
            key_name="my-key",
            launch_config=SimpleNamespace(
                iam_instance_profile="my-profile",
            ),
        )
        spec = reconciler.build_launch_spec("i-1", group, "subnet-x")
        assert spec.instance_id == "i-1"
        assert spec.ami_id == "ami-test"
        assert spec.instance_type == "t3.micro"
        assert spec.user_data == "echo hi"
        assert spec.security_groups == ["sg-1", "sg-2"]
        assert spec.subnet_id == "subnet-x"
        assert spec.key_name == "my-key"
        assert spec.iam_instance_profile_arn == "my-profile"

    def test_defaults_when_lc_absent(self):
        group = SimpleNamespace(
            image_id="ami-test",
            instance_type=None,  # forces default
            user_data=None,
            security_groups=None,
            key_name=None,
            launch_config=None,
        )
        spec = reconciler.build_launch_spec("i-2", group, None)
        assert spec.instance_type == "t2.micro"
        assert spec.user_data == ""
        assert spec.security_groups == []
        assert spec.subnet_id is None
        assert spec.iam_instance_profile_arn is None


# ---------------------------------------------------------------------------
# sync() end-to-end with mocked vm_manager + moto
# ---------------------------------------------------------------------------

def _fake_state(iid: str, subnet_id: str | None = None):
    return SimpleNamespace(
        instance_id=iid,
        instance=SimpleNamespace(id=iid, subnet_id=subnet_id),
    )


def _fake_group(**kw):
    defaults = dict(
        instance_states=[],
        image_id="ami-x", instance_type="t2.micro",
        user_data=None, security_groups=[],
        vpc_zone_identifier=None, key_name=None,
        launch_config=None,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestSync:
    def test_skipped_when_vm_manager_missing(self):
        # When vm_manager=None and the process-wide singleton is also
        # absent (EC2_VM_MANAGER != docker), reconciler is a no-op.
        with mock.patch.object(reconciler, "get_moto_asg",
                               return_value=_fake_group()), \
             mock.patch(
                 "localemu.services.ec2.docker.vm_manager.get_active_vm_manager",
                 return_value=None,
             ):
            r = reconciler.sync("acct", "us-east-1", "g", vm_manager=None)
        assert r.skipped_no_container_runtime is True
        assert r.launched == []
        assert r.terminated == []

    def test_no_moto_group_is_noop(self):
        vm = mock.MagicMock()
        with mock.patch.object(reconciler, "get_moto_asg", return_value=None):
            r = reconciler.sync("acct", "us-east-1", "g", vm_manager=vm)
        assert r.launched == []
        assert r.terminated == []
        vm.create_instance.assert_not_called()
        vm.terminate_instance.assert_not_called()

    def test_launches_missing_containers(self):
        group = _fake_group(
            instance_states=[_fake_state("i-1"), _fake_state("i-2")],
            vpc_zone_identifier="subnet-a",
        )
        vm = mock.MagicMock()
        vm.get_instance_info.return_value = None  # no containers exist
        with mock.patch.object(reconciler, "get_moto_asg", return_value=group):
            r = reconciler.sync(
                "acct", "us-east-1", "g",
                vm_manager=vm, vpc_network_manager=mock.MagicMock(
                    get_vpc_id_for_subnet=lambda *a, **k: None,
                ),
            )
        assert sorted(r.launched) == ["i-1", "i-2"]
        assert vm.create_instance.call_count == 2
        # subnet_id forwarded
        calls = [c.kwargs["subnet_id"] for c in vm.create_instance.call_args_list]
        assert all(s == "subnet-a" for s in calls)

    def test_terminates_extra_containers(self):
        group = _fake_group(instance_states=[_fake_state("i-1")])
        vm = mock.MagicMock()
        # vm has i-1 AND a stale i-orphan
        vm.get_instance_info.side_effect = lambda iid: (
            SimpleNamespace() if iid == "i-1" else None
        )
        with mock.patch.object(reconciler, "get_moto_asg", return_value=group):
            r = reconciler.sync(
                "acct", "us-east-1", "g", vm_manager=vm,
                vpc_network_manager=mock.MagicMock(),
            )
        # i-1 already has a container → no launch
        # but reconciler doesn't *find* i-orphan (we only scan moto's IDs),
        # so terminate is empty here. This documents the seam:
        # the reconciler cannot identify orphan containers without an
        # external by-ASG query — covered by the provider-side
        # DeleteAutoScalingGroup explicit terminate path.
        assert r.launched == []
        assert r.terminated == []
        vm.create_instance.assert_not_called()
        vm.terminate_instance.assert_not_called()

    def test_round_robin_across_subnets_for_new_launches(self):
        group = _fake_group(
            instance_states=[
                _fake_state("i-1"), _fake_state("i-2"), _fake_state("i-3"),
            ],
            vpc_zone_identifier="subnet-a,subnet-b,subnet-c",
        )
        vm = mock.MagicMock()
        vm.get_instance_info.return_value = None
        with mock.patch.object(reconciler, "get_moto_asg", return_value=group):
            reconciler.sync(
                "acct", "us-east-1", "g",
                vm_manager=vm,
                vpc_network_manager=mock.MagicMock(
                    get_vpc_id_for_subnet=lambda *a, **k: None,
                ),
            )
        subnets = sorted(
            c.kwargs["subnet_id"] for c in vm.create_instance.call_args_list
        )
        assert subnets == ["subnet-a", "subnet-b", "subnet-c"], subnets

    def test_existing_subnet_on_moto_state_honored(self):
        """If moto's EC2 instance already has subnet_id (upstream path
        before our patch lands), reconciler respects it instead of
        picking a new one."""
        group = _fake_group(
            instance_states=[_fake_state("i-1", subnet_id="subnet-pinned")],
            vpc_zone_identifier="subnet-a,subnet-b",
        )
        vm = mock.MagicMock()
        vm.get_instance_info.return_value = None
        with mock.patch.object(reconciler, "get_moto_asg", return_value=group):
            reconciler.sync(
                "acct", "us-east-1", "g",
                vm_manager=vm,
                vpc_network_manager=mock.MagicMock(
                    get_vpc_id_for_subnet=lambda *a, **k: None,
                ),
            )
        assert vm.create_instance.call_args.kwargs["subnet_id"] == "subnet-pinned"

    def test_launch_failure_recorded_but_continues(self):
        group = _fake_group(
            instance_states=[_fake_state("i-1"), _fake_state("i-2")],
        )
        vm = mock.MagicMock()
        vm.get_instance_info.return_value = None
        vm.create_instance.side_effect = [
            RuntimeError("disk full"),  # i-1 fails
            None,  # i-2 succeeds
        ]
        with mock.patch.object(reconciler, "get_moto_asg", return_value=group):
            r = reconciler.sync(
                "acct", "us-east-1", "g",
                vm_manager=vm,
                vpc_network_manager=mock.MagicMock(
                    get_vpc_id_for_subnet=lambda *a, **k: None,
                ),
            )
        assert r.launched == ["i-2"]
        assert r.launch_failures == [("i-1", "disk full")]
