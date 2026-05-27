"""Provider-level tests with mocked vm_manager + moto.

Verifies the @handler intercepts call moto first and then drive the
reconciler on the right operations.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from localemu.services.autoscaling import provider as asg_provider
from localemu.services.autoscaling.provider import AutoscalingProvider


def _ctx(values: dict, account_id: str = "000000000000",
          region: str = "us-east-1"):
    return SimpleNamespace(
        request=SimpleNamespace(values=values),
        account_id=account_id, region=region,
    )


@pytest.fixture
def vm():
    return mock.MagicMock()


@pytest.fixture(autouse=True)
def _stub_active_vm(vm):
    with mock.patch(
        "localemu.services.ec2.docker.vm_manager.get_active_vm_manager",
        return_value=vm,
    ):
        yield


class TestCreateUpdateSetDesired:
    def test_create_calls_moto_then_sync(self, vm):
        with mock.patch.object(asg_provider, "call_moto", return_value={}) as cm, \
             mock.patch.object(asg_provider.reconciler, "sync") as sync:
            AutoscalingProvider().create_auto_scaling_group(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        cm.assert_called_once()
        sync.assert_called_once_with(
            "000000000000", "us-east-1", "web", vm_manager=vm,
        )

    def test_update_calls_sync(self):
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync, \
             mock.patch.object(
                 AutoscalingProvider, "_snapshot_member_ids",
                 return_value=set(),
             ):
            AutoscalingProvider().update_auto_scaling_group(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        sync.assert_called_once()

    def test_set_desired_calls_sync(self):
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync, \
             mock.patch.object(
                 AutoscalingProvider, "_snapshot_member_ids",
                 return_value=set(),
             ):
            AutoscalingProvider().set_desired_capacity(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        sync.assert_called_once()

    def test_scale_in_terminates_removed_containers(self, vm):
        """SetDesiredCapacity from 3→1 removes 2 instances from moto;
        the provider must terminate the 2 dropped containers, since
        the reconciler alone only iterates the surviving moto IDs."""
        snapshots = [
            {"i-A", "i-B", "i-C"},  # before
            {"i-A"},                 # after moto scale-in
        ]
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync"), \
             mock.patch.object(
                 AutoscalingProvider, "_snapshot_member_ids",
                 side_effect=lambda *a, **k: snapshots.pop(0),
             ):
            AutoscalingProvider().set_desired_capacity(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        terminated = sorted(
            c.args[0] for c in vm.terminate_instance.call_args_list
        )
        assert terminated == ["i-B", "i-C"]

    def test_no_sync_when_group_name_missing(self):
        """Hardening: the AWS request shape should always include
        AutoScalingGroupName, but if a malformed payload lands we
        shouldn't NPE the reconciler."""
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync:
            AutoscalingProvider().create_auto_scaling_group(_ctx({}), {})
        sync.assert_not_called()


class TestDelete:
    def test_terminate_each_known_instance_before_moto_delete(self, vm):
        fake_group = SimpleNamespace(
            instance_states=[
                SimpleNamespace(instance_id="i-1",
                                instance=SimpleNamespace(id="i-1")),
                SimpleNamespace(instance_id="i-2",
                                instance=SimpleNamespace(id="i-2")),
            ],
        )
        with mock.patch.object(
            asg_provider.reconciler, "get_moto_asg", return_value=fake_group,
        ), mock.patch.object(asg_provider, "call_moto", return_value={}):
            AutoscalingProvider().delete_auto_scaling_group(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        assert vm.terminate_instance.call_args_list == [
            mock.call("i-1"), mock.call("i-2"),
        ]

    def test_delete_with_no_instances_is_a_passthrough(self, vm):
        with mock.patch.object(
            asg_provider.reconciler, "get_moto_asg",
            return_value=SimpleNamespace(instance_states=[]),
        ), mock.patch.object(asg_provider, "call_moto", return_value={}):
            AutoscalingProvider().delete_auto_scaling_group(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        vm.terminate_instance.assert_not_called()

    def test_terminate_failures_are_swallowed(self, vm):
        fake_group = SimpleNamespace(
            instance_states=[
                SimpleNamespace(instance_id="i-1",
                                instance=SimpleNamespace(id="i-1")),
            ],
        )
        vm.terminate_instance.side_effect = RuntimeError("docker gone")
        with mock.patch.object(
            asg_provider.reconciler, "get_moto_asg", return_value=fake_group,
        ), mock.patch.object(asg_provider, "call_moto", return_value={}):
            # No raise — provider must keep moto's response shape clean.
            AutoscalingProvider().delete_auto_scaling_group(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )


class TestTerminateInstanceInAsg:
    def test_calls_moto_then_sync_for_group(self):
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync, \
             mock.patch.object(
                 AutoscalingProvider, "_group_name_for_instance",
                 return_value="web",
             ):
            AutoscalingProvider().terminate_instance_in_auto_scaling_group(
                _ctx({"InstanceId": "i-1"}), {},
            )
        sync.assert_called_once()

    def test_no_sync_when_instance_has_no_group(self):
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync, \
             mock.patch.object(
                 AutoscalingProvider, "_group_name_for_instance",
                 return_value=None,
             ):
            AutoscalingProvider().terminate_instance_in_auto_scaling_group(
                _ctx({"InstanceId": "i-1"}), {},
            )
        sync.assert_not_called()


class TestAttachDetach:
    def test_attach_resyncs(self):
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync:
            AutoscalingProvider().attach_instances(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        sync.assert_called_once()

    def test_detach_does_NOT_terminate_containers(self, vm):
        """Detach explicitly LEAVES the EC2 instance running per AWS
        contract — the user can re-attach later. The reconciler must
        not race in and kill them."""
        with mock.patch.object(asg_provider, "call_moto", return_value={}), \
             mock.patch.object(asg_provider.reconciler, "sync") as sync:
            AutoscalingProvider().detach_instances(
                _ctx({"AutoScalingGroupName": "web"}), {},
            )
        sync.assert_not_called()
        vm.terminate_instance.assert_not_called()
