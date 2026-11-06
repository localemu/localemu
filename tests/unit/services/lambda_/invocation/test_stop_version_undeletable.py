"""Regression test: a Lambda version with no tracked version manager
(e.g. one that reached ``State.Failed`` during startup - Docker
unavailable, image pull failure, ...) must not make ``stop_version``
raise.

Before the fix, ``update_version_state`` popped a failed version out of
``lambda_starting_versions`` without ever adding it to
``lambda_running_versions``, and ``stop_version`` raised ``ValueError``
when it found the ARN in neither dict. Since ``DeleteFunction`` and
``UpdateFunctionConfiguration`` both call ``stop_version`` for every
version unconditionally, that exception aborted the whole call -
leaving a function stuck forever (undeletable, unupdatable, can't even
free the name for reuse).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from localemu.services.lambda_.invocation.lambda_service import LambdaService


def _bare_service() -> LambdaService:
    service = LambdaService.__new__(LambdaService)
    service.lambda_running_versions = {}
    service.lambda_starting_versions = {}
    service.event_managers = {}
    service.task_executor = ThreadPoolExecutor(max_workers=1)
    return service


class TestStopVersionOnUntrackedArn:
    def test_stop_version_is_a_noop_when_nothing_is_tracked(self):
        service = _bare_service()
        # Real repro: the ARN is in neither dict (version failed to
        # start and was already popped/stopped elsewhere).
        service.stop_version("arn:aws:lambda:us-east-1:000000000000:function:f:$LATEST")
        # No exception == fixed. Also confirm it didn't resurrect any
        # tracking entries as a side effect.
        assert service.lambda_running_versions == {}
        assert service.lambda_starting_versions == {}

    def test_stop_version_still_stops_a_real_running_version(self):
        from unittest import mock

        service = _bare_service()
        arn = "arn:aws:lambda:us-east-1:000000000000:function:f:$LATEST"
        mgr = mock.Mock(name="version_manager")
        service.lambda_running_versions[arn] = mgr

        service.stop_version(arn)

        assert arn not in service.lambda_running_versions
        service.task_executor.shutdown(wait=True)
        mgr.stop.assert_called_once()

    def test_delete_like_loop_over_multiple_versions_does_not_abort_on_one_untracked(self):
        """Mirrors LambdaProvider.delete_function's loop over every
        version - one untracked version must not stop the others from
        being cleaned up."""
        service = _bare_service()
        tracked_arn = "arn:aws:lambda:us-east-1:000000000000:function:f:1"
        untracked_arn = "arn:aws:lambda:us-east-1:000000000000:function:f:$LATEST"
        from unittest import mock

        mgr = mock.Mock(name="version_manager")
        service.lambda_running_versions[tracked_arn] = mgr

        for arn in (tracked_arn, untracked_arn):
            service.stop_version(arn)  # must not raise for either

        service.task_executor.shutdown(wait=True)
        mgr.stop.assert_called_once()
