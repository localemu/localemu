"""PipeTargetDispatcher — sender wiring + partial-batch failure capture."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from localemu.services.pipes.target import PipeTargetDispatcher


def _dispatcher(target_arn: str = "arn:aws:lambda:us-east-1:000000000000:function:foo"):
    return PipeTargetDispatcher(
        pipe_arn="arn:aws:pipes:us-east-1:000000000000:pipe/p",
        pipe_name="p",
        target_arn=target_arn,
        role_arn="arn:aws:iam::000000000000:role/r",
        target_parameters={},
        account_id="000000000000",
        region="us-east-1",
    )


class TestDispatcher:
    def test_builds_events_target_with_pipes_caller_principal(self):
        with patch(
            "localemu.services.pipes.target.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = MagicMock()
            _dispatcher().dispatch([{"k": "v"}])
        kwargs = MockFactory.call_args.kwargs
        assert kwargs["caller_service_principal"] == "pipes"
        assert kwargs["rule_arn"] == "arn:aws:pipes:us-east-1:000000000000:pipe/p"
        assert kwargs["rule_name"] == "p"
        # Target dict carries arn + role + the pipe name as id.
        target = kwargs["target"]
        assert target["Arn"] == "arn:aws:lambda:us-east-1:000000000000:function:foo"
        assert target["RoleArn"] == "arn:aws:iam::000000000000:role/r"
        assert target["Id"] == "p"

    def test_sends_each_event_through_the_sender(self):
        mock_sender = MagicMock()
        with patch(
            "localemu.services.pipes.target.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = mock_sender
            result = _dispatcher().dispatch([
                {"i": 1}, {"i": 2}, {"i": 3},
            ])
        assert result is None  # no failures
        assert mock_sender.send_event.call_count == 3

    def test_partial_failures_produce_batch_item_failures_payload(self):
        mock_sender = MagicMock()
        # Fail the second event only.
        mock_sender.send_event.side_effect = [None, Exception("boom"), None]
        with patch(
            "localemu.services.pipes.target.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = mock_sender
            result = _dispatcher().dispatch([
                {"i": 1}, {"i": 2}, {"i": 3},
            ])
        assert result == {"batchItemFailures": [{"itemIdentifier": "1"}]}

    def test_empty_batch_is_noop(self):
        with patch(
            "localemu.services.pipes.target.TargetSenderFactory"
        ) as MockFactory:
            assert _dispatcher().dispatch([]) is None
            MockFactory.assert_not_called()

    def test_sender_is_cached_across_dispatches(self):
        with patch(
            "localemu.services.pipes.target.TargetSenderFactory"
        ) as MockFactory:
            MockFactory.return_value.get_target_sender.return_value = MagicMock()
            d = _dispatcher()
            d.dispatch([{"a": 1}])
            d.dispatch([{"b": 2}])
        MockFactory.assert_called_once()
