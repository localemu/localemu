"""Unit tests for full-traffic VPC Flow Logs .

Before: ``FlowLogRecorder.record`` was only called from ``sg_proxy``,
which only handled port 22. So VPC Flow Logs were effectively an SSH
access log — no TCP/80, no UDP, no egress, no iptables-rejected
traffic.

After: the SG/NACL iptables scripts inject ``-j LOG --log-prefix
"LE-FL:..."`` rules, and ``FlowLogRecorder.parse_iptables_log_line``
turns dmesg output into a ``FlowLogEntry``. A ``FlowLogPoller``
periodically drains container dmesg and feeds the recorder.
"""
from __future__ import annotations

from unittest import mock

import pytest

from localemu.services.ec2.docker import flow_log_recorder as flr
from localemu.services.ec2.docker import sg_iptables


class TestParseIptablesLogLine:
    """dmesg lines produced by iptables ``LOG`` target look like:

        [12345.678] LE-FL:6c8b9b95:I:D: IN=eth0 OUT= MAC=...
        SRC=1.2.3.4 DST=172.17.0.2 LEN=60 ... PROTO=TCP SPT=12345 DPT=80

    The compact prefix is mandatory: iptables ``--log-prefix`` truncates
    at 29 bytes so we use the LAST 8 chars of the instance id, a single
    ``I``/``O`` for chain (in/out) and ``A``/``D`` for action (accept/drop).
    """

    def test_parse_tcp_ingress_reject(self):
        line = (
            "[12345.678] LE-FL:6c8b9b95:I:D: IN=eth0 OUT= "
            "MAC=02:42:ac:11:00:02 SRC=1.2.3.4 DST=172.17.0.2 LEN=60 "
            "TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=12345 "
            "DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"
        )
        entry = flr.parse_iptables_log_line(line, account_id="000000000000")
        assert entry is not None
        assert entry.srcaddr == "1.2.3.4"
        assert entry.dstaddr == "172.17.0.2"
        assert entry.srcport == 12345
        assert entry.dstport == 80
        assert entry.protocol == 6  # TCP
        assert entry.action == "REJECT"
        assert entry.interface_id == "eni-6c8b9b95"

    def test_parse_udp_egress_accept(self):
        line = (
            "[12346.123] LE-FL:abcdef12:O:A: IN= OUT=eth0 "
            "SRC=172.17.0.3 DST=8.8.8.8 LEN=70 TOS=0x00 PREC=0x00 TTL=64 "
            "PROTO=UDP SPT=34567 DPT=53 LEN=50"
        )
        entry = flr.parse_iptables_log_line(line, account_id="000000000000")
        assert entry is not None
        assert entry.protocol == 17  # UDP
        assert entry.action == "ACCEPT"
        assert entry.srcport == 34567
        assert entry.dstport == 53
        assert entry.interface_id == "eni-abcdef12"

    def test_non_lefl_line_returns_none(self):
        assert flr.parse_iptables_log_line(
            "[12347.000] random kernel spew not from us",
            account_id="000000000000",
        ) is None

    def test_malformed_lefl_line_returns_none(self):
        assert flr.parse_iptables_log_line(
            "LE-FL:bad: missing all the fields",
            account_id="000000000000",
        ) is None


class TestIptablesBuildsLogRules:
    """sg_iptables must emit ``-j LOG --log-prefix`` before the terminal
    DROP so dmesg captures denied packets."""

    def test_apply_script_contains_log_directives_when_instance_id_set(self):
        script = sg_iptables._build_apply_script(
            in_rules=[
                "-A SG_IN -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "-A SG_IN -j DROP",
            ],
            out_rules=[
                "-A SG_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "-A SG_OUT -j DROP",
            ],
            instance_id="i-1234567890logtest",  # last 8 chars = "0logtest"
        )
        assert "--log-prefix" in script
        # Compact prefix: "LE-FL:0logtest:I:A:" / etc.
        assert "LE-FL:0logtest:I:A:" in script
        assert "LE-FL:0logtest:I:D:" in script
        assert "LE-FL:0logtest:O:A:" in script
        assert "LE-FL:0logtest:O:D:" in script

    def test_apply_script_no_log_directives_without_instance_id(self):
        """Called without instance_id (legacy callers / emergency path)
        the LOG injection is suppressed so the script stays minimal."""
        script = sg_iptables._build_apply_script(
            in_rules=["-A SG_IN -j DROP"],
            out_rules=["-A SG_OUT -j DROP"],
        )
        assert "--log-prefix" not in script
        assert "LE-FL:" not in script


class TestFlowLogPoller:
    """Poller reads ``dmesg`` from inside a container and feeds the recorder."""

    def test_poll_once_records_new_entries(self):
        dmesg_output = (
            "[12345.678] LE-FL:abcdef12:I:D: IN=eth0 OUT= "
            "SRC=1.2.3.4 DST=172.17.0.2 "
            "PROTO=TCP SPT=12345 DPT=80\n"
            "[12346.000] LE-FL:abcdef12:O:A: IN= OUT=eth0 "
            "SRC=172.17.0.2 DST=8.8.8.8 "
            "PROTO=TCP SPT=45678 DPT=443\n"
            "[12346.100] unrelated kernel message\n"
        ).encode()

        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (dmesg_output, b"")

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.FlowLogPoller(
                container_name="localemu-ec2-i-p",
                instance_id="i-p",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()

        lines = recorder.get_recent(limit=10)
        # Two LE-FL lines → two entries recorded
        assert len(lines) == 2
        assert any("REJECT" in line for line in lines)
        assert any("ACCEPT" in line for line in lines)

    def test_poll_once_dedupes_identical_lines(self):
        """Two polls should not create duplicate entries for the same
        kernel-log line — we remember the high-water timestamp."""
        dmesg_output = (
            "[100.000] LE-FL:dededede:I:D: IN=eth0 OUT= "
            "SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=80\n"
        ).encode()
        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (dmesg_output, b"")

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.FlowLogPoller(
                container_name="localemu-ec2-i-d",
                instance_id="i-d",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()
            poller.poll_once()

        assert len(recorder.get_recent(limit=10)) == 1

    def test_dmesg_failure_does_not_raise(self):
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = RuntimeError("exec failed")

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.FlowLogPoller(
                container_name="localemu-ec2-i-f",
                instance_id="i-f",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()
        # Must not raise, and no entries recorded.
        assert recorder.get_recent(limit=10) == []


class TestSidecarFlowLogPoller:
    """NFLOG-based poller reads ulogd2's LOGEMU output file via
    ``docker exec`` on the sidecar container.

    ulogd2's LOGEMU plugin emits each packet as one line in exactly
    the same ``LE-FL:...`` + ``SRC=... DST=... PROTO=... SPT=... DPT=...``
    format iptables ``-j LOG`` writes to dmesg — minus the
    ``[<monotonic>]`` prefix. The poller therefore reuses
    ``parse_iptables_log_line`` and relies on file-offset dedup rather
    than timestamp dedup.
    """

    def _ulogd_line(self, iid: str, direction: str, action: str) -> str:
        """Reproduce a LOGEMU-formatted line."""
        return (
            f"Jan 01 12:00:00 sidecar LE-FL:{iid}:{direction}:{action}: "
            f"IN=eth0 OUT= MAC=02:42:ac:11:00:02 "
            f"SRC=1.2.3.4 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
            f"ID=1 DF PROTO=TCP SPT=12345 DPT=443 WINDOW=65535 RES=0x00 "
            f"SYN URGP=0"
        )

    def test_poll_once_records_new_lines(self):
        line = self._ulogd_line("abcdef12", "I", "D")
        sidecar_blob = f"__LEFL_SIZE__=500\n{line}\n".encode()

        dc = mock.MagicMock()
        dc.exec_in_container.return_value = (sidecar_blob, b"")

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.SidecarFlowLogPoller(
                sidecar_name="localemu-flowlog-i-x",
                instance_id="i-x",
                account_id="000000000000",
                recorder=recorder,
            )
            recorded = poller.poll_once()

        assert recorded == 1
        lines = recorder.get_recent(limit=5)
        assert len(lines) == 1
        assert "REJECT" in lines[0]
        # Offset must have advanced so a second identical poll returns 0.
        assert poller._read_bytes == 500

    def test_offset_dedup_prevents_double_record(self):
        line = self._ulogd_line("abcdef12", "O", "A")
        blob_first = f"__LEFL_SIZE__=400\n{line}\n".encode()
        # Second poll: size unchanged, no new lines in tail.
        blob_second = b"__LEFL_SIZE__=400\n"

        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = [
            (blob_first, b""),
            (blob_second, b""),
        ]

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.SidecarFlowLogPoller(
                sidecar_name="localemu-flowlog-i-y",
                instance_id="i-y",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()
            poller.poll_once()

        assert len(recorder.get_recent(limit=5)) == 1

    def test_file_shrink_resets_offset(self):
        """If the sidecar was restarted and the flow.log re-truncated,
        the reported size will be smaller than our cached offset — we
        must reset rather than discard all subsequent lines."""
        dc = mock.MagicMock()
        # First: file at 1000 bytes with one line. Second: sidecar
        # restarted, file is now 10 bytes (one fresh line) — we must
        # reset and be ready to pick up fresh traffic on the NEXT poll.
        dc.exec_in_container.side_effect = [
            (f"__LEFL_SIZE__=1000\n{self._ulogd_line('zzzzzzzz', 'I', 'D')}\n".encode(), b""),
            (b"__LEFL_SIZE__=10\n", b""),
        ]

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.SidecarFlowLogPoller(
                sidecar_name="localemu-flowlog-i-z",
                instance_id="i-z",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()
            assert poller._read_bytes == 1000
            poller.poll_once()
            assert poller._read_bytes == 0  # reset

    def test_exec_failure_does_not_raise(self):
        dc = mock.MagicMock()
        dc.exec_in_container.side_effect = RuntimeError("exec failed")

        recorder = flr.FlowLogRecorder()
        with mock.patch.object(flr, "DOCKER_CLIENT", dc):
            poller = flr.SidecarFlowLogPoller(
                sidecar_name="localemu-flowlog-i-f",
                instance_id="i-f",
                account_id="000000000000",
                recorder=recorder,
            )
            poller.poll_once()
        assert recorder.get_recent(limit=5) == []


class TestIptablesBuildsNflogRules:
    """sg_iptables must also emit ``-j NFLOG`` so the per-instance
    sidecar (running ulogd2 in the EC2 container's netns) can observe
    denied / accepted packets on platforms where dmesg is empty
    (macOS Docker Desktop)."""

    def test_apply_script_contains_nflog_directives_when_instance_id_set(self):
        script = sg_iptables._build_apply_script(
            in_rules=[
                "-A SG_IN -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "-A SG_IN -j DROP",
            ],
            out_rules=[
                "-A SG_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "-A SG_OUT -j DROP",
            ],
            instance_id="i-1234567890logtest",
        )
        assert "-j NFLOG" in script
        assert "--nflog-group 42" in script
        assert "--nflog-prefix" in script
        # Same compact LE-FL prefix used by the LOG path — the sidecar
        # parser reuses ``parse_iptables_log_line`` verbatim.
        assert "LE-FL:0logtest:I:D:" in script
        assert "LE-FL:0logtest:O:A:" in script
