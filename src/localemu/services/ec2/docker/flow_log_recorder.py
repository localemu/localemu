"""
VPC Flow Log recorder.

Records network connection attempts captured by iptables ``LOG`` /
``NFLOG`` targets: SG/NACL chains emit ``LE-FL:...`` markers for
accepted/denied packets on every port and direction. A
``FlowLogPoller`` (macOS fallback path) reads ``dmesg`` inside each
EC2 container and a per-instance sidecar drains the NFLOG netlink
group on Linux — both feed this recorder. The legacy asyncio SG
proxy (SSH-only, source-IP-lying) has been removed.

Flow log entry format (v2):
  version account-id interface-id srcaddr dstaddr srcport dstport
  protocol packets bytes start end action log-status
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# Maximum buffered entries before flushing
_MAX_BUFFER = 500
_FLUSH_INTERVAL = 60  # seconds


class FlowLogEntry:
    """A single flow log record."""

    __slots__ = (
        "version", "account_id", "interface_id", "srcaddr", "dstaddr",
        "srcport", "dstport", "protocol", "packets", "bytes_count",
        "start", "end", "action", "log_status",
    )

    def __init__(
        self,
        account_id: str = "000000000000",
        interface_id: str = "eni-0",
        srcaddr: str = "0.0.0.0",
        dstaddr: str = "0.0.0.0",
        srcport: int = 0,
        dstport: int = 0,
        protocol: int = 6,  # TCP
        action: str = "ACCEPT",
    ):
        self.version = 2
        self.account_id = account_id
        self.interface_id = interface_id
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.srcport = srcport
        self.dstport = dstport
        self.protocol = protocol
        self.packets = 1
        self.bytes_count = 0
        now = int(time.time())
        self.start = now
        self.end = now
        self.action = action
        self.log_status = "OK"

    def to_log_line(self) -> str:
        """Format as a single flow log line."""
        return (
            f"{self.version} {self.account_id} {self.interface_id} "
            f"{self.srcaddr} {self.dstaddr} {self.srcport} {self.dstport} "
            f"{self.protocol} {self.packets} {self.bytes_count} "
            f"{self.start} {self.end} {self.action} {self.log_status}"
        )


class FlowLogRecorder:
    """Buffers flow log entries and flushes to CloudWatch Logs.

    Thread-safe.  The SG proxy calls ``record()`` on every connection
    attempt.  A background thread periodically flushes to CloudWatch.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffer: deque[FlowLogEntry] = deque(maxlen=_MAX_BUFFER)
        self._flush_thread: threading.Thread | None = None
        self._running = False

    def record(self, entry: FlowLogEntry) -> None:
        """Record a flow log entry. Called from the SG proxy hot path."""
        with self._lock:
            self._buffer.append(entry)

        # Start flush thread on first record
        if not self._running:
            self._start_flush_thread()

    def _start_flush_thread(self) -> None:
        """Start background thread to periodically flush entries."""
        if self._flush_thread and self._flush_thread.is_alive():
            return
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def _flush_loop(self) -> None:
        """Periodically flush buffered entries to CloudWatch Logs."""
        while self._running:
            time.sleep(_FLUSH_INTERVAL)
            self._flush()

    def _flush(self) -> None:
        """Route buffered entries to CloudWatch Logs.

        For each captured ``FlowLogEntry``, query the subscription
        registry for the destinations the user actually asked for in
        ``CreateFlowLogs`` (matching by ENI / Subnet / VPC scope and
        ``TrafficType``) and write to each match's log group. When no
        subscription matches an entry, fall back to the legacy
        ``/localemu/vpc-flow-logs`` group so dashboards built against
        the old hard-coded path keep working (set
        ``FLOW_LOGS_LEGACY_GROUP=0`` to drop unmatched records)."""
        with self._lock:
            if not self._buffer:
                return
            entries = list(self._buffer)
            self._buffer.clear()

        if not entries:
            return

        # Group entries by (region, log_group) to minimise put_log_events
        # calls. The default key carries the legacy group for entries no
        # subscription claimed.
        from localemu.services.ec2.flow_logs import (
            LEGACY_GROUP, get_flow_log_subscriptions,
        )
        legacy_enabled = os.environ.get(
            "FLOW_LOGS_LEGACY_GROUP", "1",
        ).strip() != "0"
        registry = get_flow_log_subscriptions()

        # destination key: (region, log_group) → list[FlowLogEntry]
        buckets: dict[tuple[str, str], list[FlowLogEntry]] = {}
        for entry in entries:
            matches = registry.matches_eni(entry.interface_id, entry.action)
            if matches:
                for sub in matches:
                    key = (sub.region, sub.log_group)
                    buckets.setdefault(key, []).append(entry)
            elif legacy_enabled:
                key = ("us-east-1", LEGACY_GROUP)
                buckets.setdefault(key, []).append(entry)

        if not buckets:
            return

        from localemu.aws.connect import connect_to

        for (region, log_group), bucket_entries in buckets.items():
            try:
                logs_client = connect_to(
                    aws_access_key_id="000000000000",
                    region_name=region,
                ).logs
                log_stream = (
                    f"flow-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
                )

                try:
                    logs_client.create_log_group(logGroupName=log_group)
                except Exception:
                    pass
                try:
                    logs_client.create_log_stream(
                        logGroupName=log_group, logStreamName=log_stream,
                    )
                except Exception:
                    pass

                log_events = [
                    {
                        "timestamp": int(e.start * 1000),
                        "message": e.to_log_line(),
                    }
                    for e in bucket_entries
                ]
                logs_client.put_log_events(
                    logGroupName=log_group,
                    logStreamName=log_stream,
                    logEvents=log_events,
                )
                LOG.debug(
                    "Flushed %d flow log entries to %s/%s",
                    len(bucket_entries), log_group, log_stream,
                )
            except Exception as exc:
                LOG.debug(
                    "Failed to flush %d flow logs to %s: %s",
                    len(bucket_entries), log_group, exc,
                )

    def get_recent(self, limit: int = 100) -> list[str]:
        """Return recent flow log lines (for dashboard)."""
        with self._lock:
            entries = list(self._buffer)
        return [e.to_log_line() for e in entries[-limit:]]

    def stop(self) -> None:
        """Stop the flush thread and write remaining entries."""
        self._running = False
        self._flush()


# ---------------------------------------------------------------------------
# Iptables LOG parser 
# ---------------------------------------------------------------------------

# Matches the compact prefix we set in sg_iptables / nacl_enforcer:
# LE-FL:<8char-iid-suffix>:<I|O>:<A|D>:
# Compact form is required because iptables LOG --log-prefix truncates
# at 29 bytes. ``iid`` here is the LAST 8 chars of the instance id so
# the FlowLogEntry.interface_id (eni-<8>) maps cleanly.
_LOG_PREFIX_RE = re.compile(
    r"LE-FL:(?P<iid>[A-Za-z0-9]{1,8}):(?P<chain>[IO]):(?P<action>[AD]):"
)
_FIELD_RE = re.compile(r"(?P<key>[A-Z]{2,})=(?P<value>[^ \n]+)")

# Protocol name → AWS Flow Log protocol number.
_PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1}


def parse_iptables_log_line(
    line: str, account_id: str = "000000000000",
) -> FlowLogEntry | None:
    """Parse one dmesg line produced by the iptables LOG target.

    Returns a populated ``FlowLogEntry`` or ``None`` if the line is
    either not a LocalEmu flow-log line or is missing required fields.
    Malformed lines never raise — they're just skipped.
    """
    m = _LOG_PREFIX_RE.search(line)
    if not m:
        return None

    fields = {
        hit.group("key"): hit.group("value")
        for hit in _FIELD_RE.finditer(line)
    }

    src = fields.get("SRC")
    dst = fields.get("DST")
    proto = fields.get("PROTO", "").upper()
    if not src or not dst or not proto:
        return None

    try:
        spt = int(fields.get("SPT") or 0)
        dpt = int(fields.get("DPT") or 0)
    except (TypeError, ValueError):
        return None

    action = "ACCEPT" if m.group("action") == "A" else "REJECT"
    iid = m.group("iid")
    # The prefix already carries only the last 8 chars (29-byte LOG
    # truncation), so use it directly as the synthetic ENI suffix.
    interface_id = f"eni-{iid}"

    return FlowLogEntry(
        account_id=account_id,
        interface_id=interface_id,
        srcaddr=src,
        dstaddr=dst,
        srcport=spt,
        dstport=dpt,
        protocol=_PROTO_NUM.get(proto, 0),
        action=action,
    )


class FlowLogPoller:
    """Periodically drains ``dmesg`` inside an EC2 container and feeds
    parsed LE-FL lines to ``FlowLogRecorder``.

    Runs a lightweight high-water-mark dedup using each line's leading
    ``[<monotonic-seconds>]`` timestamp so two successive polls of the
    same kernel buffer don't record duplicate entries.

    Callers typically start one poller per EC2 container when the SG
    iptables script has been applied successfully, then ``stop()`` at
    ``terminate_instance``. Polling is intentionally low-frequency to
    keep docker-exec overhead minimal.

    Note: this ``dmesg``-based poller works on Linux but NOT on macOS
    Docker Desktop (per-container dmesg returns empty — the kernel ring
    buffer is shared across all containers in the LinuxKit VM). The
    NFLOG-based ``SidecarFlowLogPoller`` below replaces it on both
    platforms; we keep this class for backward compatibility and for
    hosts where the sidecar can't be started.
    """

    def __init__(
        self,
        container_name: str,
        instance_id: str,
        account_id: str,
        recorder: "FlowLogRecorder",
        interval_seconds: int = 30,
    ) -> None:
        self.container_name = container_name
        self.instance_id = instance_id
        self.account_id = account_id
        self.recorder = recorder
        self.interval_seconds = interval_seconds
        self._seen_max_ts: float = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    _TS_RE = re.compile(r"^\[\s*(\d+(?:\.\d+)?)\s*\]")

    def poll_once(self) -> int:
        """Pull current dmesg contents, record any LE-FL lines newer
        than the high-water mark. Returns number of entries recorded."""
        try:
            out, _ = DOCKER_CLIENT.exec_in_container(
                self.container_name, ["sh", "-c", "dmesg 2>/dev/null || true"],
            )
        except Exception:
            LOG.debug(
                "flow-log poll %s: dmesg exec failed",
                self.container_name, exc_info=True,
            )
            return 0

        text = (out or b"").decode("utf-8", errors="replace")
        recorded = 0
        max_seen = self._seen_max_ts
        for line in text.splitlines():
            ts_match = self._TS_RE.match(line)
            if not ts_match:
                continue
            try:
                ts = float(ts_match.group(1))
            except ValueError:
                continue
            if ts <= self._seen_max_ts:
                continue
            entry = parse_iptables_log_line(line, account_id=self.account_id)
            if entry is None:
                continue
            self.recorder.record(entry)
            recorded += 1
            if ts > max_seen:
                max_seen = ts
        self._seen_max_ts = max_seen
        return recorded

    def start(self) -> None:
        """Start a background thread that polls at ``interval_seconds``."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"flow-log-poll-{self.instance_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                LOG.debug(
                    "flow-log poll %s raised",
                    self.container_name, exc_info=True,
                )
            self._stop.wait(self.interval_seconds)


class SidecarFlowLogPoller:
    """Periodically drains the per-EC2-instance flow-log sidecar and
    feeds parsed LE-FL lines to ``FlowLogRecorder``.

    This replaces ``FlowLogPoller`` (the dmesg-based implementation)
    for the cross-platform NFLOG → ulogd2 path. The sidecar writes
    each packet to ``/var/log/localemu-flow/flow.log`` in
    iptables-``LOG``-compatible format (ulogd2's ``LOGEMU`` output
    plugin). We ``docker exec`` into the sidecar and ``tail`` the file
    from the last byte offset we read — a file-offset high-water mark
    replaces the dmesg timestamp dedup the old poller used.

    Dedup strategy
    --------------
    ulogd2 does not prefix lines with ``[<monotonic>]`` the way dmesg
    does, so we can't reuse the kernel-timestamp watermark. Instead
    we remember ``_read_bytes`` — the offset we consumed last time —
    and on each poll request ``tail -c +<offset+1>`` so only new bytes
    are returned. The sidecar file is append-only by design (ulogd2
    never truncates it) so the offset monotonically grows. If the file
    shrinks (sidecar restarted, log got truncated) we reset to 0.
    """

    def __init__(
        self,
        sidecar_name: str,
        instance_id: str,
        account_id: str,
        recorder: "FlowLogRecorder",
        interval_seconds: int = 5,
        log_path: str = "/var/log/localemu-flow/flow.log",
    ) -> None:
        self.sidecar_name = sidecar_name
        self.instance_id = instance_id
        self.account_id = account_id
        self.recorder = recorder
        self.interval_seconds = interval_seconds
        self.log_path = log_path
        self._read_bytes: int = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_once(self) -> int:
        """Pull new content from the sidecar's flow log file, record
        any new LE-FL entries. Returns the number recorded."""
        # Ask the sidecar for current size + the bytes past our offset
        # in one exec to keep overhead low. ``stat -c %s`` is portable
        # on busybox / alpine / coreutils; fall back to ``wc -c`` if
        # stat is missing (extremely unlikely on alpine).
        probe = (
            f"size=$(stat -c %s {self.log_path} 2>/dev/null "
            f"|| wc -c < {self.log_path} 2>/dev/null || echo 0); "
            f"echo __LEFL_SIZE__=$size; "
            f"tail -c +$(( {self._read_bytes} + 1 )) {self.log_path} 2>/dev/null || true"
        )
        try:
            out, _ = DOCKER_CLIENT.exec_in_container(
                self.sidecar_name, ["sh", "-c", probe],
            )
        except Exception:
            LOG.debug(
                "sidecar flow-log poll %s: exec failed",
                self.sidecar_name, exc_info=True,
            )
            return 0

        text = (out or b"").decode("utf-8", errors="replace")
        # Split the SIZE marker from the log content.
        size = None
        content_lines: list[str] = []
        for line in text.splitlines():
            if line.startswith("__LEFL_SIZE__="):
                try:
                    size = int(line.split("=", 1)[1].strip())
                except ValueError:
                    size = None
                continue
            content_lines.append(line)

        # If the file shrank (sidecar restart / truncation), reset.
        if size is not None and size < self._read_bytes:
            self._read_bytes = 0
            return 0

        recorded = 0
        for line in content_lines:
            if "LE-FL:" not in line:
                continue
            entry = parse_iptables_log_line(line, account_id=self.account_id)
            if entry is None:
                continue
            self.recorder.record(entry)
            recorded += 1

        if size is not None:
            # Advance to the reported size (inclusive of any trailing
            # bytes we didn't get because the file grew mid-read — next
            # poll will catch the tail).
            self._read_bytes = size
        return recorded

    def start(self) -> None:
        """Start a background thread that polls at ``interval_seconds``."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"sidecar-flow-log-poll-{self.instance_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                LOG.debug(
                    "sidecar flow-log poll %s raised",
                    self.sidecar_name, exc_info=True,
                )
            self._stop.wait(self.interval_seconds)


# Module-level singleton
_recorder: FlowLogRecorder | None = None
_recorder_lock = threading.Lock()


def get_flow_log_recorder() -> FlowLogRecorder:
    global _recorder
    if _recorder is None:
        with _recorder_lock:
            if _recorder is None:
                _recorder = FlowLogRecorder()
    return _recorder
