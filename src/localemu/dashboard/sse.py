"""
Server-Sent Events endpoint for the dashboard.

Single endpoint ``GET /_localemu/api/stream``. Returns a long-lived
HTTP response with ``Content-Type: text/event-stream`` that pushes
events from the dashboard event bus to one connected client.

Wire format (https://html.spec.whatwg.org/multipage/server-sent-events.html):

    id: 42\\n
    event: activity\\n
    data: {"service":"lambda","operation":"Invoke","status":200,...}\\n
    \\n

Every connection iterates the subscriber's queue, blocking with a
short timeout so the generator can emit periodic ``: ping\\n\\n``
comments to keep idle connections from being killed by intermediaries
(or by browser EventSource's own 45-second idle behavior).

Re-connection: clients honour ``Last-Event-ID`` automatically. The
endpoint reads the header and, if the requested id is older than the
oldest event still buffered, sends a ``dropped`` event so the client
knows to reconcile via a snapshot GET.
"""
from __future__ import annotations

import json
import logging
import queue
import time
from typing import Iterator

from localemu.http import Request, Response

from .bus import HEARTBEAT_INTERVAL_SECONDS, Event, get_bus

LOG = logging.getLogger(__name__)


def _format_event(evt: Event) -> bytes:
    """Encode one Event in SSE wire format."""
    try:
        data_json = json.dumps(evt.payload, default=str)
    except Exception:
        data_json = "{}"
    lines = [
        f"id: {evt.event_id}",
        f"event: {evt.kind}",
        f"data: {data_json}",
        "",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _format_comment(message: str) -> bytes:
    """Encode an SSE comment (``: <msg>\\n\\n``).

    Comments are not delivered to the EventSource ``onmessage``
    handler but DO traverse the wire, so they double as heartbeats
    that defeat proxy idle timeouts.
    """
    return f": {message}\n\n".encode("utf-8")


def _iter_events(last_event_id: int | None = None) -> Iterator[bytes]:
    """Generator that yields SSE-encoded bytes for one client connection.

    Loops forever (until the consumer disconnects). Blocks on the
    subscriber queue with a 1-second timeout so we can periodically
    emit heartbeats.
    """
    bus = get_bus()
    sub = bus.subscribe(("*",), name=f"sse-{int(time.time())}")
    LOG.debug("SSE subscriber attached (#%d)", bus.subscriber_count())

    # Synthetic boot event so the client knows the connection is up.
    yield _format_event(Event(
        event_id=0, ts=time.time(), kind="hello",
        tags=("system",),
        payload={
            "ts": time.time(),
            "last_event_id_in": last_event_id,
            "subscriber_count": bus.subscriber_count(),
        },
    ))

    # Honest reconnect signal: if the client reconnected with a
    # Last-Event-ID strictly less than the next id the bus is about
    # to emit, there is a gap. Emit a ``dropped`` event up-front so
    # the client knows to refetch caches/listings instead of trusting
    # the live stream to fill in the missing slice. This implements
    # the contract the module docstring already promised.
    try:
        stats = bus.stats() or {}
        next_id = int(stats.get("next_event_id") or 0)
        if last_event_id is not None and last_event_id + 1 < next_id:
            yield _format_event(Event(
                event_id=next_id - 1, ts=time.time(), kind="dropped",
                tags=("system",),
                payload={
                    "last_event_id_in": last_event_id,
                    "current_next_id": next_id,
                    "gap": next_id - 1 - last_event_id,
                    "reason": "reconnect-gap",
                },
            ))
    except Exception:
        LOG.debug("could not compute reconnect-gap", exc_info=True)

    last_heartbeat = time.time()
    try:
        while True:
            try:
                evt = sub.queue.get(timeout=1.0)
            except queue.Empty:
                evt = None

            if evt is not None:
                if evt.kind == "closed":
                    # Bus signaled infra shutdown; emit the event so the
                    # client sees the reason, then exit the generator so
                    # the serving thread can be joined by the gateway.
                    yield _format_event(evt)
                    break
                yield _format_event(evt)
                continue

            # No event for a second. If the heartbeat interval has
            # elapsed, send a comment to keep the pipe warm.
            now = time.time()
            if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_SECONDS:
                last_heartbeat = now
                yield _format_comment(f"ping ts={int(now)}")
    except GeneratorExit:
        LOG.debug("SSE generator closed by client")
    except Exception:
        LOG.debug("SSE generator failed", exc_info=True)
    finally:
        bus.unsubscribe(sub)


class StreamResource:
    """``GET /_localemu/api/stream`` -- SSE event stream."""

    def on_get(self, request: Request):
        last_id_raw = ""
        try:
            last_id_raw = request.headers.get("Last-Event-ID", "") or ""
        except Exception:
            pass
        try:
            last_event_id: int | None = int(last_id_raw) if last_id_raw else None
        except ValueError:
            last_event_id = None

        # ``direct_passthrough`` tells werkzeug to pass our generator
        # to the WSGI server as-is rather than buffering it.
        resp = Response(
            _iter_events(last_event_id),
            status=200,
            content_type="text/event-stream; charset=utf-8",
            direct_passthrough=True,
        )
        resp.headers["Cache-Control"] = "no-cache, no-transform"
        resp.headers["Connection"] = "keep-alive"
        # Disable proxy buffering (nginx ``X-Accel-Buffering``,
        # generic ``Pragma``).
        resp.headers["X-Accel-Buffering"] = "no"
        resp.headers["Pragma"] = "no-cache"
        return resp


class StreamStatsResource:
    """``GET /_localemu/api/stream/stats`` -- diagnostic counters."""

    def on_get(self, request: Request):
        from .api import _json_response

        return _json_response(get_bus().stats())
