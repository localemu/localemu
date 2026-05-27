"""
In-process event bus for the LocalEmu dashboard.

Producers (recorded API calls, state-mutating handlers, persistence
save/load) publish events via :func:`publish`. Consumers (the SSE
endpoint, server-side caches) subscribe via :func:`subscribe`.

Each event carries a tag list. Subscribers can pin to specific tags
(``["resources:lambda"]``) or accept everything (``["*"]``). Tag-based
fan-out keeps high-volume topics (``activity``) from waking up
consumers that only care about ``count`` updates.

A monotonic generation counter is maintained per tag so REST snapshot
endpoints can serve ETag-based conditional GET: when nothing tagged
``resources:lambda`` has happened since the client's last fetch, the
endpoint returns ``304 Not Modified`` without recomputing the snapshot.

Thread-safe. Uses an unbounded ``queue.Queue`` per subscriber so a
slow consumer cannot back-pressure publishers. If a subscriber's queue
exceeds :data:`MAX_QUEUED_EVENTS`, the oldest events are dropped and
a single ``dropped`` event is enqueued so the client can resync.
"""
from __future__ import annotations

import itertools
import logging
import queue
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

LOG = logging.getLogger(__name__)

# Maximum number of pending events per subscriber queue. Beyond this the
# oldest events are dropped and a single "dropped" sentinel is enqueued
# so the consumer can decide to resync via a snapshot GET.
MAX_QUEUED_EVENTS = 1000

# Wildcard tag — matches every event.
TAG_WILDCARD = "*"

# Heartbeat cadence in seconds. Subscribers receive a ``ping`` event so
# they know the connection is alive even when no real events fire.
HEARTBEAT_INTERVAL_SECONDS = 15.0


@dataclass
class Event:
    """A single event broadcast through the bus.

    ``event_id`` is a process-wide monotonic counter that doubles as the
    SSE ``id:`` field; clients use ``Last-Event-ID`` on reconnect to
    request only events newer than what they already saw.

    ``kind`` is the event-type label: ``activity``, ``count``,
    ``resource``, ``state``, ``ping``, ``dropped``.

    ``tags`` is a list of strings used by subscribers and the
    generation counter (e.g. ``["resources:lambda", "count"]``).

    ``payload`` is whatever JSON-serialisable dict the producer
    attached. The SSE encoder serialises it via the standard
    ``CustomEncoder``.
    """

    event_id: int
    ts: float
    kind: str
    tags: tuple[str, ...]
    payload: dict[str, Any] = field(default_factory=dict)


class _Subscriber:
    """One open subscription. Holds an unbounded queue of pending events."""

    __slots__ = ("tags", "queue", "name", "dropped")

    def __init__(self, tags: tuple[str, ...], name: str = "") -> None:
        self.tags: tuple[str, ...] = tags
        self.queue: queue.Queue[Event] = queue.Queue()
        self.name: str = name or f"sub-{id(self):x}"
        self.dropped: int = 0

    def wants(self, event: Event) -> bool:
        """Whether this subscriber's tag filter accepts the event."""
        if TAG_WILDCARD in self.tags:
            return True
        for t in event.tags:
            if t in self.tags:
                return True
        return False

    def enqueue(self, event: Event) -> None:
        """Add an event, with bounded backpressure handling."""
        if self.queue.qsize() >= MAX_QUEUED_EVENTS:
            # Drop the oldest entry. A single sentinel is enqueued the
            # first time this happens so the client can reconcile via a
            # snapshot GET.
            try:
                self.queue.get_nowait()
            except queue.Empty:
                pass
            self.dropped += 1
            if self.dropped == 1:
                sentinel = Event(
                    event_id=-1, ts=time.time(), kind="dropped",
                    tags=("system",),
                    payload={"reason": "subscriber queue overflow"},
                )
                self.queue.put_nowait(sentinel)
        self.queue.put_nowait(event)


class Bus:
    """Thread-safe in-process event bus.

    Singleton-like usage via :func:`get_bus`. Lifecycle owned by the
    dashboard plugin: a single instance per process.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        # Track the next event id explicitly so stats() does not have
        # to reach into the itertools.count internals (fragile across
        # Python versions).
        self._next_event_id: int = 1
        # Per-tag monotonic generation counter for ETag support.
        # Incremented on every publish that touches the tag. The global
        # ``"*"`` tag is incremented on every publish.
        self._generations: dict[str, int] = defaultdict(int)
        # Active subscribers.
        self._subscribers: list[_Subscriber] = []
        # Last heartbeat timestamp used by the SSE writer to decide
        # when to inject a synthetic ping event.
        self._last_heartbeat: float = time.time()

    # ------------------------------------------------------------------
    # Publish / subscribe
    # ------------------------------------------------------------------

    def publish(
        self,
        kind: str,
        tags: Iterable[str],
        payload: dict[str, Any] | None = None,
    ) -> Event:
        """Broadcast an event to every matching subscriber.

        :param kind: event-type label (``"activity"``, ``"count"``, ...).
        :param tags: list of tags used for generation tracking and
            subscriber filtering. The ``"*"`` tag is added implicitly.
        :param payload: optional JSON-serialisable dict.
        :returns: the published :class:`Event`.
        """
        tag_list = tuple(set(tags) | {TAG_WILDCARD})
        with self._lock:
            event_id = next(self._counter)
            self._next_event_id = event_id + 1
            for t in tag_list:
                self._generations[t] += 1
            # Snapshot subscribers under the lock; dispatch outside so a
            # slow consumer can't block publishers.
            subs = list(self._subscribers)
        evt = Event(
            event_id=event_id,
            ts=time.time(),
            kind=kind,
            tags=tag_list,
            payload=payload or {},
        )
        for sub in subs:
            if sub.wants(evt):
                try:
                    sub.enqueue(evt)
                except Exception:
                    LOG.debug("bus enqueue failed for %s", sub.name, exc_info=True)
        return evt

    def subscribe(
        self,
        tags: Iterable[str] = (TAG_WILDCARD,),
        name: str = "",
    ) -> _Subscriber:
        """Register a subscriber. Caller owns the returned object and
        must call :meth:`unsubscribe` when done."""
        sub = _Subscriber(tuple(tags), name=name)
        with self._lock:
            self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: _Subscriber) -> None:
        with self._lock:
            try:
                self._subscribers.remove(sub)
            except ValueError:
                pass

    def shutdown(self) -> None:
        """Wake every subscriber and signal end-of-stream.

        Enqueues a synthetic ``kind="closed"`` event into each
        subscriber's queue. Long-poll consumers (SSE generators)
        observe this event and break out of their wait loop so the
        gateway's request-handling threads can exit before the
        thread-pool join timeout.
        """
        with self._lock:
            subs = list(self._subscribers)
        evt = Event(
            event_id=-1,
            ts=time.time(),
            kind="closed",
            tags=("system",),
            payload={"reason": "infra shutdown"},
        )
        for sub in subs:
            try:
                sub.queue.put_nowait(evt)
            except Exception:
                LOG.debug("bus shutdown enqueue failed for %s", sub.name, exc_info=True)

    # ------------------------------------------------------------------
    # ETag / generation helpers
    # ------------------------------------------------------------------

    def generation(self, tag: str) -> int:
        """Monotonic counter for ``tag``. Used as the ETag value for
        snapshot endpoints. ``0`` means "no event ever touched this tag"."""
        with self._lock:
            return self._generations[tag]

    def etag_for(self, tag: str) -> str:
        """Quoted-string ETag value for HTTP headers."""
        return f'W/"g{self.generation(tag)}"'

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def stats(self) -> dict[str, Any]:
        """Coarse stats for the ``/_localemu/api/stream/stats`` debug
        endpoint. Read-only."""
        with self._lock:
            return {
                "subscribers": len(self._subscribers),
                "next_event_id": self._next_event_id,
                "generations": dict(self._generations),
            }


# Singleton accessor ---------------------------------------------------------

_bus: Bus | None = None
_bus_lock = threading.Lock()


def get_bus() -> Bus:
    """Return the process-wide singleton :class:`Bus`."""
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = Bus()
    return _bus


# ---------------------------------------------------------------------------
# Convenience helpers for producers
# ---------------------------------------------------------------------------


def publish_activity(
    service: str,
    operation: str,
    status: int,
    request_id: str,
    account_id: str,
    region: str,
    source_ip: str = "",
) -> Event:
    """Producer helper: an AWS API call was just recorded.

    Tagged ``activity`` plus ``service:<svc>`` so a per-service
    subscriber can filter.
    """
    return get_bus().publish(
        kind="activity",
        tags=("activity", f"service:{service}"),
        payload={
            "service": service,
            "operation": operation,
            "status": status,
            "request_id": request_id,
            "account_id": account_id,
            "region": region,
            "source_ip": source_ip,
            "timestamp": time.time(),
        },
    )


def publish_resource_changed(
    service: str,
    operation: str,
    resource_id: str,
    region: str = "",
    account_id: str = "",
) -> Event:
    """Producer helper: a Create/Update/Delete/Put operation affected a
    resource. Invalidates ``resources:<svc>`` and ``count`` tags."""
    return get_bus().publish(
        kind="resource",
        tags=(
            "resource",
            "count",
            f"resources:{service}",
            f"count:{service}",
        ),
        payload={
            "service": service,
            "operation": operation,
            "resource_id": resource_id,
            "region": region,
            "account_id": account_id,
        },
    )


def publish_count(service: str, count: int) -> Event:
    """Producer helper: a service's resource count has changed."""
    return get_bus().publish(
        kind="count",
        tags=("count", f"count:{service}"),
        payload={"service": service, "count": count},
    )


def publish_state(kind: str, payload: dict[str, Any] | None = None) -> Event:
    """Producer helper: persistence state event (snapshot / restored)."""
    return get_bus().publish(
        kind="state",
        tags=("state",),
        payload={"kind": kind, **(payload or {})},
    )


# ---------------------------------------------------------------------------
# Classification: turn raw AWS API calls into resource.changed events
# ---------------------------------------------------------------------------

# Operations whose name starts with any of these prefixes mutate state
# and therefore warrant a ``resource.changed`` event. Read-only ops
# (``GetX``, ``ListX``, ``DescribeX``, ``HeadX``) do NOT publish a
# resource event; they still produce ``activity`` so the live feed
# shows them.
_MUTATING_PREFIXES = (
    "Create", "Delete", "Put", "Update", "Modify", "Attach", "Detach",
    "Associate", "Disassociate", "Register", "Deregister", "Add",
    "Remove", "Start", "Stop", "Run", "Terminate", "Reboot", "Restore",
    "Cancel", "Rotate", "Replicate", "Tag", "Untag", "Enable", "Disable",
    "Subscribe", "Unsubscribe", "Send", "Publish", "Invoke", "Execute",
    "Import", "Export", "Replace", "Reset", "Set", "Configure",
)


def is_mutating(operation: str) -> bool:
    """Heuristic: does *operation* mutate state?"""
    return operation.startswith(_MUTATING_PREFIXES)
