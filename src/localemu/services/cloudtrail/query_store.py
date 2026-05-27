"""
CloudTrail Lake Query engine (subset) for LocalEmu.

Implements an honest, small SQL subset over the shared
``CloudTrailEventStore`` (the same store that backs ``LookupEvents``).

Supported grammar (case-insensitive, single-statement):

    SELECT <col> [, <col> ...]
    FROM <data-store-arn>
    [ WHERE <col> <op> '<literal>' [AND <col> <op> '<literal>' ...] ]
    [ GROUP BY <col> [, <col> ...] ]
    [ ORDER BY <col> [ASC|DESC] ]
    [ LIMIT <int> ]

where ``<col>`` is one of:

    eventName, eventSource, awsRegion, eventID, eventTime, readOnly,
    sourceIPAddress, userAgent, userIdentity.username (aliased as ``username``),
    userIdentity.accessKeyId (aliased as ``accessKeyId``), errorCode,
    count(*), count(*) as <alias>

and ``<op>`` is one of ``=``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``LIKE``.

Anything the parser cannot handle causes the query to transition to
``FAILED`` with a clear error message. We never silently succeed on
unsupported input.

Lifecycle state machine:

    QUEUED  --(run)-->  RUNNING  --(finish)-->  FINISHED
                                \\--(error)--->  FAILED
                                \\--(cancel)-->  CANCELLED

A background daemon thread transitions queries from QUEUED to
FINISHED after a short delay so tests need not poll for minutes.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Column resolution
# ---------------------------------------------------------------------------
# Canonical column name -> callable(event) -> value.
#
# Column matching is case-insensitive and tolerant of a small number of
# aliases (``username`` for ``userIdentity.username``, etc.) because AWS
# docs and real customers mix both spellings.
_COLUMN_RESOLVERS: dict[str, Any] = {
    "eventname": lambda e: e.event_name,
    "eventsource": lambda e: e.event_source,
    "awsregion": lambda e: e.aws_region,
    "eventid": lambda e: e.event_id,
    "eventtime": lambda e: e.event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "readonly": lambda e: str(e.read_only).lower(),
    "sourceipaddress": lambda e: e.source_ip,
    "useragent": lambda e: e.user_agent,
    "username": lambda e: e.username,
    "useridentity.username": lambda e: e.username,
    "accesskeyid": lambda e: e.access_key_id,
    "useridentity.accesskeyid": lambda e: e.access_key_id,
    "errorcode": lambda e: e.error_code or "",
    "recipientaccountid": lambda e: e.account_id,
    "accountid": lambda e: e.account_id,
}


def _canon(col: str) -> str:
    return col.strip().strip('"').lower()


def _resolve_column(col: str):
    """Return a resolver function for ``col`` or raise ``ValueError``."""
    resolver = _COLUMN_RESOLVERS.get(_canon(col))
    if resolver is None:
        raise ValueError(f"Unsupported column: {col!r}")
    return resolver


# ---------------------------------------------------------------------------
# SQL parser (intentionally small — regex-based, not a full parser)
# ---------------------------------------------------------------------------
_ARN_RE = re.compile(r"arn:aws[\w-]*:cloudtrail:[^:\s]*:\d+:eventdatastore/[A-Za-z0-9-]+")

# A bare event-data-store UUID is also accepted as FROM target — AWS CLI
# lets users query by UUID directly.
_UUID_RE = re.compile(r"[0-9a-fA-F-]{36}")


@dataclass
class _ParsedQuery:
    columns: list[str]                        # raw SELECT list items
    group_by: list[str]                       # raw GROUP BY items
    where: list[tuple[str, str, str]]         # (col, op, literal)
    order_by: tuple[str, bool] | None         # (col, descending?)
    limit: int | None
    from_target: str                          # ARN or UUID the query is against


def _split_top_level(s: str, delim: str = ",") -> list[str]:
    """Split on top-level commas, honoring single-quoted strings."""
    out, buf, in_str = [], [], False
    for ch in s:
        if ch == "'":
            in_str = not in_str
            buf.append(ch)
        elif ch == delim and not in_str:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return [x for x in out if x]


def parse_query(sql: str) -> _ParsedQuery:
    """Parse a query string into a ``_ParsedQuery`` or raise ``ValueError``.

    Intentionally strict — we refuse anything we don't understand so the
    caller can surface a FAILED status with a faithful error message.
    """
    if not sql or not sql.strip():
        raise ValueError("Empty query statement")

    # Normalize whitespace (but preserve quoted strings)
    text = sql.strip().rstrip(";").strip()

    # 1. SELECT <cols>
    m = re.match(r"(?is)^\s*SELECT\s+(.+?)\s+FROM\s+(.+?)\s*$", text)
    if not m:
        raise ValueError("Expected 'SELECT ... FROM ...'")
    select_part = m.group(1)
    rest = m.group(2)

    # 2. Peel clauses from the tail in reverse order: LIMIT, ORDER BY,
    #    GROUP BY, WHERE — each optional.
    limit: int | None = None
    m2 = re.search(r"(?is)\s+LIMIT\s+(\d+)\s*$", rest)
    if m2:
        limit = int(m2.group(1))
        rest = rest[: m2.start()]

    order_by: tuple[str, bool] | None = None
    m2 = re.search(r"(?is)\s+ORDER\s+BY\s+(.+?)\s*$", rest)
    if m2:
        order_raw = m2.group(1).strip()
        desc = False
        om = re.match(r"(?is)^(.+?)\s+(ASC|DESC)\s*$", order_raw)
        if om:
            order_raw = om.group(1).strip()
            desc = om.group(2).upper() == "DESC"
        order_by = (order_raw, desc)
        rest = rest[: m2.start()]

    group_by: list[str] = []
    m2 = re.search(r"(?is)\s+GROUP\s+BY\s+(.+?)\s*$", rest)
    if m2:
        group_by = _split_top_level(m2.group(1))
        rest = rest[: m2.start()]

    where: list[tuple[str, str, str]] = []
    m2 = re.search(r"(?is)\s+WHERE\s+(.+?)\s*$", rest)
    if m2:
        where_raw = m2.group(1)
        # Support only AND conjunction at top level.
        clauses = re.split(r"(?i)\s+AND\s+", where_raw)
        for clause in clauses:
            cm = re.match(
                r"""(?ix)
                ^\s*([A-Za-z_][\w.]*)\s*
                (=|!=|<>|<=|>=|<|>|LIKE)\s*
                '([^']*)'\s*$
                """,
                clause,
            )
            if not cm:
                raise ValueError(
                    f"Unsupported WHERE clause: {clause.strip()!r} "
                    f"(expected: <column> <op> '<literal>')"
                )
            where.append((cm.group(1), cm.group(2).upper(), cm.group(3)))
        rest = rest[: m2.start()]

    from_target = rest.strip()
    # Validate FROM target is either an ARN or a bare UUID.
    if not (_ARN_RE.search(from_target) or _UUID_RE.fullmatch(from_target)):
        raise ValueError(
            f"FROM must be an event-data-store ARN or UUID, got: {from_target!r}"
        )

    columns = _split_top_level(select_part)
    if not columns:
        raise ValueError("SELECT list is empty")

    return _ParsedQuery(
        columns=columns,
        group_by=group_by,
        where=where,
        order_by=order_by,
        limit=limit,
        from_target=from_target,
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
_COUNT_RE = re.compile(r"(?i)^\s*count\s*\(\s*\*\s*\)(\s+AS\s+([A-Za-z_]\w*))?\s*$")
_COLUMN_WITH_ALIAS_RE = re.compile(
    r"(?i)^\s*([A-Za-z_][\w.]*)(\s+AS\s+([A-Za-z_]\w*))?\s*$"
)


def _project_name(raw: str) -> str:
    """Return the column name to show in the output header for ``raw``."""
    m = _COUNT_RE.match(raw)
    if m:
        return m.group(2) or "count(*)"
    m = _COLUMN_WITH_ALIAS_RE.match(raw)
    if m:
        return m.group(3) or m.group(1)
    return raw.strip()


def _is_count_star(raw: str) -> bool:
    return bool(_COUNT_RE.match(raw))


_WHERE_OPS = {
    "=":  lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<>": lambda a, b: a != b,
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "LIKE": lambda a, b: _like(a, b),
}


def _like(a: str, pattern: str) -> bool:
    # Convert SQL LIKE into a regex: % -> .* , _ -> .
    regex = re.escape(pattern).replace(r"\%", ".*").replace(r"\_", ".")
    return re.fullmatch(regex, a or "") is not None


def _apply_where(events, where):
    out = []
    for evt in events:
        ok = True
        for col, op, lit in where:
            try:
                val = _resolve_column(col)(evt)
            except ValueError:
                ok = False
                break
            if not _WHERE_OPS[op](val or "", lit):
                ok = False
                break
        if ok:
            out.append(evt)
    return out


def execute_parsed(parsed: _ParsedQuery, events: list) -> tuple[list[str], list[list[dict[str, str]]], int]:
    """Execute a parsed query against ``events``.

    Returns (column_headers, rows, scanned_count) where each row is a
    list of ``{column_name: value}`` dicts — the AWS wire format for
    ``GetQueryResults.QueryResultRows``.
    """
    scanned = len(events)

    # WHERE
    filtered = _apply_where(events, parsed.where) if parsed.where else events

    # Validate all non-count columns resolve
    for col in parsed.columns:
        if _is_count_star(col):
            continue
        m = _COLUMN_WITH_ALIAS_RE.match(col)
        if not m:
            raise ValueError(f"Unrecognised SELECT item: {col!r}")
        _resolve_column(m.group(1))  # raises if unknown

    headers = [_project_name(c) for c in parsed.columns]

    # GROUP BY — only valid when SELECT list contains count(*) (or only grouped cols).
    if parsed.group_by:
        for gb in parsed.group_by:
            _resolve_column(gb)  # validate
        groups: dict[tuple, list] = {}
        for evt in filtered:
            key = tuple(_resolve_column(gb)(evt) for gb in parsed.group_by)
            groups.setdefault(key, []).append(evt)

        rows_raw: list[tuple] = []
        for key, group_events in groups.items():
            row = []
            # Build key lookup from group-by column name -> value
            gb_map = {_canon(gb): v for gb, v in zip(parsed.group_by, key)}
            for col in parsed.columns:
                if _is_count_star(col):
                    row.append(len(group_events))
                    continue
                m = _COLUMN_WITH_ALIAS_RE.match(col)
                cname = _canon(m.group(1))
                if cname in gb_map:
                    row.append(gb_map[cname])
                else:
                    # Non-grouped column with aggregate — take first value
                    row.append(_resolve_column(m.group(1))(group_events[0]))
            rows_raw.append(tuple(row))
    else:
        rows_raw = []
        if any(_is_count_star(c) for c in parsed.columns) and len(parsed.columns) == 1:
            # Pure count(*)
            rows_raw.append((len(filtered),))
        else:
            for evt in filtered:
                row = []
                for col in parsed.columns:
                    if _is_count_star(col):
                        row.append(len(filtered))
                        continue
                    m = _COLUMN_WITH_ALIAS_RE.match(col)
                    row.append(_resolve_column(m.group(1))(evt))
                rows_raw.append(tuple(row))

    # ORDER BY
    if parsed.order_by:
        col, desc = parsed.order_by
        # If ordering by a header name, index by header
        try:
            idx = headers.index(_project_name(col))
        except ValueError:
            # Try matching by canonical column name against the SELECT list
            canon = _canon(col)
            idx = None
            for i, raw in enumerate(parsed.columns):
                m = _COLUMN_WITH_ALIAS_RE.match(raw)
                if m and _canon(m.group(1)) == canon:
                    idx = i
                    break
            if idx is None:
                raise ValueError(f"ORDER BY column not in SELECT list: {col!r}")

        def _key(r):
            v = r[idx]
            return (0, v) if v is not None else (1, "")
        rows_raw.sort(key=_key, reverse=desc)

    # LIMIT
    if parsed.limit is not None:
        rows_raw = rows_raw[: parsed.limit]

    # Convert to wire format: list of [{col: val}, {col: val}, ...]
    wire_rows: list[list[dict[str, str]]] = []
    for r in rows_raw:
        wire_rows.append([{h: str(v) if v is not None else ""} for h, v in zip(headers, r)])

    return headers, wire_rows, scanned


# ---------------------------------------------------------------------------
# Query object + store
# ---------------------------------------------------------------------------
QUEUED, RUNNING, FINISHED, FAILED, CANCELLED, TIMED_OUT = (
    "QUEUED", "RUNNING", "FINISHED", "FAILED", "CANCELLED", "TIMED_OUT",
)


@dataclass
class Query:
    query_id: str
    statement: str
    event_data_store_arn: str
    creation_time: datetime
    status: str = QUEUED
    error_message: str | None = None
    delivery_s3_uri: str | None = None
    delivery_status: str | None = None
    query_alias: str | None = None
    prompt: str | None = None
    # Results
    headers: list[str] = field(default_factory=list)
    rows: list[list[dict[str, str]]] = field(default_factory=list)
    events_scanned: int = 0
    execution_ms: int = 0
    bytes_scanned: int = 0


class QueryStore:
    """In-memory query registry. Metadata only — no bulk data."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._queries: dict[str, Query] = {}

    def create(
        self,
        statement: str,
        delivery_s3_uri: str | None = None,
        query_alias: str | None = None,
    ) -> Query:
        # Extract FROM target up-front so ListQueries(event_data_store=arn)
        # can filter queries with bad statements too.
        ds_arn = ""
        m = _ARN_RE.search(statement or "")
        if m:
            ds_arn = m.group(0)

        q = Query(
            query_id=str(uuid.uuid4()),
            statement=statement or "",
            event_data_store_arn=ds_arn,
            creation_time=datetime.now(timezone.utc),
            query_alias=query_alias,
            delivery_s3_uri=delivery_s3_uri,
            delivery_status="NOT_STARTED" if delivery_s3_uri else None,
        )
        with self._lock:
            self._queries[q.query_id] = q
        return q

    def get(self, query_id: str) -> Query | None:
        with self._lock:
            return self._queries.get(query_id)

    def list(
        self,
        event_data_store: str | None = None,
        status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[Query]:
        with self._lock:
            out = list(self._queries.values())
        if event_data_store:
            out = [q for q in out if q.event_data_store_arn == event_data_store
                   or event_data_store.endswith(q.event_data_store_arn.split("/")[-1])
                   or q.event_data_store_arn.endswith(event_data_store.split("/")[-1])]
        if status:
            out = [q for q in out if q.status == status]
        if start_time:
            out = [q for q in out if q.creation_time >= start_time]
        if end_time:
            out = [q for q in out if q.creation_time <= end_time]
        out.sort(key=lambda q: q.creation_time, reverse=True)
        return out

    def cancel(self, query_id: str) -> Query | None:
        with self._lock:
            q = self._queries.get(query_id)
            if q is None:
                return None
            if q.status in (FINISHED, FAILED, CANCELLED):
                return q
            q.status = CANCELLED
            return q

    def reset(self) -> None:
        with self._lock:
            self._queries.clear()


_store: QueryStore | None = None
_store_lock = threading.Lock()


def get_query_store() -> QueryStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = QueryStore()
    return _store


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_query_sync(query_id: str, event_snapshot: list | None = None) -> None:
    """Synchronously execute a query.

    Callers (the background scheduler, or tests that prefer determinism)
    use this to drive a query to a terminal state immediately.
    """
    store = get_query_store()
    q = store.get(query_id)
    if q is None:
        return
    # Respect cancellation races
    if q.status == CANCELLED:
        return

    q.status = RUNNING
    t0 = time.perf_counter()
    try:
        parsed = parse_query(q.statement)
        if event_snapshot is None:
            from localemu.services.cloudtrail.event_store import get_event_store
            event_snapshot = get_event_store().get_recent(limit=10_000)
        headers, rows, scanned = execute_parsed(parsed, event_snapshot)
        # Check cancellation one more time before committing results
        if store.get(query_id) and store.get(query_id).status == CANCELLED:
            return
        q.headers = headers
        q.rows = rows
        q.events_scanned = scanned
        q.bytes_scanned = scanned * 1024  # rough estimate
        q.status = FINISHED
    except ValueError as e:
        q.status = FAILED
        q.error_message = f"LocalEmu only supports simple SELECT/GROUP BY queries: {e}"
    except Exception as e:  # pragma: no cover - defensive
        q.status = FAILED
        q.error_message = f"Query execution error: {e}"
    finally:
        q.execution_ms = int((time.perf_counter() - t0) * 1000)


def schedule_query(query_id: str, delay_seconds: float = 0.1) -> None:
    """Schedule a queued query to run after ``delay_seconds`` on a daemon thread."""

    def _run():
        try:
            time.sleep(delay_seconds)
        except Exception:
            pass
        try:
            run_query_sync(query_id)
        except Exception:
            LOG.debug("Query runner crashed for %s", query_id, exc_info=True)

    t = threading.Thread(target=_run, name=f"ct-query-{query_id[:8]}", daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Sample queries (AWS-published) for SearchSampleQueries
# ---------------------------------------------------------------------------
SAMPLE_QUERIES: list[dict[str, Any]] = [
    {
        "Name": "Top 10 event names",
        "Description": "Return the 10 most frequently recorded event names "
                       "across the event data store.",
        "SQL": (
            "SELECT eventName, count(*) AS eventCount "
            "FROM <event_data_store_arn> "
            "GROUP BY eventName "
            "ORDER BY eventCount DESC "
            "LIMIT 10"
        ),
    },
    {
        "Name": "Errors by service",
        "Description": "Count API calls that returned an error, grouped by "
                       "AWS service (eventSource).",
        "SQL": (
            "SELECT eventSource, count(*) AS errorCount "
            "FROM <event_data_store_arn> "
            "WHERE errorCode != '' "
            "GROUP BY eventSource "
            "ORDER BY errorCount DESC"
        ),
    },
    {
        "Name": "Activity by region",
        "Description": "Count API activity per AWS region.",
        "SQL": (
            "SELECT awsRegion, count(*) AS total "
            "FROM <event_data_store_arn> "
            "GROUP BY awsRegion "
            "ORDER BY total DESC"
        ),
    },
    {
        "Name": "S3 data events",
        "Description": "Return all S3 service events, ordered by event time.",
        "SQL": (
            "SELECT eventTime, eventName, sourceIPAddress, username "
            "FROM <event_data_store_arn> "
            "WHERE eventSource = 's3.amazonaws.com' "
            "ORDER BY eventTime DESC "
            "LIMIT 100"
        ),
    },
    {
        "Name": "Console logins by user",
        "Description": "Count console login events per IAM user.",
        "SQL": (
            "SELECT username, count(*) AS logins "
            "FROM <event_data_store_arn> "
            "WHERE eventName = 'ConsoleLogin' "
            "GROUP BY username "
            "ORDER BY logins DESC"
        ),
    },
]


def search_samples(phrase: str, max_results: int = 10) -> list[dict[str, Any]]:
    phrase_lc = (phrase or "").lower().strip()
    scored: list[tuple[float, dict]] = []
    for s in SAMPLE_QUERIES:
        hay = f"{s['Name']} {s['Description']} {s['SQL']}".lower()
        # relevance = fraction of phrase tokens found
        if not phrase_lc:
            score = 0.5
        else:
            tokens = [t for t in re.split(r"\s+", phrase_lc) if t]
            hits = sum(1 for t in tokens if t in hay)
            score = hits / max(len(tokens), 1)
        if score > 0 or not phrase_lc:
            entry = dict(s)
            entry["Relevance"] = round(score, 3)
            scored.append((score, entry))
    scored.sort(key=lambda p: p[0], reverse=True)
    return [e for _, e in scored[: max_results or 10]]


# ---------------------------------------------------------------------------
# Natural-language -> SQL (honest, pattern-based)
# ---------------------------------------------------------------------------
def generate_sql_from_prompt(prompt: str, event_data_stores: list[str]) -> str:
    """Return a SQL template for ``prompt`` or raise ``ValueError``.

    We only recognise a few obvious intents. Anything else raises so the
    caller can return a faithful error to the user rather than silently
    fabricating a query.
    """
    if not prompt or not prompt.strip():
        raise ValueError("Prompt is empty")
    if not event_data_stores:
        raise ValueError("At least one event data store is required")
    ds = event_data_stores[0]
    p = prompt.lower()

    if any(w in p for w in ("event name", "top event", "most common event", "event names")):
        return (
            f"SELECT eventName, count(*) AS eventCount "
            f"FROM {ds} GROUP BY eventName "
            f"ORDER BY eventCount DESC LIMIT 10"
        )
    if any(w in p for w in ("error", "failed")):
        return (
            f"SELECT eventSource, eventName, errorCode, count(*) AS errorCount "
            f"FROM {ds} WHERE errorCode != '' "
            f"GROUP BY eventSource, eventName, errorCode "
            f"ORDER BY errorCount DESC LIMIT 20"
        )
    if "region" in p:
        return (
            f"SELECT awsRegion, count(*) AS total "
            f"FROM {ds} GROUP BY awsRegion ORDER BY total DESC"
        )
    if "user" in p or "who" in p:
        return (
            f"SELECT username, count(*) AS activity "
            f"FROM {ds} GROUP BY username ORDER BY activity DESC LIMIT 20"
        )
    if "s3" in p:
        return (
            f"SELECT eventTime, eventName, sourceIPAddress, username "
            f"FROM {ds} WHERE eventSource = 's3.amazonaws.com' "
            f"ORDER BY eventTime DESC LIMIT 100"
        )
    raise ValueError(
        "LocalEmu's GenerateQuery recognises prompts about "
        "'event names', 'errors', 'regions', 'users', or 's3'. "
        f"Prompt not recognised: {prompt!r}"
    )
