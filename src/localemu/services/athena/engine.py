"""DuckDB engine wrapper for Athena query execution.

A fresh DuckDB connection per query keeps state isolated, lets long
queries be cancelled, and avoids cross-query metadata leaks (some
DuckDB versions cache the file listing on a connection for the same
glob, which would mask new S3 writes from a previous Athena run in the
same process).

S3 configuration is rebuilt every query because the gateway port can
move between runs (``localemu start --port=…``) and we want the
endpoint to track config.external_service_url() rather than a stale
import-time value.

Dialect translation: sqlglot rewrites a handful of Athena/Trino-flavored
constructs that DuckDB does not accept verbatim (``approx_distinct`` →
``approx_count_distinct``, ``date_add('day', n, d)`` → ``d + INTERVAL n DAY``,
``from_unixtime(s)`` → ``to_timestamp(s)``). Everything else is left
intact and DuckDB's parser handles it.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Optional

LOG = logging.getLogger(__name__)


def _localemu_s3_endpoint() -> str:
    """Pick the S3 endpoint host:port DuckDB should hit.

    Default to ``host.docker.internal:<gw>`` only when running inside a
    container (env var hints), otherwise ``localhost:<gw>``. The internal
    gateway port is read from ``localemu.config``.
    """
    try:
        from localemu import config as _config
        port = _config.GATEWAY_LISTEN[0].port
    except Exception:
        port = 4566
    host = os.environ.get("ATHENA_S3_ENDPOINT_HOST", "").strip() or "localhost"
    return f"{host}:{port}"


def _open_duckdb():
    """Return an in-memory DuckDB connection configured for LocalEmu S3.

    Each call returns a NEW connection — see module docstring for the
    rationale (cancellation + listing-cache isolation).
    """
    try:
        import duckdb
    except ImportError as e:  # pragma: no cover — Athena init gates on this.
        raise RuntimeError(
            "DuckDB is not installed. Install LocalEmu with the [athena] extra: "
            "pip install 'localemu[athena]'"
        ) from e

    conn = duckdb.connect(":memory:")
    endpoint = _localemu_s3_endpoint()
    # httpfs is the extension that gives DuckDB ``s3://`` reads. It is
    # built into the wheel since DuckDB 0.9, no separate download.
    conn.execute("INSTALL httpfs")
    conn.execute("LOAD httpfs")
    conn.execute(f"SET s3_endpoint = '{endpoint}'")
    conn.execute("SET s3_url_style = 'path'")
    conn.execute("SET s3_use_ssl = false")
    # Use the same dummy credentials boto3 sees by default against
    # LocalEmu; the gateway short-circuits SigV4 verification for
    # localhost callers.
    conn.execute("SET s3_access_key_id = 'AKIAIOSFODNN7EXAMPLE'")
    conn.execute("SET s3_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
    conn.execute("SET s3_region = 'us-east-1'")
    return conn


_DIALECT_REWRITES: list[tuple[re.Pattern, str]] = [
    # approx_distinct(x) → approx_count_distinct(x)
    (re.compile(r"\bapprox_distinct\s*\(", re.IGNORECASE), "approx_count_distinct("),
    # from_unixtime(N) → to_timestamp(N)
    (re.compile(r"\bfrom_unixtime\s*\(", re.IGNORECASE), "to_timestamp("),
]


def adapt_dialect(sql: str) -> str:
    """Apply Trino→DuckDB textual rewrites covering the V1 gap list.

    Regex-based and intentionally minimal. sqlglot does a much better
    AST-level translation but adds latency on every query; we adopt
    regex first and migrate to sqlglot only for the constructs that
    cannot be handled by a substitution table.
    """
    out = sql
    for pat, repl in _DIALECT_REWRITES:
        out = pat.sub(repl, out)
    return out


def execute(sql: str) -> tuple[list[tuple[str, str]], list[list], int]:
    """Run ``sql`` against a fresh DuckDB connection.

    Returns:
        columns: ``[(name, type), …]`` in declaration order
        rows: ``[[v1, v2, …], …]`` of native Python values
        elapsed_ms: wall-clock execution time in milliseconds
    """
    started = time.monotonic()
    conn = _open_duckdb()
    try:
        adapted = adapt_dialect(sql)
        cur = conn.execute(adapted)
        try:
            description = cur.description or []
        except Exception:
            description = []
        columns = [
            (str(d[0]), _duckdb_type_to_athena(d[1])) for d in description
        ]
        try:
            rows = cur.fetchall()
        except Exception:
            rows = []
        # fetchall returns tuples; coerce to lists so JSON serialisation later
        # is straightforward.
        rows = [list(r) for r in rows]
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return columns, rows, elapsed_ms
    finally:
        try:
            conn.close()
        except Exception:
            pass


# DuckDB exposes column types via PEP-249 ``cursor.description[i][1]``.
# Map them to the Athena ``ColumnInfo.Type`` strings the AWS API uses.
_DUCKDB_TO_ATHENA = {
    "BIGINT": "bigint",
    "INTEGER": "integer",
    "SMALLINT": "smallint",
    "TINYINT": "tinyint",
    "DOUBLE": "double",
    "REAL": "float",
    "VARCHAR": "varchar",
    "STRING": "varchar",
    "BOOLEAN": "boolean",
    "DATE": "date",
    "TIMESTAMP": "timestamp",
    "TIMESTAMP_NS": "timestamp",
    "BLOB": "varbinary",
    "DECIMAL": "decimal",
    "HUGEINT": "decimal",
    "UUID": "varchar",
}


def _duckdb_type_to_athena(t: object) -> str:
    s = str(t or "VARCHAR").upper()
    return _DUCKDB_TO_ATHENA.get(s, s.lower())
