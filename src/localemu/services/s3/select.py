"""S3 Select query evaluation over parsed CSV/JSON records, backed by DuckDB.

The S3 provider parses an object into a list of row dicts (CSV rows become
``{"_1": ..., "_2": ...}`` without a header or ``{col: ...}`` with one; JSON
records keep their fields). This module loads those rows into an in-memory
DuckDB table named ``s3object`` and runs the S3 Select expression against it,
so WHERE filters, column projection and aggregates (COUNT/SUM/...) actually
take effect.

DuckDB is already a runtime dependency (the Athena engine uses it). If it is
unavailable, or the expression cannot be executed, we fall back to returning
all rows so a Select request never fails outright.
"""

from __future__ import annotations

import logging
import re

LOG = logging.getLogger(__name__)

# S3 Select allows ``FROM S3Object[*]`` (flatten a top-level JSON array). DuckDB
# has no such syntax; the provider already flattens arrays into rows, so the
# ``[*]`` is redundant and we strip it.
_ARRAY_SUFFIX = re.compile(r"(s3object)\s*\[\s*\*\s*\]", re.IGNORECASE)


def _normalize(expression: str) -> str:
    return _ARRAY_SUFFIX.sub(r"\1", expression)


def _infer_type(col: str, records: list[dict]) -> str:
    """Pick a DuckDB column type. CSV values are strings (VARCHAR, with the
    user CASTing as S3 Select requires); JSON keeps real numeric/bool types so
    ``WHERE s.age > 30`` works without a CAST."""
    vals = [r.get(col) for r in records if r.get(col) is not None]
    if not vals:
        return "VARCHAR"
    if all(isinstance(v, bool) for v in vals):
        return "BOOLEAN"
    if all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return "BIGINT"
    if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "DOUBLE"
    return "VARCHAR"


def evaluate_s3_select(records: list[dict], expression: str) -> list[dict]:
    """Run an S3 Select SQL expression over the parsed records.

    Returns the result rows as dicts (column name -> value). Falls back to the
    full record set if DuckDB is unavailable or the query fails.
    """
    if not records:
        return []

    try:
        import duckdb
    except Exception:
        LOG.debug("duckdb unavailable; S3 Select returns all rows")
        return records

    # Ordered union of column names across all rows.
    cols: list[str] = []
    seen: set[str] = set()
    for record in records:
        for key in record:
            if key not in seen:
                seen.add(key)
                cols.append(key)

    conn = None
    try:
        conn = duckdb.connect(":memory:")
        col_defs = ", ".join(f'"{c}" {_infer_type(c, records)}' for c in cols)
        conn.execute(f"CREATE TABLE s3object ({col_defs})")
        placeholders = ", ".join("?" for _ in cols)
        conn.executemany(
            f"INSERT INTO s3object VALUES ({placeholders})",
            [[record.get(c) for c in cols] for record in records],
        )
        cursor = conn.execute(_normalize(expression))
        out_cols = [d[0] for d in cursor.description]
        return [dict(zip(out_cols, row)) for row in cursor.fetchall()]
    except Exception as exc:
        LOG.warning("S3 Select query failed (%s); returning all rows", exc)
        return records
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
