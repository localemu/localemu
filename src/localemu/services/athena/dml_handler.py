"""Athena CTAS + INSERT INTO via DuckDB ``COPY TO``.

CTAS (``CREATE TABLE … AS SELECT``) materialises the SELECT to S3 and
registers a new Glue table pointing at that prefix. INSERT INTO
appends new files under an existing table's S3 location, optionally
under new partition prefixes.

Both are detected with sqlglot rather than regex — Athena's CTAS
``WITH (...)`` clause is awkward to parse otherwise. Once classified,
the handler builds a DuckDB ``COPY (<select>) TO 's3://...' (FORMAT
PARQUET, PARTITION_BY (dt))`` and runs it; on success, Glue is
updated.

Scope per design-doc §12: Parquet (default Athena CTAS format) and
JSON. ORC / Avro / Iceberg-style tables are out of scope for V1.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional

LOG = logging.getLogger(__name__)


# Statement classification --------------------------------------------------


@dataclass(slots=True)
class CtasPlan:
    target_db: str
    target_table: str
    external_location: str  # s3://bucket/prefix/
    fmt: str                # "parquet" | "json"
    partition_by: list[str] = field(default_factory=list)
    select_sql: str = ""    # the right-hand SELECT


@dataclass(slots=True)
class InsertPlan:
    target_db: str
    target_table: str
    select_sql: str


def classify_dml(
    sql: str, default_db: str,
) -> Optional[CtasPlan] | Optional[InsertPlan]:
    """Return a CtasPlan, InsertPlan, or None.

    None means "this is a SELECT or another statement type — let the
    existing read path handle it".
    """
    try:
        import sqlglot
        import sqlglot.expressions as exp
    except Exception:
        return None

    try:
        parsed = sqlglot.parse_one(sql, read="athena")
    except Exception:
        try:
            # Fallback: try the generic dialect. Athena's CTAS uses Trino syntax;
            # if athena dialect isn't shipped by this sqlglot version, this still
            # parses the surface shape.
            parsed = sqlglot.parse_one(sql)
        except Exception:
            return None

    if isinstance(parsed, exp.Create) and (parsed.kind or "").upper() == "TABLE":
        return _build_ctas(parsed, default_db)
    if isinstance(parsed, exp.Insert):
        return _build_insert(parsed, default_db)
    return None


def _build_ctas(node, default_db: str) -> Optional[CtasPlan]:
    import sqlglot.expressions as exp

    select = node.expression
    if select is None or not isinstance(select, (exp.Select, exp.Subquery, exp.Union)):
        return None
    target = node.this
    if not isinstance(target, (exp.Table, exp.Schema)):
        return None
    table_obj = target if isinstance(target, exp.Table) else target.this
    if not isinstance(table_obj, exp.Table):
        return None
    db = (table_obj.args.get("db") and table_obj.args["db"].name) or default_db or ""
    name = table_obj.name
    props = node.args.get("properties")
    fmt = "parquet"
    external_location = ""
    partition_by: list[str] = []
    if props is not None:
        for p in props.expressions:
            cls = type(p).__name__
            # sqlglot uses dedicated subclasses for the well-known CTAS
            # properties (FileFormatProperty, PartitionedByProperty, …)
            # and a generic ``Property(this=Var(...), value=Literal(...))``
            # for everything else. Dispatch on class name first; fall
            # back to ``name`` for the generic case.
            if cls == "FileFormatProperty":
                fmt = (_literal_or_name(getattr(p, "this", None)) or "parquet").lower()
                continue
            if cls == "PartitionedByProperty":
                partition_by = _extract_string_list_from_node(getattr(p, "this", None))
                continue
            pname = (p.name.lower() if hasattr(p, "name") and p.name else "")
            val = _property_value(p)
            if pname == "external_location":
                external_location = (val or "").strip()
            elif pname == "format" and not fmt:
                fmt = (val or "parquet").lower()
            elif pname == "partitioned_by":
                # Generic-property fallback for older sqlglot dialects
                partition_by = _extract_string_list(p)
    if not external_location:
        return None
    return CtasPlan(
        target_db=db,
        target_table=name,
        external_location=external_location,
        fmt=fmt,
        partition_by=partition_by,
        select_sql=select.sql(),
    )


def _build_insert(node, default_db: str) -> Optional[InsertPlan]:
    import sqlglot.expressions as exp

    target = node.this
    if isinstance(target, exp.Schema):
        target = target.this
    if not isinstance(target, exp.Table):
        return None
    db = (target.args.get("db") and target.args["db"].name) or default_db or ""
    name = target.name
    select = node.args.get("expression")
    if select is None:
        return None
    return InsertPlan(
        target_db=db, target_table=name, select_sql=select.sql(),
    )


def _property_value(prop) -> str:
    """Pull the string/literal value out of a sqlglot Property node."""
    v = getattr(prop, "args", {}).get("value")
    if v is None:
        return ""
    return v.name if hasattr(v, "name") and v.name else str(v.sql())


def _literal_or_name(node) -> str:
    """Best-effort: pull a string out of a sqlglot Literal/Identifier/Var."""
    if node is None:
        return ""
    return node.name if hasattr(node, "name") and node.name else str(node)


def _extract_string_list_from_node(node) -> list[str]:
    """Pull a list of strings out of an ``Array`` / ``Tuple`` literal node."""
    if node is None:
        return []
    import sqlglot.expressions as exp

    out: list[str] = []
    items = getattr(node, "expressions", None) or []
    for item in items:
        s = _literal_or_name(item)
        if s:
            out.append(s.strip().strip("'").strip('"'))
    return out


def _extract_string_list(prop) -> list[str]:
    import sqlglot.expressions as exp

    v = getattr(prop, "args", {}).get("value")
    if v is None:
        return []
    items: list[str] = []
    # Array literal: ARRAY['a','b']
    if isinstance(v, (exp.Array, exp.Tuple)):
        for item in v.expressions:
            n = item.name if hasattr(item, "name") and item.name else str(item)
            items.append(n.strip().strip("'").strip('"'))
    return items


# DML execution -------------------------------------------------------------


def execute_ctas(
    plan: CtasPlan, account_id: str, region: str,
) -> tuple[list[tuple[str, str]], int]:
    """Materialise the SELECT to S3 and register a new Glue table.

    Returns ``(columns, elapsed_ms)`` — there are no rows to return for
    CTAS, but Athena does report the number of rows written via
    Statistics.DataScannedInBytes etc.
    """
    from .engine import _open_duckdb, adapt_dialect
    import time

    started = time.monotonic()
    conn = _open_duckdb()
    try:
        # Resolve table refs in the SELECT (a CTAS can read from Glue tables).
        from .provider import _rewrite_table_refs

        rewritten_select, unresolved = _rewrite_table_refs(
            plan.select_sql, account_id, region, plan.target_db,
        )
        if unresolved:
            raise RuntimeError(
                f"Athena CTAS: source table(s) not found: {', '.join(unresolved)}",
            )

        # Probe the column schema first by running the SELECT bound to a
        # zero-row LIMIT. DuckDB returns description metadata even when
        # no rows match.
        desc_sql = f"SELECT * FROM ({adapt_dialect(rewritten_select)}) WHERE FALSE"
        cur = conn.execute(desc_sql)
        description = cur.description or []
        columns = [(str(d[0]), _duckdb_to_glue_type(d[1])) for d in description]

        # DuckDB COPY TO has different semantics based on partitioning:
        #
        #   * Unpartitioned + trailing-slash path: writes a SINGLE S3
        #     object whose key INCLUDES the trailing slash (e.g.
        #     ``dst/``, 277 bytes). The "directory" then appears empty
        #     to ``read_parquet('dst/**/*.parquet')`` because the object
        #     has no ``.parquet`` extension. Must point TO a specific
        #     filename.
        #   * Partitioned: needs a trailing-slash *prefix*; DuckDB
        #     creates ``<col>=<value>/data_0.parquet`` under it.
        target_loc = plan.external_location.rstrip("/") + "/"
        copy_format = "PARQUET" if plan.fmt.lower() == "parquet" else "JSON"
        ext = "parquet" if copy_format == "PARQUET" else "json"
        if plan.partition_by:
            partition_clause = (
                ", PARTITION_BY (" + ", ".join(plan.partition_by) + ")"
            )
            copy_target = target_loc
        else:
            partition_clause = ""
            copy_target = f"{target_loc}data_{uuid.uuid4().hex[:8]}.{ext}"
        copy_sql = (
            f"COPY ({adapt_dialect(rewritten_select)}) "
            f"TO {copy_target!r} (FORMAT {copy_format}{partition_clause})"
        )
        conn.execute(copy_sql)
        elapsed_ms = int((time.monotonic() - started) * 1000)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Register the new Glue table at external_location.
    _register_glue_table(
        plan.target_db, plan.target_table, target_loc,
        columns, plan.partition_by, plan.fmt, account_id, region,
    )

    return columns, elapsed_ms


def execute_insert(
    plan: InsertPlan, account_id: str, region: str,
) -> tuple[list[tuple[str, str]], int]:
    """Append SELECT results to an existing Glue table's S3 location."""
    from .engine import _open_duckdb, adapt_dialect
    from .glue_resolver import resolve_table
    import time

    target = resolve_table(account_id, region, plan.target_db, plan.target_table)
    if target is None:
        raise RuntimeError(
            f"Athena INSERT INTO: target table {plan.target_db}.{plan.target_table} "
            "does not exist in Glue catalog",
        )
    target_loc = (target.s3_location.rstrip("/") + "/")
    # We write a single new file with a UUID prefix so concurrent INSERTs
    # don't overwrite each other. Real Athena writes
    # ``<region>_<id>_<random>.parquet`` — we follow the same pattern.
    new_file = f"{target_loc}localemu_insert_{uuid.uuid4().hex}.parquet"

    started = time.monotonic()
    conn = _open_duckdb()
    try:
        from .provider import _rewrite_table_refs

        rewritten_select, unresolved = _rewrite_table_refs(
            plan.select_sql, account_id, region, plan.target_db,
        )
        if unresolved:
            raise RuntimeError(
                f"Athena INSERT INTO: source table(s) not found: {', '.join(unresolved)}",
            )
        cur = conn.execute(
            f"SELECT * FROM ({adapt_dialect(rewritten_select)}) WHERE FALSE",
        )
        description = cur.description or []
        columns = [(str(d[0]), _duckdb_to_glue_type(d[1])) for d in description]

        copy_format = "PARQUET" if target.format.lower() == "parquet" else "JSON"
        conn.execute(
            f"COPY ({adapt_dialect(rewritten_select)}) "
            f"TO {new_file!r} (FORMAT {copy_format})",
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return columns, elapsed_ms


def _register_glue_table(
    db: str, table: str, s3_location: str,
    columns: list[tuple[str, str]], partition_by: list[str],
    fmt: str, account_id: str, region: str,
) -> None:
    """Add a new table to moto's Glue backend with the right StorageDescriptor."""
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("glue")[account_id][region]
    except Exception:
        LOG.warning(
            "Athena CTAS: cannot reach Glue backend to register %s.%s",
            db, table,
        )
        return

    # Make sure the database exists; if not, create it (Athena CTAS
    # implicitly assumes the target DB exists, but tests sometimes
    # forget — silent failure here would be worse than auto-creating).
    try:
        backend.get_database(db)
    except Exception:
        try:
            backend.create_database(database_name=db, database_input={"Name": db})
        except Exception:
            LOG.debug("Athena CTAS: failed to auto-create Glue database %s", db, exc_info=True)

    # Filter partition columns out of the regular column list — Glue
    # represents partition keys separately.
    partition_set = set(partition_by)
    cols = [
        {"Name": name, "Type": typ}
        for name, typ in columns if name not in partition_set
    ]
    p_keys = [
        {"Name": name, "Type": typ}
        for name, typ in columns if name in partition_set
    ]

    serde, input_fmt, output_fmt = _format_to_serde(fmt)
    table_input = {
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": {
            "Columns": cols,
            "Location": s3_location,
            "InputFormat": input_fmt,
            "OutputFormat": output_fmt,
            "SerdeInfo": {"SerializationLibrary": serde},
        },
        "PartitionKeys": p_keys,
    }
    try:
        backend.create_table(
            database_name=db, table_name=table, table_input=table_input,
        )
        LOG.info("Athena CTAS: registered Glue table %s.%s at %s", db, table, s3_location)
    except Exception as exc:
        # Table already exists — that's allowed for CTAS IF NOT EXISTS, otherwise
        # Athena would error. For now we treat it as non-fatal: the COPY already
        # wrote the data; the user can recreate the table manually if they care.
        LOG.warning(
            "Athena CTAS: Glue create_table failed for %s.%s (%s) — data was still "
            "written to %s",
            db, table, exc, s3_location,
        )


def _format_to_serde(fmt: str) -> tuple[str, str, str]:
    """Pick the SerDe + Input/Output format for a Glue table input."""
    f = (fmt or "parquet").lower()
    if f == "parquet":
        return (
            "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
            "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
        )
    if f == "json":
        return (
            "org.openx.data.jsonserde.JsonSerDe",
            "org.apache.hadoop.mapred.TextInputFormat",
            "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        )
    # Fallback to TEXTFILE / CSV-ish (matches AWS default when format is unspecified
    # for textfile tables).
    return (
        "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
        "org.apache.hadoop.mapred.TextInputFormat",
        "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
    )


_DUCKDB_TO_GLUE = {
    "BIGINT": "bigint",
    "INTEGER": "int",
    "SMALLINT": "smallint",
    "TINYINT": "tinyint",
    "DOUBLE": "double",
    "REAL": "float",
    "VARCHAR": "string",
    "STRING": "string",
    "BOOLEAN": "boolean",
    "DATE": "date",
    "TIMESTAMP": "timestamp",
    "TIMESTAMPTZ": "timestamp",
    "BLOB": "binary",
    "DECIMAL": "decimal",
}


def _duckdb_to_glue_type(t: object) -> str:
    s = str(t or "VARCHAR").upper()
    return _DUCKDB_TO_GLUE.get(s, s.lower())
