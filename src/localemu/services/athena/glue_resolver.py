"""Glue Data Catalog → DuckDB reader translator.

Resolves ``database.table`` identifiers used in Athena SQL into the
DuckDB read-function call that scans the right S3 location with the
right format options. The mapping is driven entirely by Glue's
``StorageDescriptor.SerdeInfo.SerializationLibrary`` field, exactly like
real Athena.

Returns ``None`` if the table is unknown — the caller should turn that
into a ``MetadataException``-shaped FAILED query state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

LOG = logging.getLogger(__name__)


# SerDe class → reader name + per-format extra options. The reader names
# are DuckDB's table functions (``read_csv_auto``, ``read_parquet``,
# ``read_json``, ``read_orc``).
SERDE_MAP: dict[str, str] = {
    "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe": "csv",
    "org.apache.hadoop.hive.serde2.OpenCSVSerde": "csv",
    "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe": "parquet",
    "org.openx.data.jsonserde.JsonSerDe": "json",
    "org.apache.hive.hcatalog.data.JsonSerDe": "json",
    "org.apache.hadoop.hive.ql.io.orc.OrcSerde": "orc",
}


@dataclass(slots=True)
class ResolvedTable:
    database: str
    name: str
    s3_location: str        # e.g. "s3://my-bucket/dir/" (always trailing-slash terminated when from Glue)
    format: str             # "csv" | "parquet" | "json" | "orc"
    options: dict           # extras for the DuckDB reader (delim, quote, hive_partitioning)
    columns: list[tuple]    # [(name, type), ...]
    partition_keys: list[tuple]  # [(name, type), ...]

    def duckdb_read_call(self) -> str:
        """Build the DuckDB table-function call that scans this table."""
        loc = self.s3_location.rstrip("/")
        if self.format == "parquet":
            glob = f"{loc}/**/*.parquet" if not loc.endswith(".parquet") else loc
            args = [repr(glob)]
            if self.partition_keys:
                args.append("hive_partitioning = 1")
            return f"read_parquet({', '.join(args)})"
        if self.format == "csv":
            glob = f"{loc}/**/*"
            args = [repr(glob)]
            delim = self.options.get("field.delim") or self.options.get("separatorChar") or ","
            args.append(f"delim = {delim!r}")
            quote = self.options.get("quoteChar")
            if quote:
                args.append(f"quote = {quote!r}")
            args.append("header = TRUE")
            return f"read_csv_auto({', '.join(args)})"
        if self.format == "json":
            glob = f"{loc}/**/*.json"
            return f"read_json_auto({glob!r}, format = 'auto')"
        if self.format == "orc":
            glob = f"{loc}/**/*"
            return f"read_orc({glob!r})"
        raise ValueError(f"unsupported format: {self.format!r}")


def resolve_table(account_id: str, region: str, db: str, table: str) -> Optional[ResolvedTable]:
    """Look up a Glue table from moto's backend, normalise to ResolvedTable.

    Returns ``None`` when the table or database is unknown.
    """
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("glue")[account_id][region]
    except Exception:
        LOG.debug("Glue backend not reachable", exc_info=True)
        return None

    try:
        # backend.get_table(db, table) raises TableNotFoundException if missing
        t = backend.get_table(db, table)
    except Exception:
        return None

    table_input = getattr(t, "as_dict", None) and t.as_dict() or {}
    storage = table_input.get("StorageDescriptor") or {}
    location = storage.get("Location") or ""
    serde_info = storage.get("SerdeInfo") or {}
    serde = serde_info.get("SerializationLibrary") or ""

    fmt = SERDE_MAP.get(serde)
    if not fmt:
        # Fall back to a CSV reader for unknown SerDes — this matches AWS's
        # "Athena guesses textfile is CSV" behaviour for older tables.
        LOG.info(
            "Unknown SerDe %r for %s.%s; defaulting to CSV reader", serde, db, table,
        )
        fmt = "csv"

    parameters = serde_info.get("Parameters") or {}
    cols = [
        (c.get("Name", ""), c.get("Type", "varchar"))
        for c in (storage.get("Columns") or [])
    ]
    partition_keys = [
        (c.get("Name", ""), c.get("Type", "varchar"))
        for c in (table_input.get("PartitionKeys") or [])
    ]

    return ResolvedTable(
        database=db,
        name=table,
        s3_location=location,
        format=fmt,
        options=dict(parameters),
        columns=cols,
        partition_keys=partition_keys,
    )
