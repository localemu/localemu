"""Rehydrate a QueryResult from the CSV + metadata that result_writer
emitted to S3.

Used by ``GetQueryResults`` after a LocalEmu restart: the in-memory
registry was cleared by the lifecycle hook, but the result CSV still
lives at ``OutputLocation/{exec_id}.csv`` (because S3 is persisted by
the regular state visitor). Pull both objects, parse, and repopulate
the registry so the call returns real data instead of empty Rows[].

The moto Execution record carries the OutputLocation in
``execution.config["OutputLocation"]`` (and moto has already appended
``/{exec_id}.csv`` to it — strip that to find the parent prefix).
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Optional
from urllib.parse import urlparse

from .registry import ColumnMeta, QueryResult

LOG = logging.getLogger(__name__)


def _split_s3_url(url: str) -> tuple[str, str]:
    p = urlparse(url)
    return p.netloc, p.path.lstrip("/")


def rehydrate(
    exec_id: str, output_location_csv: str,
    *, account_id: str, region: str,
) -> Optional[QueryResult]:
    """Try to read back the result files and build a QueryResult.

    Returns ``None`` when the S3 objects are missing or unparseable — the
    caller then falls back to the canonical empty response.
    """
    if not output_location_csv:
        return None
    try:
        from localemu.aws.connect import connect_to
        from localemu.constants import INTERNAL_AWS_SECRET_ACCESS_KEY

        s3 = connect_to(
            aws_access_key_id=account_id,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            region_name=region,
        ).s3
    except Exception:
        LOG.debug("Athena rehydrate: cannot get internal S3 client", exc_info=True)
        return None

    bucket, csv_key = _split_s3_url(output_location_csv)
    if not bucket or not csv_key:
        return None
    meta_key = csv_key + ".metadata"

    try:
        csv_obj = s3.get_object(Bucket=bucket, Key=csv_key)
        csv_bytes = csv_obj["Body"].read()
    except Exception:
        return None

    columns: list[ColumnMeta] = []
    try:
        meta_obj = s3.get_object(Bucket=bucket, Key=meta_key)
        meta = json.loads(meta_obj["Body"].read())
        for c in meta.get("ColumnInfo") or []:
            columns.append(ColumnMeta(name=c.get("Name", ""), type=c.get("Type", "varchar")))
    except Exception:
        # No metadata sidecar — fall back to CSV header names only.
        LOG.debug(
            "Athena rehydrate: no metadata sidecar at s3://%s/%s; column types default to varchar",
            bucket, meta_key,
        )

    try:
        text = csv_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    rows_iter = iter(reader)
    try:
        header = next(rows_iter)
    except StopIteration:
        return None

    if not columns:
        columns = [ColumnMeta(name=n, type="varchar") for n in header]
    elif len(columns) != len(header):
        # Defensive: prefer the header names if they diverge from the sidecar.
        columns = [
            ColumnMeta(
                name=header[i] if i < len(header) else (columns[i].name if i < len(columns) else f"col{i}"),
                type=columns[i].type if i < len(columns) else "varchar",
            )
            for i in range(max(len(header), len(columns)))
        ]

    rows = [list(r) for r in rows_iter]

    return QueryResult(
        exec_id=exec_id, columns=columns, rows=rows,
        output_location=output_location_csv,
    )
