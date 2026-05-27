"""Write Athena result CSV + sidecar metadata to S3 at OutputLocation.

AWS writes two objects per query under the caller-supplied
``OutputLocation``:

* ``{exec_id}.csv``          — RFC-4180 CSV, header row, all values quoted
* ``{exec_id}.csv.metadata`` — protobuf with column types

LocalEmu emits the CSV verbatim (matches AWS bit-for-bit for downstream
S3 SELECT, Lambda triggers, etc.). The metadata file is emitted as JSON
with the same field names because the AWS protobuf schema is not
publicly documented; downstream tools that parse the protobuf binary
must call ``GetQueryResults`` instead. This is captured as an open
question in the design doc (§14).
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Iterable
from urllib.parse import urlparse

LOG = logging.getLogger(__name__)


def _parse_s3_location(loc: str) -> tuple[str, str]:
    """Split an ``s3://bucket/prefix/`` URL into (bucket, prefix)."""
    p = urlparse(loc)
    if p.scheme != "s3":
        raise ValueError(f"OutputLocation must be s3://… (got {loc!r})")
    bucket = p.netloc
    prefix = p.path.lstrip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return bucket, prefix


def write_results(
    output_location: str,
    exec_id: str,
    columns: Iterable[tuple[str, str]],
    rows: Iterable[Iterable],
    *,
    account_id: str,
    region: str,
) -> str:
    """Write the result CSV (+ metadata sidecar) to S3.

    Returns the full ``s3://...`` URL of the CSV object so the caller
    can stash it in the ``OutputLocation`` field of the
    ``QueryExecution`` record.
    """
    bucket, prefix = _parse_s3_location(output_location)

    columns = list(columns)
    rows = list(rows)

    csv_key = f"{prefix}{exec_id}.csv"
    meta_key = f"{prefix}{exec_id}.csv.metadata"

    # Build CSV in-memory. AWS quotes every field with `"`; we do the
    # same (``QUOTE_ALL``) so downstream parsers that special-case the
    # AWS shape keep working.
    csv_buf = io.StringIO()
    writer = csv.writer(
        csv_buf, quoting=csv.QUOTE_ALL,
        lineterminator="\n",
    )
    writer.writerow([c[0] for c in columns])
    for r in rows:
        writer.writerow(["" if v is None else str(v) for v in r])

    metadata = {
        "ColumnInfo": [
            {"Name": name, "Type": typ}
            for name, typ in columns
        ],
    }

    try:
        from localemu.aws.connect import connect_to
        from localemu.constants import INTERNAL_AWS_SECRET_ACCESS_KEY

        s3 = connect_to(
            aws_access_key_id=account_id,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
            region_name=region,
        ).s3
    except Exception:
        LOG.debug("Could not get internal S3 client", exc_info=True)
        return ""

    body = csv_buf.getvalue().encode("utf-8")
    try:
        s3.put_object(
            Bucket=bucket, Key=csv_key, Body=body,
            ContentType="text/csv",
        )
        s3.put_object(
            Bucket=bucket, Key=meta_key,
            Body=json.dumps(metadata).encode("utf-8"),
            ContentType="application/json",
        )
    except Exception:
        LOG.warning(
            "Failed to write Athena results to s3://%s/%s",
            bucket, csv_key, exc_info=True,
        )
        return ""

    return f"s3://{bucket}/{csv_key}"
