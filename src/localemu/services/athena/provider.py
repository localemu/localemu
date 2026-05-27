"""Athena provider — DuckDB-backed query execution.

Wraps moto's Athena backend for CRUD (catalogs, workgroups, named
queries, data catalogs, prepared statements) and intercepts the three
ops that *actually run a query*:

* ``StartQueryExecution`` — parse, resolve Glue tables, execute on
  DuckDB, write CSV results to S3, register rows in the registry.
* ``GetQueryResults``    — return paginated rows from the registry.
* ``GetQueryExecution``  — return moto's record verbatim; status flips
  to SUCCEEDED/FAILED synchronously after StartQueryExecution finishes.
* ``StopQueryExecution`` — best-effort cancel + state=CANCELLED.

Design background: see LocalEmuResearch/28-athena-query-engine-design.md.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Optional

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service, ServiceLifecycleHook

from .glue_resolver import resolve_table
from .registry import AthenaResultRegistry, ColumnMeta, QueryResult, get_registry

LOG = logging.getLogger(__name__)


_engine_lock = threading.Lock()
_engine_initialised: bool = False
_engine_available: bool = False


def _engine_ready() -> bool:
    """Lazy-import DuckDB. Cache the verdict so we don't keep re-trying."""
    global _engine_initialised, _engine_available
    if _engine_initialised:
        return _engine_available
    with _engine_lock:
        if _engine_initialised:
            return _engine_available
        backend = os.environ.get("ATHENA_BACKEND", "duckdb").strip().lower()
        if backend in ("off", "none", "disabled", "moto"):
            LOG.info(
                "ATHENA_BACKEND=%s — staying with moto fallback (queries will return empty Rows[]).",
                backend,
            )
            _engine_initialised = True
            _engine_available = False
            return False
        try:
            import duckdb  # noqa: F401  — probe import only
            _engine_available = True
            LOG.info("Athena DuckDB engine enabled.")
        except ImportError:
            LOG.info(
                "Athena: DuckDB not installed; queries will return empty results. "
                "Install with: pip install 'localemu[athena]'",
            )
            _engine_available = False
        _engine_initialised = True
        return _engine_available


# ---------------------------------------------------------------------------
# Query rewriting — replace ``db.table`` (or ``"db"."table"``) with the
# DuckDB read-function call returned by glue_resolver.
# ---------------------------------------------------------------------------


_TABLE_REF_RE = re.compile(
    r"""
    (?<![.\w"])           # not preceded by . or word char or quote
    (?:                    # optional database qualifier
       "?(?P<db>[A-Za-z_][\w-]*)"?
       \s*\.\s*
    )?
    "?(?P<table>[A-Za-z_][\w-]*)"?
    """,
    re.VERBOSE,
)


def _rewrite_table_refs(
    sql: str, account_id: str, region: str, default_db: str,
) -> tuple[str, list[str]]:
    """Best-effort rewrite of ``[db.]table`` references after ``FROM``/``JOIN``.

    Returns the rewritten SQL plus a list of any unresolved
    ``db.table`` identifiers — the caller fails the query with a
    Glue-style MetadataException when this list is non-empty.

    Limitations: regex-based, not a full SQL parser. Handles the common
    Athena/Trino shapes
        SELECT … FROM db.tbl
        SELECT … FROM tbl
        SELECT … FROM "db"."tbl"
        SELECT … FROM db.tbl AS t
        JOIN db.tbl ON …
    Subqueries are processed recursively by virtue of operating on the
    whole string. CTEs (``WITH x AS (SELECT …)``) work because the CTE
    name is a local alias and never resolves through Glue.
    """
    unresolved: list[str] = []

    # Find each FROM/JOIN <identifier>[.<identifier>] and rewrite it.
    pattern = re.compile(
        r"""(\bFROM\b|\bJOIN\b)\s+              # keyword
            (?P<id>                              # identifier with optional db
              (?:"[^"]+"|`[^`]+`|[A-Za-z_][\w-]*)
              (?:\s*\.\s*(?:"[^"]+"|`[^`]+`|[A-Za-z_][\w-]*))?
            )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def _strip(name: str) -> str:
        n = name.strip()
        if (n.startswith('"') and n.endswith('"')) or (n.startswith("`") and n.endswith("`")):
            return n[1:-1]
        return n

    out_parts: list[str] = []
    last = 0
    for m in pattern.finditer(sql):
        keyword = m.group(1)
        ident = m.group("id")
        if "." in ident:
            db_raw, tbl_raw = ident.split(".", 1)
            db = _strip(db_raw)
            tbl = _strip(tbl_raw)
        else:
            db = default_db
            tbl = _strip(ident)

        if not db:
            # No default database and unqualified identifier — fall through.
            out_parts.append(sql[last:m.end()])
            last = m.end()
            continue

        resolved = resolve_table(account_id, region, db, tbl)
        if resolved is None:
            unresolved.append(f"{db}.{tbl}")
            # Leave the original text in place so DuckDB raises a sensible error
            out_parts.append(sql[last:m.end()])
            last = m.end()
            continue

        out_parts.append(sql[last:m.start()])
        out_parts.append(f"{keyword} {resolved.duckdb_read_call()}")
        last = m.end()

    out_parts.append(sql[last:])
    return "".join(out_parts), unresolved


# ---------------------------------------------------------------------------
# Op handlers
# ---------------------------------------------------------------------------


def _handle_start_query_execution(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """Run the query synchronously and store rows for GetQueryResults."""
    result = call_moto(context)
    exec_id = result.get("QueryExecutionId")
    if not exec_id:
        return result

    if not _engine_ready():
        return result  # moto path returns empty rows — documented

    try:
        from .engine import execute
        from .result_writer import write_results

        # Read moto's stored Execution to grab the rewritten query +
        # mutated OutputLocation.
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("athena")[context.account_id][context.region]
        execution = backend.executions.get(exec_id)
        if execution is None:
            return result

        query = execution.query or ""
        default_db = (
            (execution.context or {}).get("Database", "") if isinstance(execution.context, dict) else ""
        )
        cfg = execution.config or {}
        # moto appends "/{exec_id}.csv" to OutputLocation at StartQueryExecution
        # time (models.py:131-134); strip it to get the parent prefix back
        # for write_results.
        raw_output = cfg.get("OutputLocation", "") or ""
        if raw_output.endswith(f"{exec_id}.csv"):
            parent_output = raw_output[: -len(f"{exec_id}.csv")]
        else:
            parent_output = raw_output
        if parent_output and not parent_output.endswith("/"):
            parent_output += "/"

        # Phase-4 DML: CTAS and INSERT INTO. Classify the statement
        # with sqlglot; on a hit, run the dedicated handler. Otherwise
        # fall through to the existing read path.
        from .dml_handler import (
            CtasPlan, InsertPlan, classify_dml, execute_ctas, execute_insert,
        )

        plan = classify_dml(query, default_db)
        if isinstance(plan, CtasPlan):
            try:
                columns, elapsed_ms = execute_ctas(
                    plan, context.account_id, context.region,
                )
            except Exception as exc:
                LOG.info("Athena CTAS failed exec=%s err=%s", exec_id, exc)
                _set_failed(execution, exec_id, f"Athena: CTAS failed — {exc}")
                return result
            col_meta = [
                ColumnMeta(name=name, type=typ, case_sensitive=False)
                for name, typ in columns
            ]
            get_registry().put(QueryResult(
                exec_id=exec_id, columns=col_meta, rows=[],
                output_location=raw_output, execution_time_ms=elapsed_ms,
            ))
            try:
                execution.status = "SUCCEEDED"
                execution.end_time = execution.start_time + (elapsed_ms / 1000.0)
            except Exception:
                pass
            return result
        if isinstance(plan, InsertPlan):
            try:
                columns, elapsed_ms = execute_insert(
                    plan, context.account_id, context.region,
                )
            except Exception as exc:
                LOG.info("Athena INSERT INTO failed exec=%s err=%s", exec_id, exc)
                _set_failed(execution, exec_id, f"Athena: INSERT INTO failed — {exc}")
                return result
            col_meta = [
                ColumnMeta(name=name, type=typ, case_sensitive=False)
                for name, typ in columns
            ]
            get_registry().put(QueryResult(
                exec_id=exec_id, columns=col_meta, rows=[],
                output_location=raw_output, execution_time_ms=elapsed_ms,
            ))
            try:
                execution.status = "SUCCEEDED"
                execution.end_time = execution.start_time + (elapsed_ms / 1000.0)
            except Exception:
                pass
            return result

        # Rewrite table refs via Glue
        rewritten, unresolved = _rewrite_table_refs(
            query, context.account_id, context.region, default_db,
        )
        if unresolved:
            _set_failed(
                execution, exec_id,
                f"Athena: table(s) not found in Glue catalog: {', '.join(unresolved)}",
            )
            return result

        try:
            columns, rows, elapsed_ms = execute(rewritten)
        except Exception as exc:
            LOG.info(
                "Athena query failed exec=%s rewritten=%r err=%s",
                exec_id, rewritten, exc,
            )
            _set_failed(execution, exec_id, f"Athena: query failed — {exc}")
            return result

        col_meta = [
            ColumnMeta(name=name, type=typ, case_sensitive=False)
            for name, typ in columns
        ]
        # Stash a copy in the in-memory registry for GetQueryResults
        get_registry().put(QueryResult(
            exec_id=exec_id,
            columns=col_meta,
            rows=rows,
            output_location=raw_output,
            execution_time_ms=elapsed_ms,
        ))

        # Write CSV + metadata sidecar to S3 (best-effort; non-fatal).
        if parent_output:
            try:
                write_results(
                    parent_output, exec_id, columns, rows,
                    account_id=context.account_id, region=context.region,
                )
            except Exception:
                LOG.debug("Athena result S3 write failed", exc_info=True)

        # Flip moto's state to SUCCEEDED so DescribeExecution polls don't
        # hang in QUEUED forever (moto's polling-based ManagedState
        # eventually advances, but we already have the answer).
        try:
            execution.status = "SUCCEEDED"
            execution.end_time = execution.start_time + (elapsed_ms / 1000.0)
        except Exception:
            pass
    except Exception:
        LOG.warning("Athena StartQueryExecution post-processing failed", exc_info=True)
    return result


def _set_failed(execution, exec_id: str, reason: str) -> None:
    """Mark moto's Execution as FAILED with a ``StateChangeReason``."""
    try:
        execution.status = "FAILED"
        execution.state_change_reason = reason  # consumed by moto's response
    except Exception:
        pass
    # Register an empty result so GetQueryResults returns the canonical empty shape.
    get_registry().put(QueryResult(
        exec_id=exec_id, columns=[], rows=[], error=reason,
    ))


def _handle_get_query_results(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """Return rows from the in-memory registry (paginated)."""
    exec_id = request.get("QueryExecutionId") or ""
    result = get_registry().get(exec_id)
    if result is None:
        # Cache miss. Two scenarios:
        #   * The engine never produced results for this exec_id (engine
        #     was off, query failed pre-execution, unknown id). Fall through
        #     to moto so the caller sees the canonical empty shape.
        #   * The result is still in S3 from a prior LocalEmu run but our
        #     in-memory registry was cleared by ``on_before_state_load`` /
        #     ``on_before_state_reset``. Try a lazy rehydrate from
        #     ``OutputLocation/{exec_id}.csv`` (+ ``.metadata`` sidecar).
        try:
            import moto.backends as moto_backends

            backend = moto_backends.get_backend("athena")[context.account_id][context.region]
            execution = backend.executions.get(exec_id)
            output_csv = (
                (execution.config or {}).get("OutputLocation", "")
                if execution is not None else ""
            )
        except Exception:
            output_csv = ""

        if output_csv:
            from .result_reader import rehydrate

            rehydrated = rehydrate(
                exec_id, output_csv,
                account_id=context.account_id, region=context.region,
            )
            if rehydrated is not None:
                get_registry().put(rehydrated)
                result = rehydrated

    if result is None:
        return call_moto(context)

    # AWS pagination contract: row 0 = header, then up to MaxResults-1 data rows.
    max_results = int(request.get("MaxResults") or 1000)
    if max_results < 1:
        max_results = 1000
    if max_results > 1000:
        max_results = 1000

    next_token = request.get("NextToken") or ""
    try:
        start = int(next_token) if next_token else 0
    except ValueError:
        start = 0

    rows_payload: list[dict] = []
    if start == 0:
        # Header row (column names)
        rows_payload.append({
            "Data": [{"VarCharValue": c.name} for c in result.columns],
        })
        max_results -= 1
    end = min(start + max_results, len(result.rows))
    for r in result.rows[start:end]:
        rows_payload.append({
            "Data": [
                {} if v is None else {"VarCharValue": str(v)}
                for v in r
            ],
        })

    new_next_token = str(end) if end < len(result.rows) else None
    column_info = [
        {
            "CatalogName": "hive",
            "SchemaName": "",
            "TableName": "",
            "Name": c.name,
            "Label": c.name,
            "Type": c.type,
            "Precision": c.precision,
            "Scale": c.scale,
            "Nullable": c.nullable,
            "CaseSensitive": c.case_sensitive,
        }
        for c in result.columns
    ]
    response = {
        "ResultSet": {
            "Rows": rows_payload,
            "ResultSetMetadata": {"ColumnInfo": column_info},
        },
        "UpdateCount": 0,
    }
    if new_next_token:
        response["NextToken"] = new_next_token
    return response


def _handle_get_query_execution(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """Pass through to moto and inject StateChangeReason from our registry.

    Moto's GetQueryExecution response Status block only includes
    ``State``, ``SubmissionDateTime``, ``CompletionDateTime`` — it does
    not echo back any reason string. Real AWS returns
    ``Status.StateChangeReason`` on FAILED queries so users can see
    *why*. Pull it from the registry and splice it in.
    """
    result = call_moto(context)
    exec_id = request.get("QueryExecutionId") or ""
    cached = get_registry().get(exec_id)
    if cached and cached.error:
        try:
            result["QueryExecution"]["Status"]["StateChangeReason"] = cached.error
        except Exception:
            pass
    if cached and cached.execution_time_ms:
        try:
            result["QueryExecution"]["Statistics"]["EngineExecutionTimeInMillis"] = cached.execution_time_ms
            result["QueryExecution"]["Statistics"]["TotalExecutionTimeInMillis"] = cached.execution_time_ms
        except Exception:
            pass
    return result


def _handle_stop_query_execution(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    exec_id = request.get("QueryExecutionId") or ""
    # Best-effort: we run queries synchronously, so by the time the
    # caller sends Stop the work is already done. Still mark CANCELLED
    # if we haven't recorded a terminal state.
    try:
        import moto.backends as moto_backends

        backend = moto_backends.get_backend("athena")[context.account_id][context.region]
        execution = backend.executions.get(exec_id)
        if execution is not None and getattr(execution, "status", "") not in {
            "SUCCEEDED", "FAILED", "CANCELLED",
        }:
            execution.status = "CANCELLED"
    except Exception:
        pass
    return call_moto(context)


# ---------------------------------------------------------------------------
# Dispatch table + Service factory
# ---------------------------------------------------------------------------


def _handle_list_tags_for_resource(
    context: RequestContext, request: ServiceRequest,
) -> ServiceResponse:
    """Distinguish "resource has no tags" from "resource does not exist".

    Moto's responses.py::list_tags_for_resource short-circuits to
    ``Athena Resource <arn> Does Not Exist`` whenever the tagger returns
    a falsy value — which is the *normal* state for a freshly created
    workgroup that has no tags yet. Terraform's aws_athena_workgroup
    read step calls ListTagsForResource immediately after CreateWorkGroup
    and fails the whole apply on this 400.

    Resolve by classifying the resource ourselves: if the workgroup /
    data-catalog / capacity-reservation exists in the moto backend,
    return ``{"Tags": [...]}`` (empty list when untagged); otherwise
    surface the upstream "Does Not Exist" error.
    """
    import moto.backends as moto_backends

    resource_arn = request.get("ResourceARN") or ""
    backend = moto_backends.get_backend("athena")[context.account_id][context.region]

    # Pull the {resource_name} from "arn:aws:athena:{region}:{account}:{resource}".
    try:
        resource_path = resource_arn.split(":", 5)[5]
    except IndexError:
        resource_path = ""

    exists = False
    if resource_path.startswith("workgroup/"):
        exists = resource_path.removeprefix("workgroup/") in backend.work_groups
    elif resource_path.startswith("datacatalog/"):
        exists = resource_path.removeprefix("datacatalog/") in backend.data_catalogs
    elif resource_path.startswith("capacityreservation/"):
        exists = resource_path.removeprefix("capacityreservation/") in getattr(
            backend, "capacity_reservations", {},
        )

    if not exists:
        from localemu.aws.api import CommonServiceException

        raise CommonServiceException(
            code="InvalidRequestException",
            message=f"Athena Resource, {resource_arn} Does Not Exist",
            status_code=400,
            sender_fault=True,
        )

    # Resource exists — pull whatever tags the tagger has, default to [].
    tags = backend.list_tags_for_resource(resource_arn) or {}
    return {"Tags": tags.get("Tags", []) if isinstance(tags, dict) else []}


_INTERCEPTED_OPS = {
    "StartQueryExecution": _handle_start_query_execution,
    "GetQueryResults": _handle_get_query_results,
    "GetQueryExecution": _handle_get_query_execution,
    "StopQueryExecution": _handle_stop_query_execution,
    "ListTagsForResource": _handle_list_tags_for_resource,
}


def AthenaDispatcher(service_model) -> DispatchTable:
    table = {}
    for op in service_model.operation_names:
        table[op] = _INTERCEPTED_OPS.get(op, _proxy_moto)
    return table


class AthenaLifecycle(ServiceLifecycleHook):
    """Clear the result registry on state reset / load."""

    def on_before_state_reset(self) -> None:
        get_registry().reset()

    def on_before_state_load(self) -> None:
        get_registry().reset()


def create_athena_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("athena")
    dispatch_table = AthenaDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(
        name="athena", skeleton=skeleton, lifecycle_hook=AthenaLifecycle(),
    )
