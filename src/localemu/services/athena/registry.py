"""Process-wide registry of Athena query results.

Holds the rows + column metadata that ``GetQueryResults`` will return,
keyed by the moto-assigned ``QueryExecutionId``. Survives across the
gateway thread that handled ``StartQueryExecution`` and the (possibly
different) thread that later serves ``GetQueryResults``.

Persistence: the underlying CSV result file lives in S3 at
``OutputLocation/{exec_id}.csv``; the registry is in-memory only and is
rebuilt lazily from S3 if a process restart loses the cache (see
``AthenaResultRegistry.get_or_load``).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class ColumnMeta:
    name: str
    type: str  # Athena-style: "integer" | "varchar" | "double" | ...
    nullable: str = "UNKNOWN"
    precision: int = 0
    scale: int = 0
    case_sensitive: bool = False


@dataclass(slots=True)
class QueryResult:
    exec_id: str
    columns: list[ColumnMeta]
    # Rows as native Python values; serialised to strings only when the
    # ``GetQueryResults`` wire response is built.
    rows: list[list]
    output_location: str = ""
    error: Optional[str] = None
    data_scanned_bytes: int = 0
    execution_time_ms: int = 0


class AthenaResultRegistry:
    def __init__(self) -> None:
        self._results: dict[str, QueryResult] = {}
        self._lock = threading.Lock()

    def put(self, result: QueryResult) -> None:
        with self._lock:
            self._results[result.exec_id] = result

    def get(self, exec_id: str) -> Optional[QueryResult]:
        with self._lock:
            return self._results.get(exec_id)

    def remove(self, exec_id: str) -> None:
        with self._lock:
            self._results.pop(exec_id, None)

    def reset(self) -> None:
        with self._lock:
            self._results.clear()


_registry: Optional[AthenaResultRegistry] = None
_registry_lock = threading.Lock()


def get_registry() -> AthenaResultRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = AthenaResultRegistry()
    return _registry
