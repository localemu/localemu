"""Unit tests for S3 Select query evaluation (DuckDB-backed)."""

from __future__ import annotations

from localemu.services.s3.select import evaluate_s3_select

CSV_ROWS = [
    {"_1": "alice", "_2": "30"},
    {"_1": "bob", "_2": "20"},
    {"_1": "carol", "_2": "40"},
]
JSON_ROWS = [
    {"name": "alice", "age": 30, "admin": True},
    {"name": "bob", "age": 20, "admin": False},
]


def test_where_filters_csv_positional():
    out = evaluate_s3_select(
        CSV_ROWS, "SELECT s._1 FROM s3object s WHERE CAST(s._2 AS INTEGER) > 25"
    )
    names = sorted(r["_1"] for r in out)
    assert names == ["alice", "carol"]


def test_projection_only_selected_columns():
    out = evaluate_s3_select(CSV_ROWS, "SELECT s._1 FROM s3object s")
    assert all(set(r.keys()) == {"_1"} for r in out)
    assert len(out) == 3


def test_select_star_returns_all_columns():
    out = evaluate_s3_select(CSV_ROWS, "SELECT * FROM s3object")
    assert len(out) == 3
    assert set(out[0].keys()) == {"_1", "_2"}


def test_count_star():
    out = evaluate_s3_select(CSV_ROWS, "SELECT COUNT(*) FROM s3object")
    assert len(out) == 1
    assert list(out[0].values())[0] == 3


def test_json_typed_where_without_cast():
    out = evaluate_s3_select(
        JSON_ROWS, "SELECT s.name FROM s3object s WHERE s.age > 25"
    )
    assert [r["name"] for r in out] == ["alice"]


def test_json_boolean_filter():
    out = evaluate_s3_select(
        JSON_ROWS, "SELECT s.name FROM s3object s WHERE s.admin = true"
    )
    assert [r["name"] for r in out] == ["alice"]


def test_array_flatten_suffix_is_stripped():
    # S3 Select FROM S3Object[*] s -> DuckDB has no [*]; must still work.
    out = evaluate_s3_select(JSON_ROWS, "SELECT s.name FROM S3Object[*] s WHERE s.age < 25")
    assert [r["name"] for r in out] == ["bob"]


def test_empty_records():
    assert evaluate_s3_select([], "SELECT * FROM s3object") == []


def test_malformed_query_falls_back_to_all_rows():
    # An unrunnable expression must not raise; it returns all rows.
    out = evaluate_s3_select(CSV_ROWS, "SELECT bogus_fn(zzz) FROM not_a_table")
    assert out == CSV_ROWS
