"""Failing test for the drill-framework ``keyOf(row)`` helper.

The bug
-------
``_framework.js`` looks up a drill row's identifier as::

    row.name || row.key || row.id || ""

This works for most resources (an SQS queue has ``name``, an IAM role
has ``name``, an S3 bucket has ``name``), but breaks for resources
whose identifier lives under a different field:

  * EC2 instance  -> instance_id
  * Lambda fn     -> function_name
  * KMS key       -> key_id
  * RDS instance  -> db_instance_identifier
  * IAM role/user -> arn (when name is missing)

When the lookup returns ``""``, two things go wrong:

  1. Tab-click navigation calls ``navigate({resource: ""})``.
     ``navigate`` normalizes ``""`` to ``null``, the short-circuit
     check fails (prev.resource was the real instance id), and the
     framework bounces the user back to the SERVICE LIST instead of
     staying on the drill page.

  2. The destructive-action confirm compares the user's typed input
     against ``""``. Whatever they type is rejected with
     "Cancelled: name did not match" and the action never runs.

The fix
-------
Expose ``DASH.drills.framework.keyOf(row, spec)`` that chains through
every common identifier field. Tab-click navigation and
destructive-confirm both call it. The prompt also calls ``spec.title``
to show the user WHAT to type.

This test loads ``_framework.js`` into a stubbed-DOM Node sandbox and
asserts ``keyOf`` produces non-empty identifiers for every common AWS
resource shape.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

FRAMEWORK_JS = (
    Path(__file__).resolve().parents[3]
    / "src" / "localemu" / "dashboard" / "static" / "js"
    / "drills" / "_framework.js"
)


def _run_node(script: str) -> str:
    """Execute ``script`` with node and return stdout."""
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"node exited {result.returncode}\nstdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    return result.stdout


def _load_framework_and_call(rows: list[dict]) -> list[str]:
    """Run the framework's keyOf against each row, return list of keys."""
    fw_src = FRAMEWORK_JS.read_text()
    payload = json.dumps(rows)
    script = f"""
      // Minimal stubs so the IIFE in _framework.js does not crash.
      global.window = global;
      global.DASH = {{
        utils: {{
          esc: (s) => String(s == null ? '' : s),
          iconHtml: () => '',
          copyToClipboard: () => {{}},
          showToast: () => {{}},
          showApiError: () => {{}},
          statusClass: () => '',
          formatTimestamp: () => '',
        }},
        registry: {{
          tierBadge: () => ({{ cls: '', label: '' }}),
          label: (s) => s,
          tier: () => 'live',
          banner: () => '',
        }},
        api: {{ fetchJSON: () => Promise.resolve({{ data: {{ events: [] }} }}) }},
        app: {{ state: {{ resources: [] }}, navigate: () => {{}} }},
      }};
      global.document = {{
        getElementById: () => null,
        querySelectorAll: () => [],
      }};
      {fw_src}
      const rows = {payload};
      const fw = global.DASH.drills.framework;
      if (typeof fw.keyOf !== 'function') {{
        console.error('keyOf-missing');
        process.exit(2);
      }}
      const out = rows.map((r) => fw.keyOf(r));
      console.log(JSON.stringify(out));
    """
    return json.loads(_run_node(script).strip())


class TestKeyOfHandlesEveryAwsResourceShape:
    """``keyOf(row)`` must return a non-empty identifier for every
    common AWS resource. The fallback chain must cover all the
    fields the per-service drills actually use."""

    ROWS = [
        # (resource type, row, expected non-empty key)
        ("ec2-instance",      {"instance_id": "i-abc123"},                "i-abc123"),
        ("lambda-fn",         {"function_name": "my-fn"},                 "my-fn"),
        ("kms-key",           {"key_id": "9fc314c1-..."},                 "9fc314c1-..."),
        ("rds-instance",      {"db_instance_identifier": "prod-db"},      "prod-db"),
        ("iam-role-by-arn",   {"arn": "arn:aws:iam::000000000000:role/r"},
                              "arn:aws:iam::000000000000:role/r"),
        ("eks-cluster",       {"cluster_name": "my-cluster"},             "my-cluster"),
        ("ddb-table",         {"table_name": "Users"},                    "Users"),
        ("sqs-queue",         {"queue_name": "my-q"},                     "my-q"),
        ("s3-bucket",         {"bucket_name": "my-bucket"},               "my-bucket"),
        ("sns-topic",         {"topic_name": "my-topic"},                 "my-topic"),
        # Generic fallbacks that already work today
        ("generic-name",      {"name": "some-name"},                      "some-name"),
        ("generic-key",       {"key": "some-key"},                        "some-key"),
        ("generic-id",        {"id": "some-id"},                          "some-id"),
    ]

    def test_every_row_resolves_to_its_identifier(self):
        keys = _load_framework_and_call([r[1] for r in self.ROWS])
        failures = []
        for (label, row, expected), got in zip(self.ROWS, keys):
            if got != expected:
                failures.append(f"  {label}: row={row} expected={expected!r} got={got!r}")
        assert not failures, (
            "keyOf returned the wrong identifier for these resource "
            "shapes (the bug that bounces tab clicks back to the "
            "service list, and breaks every destructive-confirm):\n"
            + "\n".join(failures)
        )

    def test_empty_row_returns_empty_string(self):
        keys = _load_framework_and_call([{}])
        assert keys == [""], (
            "keyOf({}) must return '' (not throw) so callers can "
            "fall back gracefully on truly unidentifiable rows"
        )
