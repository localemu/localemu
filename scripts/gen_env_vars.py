#!/usr/bin/env python3
"""Emit env_vars.json for the website's env-vars reference page.

The website's env-vars table used to be hand-curated, which drifted as
``src/localemu/config.py`` grew. Run this script after changing any
env-var declaration in config.py to refresh the data file:

    python3 scripts/gen_env_vars.py \\
        > ../localemu-cloud-website/src/data/env_vars.json

The output is a list of objects::

    {"name": "LAMBDA_RUNTIME_EXECUTOR",
     "default": "docker",
     "category": "lambda",
     "tier": "PUBLIC",
     "description": "How Lambda functions are executed..."}

Categorization is derived from the variable-name prefix. Tier comes from
the leading marker comment (``# PUBLIC: ...``, ``# EXPERIMENTAL: ...``,
``# DEV: ...``); the absence of a marker falls back to ``OTHER`` so the
website can group it under "Advanced".
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

CONFIG = pathlib.Path(__file__).resolve().parent.parent / "src" / "localemu" / "config.py"

# Order matters: longer prefixes first so LAMBDA_INIT_* doesn't fall
# under LAMBDA_*.
CATEGORIES: list[tuple[str, str]] = [
    ("LAMBDA_INIT_", "lambda-init"),
    ("LAMBDA_", "lambda"),
    ("IAM_", "iam"),
    ("EC2_", "ec2"),
    ("RDS_", "rds"),
    ("ECS_", "ecs"),
    ("EKS_", "eks"),
    ("MSK_", "msk"),
    ("MQ_", "mq"),
    ("OPENSEARCH_", "opensearch"),
    ("SQS_", "sqs"),
    ("SNS_", "sns"),
    ("DYNAMODB_", "dynamodb"),
    ("KINESIS_", "kinesis"),
    ("SFN_", "stepfunctions"),
    ("CFN_", "cloudformation"),
    ("APIGW_", "apigateway"),
    ("S3_", "s3"),
    ("KMS_", "kms"),
    ("CLOUDWATCH_", "cloudwatch"),
    ("SNAPSHOT_", "persistence"),
    ("STATE_", "persistence"),
    ("DOCKER_", "docker"),
    ("MAIN_DOCKER_", "docker"),
    ("CONTAINER_", "docker"),
    ("CONFIG_", "core"),
    ("BOTO_", "core"),
    ("GATEWAY_", "core"),
    ("DEBUG", "core"),
    ("DEVELOP", "core"),
    ("DATA_DIR", "core"),
    ("VOLUME_DIR", "core"),
    ("PERSISTENCE", "persistence"),
    ("USE_SSL", "core"),
    ("USE_HTTP2", "core"),
    ("HOSTNAME", "core"),
    ("EDGE_", "core"),
    ("EXTERNAL_", "core"),
    ("LOCALSTACK_", "core"),
    ("LOCALEMU_", "core"),
    ("ALLOW_", "core"),
    ("ROOT_", "iam"),
    ("DNS_", "core"),
    ("CUSTOM_SSL_", "core"),
    ("LOG_", "core"),
    ("LS_LOG", "core"),
    ("RUNTIME_", "core"),
    ("WAIT_", "core"),
    ("DISABLE_", "core"),
    ("SIMULATE_", "simulation"),
    ("ENFORCE_", "iam"),
]

MARKER_RE = re.compile(r"^#\s*(PUBLIC|EXPERIMENTAL|DEV|PRIVATE|LEGACY|CLI specific)\b\s*:?\s*(.*)$", re.IGNORECASE)
VAR_RE = re.compile(r"^([A-Z_][A-Z0-9_]+)\s*=\s*(.+)$")
COMMENT_RE = re.compile(r"^#\s?(.*)$")


def categorize(name: str) -> str:
    for prefix, cat in CATEGORIES:
        if name.startswith(prefix):
            return cat
    return "other"


def extract_default(rhs: str) -> str:
    """Best-effort default-value extraction from the right-hand side."""
    # is_env_true("VAR") -> bool with implicit False default
    if "is_env_true" in rhs:
        return "0"
    # os.environ.get("X", default) / os.getenv("X", default)
    m = re.search(r'(?:os\.environ\.get|os\.getenv)\(\s*"[^"]+"\s*,\s*([^)]+)\)', rhs)
    if m:
        return m.group(1).strip().strip('"').strip("'")
    # os.environ.get("X") with no default
    if "os.environ.get" in rhs or "os.getenv" in rhs:
        return "(unset)"
    # int(...) / float(...) wrappers
    m = re.search(r'(?:int|float)\(\s*os\.environ\.get\([^,]+,\s*([^)]+)\)', rhs)
    if m:
        return m.group(1).strip()
    return "(see source)"


def main() -> int:
    lines = CONFIG.read_text().split("\n")
    out: list[dict] = []
    pending_comments: list[str] = []
    pending_marker: str | None = None
    for ln in lines:
        if ln.startswith("#"):
            mk = MARKER_RE.match(ln)
            if mk:
                pending_marker = mk.group(1).upper()
                rest = mk.group(2).strip()
                if rest:
                    pending_comments.append(rest)
                continue
            cm = COMMENT_RE.match(ln)
            if cm:
                txt = cm.group(1).strip()
                if txt:
                    pending_comments.append(txt)
                continue
        vm = VAR_RE.match(ln)
        if vm and ("os.environ" in vm.group(2) or "is_env_true" in vm.group(2) or "os.getenv" in vm.group(2)):
            name, rhs = vm.group(1), vm.group(2)
            description = " ".join(pending_comments).strip()
            # Trim runaway descriptions to keep the table readable.
            if len(description) > 400:
                description = description[:397] + "..."
            out.append({
                "name": name,
                "default": extract_default(rhs),
                "category": categorize(name),
                "tier": pending_marker or "OTHER",
                "description": description or "(no description in config.py - see source)",
            })
        # reset accumulators on every non-comment line
        pending_comments = []
        pending_marker = None
    # sort: tier (PUBLIC first), then category, then name
    tier_rank = {"PUBLIC": 0, "EXPERIMENTAL": 1, "DEV": 2, "CLI SPECIFIC": 3,
                 "LEGACY": 4, "PRIVATE": 5, "OTHER": 6}
    out.sort(key=lambda r: (tier_rank.get(r["tier"], 9), r["category"], r["name"]))
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    print(f"\n# {len(out)} env vars emitted", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
