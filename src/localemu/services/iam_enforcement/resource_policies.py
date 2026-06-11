"""Cross-account resource-based policy evaluator.

When the caller (account A) targets a resource owned by account B, the
identity-based policies in A allow the action but real AWS only completes
the request if the resource-based policy on B explicitly authorises A.
This module loads the resource-based policy from the target service
backend, runs it through the same condition-key / action / principal
matching used by identity policies, and produces an ALLOW / DENY /
NEUTRAL decision.

Handlers covered (each with its own ``_load_*_policy`` loader):

* S3 bucket policy             — moto: ``backend.get_bucket(name).policy``
* SQS queue policy             — moto: ``queue.policy``
* SNS topic policy             — moto: ``topic.policy``
* KMS key policy               — moto: ``key.policy`` (JSON string)
* Lambda function policy       — moto: ``function.policy._policy``
* EventBridge bus policy       — moto: ``event_bus.policy``

The evaluator is opt-in by ``IAM_ENFORCEMENT=1`` and gated on cross-account
calls (``caller.account_id != resource.account_id``); for same-account
calls it returns ``Decision.NEUTRAL`` and lets the identity evaluator do
its work.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

LOG = logging.getLogger(__name__)


class Decision(Enum):
    NEUTRAL = "neutral"          # not a cross-account call, or no policy hits
    ALLOW = "allow"              # explicit allow in the resource policy
    EXPLICIT_DENY = "deny"       # explicit deny in the resource policy


@dataclass
class ResourceTarget:
    """The resource being accessed."""
    service: str
    arn: str
    account_id: str         # account that OWNS the resource
    region: str
    name: str               # bucket name / queue name / function name / etc.


# --------------------------------------------------------------------------
# Per-service policy loaders
# --------------------------------------------------------------------------


def _load_s3_bucket_policy(target: ResourceTarget) -> dict | None:
    """Load the bucket policy from LocalEmu's native S3 store.

    LocalEmu owns S3's data plane (the buckets live in
    ``localemu.services.s3.models.s3_stores`` and the policy hangs off
    the FakeBucket), so we read from there. moto's ``s3_backends`` does
    not have the bucket.
    """
    try:
        from localemu.constants import AWS_REGION_US_EAST_1
        from localemu.services.s3.models import s3_stores

        store = s3_stores[target.account_id][AWS_REGION_US_EAST_1]
        bucket = store.buckets.get(target.name)
        if bucket is None:
            owner = store.global_bucket_map.get(target.name) \
                if hasattr(store, "global_bucket_map") else None
            if owner:
                bucket = s3_stores[owner][AWS_REGION_US_EAST_1].buckets.get(
                    target.name,
                )
        if bucket is None:
            return None
        policy = getattr(bucket, "policy", None)
        if policy is None:
            return None
        if isinstance(policy, (bytes, bytearray)):
            policy = policy.decode("utf-8")
        if isinstance(policy, str):
            try:
                return json.loads(policy)
            except json.JSONDecodeError:
                return None
        if isinstance(policy, dict):
            return policy
        return None
    except Exception as e:
        LOG.debug("S3 bucket policy load failed for %s: %s", target.arn, e)
        return None


def _load_sqs_queue_policy(target: ResourceTarget) -> dict | None:
    try:
        from moto.sqs import sqs_backends
        backend = sqs_backends[target.account_id][target.region]
        queue = backend.queues.get(target.name)
        if queue is None:
            return None
        policy = (getattr(queue, "policy", None)
                  or getattr(queue, "attributes", {}).get("Policy")
                  or None)
        if isinstance(policy, str):
            try:
                return json.loads(policy)
            except json.JSONDecodeError:
                return None
        if isinstance(policy, dict):
            return policy
        return None
    except Exception as e:
        LOG.debug("SQS policy load failed for %s: %s", target.arn, e)
        return None


def _load_sns_topic_policy(target: ResourceTarget) -> dict | None:
    try:
        from moto.sns import sns_backends
        backend = sns_backends[target.account_id][target.region]
        topic = None
        for arn, t in (getattr(backend, "topics", {}) or {}).items():
            if arn == target.arn or getattr(t, "name", None) == target.name:
                topic = t
                break
        if topic is None:
            return None
        policy = getattr(topic, "policy", None)
        if isinstance(policy, str):
            try:
                return json.loads(policy)
            except json.JSONDecodeError:
                return None
        if isinstance(policy, dict):
            return policy
        return None
    except Exception as e:
        LOG.debug("SNS topic policy load failed for %s: %s", target.arn, e)
        return None


def _load_kms_key_policy(target: ResourceTarget) -> dict | None:
    try:
        from moto.kms import kms_backends
        backend = kms_backends[target.account_id][target.region]
        # target.name is the key id or alias
        key = None
        for k_id, k in (getattr(backend, "keys", {}) or {}).items():
            if k_id == target.name or getattr(k, "arn", None) == target.arn:
                key = k
                break
        if key is None:
            return None
        policy = getattr(key, "policy", None)
        if isinstance(policy, str):
            try:
                return json.loads(policy)
            except json.JSONDecodeError:
                return None
        if isinstance(policy, dict):
            return policy
        return None
    except Exception as e:
        LOG.debug("KMS key policy load failed for %s: %s", target.arn, e)
        return None


def _load_lambda_function_policy(target: ResourceTarget) -> dict | None:
    try:
        from moto.awslambda import lambda_backends
        backend = lambda_backends[target.account_id][target.region]
        function = backend.get_function(target.name) if hasattr(backend, "get_function") else None
        if function is None:
            return None
        raw = getattr(function, "policy", None)
        # moto wraps the function policy in a Policy object with ``_policy`` dict
        if raw is None:
            return None
        if hasattr(raw, "_policy"):
            raw = raw._policy
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None
        if isinstance(raw, dict):
            return raw
        return None
    except Exception as e:
        LOG.debug("Lambda policy load failed for %s: %s", target.arn, e)
        return None


def _load_event_bus_policy(target: ResourceTarget) -> dict | None:
    try:
        from moto.events import events_backends
        backend = events_backends[target.account_id][target.region]
        bus = None
        for b in (getattr(backend, "event_buses", {}) or {}).values():
            if getattr(b, "arn", None) == target.arn or getattr(b, "name", None) == target.name:
                bus = b
                break
        if bus is None:
            return None
        policy = getattr(bus, "policy", None)
        if isinstance(policy, str):
            try:
                return json.loads(policy)
            except json.JSONDecodeError:
                return None
        if isinstance(policy, dict):
            return policy
        return None
    except Exception as e:
        LOG.debug("EventBridge bus policy load failed for %s: %s", target.arn, e)
        return None


_LOADERS = {
    "s3":     _load_s3_bucket_policy,
    "sqs":    _load_sqs_queue_policy,
    "sns":    _load_sns_topic_policy,
    "kms":    _load_kms_key_policy,
    "lambda": _load_lambda_function_policy,
    "events": _load_event_bus_policy,
}


# --------------------------------------------------------------------------
# Evaluator
# --------------------------------------------------------------------------


def _principal_matches(principal_block: Any, caller_account: str,
                       caller_arn: str, caller_org_id: str | None) -> bool:
    """Match a Principal block against the caller.

    Handles:
      - "*"  (everyone)
      - {"AWS": <arn or account-id or list>}
      - {"AWS": "*"}
    Notably does NOT support Service / Federated / CanonicalUser (rarely
    needed for cross-account; can be added later).
    """
    if principal_block == "*":
        return True
    if isinstance(principal_block, dict):
        # AWS field
        aws_p = principal_block.get("AWS")
        if aws_p is None:
            return False
        if isinstance(aws_p, str):
            aws_p = [aws_p]
        if not isinstance(aws_p, list):
            return False
        for p in aws_p:
            ps = str(p).strip()
            if ps == "*":
                return True
            # 12-digit ID
            if ps == caller_account:
                return True
            # arn:aws:iam::<acct>:root
            if ps == f"arn:aws:iam::{caller_account}:root":
                return True
            # exact ARN match against caller_arn (user / role / assumed-role)
            if ps == caller_arn:
                return True
        return False
    return False


def _action_matches(statement_action: Any, action: str) -> bool:
    if statement_action == "*":
        return True
    actions = statement_action if isinstance(statement_action, list) else [statement_action]
    action_lower = action.lower()
    for a in actions:
        a_lower = str(a).lower()
        if a_lower == "*" or a_lower == action_lower:
            return True
        # service:* form
        if a_lower.endswith(":*"):
            prefix = a_lower[:-1]   # keep the colon
            if action_lower.startswith(prefix):
                return True
        # glob via fnmatch semantics on the action string
        import fnmatch
        if fnmatch.fnmatchcase(action_lower, a_lower):
            return True
    return False


def _resource_matches(statement_resource: Any, resource_arn: str) -> bool:
    if statement_resource == "*":
        return True
    if statement_resource is None:
        return True
    resources = (statement_resource if isinstance(statement_resource, list)
                 else [statement_resource])
    import fnmatch
    for r in resources:
        rs = str(r)
        if rs == "*":
            return True
        if rs == resource_arn:
            return True
        if fnmatch.fnmatchcase(resource_arn, rs):
            return True
    return False


def evaluate_resource_policy(
    policy: dict,
    target: ResourceTarget,
    caller_account: str,
    caller_arn: str,
    action: str,
    caller_org_id: str | None = None,
    condition_context: dict | None = None,
) -> Decision:
    """Walk the resource policy statements and return a Decision.

    Standard IAM evaluation: explicit Deny beats Allow; only one explicit
    Allow is required for a positive decision; otherwise NEUTRAL (which
    callers treat as a deny for cross-account because real AWS requires
    an explicit allow on the resource policy for cross-account access).
    """
    from .condition_evaluator import matches_conditions

    if not isinstance(policy, dict):
        return Decision.NEUTRAL
    statements = policy.get("Statement")
    if statements is None:
        return Decision.NEUTRAL
    if isinstance(statements, dict):
        statements = [statements]

    saw_allow = False
    ctx = dict(condition_context or {})
    ctx.setdefault("aws:PrincipalAccount", caller_account)
    ctx.setdefault("aws:ResourceAccount", target.account_id)
    if caller_org_id:
        ctx.setdefault("aws:PrincipalOrgID", caller_org_id)

    for st in statements:
        if not isinstance(st, dict):
            continue
        effect = str(st.get("Effect", "")).lower()
        principal = st.get("Principal") or st.get("NotPrincipal")
        if not _principal_matches(principal, caller_account, caller_arn, caller_org_id):
            continue
        if not _action_matches(st.get("Action") or st.get("NotAction"), action):
            continue
        if not _resource_matches(st.get("Resource") or st.get("NotResource"),
                                 target.arn):
            continue
        if not matches_conditions(st, ctx):
            continue
        if effect == "deny":
            return Decision.EXPLICIT_DENY
        if effect == "allow":
            saw_allow = True

    return Decision.ALLOW if saw_allow else Decision.NEUTRAL


def evaluate_cross_account(
    caller_account: str,
    caller_arn: str,
    target: ResourceTarget,
    action: str,
    caller_org_id: str | None = None,
    condition_context: dict | None = None,
) -> Decision:
    """Top-level entry: load the resource policy and evaluate it.

    Returns:
      - NEUTRAL if same-account, no policy, or no matching statement
      - ALLOW if at least one matching Allow with no explicit Deny
      - EXPLICIT_DENY if any matching Deny
    """
    if caller_account == target.account_id:
        return Decision.NEUTRAL

    loader = _LOADERS.get(target.service)
    if loader is None:
        return Decision.NEUTRAL  # service not in scope; let identity eval rule

    policy = loader(target)
    if not policy:
        return Decision.NEUTRAL

    return evaluate_resource_policy(
        policy, target, caller_account, caller_arn, action,
        caller_org_id=caller_org_id,
        condition_context=condition_context,
    )
