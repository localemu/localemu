"""Native in-memory finding storage for GuardDuty.

Moto's GuardDuty backend (vendored as a dependency) implements the
detector/filter control plane but has no route at all for
``CreateSampleFindings``, ``ListFindings``, or ``GetFindings`` - a request
to any of them fails with ``No moto route for service guardduty on path
...``. This module is the native replacement for just that missing piece;
``provider.py`` keeps every other GuardDuty operation on the existing
(working) moto path.

Fidelity note on ``CreateSampleFindings``: real AWS's sample findings are
*not* tied to anything in your account either - they're synthetic
placeholders (fake instance ids, fake access keys) meant to exercise your
GuardDuty -> EventBridge wiring without waiting for a real detection. This
store does the same thing on purpose, not as a shortcut.
"""
from __future__ import annotations

import fnmatch
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .models import guardduty_stores

_lock = threading.Lock()


def reset() -> None:
    with _lock:
        guardduty_stores.reset()


def _bucket(account_id: str, region: str, detector_id: str) -> dict[str, dict[str, Any]]:
    store = guardduty_stores[account_id][region]
    with _lock:
        return store.findings.setdefault(detector_id, {})


def delete_detector_findings(account_id: str, region: str, detector_id: str) -> None:
    store = guardduty_stores[account_id][region]
    with _lock:
        store.findings.pop(detector_id, None)


# ---------------------------------------------------------------------------
# Finding synthesis
#
# GuardDuty has ~100 finding types. Rather than hand-model every one, we
# derive a schema-accurate Finding from the type string itself:
# "<category>:<resourceClass>/<threatName>" (e.g.
# "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS").
# A curated table covers the ones most used in teaching/demo material with
# real titles/descriptions/severities; anything else gets a generic but
# still schema-valid finding derived from the same heuristics AWS itself
# groups these types by.
# ---------------------------------------------------------------------------

_CATEGORY_SEVERITY = {
    "Backdoor": 8.0,
    "Behavior": 5.0,
    "CryptoCurrency": 7.0,
    "Impact": 7.0,
    "Persistence": 6.0,
    "Policy": 3.0,
    "PenTest": 2.0,
    "Recon": 5.0,
    "ResourceConsumption": 5.0,
    "Stealth": 7.0,
    "Trojan": 8.0,
    "UnauthorizedAccess": 8.0,
}

_KNOWN_TYPES: dict[str, dict[str, Any]] = {
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": {
        "severity": 8.5,
        "title": "EC2 instance credentials used from outside AWS.",
        "description": (
            "Credentials that were created exclusively for an EC2 instance "
            "through an Instance launch role are being used from an "
            "external IP address."
        ),
    },
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": {
        "severity": 8.5,
        "title": "EC2 instance credentials used from another AWS account.",
        "description": (
            "Credentials that were created exclusively for an EC2 instance "
            "through an instance launch role are being used from a "
            "different AWS account."
        ),
    },
    "Recon:IAMUser/MaliciousIPCaller": {
        "severity": 5.0,
        "title": "API calls made from a known malicious IP address.",
        "description": (
            "An API was invoked from an IP address on a threat intelligence "
            "list."
        ),
    },
    "UnauthorizedAccess:IAMUser/UnusualASNCaller": {
        "severity": 5.0,
        "title": "API calls made from an unusual network for this account.",
        "description": (
            "An API was invoked from an autonomous system (ASN) this "
            "principal has not called from before."
        ),
    },
    "UnauthorizedAccess:EC2/SSHBruteForce": {
        "severity": 2.0,
        "title": "SSH brute force attack against an EC2 instance.",
        "description": (
            "An EC2 instance is the target of an SSH brute force attack."
        ),
    },
    "Backdoor:EC2/C&CActivity.B!DNS": {
        "severity": 8.0,
        "title": "EC2 instance querying a known command-and-control domain.",
        "description": (
            "An EC2 instance is querying a domain name associated with a "
            "known command-and-control server."
        ),
    },
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": {
        "severity": 7.0,
        "title": "EC2 instance querying a cryptocurrency-mining-pool domain.",
        "description": (
            "An EC2 instance is querying a domain name associated with "
            "cryptocurrency mining."
        ),
    },
    "Policy:IAMUser/RootCredentialUsage": {
        "severity": 2.0,
        "title": "The root account was used to invoke API calls.",
        "description": "The root credentials for this account are being used to make API calls.",
    },
    "PenTest:IAMUser/KaliLinux": {
        "severity": 2.0,
        "title": "API calls from a Kali Linux host.",
        "description": "A known Kali Linux host made API calls using this account's credentials.",
    },
}


def _category_of(finding_type: str) -> str:
    return finding_type.split(":", 1)[0] if ":" in finding_type else finding_type


def _resource_class_of(finding_type: str) -> str:
    # "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
    # -> "IAMUser"
    rest = finding_type.split(":", 1)[-1]
    return rest.split("/", 1)[0] if "/" in rest else ""


def _synthetic_resource(finding_type: str) -> dict[str, Any]:
    resource_class = _resource_class_of(finding_type)
    suffix = uuid.uuid4().hex[:12]

    if resource_class in ("IAMUser", "AssumedRole"):
        return {
            "ResourceType": "AccessKey",
            "AccessKeyDetails": {
                "AccessKeyId": f"ASIASAMPLE{suffix.upper()[:9]}",
                "PrincipalId": f"AROASAMPLE{suffix.upper()[:9]}",
                "UserName": "sample-user",
                "UserType": "AssumedRole" if resource_class == "AssumedRole" else "IAMUser",
            },
        }
    if resource_class == "EC2":
        return {
            "ResourceType": "Instance",
            "InstanceDetails": {
                "InstanceId": f"i-{suffix}",
                "InstanceType": "m5.large",
                "LaunchTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "NetworkInterfaces": [
                    {"PrivateIpAddress": "10.0.0.5", "PublicIp": "198.51.100.1"}
                ],
            },
        }
    if resource_class == "S3Bucket":
        return {
            "ResourceType": "S3Bucket",
            "S3BucketDetails": [
                {"Name": f"sample-bucket-{suffix}", "Type": "Destination"}
            ],
        }
    # Fallback: still schema-valid, generically credential-shaped - matches
    # most teaching-relevant finding types even when the resource class
    # above isn't one we modeled explicitly.
    return {
        "ResourceType": "AccessKey",
        "AccessKeyDetails": {
            "AccessKeyId": f"ASIASAMPLE{suffix.upper()[:9]}",
            "PrincipalId": f"AROASAMPLE{suffix.upper()[:9]}",
            "UserName": "sample-user",
            "UserType": "IAMUser",
        },
    }


def _synthesize_finding(
    finding_type: str, *, account_id: str, region: str, detector_id: str, partition: str = "aws",
) -> dict[str, Any]:
    known = _KNOWN_TYPES.get(finding_type)
    category = _category_of(finding_type)
    severity = (known or {}).get("severity") or _CATEGORY_SEVERITY.get(category, 5.0)
    title = (known or {}).get("title") or finding_type.replace(":", " - ").replace("/", " / ")
    description = (known or {}).get("description") or (
        f"Sample finding generated by CreateSampleFindings for type {finding_type!r}."
    )

    finding_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return {
        "SchemaVersion": "2.0",
        "AccountId": account_id,
        "Region": region,
        "Partition": partition,
        "Id": finding_id,
        "Arn": f"arn:{partition}:guardduty:{region}:{account_id}:detector/{detector_id}/finding/{finding_id}",
        "Type": finding_type,
        "Severity": severity,
        "Confidence": 8.0,
        "Title": title,
        "Description": description,
        "CreatedAt": now,
        "UpdatedAt": now,
        "Resource": _synthetic_resource(finding_type),
        "Service": {
            "ServiceName": "guardduty",
            "DetectorId": detector_id,
            "Archived": False,
            "Count": 1,
            "EventFirstSeen": now,
            "EventLastSeen": now,
            "ResourceRole": "TARGET",
            "Action": {
                "ActionType": "AWS_API_CALL",
                "AwsApiCallAction": {
                    "Api": "GetCallerIdentity",
                    "ServiceName": "sts.amazonaws.com",
                    "CallerType": "Remote IP",
                    "RemoteIpDetails": {
                        "IpAddressV4": "198.51.100.1",
                        "Country": {"CountryName": "Unknown"},
                    },
                },
            },
        },
    }


def create_sample_findings(
    *, account_id: str, region: str, detector_id: str, finding_types: list[str],
) -> list[dict[str, Any]]:
    bucket = _bucket(account_id, region, detector_id)
    created = []
    for finding_type in finding_types:
        finding = _synthesize_finding(
            finding_type, account_id=account_id, region=region, detector_id=detector_id,
        )
        with _lock:
            bucket[finding["Id"]] = finding
        created.append(finding)
    return created


def _walk(value: Any, parts: list[str]) -> list[Any]:
    """Scalar values found at a dotted, case-insensitive field path."""
    if not parts:
        return [value]
    if isinstance(value, list):
        return [v for item in value for v in _walk(item, parts)]
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() == parts[0].lower():
                return _walk(child, parts[1:])
    return []


def _values(finding: dict[str, Any], path: str) -> list[Any]:
    return [v for v in _walk(finding, path.split(".")) if not isinstance(v, (dict, list))]


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _as_number(value: Any) -> float | None:
    """Numbers as-is; ISO timestamps as epoch milliseconds (the unit the
    GuardDuty comparison operators use for time fields)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000
            except ValueError:
                continue
    return None


_NUMERIC_OPS = {
    "Gt": lambda a, b: a > b, "GreaterThan": lambda a, b: a > b,
    "Gte": lambda a, b: a >= b, "GreaterThanOrEqual": lambda a, b: a >= b,
    "Lt": lambda a, b: a < b, "LessThan": lambda a, b: a < b,
    "Lte": lambda a, b: a <= b, "LessThanOrEqual": lambda a, b: a <= b,
}


def _condition_matches(values: list[Any], condition: dict[str, Any]) -> bool:
    texts = [_as_text(v) for v in values]
    for op in ("Eq", "Equals"):
        wanted = condition.get(op)
        if wanted is not None and not any(t in wanted for t in texts):
            return False
    for op in ("Neq", "NotEquals"):
        unwanted = condition.get(op)
        if unwanted is not None and any(t in unwanted for t in texts):
            return False
    patterns = condition.get("Matches")
    if patterns is not None and not any(fnmatch.fnmatchcase(t, p) for t in texts for p in patterns):
        return False
    patterns = condition.get("NotMatches")
    if patterns is not None and any(fnmatch.fnmatchcase(t, p) for t in texts for p in patterns):
        return False
    for op, compare in _NUMERIC_OPS.items():
        bound = condition.get(op)
        if bound is None:
            continue
        numbers = [n for n in (_as_number(v) for v in values) if n is not None]
        if not any(compare(n, bound) for n in numbers):
            return False
    return True


def _matches_criteria(finding: dict[str, Any], finding_criteria: dict[str, Any] | None) -> bool:
    """Every criterion must hold. Field paths are the dotted GuardDuty names
    (``type``, ``severity``, ``service.archived``, ``resource.resourceType``,
    ``updatedAt``, ...), resolved case-insensitively against the finding. A
    field the finding does not have never satisfies a positive condition."""
    for path, condition in ((finding_criteria or {}).get("Criterion") or {}).items():
        if not _condition_matches(_values(finding, path), condition):
            return False
    return True


def _sort_findings(
    findings: list[dict[str, Any]], sort_criteria: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    attribute = (sort_criteria or {}).get("AttributeName")
    if not attribute:
        return findings

    def key(finding: dict[str, Any]):
        values = _values(finding, attribute)
        if not values:
            return (2, 0.0, "")
        number = _as_number(values[0])
        return (0, number, "") if number is not None else (1, 0.0, _as_text(values[0]))

    descending = (sort_criteria or {}).get("OrderBy", "ASC") == "DESC"
    present = [f for f in findings if _values(f, attribute)]
    absent = [f for f in findings if not _values(f, attribute)]
    return sorted(present, key=key, reverse=descending) + absent


def list_findings(
    *,
    account_id: str,
    region: str,
    detector_id: str,
    finding_criteria: dict[str, Any] | None = None,
    sort_criteria: dict[str, Any] | None = None,
    max_results: int | None = None,
    next_token: str | None = None,
) -> tuple[list[str], str | None]:
    bucket = _bucket(account_id, region, detector_id)
    with _lock:
        findings = [f for f in bucket.values() if _matches_criteria(f, finding_criteria)]
    ids = [f["Id"] for f in _sort_findings(findings, sort_criteria)]

    start = int(next_token) if next_token else 0
    page_size = max_results or 50
    page = ids[start : start + page_size]
    new_next_token = str(start + page_size) if start + page_size < len(ids) else None
    return page, new_next_token


def get_findings(
    *,
    account_id: str,
    region: str,
    detector_id: str,
    finding_ids: list[str],
    sort_criteria: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    bucket = _bucket(account_id, region, detector_id)
    with _lock:
        found = [bucket[fid] for fid in finding_ids if fid in bucket]
    return _sort_findings(found, sort_criteria)


def _touch(finding: dict[str, Any]) -> None:
    finding["UpdatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def set_archived(
    *, account_id: str, region: str, detector_id: str, finding_ids: list[str], archived: bool,
) -> None:
    bucket = _bucket(account_id, region, detector_id)
    with _lock:
        for fid in finding_ids:
            finding = bucket.get(fid)
            if finding is not None:
                finding["Service"]["Archived"] = archived
                _touch(finding)


def set_feedback(
    *, account_id: str, region: str, detector_id: str, finding_ids: list[str], feedback: str,
) -> None:
    bucket = _bucket(account_id, region, detector_id)
    with _lock:
        for fid in finding_ids:
            finding = bucket.get(fid)
            if finding is not None:
                finding["Service"]["UserFeedback"] = feedback
                _touch(finding)


def _as_datetime(value: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def _resource_identity(finding: dict[str, Any]) -> tuple[str, str]:
    resource = finding.get("Resource") or {}
    rtype = resource.get("ResourceType", "")
    for details_key, id_key in (
        ("InstanceDetails", "InstanceId"),
        ("AccessKeyDetails", "AccessKeyId"),
        ("S3BucketDetails", "Name"),
    ):
        details = resource.get(details_key)
        if isinstance(details, dict):
            if isinstance(details.get(id_key), str):
                return rtype, details[id_key]
        elif isinstance(details, list) and details and isinstance(details[0], dict):
            if isinstance(details[0].get(id_key), str):
                return rtype, details[0][id_key]
    return rtype, ""


def get_statistics(
    *,
    account_id: str,
    region: str,
    detector_id: str,
    finding_criteria: dict[str, Any] | None = None,
    group_by: str | None = None,
    order_by: str | None = None,
    max_results: int | None = None,
    next_token: str | None = None,
    statistic_types: list[str] | None = None,
) -> tuple[dict[str, Any], str | None]:
    bucket = _bucket(account_id, region, detector_id)
    with _lock:
        findings = [f for f in bucket.values() if _matches_criteria(f, finding_criteria)]

    stats: dict[str, Any] = {}
    if "COUNT_BY_SEVERITY" in (statistic_types or []):
        counts: dict[str, int] = {}
        for f in findings:
            key = str(int(f["Severity"]))
            counts[key] = counts.get(key, 0) + 1
        stats["CountBySeverity"] = counts

    next_out: str | None = None
    if group_by:
        groups: dict[Any, dict[str, Any]] = {}
        for f in findings:
            updated = _as_datetime(f["UpdatedAt"])
            if group_by == "ACCOUNT":
                key, base = f["AccountId"], {"AccountId": f["AccountId"]}
            elif group_by == "FINDING_TYPE":
                key, base = f["Type"], {"FindingType": f["Type"]}
            elif group_by == "SEVERITY":
                key, base = f["Severity"], {"Severity": f["Severity"]}
            elif group_by == "DATE":
                key = updated.date()
                base = {"Date": datetime(key.year, key.month, key.day, tzinfo=timezone.utc), "Severity": 0.0}
            else:  # RESOURCE
                rtype, rid = _resource_identity(f)
                key, base = (rtype, rid), {"AccountId": f["AccountId"], "ResourceId": rid, "ResourceType": rtype}
            group = groups.setdefault(key, {**base, "TotalFindings": 0, "LastGeneratedAt": updated})
            group["TotalFindings"] += 1
            if updated > group["LastGeneratedAt"]:
                group["LastGeneratedAt"] = updated
            if group_by == "DATE":
                group["Severity"] = max(group["Severity"], f["Severity"])
        rows = list(groups.values())
        if order_by:
            rows.sort(key=lambda r: r["TotalFindings"], reverse=order_by == "DESC")
        start = int(next_token) if next_token else 0
        if max_results:
            if start + max_results < len(rows):
                next_out = str(start + max_results)
            rows = rows[start : start + max_results]
        else:
            rows = rows[start:]
        stats[{
            "ACCOUNT": "GroupedByAccount", "DATE": "GroupedByDate",
            "FINDING_TYPE": "GroupedByFindingType", "SEVERITY": "GroupedBySeverity",
            "RESOURCE": "GroupedByResource",
        }[group_by]] = rows
    return stats, next_out
