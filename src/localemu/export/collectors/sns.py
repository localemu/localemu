"""SNS collector — exports topics and subscriptions to the IR.

Walks :data:`localemu.services.sns.models.sns_stores` (LocalEmu's native
SNS store, not a moto backend) and emits one :class:`Resource` per topic
and one per subscription. Subscription ``TopicArn`` fields become
:class:`Ref` back to the owning topic; Lambda subscription endpoints
become refs to the target Lambda function.

Secret values are never read here — topics/subscriptions hold no
plaintext credentials, only policy documents and ARNs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _parse_json(value: Any) -> Any:
    """Return ``value`` parsed as JSON when it is a non-empty string.

    SNS stores policies, delivery policies and filter policies as JSON
    strings. The IR keeps them structured so writers do not have to
    re-parse them.
    """
    if not value:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _arn_last_segment(arn: str) -> str:
    """Return the resource id portion of ``arn`` (final ``:`` or ``/`` segment)."""
    if ":" in arn:
        arn = arn.rsplit(":", 1)[1]
    if "/" in arn:
        arn = arn.rsplit("/", 1)[1]
    return arn


def _parse_arn(arn: str) -> tuple[str, str, str, str] | None:
    """Parse ``arn:aws:<service>:<region>:<account>:<rest>``; return tuple or None."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    return parts[2], parts[3], parts[4], parts[5]


@register_collector("sns")
class SnsCollector(BaseCollector):
    """Collect SNS topics and subscriptions from the native LocalEmu store."""

    service = "sns"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Return topic and subscription resources for ``account_id``/``region``."""
        resources: list[Resource] = []
        try:
            from localemu.services.sns.models import sns_stores
        except Exception:  # pragma: no cover - import guard
            LOG.warning("SNS store unavailable; skipping SNS export", exc_info=True)
            return resources

        target_account = account_id
        target_region = region
        for account_id, region, store in sns_stores.iter_stores():
            if account_id != target_account or region != target_region:
                continue
            # Tags in SNS are account-scoped (CrossRegionAttribute); pull once per store.
            tag_lookup: dict[str, dict[str, str]] = {}
            try:
                raw_tags = getattr(store, "tags", {}) or {}
                # Tags is a mapping of arn -> list[{"Key":..,"Value":..}] or dict.
                for arn, entries in dict(raw_tags).items():
                    tag_lookup[arn] = _normalize_tag_entries(entries)
            except Exception:
                LOG.warning(
                    "Failed to read SNS tags for %s/%s", account_id, region, exc_info=True
                )

            for topic_arn, topic in list(store.topics.items()):
                try:
                    resources.append(
                        self._build_topic_resource(
                            account_id, region, topic_arn, topic, tag_lookup
                        )
                    )
                    policy_resource = self._build_topic_policy_resource(
                        account_id, region, topic_arn, topic
                    )
                    if policy_resource is not None:
                        resources.append(policy_resource)
                except Exception:
                    LOG.warning(
                        "Skipping malformed SNS topic %s", topic_arn, exc_info=True
                    )

            for sub_arn, sub in list(store.subscriptions.items()):
                try:
                    resources.append(
                        self._build_subscription_resource(
                            account_id, region, sub_arn, sub
                        )
                    )
                except Exception:
                    LOG.warning(
                        "Skipping malformed SNS subscription %s", sub_arn, exc_info=True
                    )

        return resources

    # --- builders --------------------------------------------------------

    def _build_topic_resource(
        self,
        account_id: str,
        region: str,
        topic_arn: str,
        topic: dict[str, Any],
        tag_lookup: dict[str, dict[str, str]],
    ) -> Resource:
        """Build a topic :class:`Resource` from the raw SNS topic dict."""
        name = topic.get("name") or _arn_last_segment(topic_arn)
        attrs: dict[str, Any] = topic.get("attributes", {}) or {}

        kms_key_id = attrs.get("KmsMasterKeyId")
        kms_ref: Ref | str | None = None
        if kms_key_id:
            kms_ref = _maybe_kms_ref(kms_key_id)

        attributes: dict[str, Any] = {
            "name": name,
            "arn": topic_arn,
            "fifo_topic": _as_bool(attrs.get("FifoTopic")),
            "display_name": attrs.get("DisplayName"),
            # ``policy`` is NOT mapped onto ``aws_sns_topic`` — the
            # Terraform idiom is a separate ``aws_sns_topic_policy``
            # resource, emitted by :meth:`_build_topic_policy_resource`
            # below when the policy is user-customized.
            "delivery_policy": _parse_json(attrs.get("DeliveryPolicy")),
            "kms_master_key_id": kms_ref if kms_ref is not None else kms_key_id,
            "content_based_deduplication": _as_bool(
                attrs.get("ContentBasedDeduplication")
            ),
            "signature_version": attrs.get("SignatureVersion"),
            "tracing_config": attrs.get("TracingConfig"),
            "data_protection_policy": _parse_json(topic.get("data_protection_policy")),
        }
        # Drop None leaves for compactness, but keep explicit False.
        attributes = {k: v for k, v in attributes.items() if v is not None}

        return Resource(
            service="sns",
            resource_type="topic",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attributes,
            tags=tag_lookup.get(topic_arn, {}),
        )

    def _build_topic_policy_resource(
        self, account_id: str, region: str, topic_arn: str, topic: dict[str, Any],
    ) -> Resource | None:
        """Emit ``aws_sns_topic_policy`` when the user set a non-default
        policy on the topic. SNS auto-creates a single ``__default_statement_ID``
        statement on every topic; we don't export that one, only customized
        policies (anything else / multiple statements / explicit Principal).
        """
        attrs = topic.get("attributes", {}) or {}
        policy_str = attrs.get("Policy")
        if not policy_str:
            return None
        policy = _parse_json(policy_str)
        if not isinstance(policy, dict):
            return None
        statements = policy.get("Statement") or []
        if not isinstance(statements, list):
            return None
        # Filter the implicit default statement so re-exporting a never-
        # touched topic doesn't drag in a no-op topic_policy resource.
        custom = [
            s for s in statements
            if isinstance(s, dict)
            and s.get("Sid") != "__default_statement_ID"
        ]
        if not custom:
            return None
        topic_name = topic.get("name") or _arn_last_segment(topic_arn)
        return Resource(
            service="sns",
            resource_type="topic_policy",
            resource_id=topic_name,
            account_id=account_id,
            region=region,
            attributes={
                "arn": Ref("sns", "topic", topic_name, attribute="arn"),
                "policy": {**policy, "Statement": custom},
            },
        )

    def _build_subscription_resource(
        self,
        account_id: str,
        region: str,
        sub_arn: str,
        sub: dict[str, Any],
    ) -> Resource:
        """Build a subscription :class:`Resource` from the raw subscription dict."""
        topic_arn = sub.get("TopicArn", "")
        topic_name = _arn_last_segment(topic_arn) if topic_arn else ""
        topic_ref = (
            Ref(service="sns", resource_type="topic", resource_id=topic_name)
            if topic_name
            else topic_arn
        )

        protocol = sub.get("Protocol")
        endpoint_raw = sub.get("Endpoint")
        endpoint: Any = endpoint_raw
        if protocol == "lambda" and isinstance(endpoint_raw, str) and endpoint_raw:
            parsed = _parse_arn(endpoint_raw)
            if parsed is not None:
                fn_name = _arn_last_segment(endpoint_raw)
                endpoint = Ref(
                    service="lambda",
                    resource_type="function",
                    resource_id=fn_name,
                )
        elif protocol == "sqs" and isinstance(endpoint_raw, str) and endpoint_raw:
            queue_name = _arn_last_segment(endpoint_raw)
            endpoint = Ref(
                service="sqs", resource_type="queue", resource_id=queue_name
            )

        sub_id = _arn_last_segment(sub_arn) or sub_arn

        attributes: dict[str, Any] = {
            "arn": sub_arn,
            "topic_arn": topic_ref,
            "protocol": protocol,
            "endpoint": endpoint,
            "filter_policy": _parse_json(sub.get("FilterPolicy")),
            "filter_policy_scope": sub.get("FilterPolicyScope"),
            "raw_message_delivery": _as_bool(sub.get("RawMessageDelivery")),
            "redrive_policy": _parse_json(sub.get("RedrivePolicy")),
            "delivery_policy": _parse_json(sub.get("DeliveryPolicy")),
            "subscription_role_arn": sub.get("SubscriptionRoleArn"),
            "pending_confirmation": _as_bool(sub.get("PendingConfirmation")),
            "owner": sub.get("Owner"),
        }
        attributes = {k: v for k, v in attributes.items() if v is not None}

        return Resource(
            service="sns",
            resource_type="subscription",
            resource_id=sub_id,
            account_id=account_id,
            region=region,
            attributes=attributes,
        )


def _as_bool(value: Any) -> bool | None:
    """Coerce SNS ``"true"``/``"false"``/bool to Python bool (or ``None``)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.lower()
        if low == "true":
            return True
        if low == "false":
            return False
    return None


def _normalize_tag_entries(entries: Any) -> dict[str, str]:
    """Normalize AWS-style ``[{Key, Value}]`` or raw dict tags to a dict."""
    if isinstance(entries, dict):
        return {str(k): str(v) for k, v in entries.items()}
    if isinstance(entries, list):
        out: dict[str, str] = {}
        for item in entries:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}


def _maybe_kms_ref(kms_key_id: str) -> Ref | str:
    """Return a :class:`Ref` for a KMS key id/arn, or the raw string as-is.

    ``alias/aws/sns`` is an AWS-managed alias, not a customer-managed key,
    and should remain a plain string so writers reproduce it verbatim.
    """
    if not kms_key_id or kms_key_id.startswith("alias/aws/"):
        return kms_key_id
    key_id = _arn_last_segment(kms_key_id)
    return Ref(service="kms", resource_type="key", resource_id=key_id)
