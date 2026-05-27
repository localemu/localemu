"""EventBridge (Events) collector — buses, rules, targets, archives, connections.

Walks the moto ``events`` backend. Each event bus (including the built-in
``default`` bus) is a resource; each rule is a resource with its targets
nested under ``attributes.targets`` (writers emit one AWS::Events::Target
per target). Target ARNs are opportunistically resolved to :class:`Ref`
instances for Lambda / SQS / SNS / Kinesis / Step Functions destinations.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _parse_json(value: Any) -> Any:
    """Return ``value`` parsed as JSON when it is a non-empty string."""
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
    if not isinstance(arn, str):
        return ""
    last = arn
    if ":" in last:
        last = last.rsplit(":", 1)[1]
    if "/" in last:
        last = last.rsplit("/", 1)[1]
    return last


# Mapping of AWS service -> (export_service, resource_type) for target Refs.
_TARGET_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "lambda": ("lambda", "function"),
    "sqs": ("sqs", "queue"),
    "sns": ("sns", "topic"),
    "kinesis": ("kinesis", "stream"),
    "states": ("stepfunctions", "state_machine"),
    "logs": ("logs", "log_group"),
    "events": ("events", "event_bus"),
}


def _target_arn_to_ref(arn: str) -> Ref | str:
    """Resolve a target ARN to a :class:`Ref` when recognized, else return string."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return arn
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return arn
    service = parts[2]
    mapping = _TARGET_SERVICE_MAP.get(service)
    if mapping is None:
        return arn
    export_service, resource_type = mapping
    # Within ``arn:aws:events:...`` ARNs the resource segment distinguishes
    # buses, rules, and archives — only ``event-bus/<name>`` should resolve
    # to an ``event_bus`` Ref. Treating ``archive/<name>`` or ``rule/<name>``
    # as a bus produced ``aws_events_event_bus.<archive>`` references that
    # ``terraform plan`` rejected as "undeclared resource".
    resource_segment = parts[5] if len(parts) > 5 else ""
    if export_service == "events":
        if resource_segment.startswith("event-bus/"):
            resource_type = "event_bus"
        elif resource_segment.startswith("archive/"):
            resource_type = "archive"
        elif resource_segment.startswith("rule/"):
            resource_type = "rule"
        else:
            return arn  # unknown events sub-type — leave the string alone
    # For Lambda/SQS/etc. the resource id is the final segment.
    resource_id = _arn_last_segment(arn)
    if not resource_id:
        return arn
    return Ref(
        service=export_service, resource_type=resource_type, resource_id=resource_id
    )


def _role_ref(role_arn: Any) -> Ref | str | None:
    """Return a :class:`Ref` for an IAM role ARN, or the original value."""
    if not role_arn or not isinstance(role_arn, str):
        return role_arn
    if not role_arn.startswith("arn:"):
        return role_arn
    role_name = _arn_last_segment(role_arn)
    if not role_name:
        return role_arn
    return Ref(service="iam", resource_type="role", resource_id=role_name)


def _connection_auth_params_to_tf(raw: Any) -> dict[str, Any] | None:
    """Translate moto's CamelCase ``auth_parameters`` blob to the TF schema.

    AWS API shape (what moto stores):
        {
          "ApiKeyAuthParameters": {"ApiKeyName": "x", "ApiKeyValue": "y"},
          "BasicAuthParameters": {"Username": "u", "Password": "p"},
          "OAuthParameters": {
              "ClientParameters": {"ClientID": "c", "ClientSecret": "s"},
              "AuthorizationEndpoint": "https://…",
              "HttpMethod": "POST",
              "OAuthHttpParameters": {...},
          },
          "InvocationHttpParameters": {...},
        }

    Terraform shape (``aws_cloudwatch_event_connection.auth_parameters``):
        api_key { key = "x"; value = "y" }
        basic   { username = "u"; password = "p" }
        oauth   { authorization_endpoint = "…"; http_method = "POST";
                  client_parameters { client_id = "c"; client_secret = "s" }
                  oauth_http_parameters { ... } }
        invocation_http_parameters { ... }
    """
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    api_key = raw.get("ApiKeyAuthParameters")
    if isinstance(api_key, dict) and api_key.get("ApiKeyName"):
        # ``ApiKeyValue`` is intentionally not returned by AWS's
        # ``describe_connection`` (and moto faithfully omits it), so we
        # never get the real secret back from a running emulator. Emit
        # ``REPLACE_ME`` rather than ``""`` so the operator notices and
        # fills it in ``terraform.tfvars`` before deploy — TF's connection
        # schema requires a non-empty value.
        out["api_key"] = {
            "key": api_key.get("ApiKeyName"),
            "value": api_key.get("ApiKeyValue") or "REPLACE_ME",
        }
    basic = raw.get("BasicAuthParameters")
    if isinstance(basic, dict) and basic.get("Username"):
        out["basic"] = {
            "username": basic.get("Username"),
            "password": basic.get("Password") or "REPLACE_ME",
        }
    oauth = raw.get("OAuthParameters")
    if isinstance(oauth, dict):
        client = oauth.get("ClientParameters") or {}
        oauth_block: dict[str, Any] = {
            "authorization_endpoint": oauth.get("AuthorizationEndpoint"),
            "http_method": oauth.get("HttpMethod") or "POST",
            "client_parameters": {
                "client_id": client.get("ClientID"),
                "client_secret": client.get("ClientSecret") or "",
            },
        }
        ohp = oauth.get("OAuthHttpParameters")
        if isinstance(ohp, dict):
            oauth_block["oauth_http_parameters"] = ohp
        out["oauth"] = {
            k: v for k, v in oauth_block.items() if v is not None
        }
    inv = raw.get("InvocationHttpParameters")
    if isinstance(inv, dict):
        out["invocation_http_parameters"] = inv
    return out or None


def _kms_ref(kms_key_id: Any) -> Ref | str | None:
    """Return a :class:`Ref` for a KMS key id/arn (or pass-through)."""
    if not kms_key_id or not isinstance(kms_key_id, str):
        return kms_key_id
    if kms_key_id.startswith("alias/aws/"):
        return kms_key_id
    key_id = _arn_last_segment(kms_key_id) or kms_key_id
    return Ref(service="kms", resource_type="key", resource_id=key_id)


@register_collector("events")
class EventsCollector(BaseCollector):
    """Collect EventBridge event buses, rules, targets, archives, connections."""

    service = "events"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        """Return EventBridge resources for ``account_id``/``region``."""
        resources: list[Resource] = []
        try:
            import moto.backends as moto_backends
        except Exception:  # pragma: no cover - import guard
            LOG.warning("moto not importable; skipping events export", exc_info=True)
            return resources

        # LocalEmu's EventsProvider stores rules / event-buses / archives /
        # connections in its OWN per-account/region :class:`EventsStore`,
        # NOT in moto's ``events_backends``. Earlier revisions of this
        # collector walked moto's BackendDict and silently returned zero
        # rules even though ``aws events list-rules`` happily returned
        # them — moto was simply never populated. Read the live store.
        try:
            from localemu.services.events.models import events_stores
        except Exception:
            LOG.warning(
                "localemu events store import failed", exc_info=True
            )
            return resources

        # ``AccountRegionBundle`` is a dict subclass that lazily creates
        # entries on item access. Probe with ``in`` to avoid spuriously
        # materialising empty stores on every export.
        if account_id not in events_stores:
            return resources
        region_bundle = events_stores[account_id]
        if region not in region_bundle:
            return resources
        try:
            store = region_bundle[region]
        except Exception:
            LOG.warning(
                "No events store for account=%s region=%s",
                account_id, region, exc_info=True,
            )
            return resources
        if store is None:
            return resources
        self._collect_backend(store, account_id, region, resources)
        return resources

    # --- per-backend walk -----------------------------------------------

    def _collect_backend(
        self,
        backend: Any,
        account_id: str,
        region: str,
        resources: list[Resource],
    ) -> None:
        """Walk a single account/region events backend."""
        # Event buses. Skip the AWS built-in ``default`` bus — it exists in
        # every AWS account at creation time, has no user-managed config, and
        # is not deployable by Terraform / CloudFormation. Exporting it would
        # make the deploy fail with "EventBus already exists".
        event_buses = getattr(backend, "event_buses", {}) or {}
        for bus_name, bus in list(event_buses.items()):
            if bus_name == "default":
                continue
            try:
                resources.append(
                    self._build_bus_resource(account_id, region, bus_name, bus)
                )
            except Exception:
                LOG.warning(
                    "Skipping malformed event bus %s", bus_name, exc_info=True
                )

        # Rules live either on the backend directly or per-bus depending on
        # moto version. Try the flat map first.
        #
        # Skip ``Events-Archive-{archive_name}`` rules: AWS auto-creates one
        # of these for every archive at CreateArchive time, and AWS will
        # re-create it again when ``aws_cloudwatch_event_archive`` is
        # applied. Re-exporting the rule yields a duplicate-rule error on
        # apply AND drags in a synthetic target whose ARN points at the
        # archive (not a bus) — which the target-arn resolver historically
        # mis-classified as an event_bus Ref. Letting AWS own these rules
        # is correct.
        def _is_archive_replay_rule(name: str) -> bool:
            return name.startswith("Events-Archive-")

        rules = getattr(backend, "rules", None)
        if rules:
            for rule_name, rule in list(rules.items()):
                if _is_archive_replay_rule(rule_name):
                    continue
                try:
                    resources.append(
                        self._build_rule_resource(account_id, region, rule_name, rule)
                    )
                except Exception:
                    LOG.warning(
                        "Skipping malformed rule %s", rule_name, exc_info=True
                    )
        else:
            # Fallback: per-bus rules attribute (older/newer moto layouts).
            for bus in list(event_buses.values()):
                bus_rules = getattr(bus, "rules", {}) or {}
                for rule_name, rule in list(bus_rules.items()):
                    if _is_archive_replay_rule(rule_name):
                        continue
                    try:
                        resources.append(
                            self._build_rule_resource(
                                account_id, region, rule_name, rule
                            )
                        )
                    except Exception:
                        LOG.warning(
                            "Skipping malformed rule %s", rule_name, exc_info=True
                        )

        # Archives (metadata only — do NOT export archived events).
        archives = getattr(backend, "archives", {}) or {}
        for name, archive in list(archives.items()):
            try:
                resources.append(
                    self._build_archive_resource(account_id, region, name, archive)
                )
            except Exception:
                LOG.warning("Skipping malformed archive %s", name, exc_info=True)

        # Connections (metadata only — auth parameters get redacted centrally).
        connections = getattr(backend, "connections", {}) or {}
        for name, conn in list(connections.items()):
            try:
                resources.append(
                    self._build_connection_resource(account_id, region, name, conn)
                )
            except Exception:
                LOG.warning("Skipping malformed connection %s", name, exc_info=True)

        # API destinations (HTTP targets reachable via a connection).
        api_dests = getattr(backend, "api_destinations", {}) or {}
        for name, ad in list(api_dests.items()):
            try:
                resources.append(
                    self._build_api_destination_resource(account_id, region, name, ad)
                )
            except Exception:
                LOG.warning("Skipping malformed api_destination %s", name, exc_info=True)

    # --- builders --------------------------------------------------------

    def _build_bus_resource(
        self, account_id: str, region: str, bus_name: str, bus: Any
    ) -> Resource:
        """Build an event-bus :class:`Resource`."""
        policy = getattr(bus, "policy", None)
        kms_key = getattr(bus, "kms_key_identifier", None) or getattr(
            bus, "kms_key_id", None
        )
        tags = _normalize_tags(getattr(bus, "tags", None))
        attrs: dict[str, Any] = {
            "name": bus_name,
            "arn": getattr(bus, "arn", None),
            "policy": _parse_json(policy),
            "kms_key_id": _kms_ref(kms_key),
            "description": getattr(bus, "description", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="events",
            resource_type="event_bus",
            resource_id=bus_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=tags,
        )

    def _build_rule_resource(
        self, account_id: str, region: str, rule_name: str, rule: Any
    ) -> Resource:
        """Build a rule :class:`Resource` with nested target list."""
        event_bus_name = getattr(rule, "event_bus_name", None) or "default"
        event_pattern = getattr(rule, "event_pattern", None)
        # moto's EventPattern may be an object with ``dump()`` or a raw str.
        if hasattr(event_pattern, "dump"):
            try:
                event_pattern_val = event_pattern.dump()
            except Exception:
                event_pattern_val = None
        else:
            event_pattern_val = event_pattern
        event_pattern_parsed = _parse_json(event_pattern_val)

        role_arn = getattr(rule, "role_arn", None)

        # ``rule.targets`` is a ``dict[target_id, Target]`` in LocalEmu's
        # events store (a list in older moto versions). Iterating a dict
        # naively yields keys, not values, so the previous implementation
        # silently emitted an empty target list. Normalise both shapes.
        targets_raw = getattr(rule, "targets", None) or []
        if isinstance(targets_raw, dict):
            target_iter = list(targets_raw.values())
        else:
            target_iter = list(targets_raw)
        targets_out: list[dict[str, Any]] = []
        for tgt in target_iter:
            try:
                targets_out.append(self._build_target(tgt))
            except Exception:
                LOG.warning(
                    "Skipping malformed target under rule %s", rule_name, exc_info=True
                )

        attrs: dict[str, Any] = {
            "name": rule_name,
            "arn": getattr(rule, "arn", None),
            "event_bus_name": event_bus_name,
            "event_pattern": event_pattern_parsed,
            "schedule_expression": getattr(rule, "schedule_exp", None)
            or getattr(rule, "schedule_expression", None),
            "state": getattr(rule, "state", None),
            "description": getattr(rule, "description", None),
            "role_arn": _role_ref(role_arn),
            "targets": targets_out,
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="events",
            resource_type="rule",
            resource_id=rule_name,
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=_normalize_tags(getattr(rule, "tags", None)),
        )

    def _build_target(self, tgt: Any) -> dict[str, Any]:
        """Normalize a target dict (or object) to a plain dict with Refs."""
        if not isinstance(tgt, dict):
            tgt = {
                k: getattr(tgt, k, None)
                for k in (
                    "Id",
                    "Arn",
                    "Input",
                    "InputPath",
                    "InputTransformer",
                    "RoleArn",
                    "RetryPolicy",
                    "DeadLetterConfig",
                )
            }
        arn = tgt.get("Arn")
        out: dict[str, Any] = {
            "id": tgt.get("Id"),
            "arn": _target_arn_to_ref(arn) if arn else arn,
            "input": tgt.get("Input"),
            "input_path": tgt.get("InputPath"),
            "input_transformer": tgt.get("InputTransformer"),
            "role_arn": _role_ref(tgt.get("RoleArn")),
            "retry_policy": tgt.get("RetryPolicy"),
            "dead_letter_config": tgt.get("DeadLetterConfig"),
        }
        return {k: v for k, v in out.items() if v is not None}

    def _build_archive_resource(
        self, account_id: str, region: str, name: str, archive: Any
    ) -> Resource:
        """Build an archive :class:`Resource` (metadata only, no events).

        Attribute-name parity matters: moto's ``Archive`` exposes the source
        bus ARN as ``source_arn`` while LocalEmu's own ``EventsStore``
        Archive (see ``services/events/models.py``) names the same field
        ``event_source_arn``. Read whichever is present so the collector
        works against both stores.
        """
        source_arn = (getattr(archive, "event_source_arn", None)
                      or getattr(archive, "source_arn", None))
        source_ref: Any = source_arn
        if source_arn:
            bus_name = _arn_last_segment(source_arn)
            if bus_name and bus_name != "default":
                source_ref = Ref(
                    service="events",
                    resource_type="event_bus",
                    resource_id=bus_name,
                )
            # else: leave as raw ARN string. The default bus is implicit
            # in every AWS account, so we don't have an exportable
            # ``aws_cloudwatch_event_bus`` resource to reference.
        attrs: dict[str, Any] = {
            "name": name,
            "arn": getattr(archive, "arn", None),
            # Terraform's ``aws_cloudwatch_event_archive`` schema requires
            # ``event_source_arn`` — keep the IR key aligned with the TF spec
            # in ``formats/tf_specs.py`` so the attribute survives translation.
            "event_source_arn": source_ref,
            "description": getattr(archive, "description", None),
            "event_pattern": _parse_json(getattr(archive, "event_pattern", None)),
            "retention_days": getattr(archive, "retention", None)
            or getattr(archive, "retention_days", None),
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="events",
            resource_type="archive",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attrs,
        )

    def _build_api_destination_resource(
        self, account_id: str, region: str, name: str, ad: Any
    ) -> Resource:
        """Build an ``aws_cloudwatch_event_api_destination`` Resource.

        The ``connection_arn`` is rewritten to a :class:`Ref` whenever the
        target connection lives in the same store, so the IaC writers can
        emit a cross-resource reference rather than a literal ARN.
        """
        conn_arn = getattr(ad, "connection_arn", None)
        conn_ref: Any = conn_arn
        if isinstance(conn_arn, str) and conn_arn.startswith("arn:"):
            # arn:...:events:...:connection/<name>/<id>
            tail = conn_arn.split(":", 5)[-1] if conn_arn.count(":") >= 5 else ""
            if tail.startswith("connection/"):
                conn_name = tail.split("/", 2)[1] if "/" in tail else None
                if conn_name:
                    conn_ref = Ref(
                        service="events",
                        resource_type="connection",
                        resource_id=conn_name,
                    )
        rate = (getattr(ad, "_invocation_rate_limit_per_second", None)
                or getattr(ad, "invocation_rate_limit_per_second", None))
        attrs: dict[str, Any] = {
            "name": name,
            "arn": getattr(ad, "arn", None),
            "description": getattr(ad, "description", None),
            "connection_arn": conn_ref,
            "invocation_endpoint": getattr(ad, "invocation_endpoint", None),
            "http_method": getattr(ad, "http_method", None),
            "invocation_rate_limit_per_second": rate,
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="events",
            resource_type="api_destination",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attrs,
        )

    def _build_connection_resource(
        self, account_id: str, region: str, name: str, conn: Any
    ) -> Resource:
        """Build a connection :class:`Resource` (auth params will be redacted).

        Moto stores ``auth_parameters`` exactly as the AWS API serializes
        them — CamelCase keys like ``ApiKeyAuthParameters``,
        ``BasicAuthParameters``, ``OAuthParameters``. Terraform's
        ``aws_cloudwatch_event_connection`` schema, by contrast, uses
        snake_case sub-blocks ``api_key`` / ``basic`` / ``oauth`` each
        with two attributes ``key``/``value`` (api_key) or
        ``username``/``password`` (basic) or a nested ``oauth_http_parameters``
        (oauth). We translate here so the IR carries TF-shaped attributes
        and downstream HCL renders without remapping.
        """
        raw_auth = getattr(conn, "auth_parameters", None)
        tf_auth = _connection_auth_params_to_tf(raw_auth)
        attrs: dict[str, Any] = {
            "name": name,
            "arn": getattr(conn, "arn", None),
            "description": getattr(conn, "description", None),
            "authorization_type": getattr(conn, "authorization_type", None),
            # Parameters contain tokens/credentials; the central redaction pass
            # will scrub these based on key names.
            "auth_parameters": tf_auth,
        }
        attrs = {k: v for k, v in attrs.items() if v is not None}
        return Resource(
            service="events",
            resource_type="connection",
            resource_id=name,
            account_id=account_id,
            region=region,
            attributes=attrs,
        )


def _normalize_tags(tags: Any) -> dict[str, str]:
    """Normalize AWS-style ``[{Key, Value}]`` or dict tags to a ``dict[str, str]``."""
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    if isinstance(tags, list):
        out: dict[str, str] = {}
        for item in tags:
            if isinstance(item, dict) and "Key" in item:
                out[str(item["Key"])] = str(item.get("Value", ""))
        return out
    return {}
