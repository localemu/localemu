"""Translate SESv2 wire shapes into the flat v1 shapes the moto SES
backend + LocalEmu v1 retrospection helpers already understand.

SESv2 nests its sending parameters under ``Content`` (Simple / Raw /
Template), while v1 keeps them flat (``Source``, ``Destination``,
``Message``, ``RawMessage``). This module is pure-function — every
adapter takes a v2 request dict and returns either a :class:`SimpleSend`,
:class:`RawSend`, or :class:`TemplateSend` dataclass that the provider
hands to the v1 helpers verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SimpleSend:
    """Normalised v2 SendEmail with ``Content.Simple``."""

    source: str
    destination: dict
    subject_data: str
    text_data: str | None
    html_data: str | None
    reply_to: list[str] | None
    tags: list[dict] | None
    config_set: str | None


@dataclass
class RawSend:
    """Normalised v2 SendEmail with ``Content.Raw``."""

    source: str | None
    destinations: list[str]
    raw_data: bytes
    config_set: str | None
    tags: list[dict] | None


@dataclass
class TemplateSend:
    """Normalised v2 SendEmail with ``Content.Template``."""

    source: str
    destination: dict
    template_name: str
    template_data: str
    tags: list[dict] | None
    config_set: str | None


class UnsupportedSendShape(ValueError):
    """Raised when the v2 SendEmail content carries no recognised branch."""


def normalize_send_request(req: dict) -> SimpleSend | RawSend | TemplateSend:
    """Turn a SESv2 SendEmail input dict into one of the SendKind variants.

    The v2 API allows exactly one of ``Simple`` / ``Raw`` / ``Template``
    under ``Content``; anything else is a malformed request which we
    surface as :class:`UnsupportedSendShape` so the caller can map it
    to an AWS-shaped ``BadRequestException``.
    """
    if not req or "Content" not in req:
        raise UnsupportedSendShape("SendEmail input missing 'Content'")
    content = req["Content"] or {}

    if "Simple" in content:
        simple = content["Simple"] or {}
        subject = (simple.get("Subject") or {}).get("Data") or ""
        body = simple.get("Body") or {}
        text = (body.get("Text") or {}).get("Data")
        html = (body.get("Html") or {}).get("Data")
        return SimpleSend(
            source=req.get("FromEmailAddress") or "",
            destination=req.get("Destination") or {},
            subject_data=subject,
            text_data=text,
            html_data=html,
            reply_to=req.get("ReplyToAddresses"),
            tags=_v2_tags_to_v1(req.get("EmailTags")),
            config_set=req.get("ConfigurationSetName"),
        )

    if "Raw" in content:
        raw_data = (content["Raw"] or {}).get("Data") or b""
        if isinstance(raw_data, str):
            raw_data = raw_data.encode("utf-8")
        destinations = _flatten_destination(req.get("Destination") or {})
        return RawSend(
            source=req.get("FromEmailAddress"),
            destinations=destinations,
            raw_data=raw_data,
            config_set=req.get("ConfigurationSetName"),
            tags=_v2_tags_to_v1(req.get("EmailTags")),
        )

    if "Template" in content:
        tpl = content["Template"] or {}
        return TemplateSend(
            source=req.get("FromEmailAddress") or "",
            destination=req.get("Destination") or {},
            template_name=tpl.get("TemplateName") or "",
            template_data=tpl.get("TemplateData") or "{}",
            tags=_v2_tags_to_v1(req.get("EmailTags")),
            config_set=req.get("ConfigurationSetName"),
        )

    raise UnsupportedSendShape(
        "SendEmail Content must include one of Simple / Raw / Template"
    )


def _v2_tags_to_v1(tags: list[dict] | None) -> list[dict] | None:
    """v1 and v2 use the same ``MessageTag{Name,Value}`` shape — this
    helper exists as a single place to extend later if AWS diverges them.
    """
    if not tags:
        return None
    return [
        {"Name": t.get("Name", ""), "Value": t.get("Value", "")}
        for t in tags
    ]


def _flatten_destination(destination: dict) -> list[str]:
    """Same logic as v1's ``recipients_from_destination`` — duplicated
    here only so the adapter is importable without pulling in the entire
    v1 provider module at import time (avoids a cycle when both providers
    instantiate)."""
    return list(
        (destination.get("ToAddresses") or [])
        + (destination.get("CcAddresses") or [])
        + (destination.get("BccAddresses") or [])
    )


def template_v1_to_v2(template: dict[str, Any]) -> dict[str, Any]:
    """Wrap moto v1's flat template dict in the v2 ``TemplateContent``
    shape so GetEmailTemplate / ListEmailTemplates can return it
    verbatim."""
    return {
        "TemplateName": template.get("template_name", ""),
        "TemplateContent": {
            "Subject": template.get("subject_part") or "",
            "Text": template.get("text_part") or "",
            "Html": template.get("html_part") or "",
        },
    }


def template_v2_to_v1(name: str, content: dict[str, Any]) -> dict[str, str]:
    """Inverse of :func:`template_v1_to_v2` — the shape moto stores."""
    return {
        "template_name": name,
        "subject_part": content.get("Subject") or "",
        "text_part": content.get("Text") or "",
        "html_part": content.get("Html") or "",
    }
