"""SESv2 provider — reuses the v1 backend store + retrospection mailbox.

Implemented (real, no mocks):
  - SendEmail (Simple / Raw / Template) with the rendered message saved
    to ``/_aws/ses`` so v2 sends show up alongside v1 sends in the
    retrospection mailbox.
  - Lightweight v1 helper reuse so we don't fork the mailbox writer,
    raw-MIME parser, or the SES backend store.

NOT implemented in v1 (delegated to moto via MotoFallbackDispatcher):
  - Configuration set + event destination CRUD (moto sesv2 handles it
    but does not dispatch the SNS/Firehose events; that's a follow-up).
  - Suppression list (Put/Get/Delete/List) — accepted via moto.
  - SendBulkEmail — moto returns OK without iterating; follow-up.
  - Dedicated IP warmup simulation, VDM, BYODKIM signing — accepted
    via moto and treated as opaque storage.

When a verb isn't overridden here it falls through to moto's sesv2
backend, so callers always get an AWS-shaped 200 OK; new behaviour
lands incrementally as we override more methods.
"""

from __future__ import annotations

import base64
import json
import logging

from localemu.aws.api import RequestContext
from localemu.aws.api.sesv2 import (
    AmazonResourceName,
    ConfigurationSetName,
    Destination,
    EmailAddress,
    EmailContent,
    EndpointId,
    ListManagementOptions,
    MessageTagList,
    SendEmailResponse,
    Sesv2Api,
)
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.ses.models import EmailType, SentEmail, SentEmailBody
from localemu.services.ses.provider import (
    SesProvider,
    get_ses_backend,
    register_ses_api_resource,
    save_for_retrospection,
)
from localemu.services.sesv2.adapters import (
    RawSend,
    SimpleSend,
    TemplateSend,
    UnsupportedSendShape,
    normalize_send_request,
    template_v1_to_v2,
    template_v2_to_v1,
)
from localemu.state import StateVisitor
from localemu.utils.strings import to_str

LOG = logging.getLogger(__name__)


class Sesv2Provider(Sesv2Api, ServiceLifecycleHook):
    """SESv2 implementation that shares state with the v1 SES backend.

    The SESv2 control-plane verbs (config sets, identities, templates,
    suppression list) flow through moto via ``MotoFallbackDispatcher``;
    we override the data-plane operations where moto's sesv2 path either
    drops information (Simple sends lose the unused body half) or is
    explicitly unimplemented (Template sends raise NotImplementedError).
    """

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.sesv2.models import sesv2_backends

        visitor.visit(sesv2_backends)

    def on_after_init(self):
        # Defensive: register the /_aws/ses retrospection endpoint even if
        # the v1 SES provider hasn't loaded yet. The helper itself is
        # idempotent via ``_EMAILS_ENDPOINT_REGISTERED``.
        try:
            register_ses_api_resource()
        except Exception:
            LOG.debug("v2 SES retrospection endpoint registration deferred", exc_info=True)

    # ------------------------------------------------------------------
    # SendEmail (Simple / Raw / Template)
    # ------------------------------------------------------------------
    def send_email(
        self,
        context: RequestContext,
        content: EmailContent,
        from_email_address: EmailAddress | None = None,
        from_email_address_identity_arn: AmazonResourceName | None = None,
        destination: Destination | None = None,
        reply_to_addresses: list[str] | None = None,
        feedback_forwarding_email_address: EmailAddress | None = None,
        feedback_forwarding_email_address_identity_arn: AmazonResourceName | None = None,
        email_tags: MessageTagList | None = None,
        configuration_set_name: ConfigurationSetName | None = None,
        endpoint_id: EndpointId | None = None,
        tenant_name: str | None = None,
        list_management_options: ListManagementOptions | None = None,
        **kwargs,
    ) -> SendEmailResponse:
        request = {
            "FromEmailAddress": from_email_address,
            "Destination": destination or {},
            "Content": content or {},
            "ReplyToAddresses": reply_to_addresses,
            "EmailTags": email_tags,
            "ConfigurationSetName": configuration_set_name,
        }
        try:
            kind = normalize_send_request(request)
        except UnsupportedSendShape as e:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "BadRequestException", str(e), status_code=400,
            )

        if isinstance(kind, SimpleSend):
            return self._send_simple(context, kind)
        if isinstance(kind, RawSend):
            return self._send_raw(context, kind)
        if isinstance(kind, TemplateSend):
            return self._send_template(context, kind)
        raise RuntimeError(f"unreachable: unknown send kind {kind!r}")

    # ------------------------------------------------------------------
    # Per-variant implementations
    # ------------------------------------------------------------------
    def _send_simple(
        self, context: RequestContext, send: SimpleSend,
    ) -> SendEmailResponse:
        """Simple send — pass both text + html through to the mailbox so
        the retrospection UI can render either. moto's sesv2 keeps only
        one of them; we work around that by talking to the v1 backend
        directly (the two share the same store via the ``core_backend``
        attribute on moto.sesv2.models.SESV2Backend)."""
        ses_backend = get_ses_backend(context)
        body = send.html_data or send.text_data or ""
        destination_dict = {
            "ToAddresses": (send.destination or {}).get("ToAddresses", []),
            "CcAddresses": (send.destination or {}).get("CcAddresses", []),
            "BccAddresses": (send.destination or {}).get("BccAddresses", []),
        }
        message = ses_backend.send_email(
            source=send.source,
            subject=send.subject_data,
            body=body,
            destinations=destination_dict,
        )
        save_for_retrospection(
            SentEmail(
                Id=message.id,
                Region=context.region,
                Destination=destination_dict,
                Source=send.source,
                Subject=send.subject_data,
                Body=SentEmailBody(
                    text_part=send.text_data,
                    html_part=send.html_data,
                ),
            )
        )
        return SendEmailResponse(MessageId=message.id)

    def _send_raw(
        self, context: RequestContext, send: RawSend,
    ) -> SendEmailResponse:
        """Raw send — derive Source from the MIME headers when the caller
        omitted ``FromEmailAddress``, then mirror v1's send_raw_email."""
        raw_str = base64.b64decode(send.raw_data).decode("utf-8") if (
            isinstance(send.raw_data, (bytes, bytearray)) and _looks_like_b64(send.raw_data)
        ) else to_str(send.raw_data)
        source = send.source
        if not (source or "").strip():
            source = SesProvider().get_source_from_raw(raw_str)
            if not source:
                from localemu.aws.api import CommonServiceException

                raise CommonServiceException(
                    "BadRequestException",
                    "FromEmailAddress is required when the raw MIME has no From header.",
                    status_code=400,
                )
        ses_backend = get_ses_backend(context)
        message = ses_backend.send_raw_email(
            source=source,
            destinations=send.destinations,
            raw_data=raw_str,
        )
        save_for_retrospection(
            SentEmail(
                Id=message.id,
                Region=context.region,
                Source=source,
                RawData=raw_str,
            )
        )
        return SendEmailResponse(MessageId=message.id)

    def _send_template(
        self, context: RequestContext, send: TemplateSend,
    ) -> SendEmailResponse:
        """Template send — render the v1 template store entry through
        moto's parse_template (Handlebars-style) so both the template
        variables and the rendered output land in the mailbox."""
        ses_backend = get_ses_backend(context)
        template = ses_backend.templates.get(send.template_name)
        if template is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Template {send.template_name!r} does not exist.",
                status_code=404,
            )
        try:
            data = json.loads(send.template_data or "{}")
        except json.JSONDecodeError:
            data = {}
        subject = _render(template.get("subject_part") or "", data)
        text = _render(template.get("text_part") or "", data)
        html = _render(template.get("html_part") or "", data)

        destination_dict = {
            "ToAddresses": (send.destination or {}).get("ToAddresses", []),
            "CcAddresses": (send.destination or {}).get("CcAddresses", []),
            "BccAddresses": (send.destination or {}).get("BccAddresses", []),
        }
        message = ses_backend.send_email(
            source=send.source,
            subject=subject,
            body=html or text or "",
            destinations=destination_dict,
        )
        save_for_retrospection(
            SentEmail(
                Id=message.id,
                Region=context.region,
                Source=send.source,
                Destination=destination_dict,
                Template=send.template_name,
                TemplateData=send.template_data,
                Subject=subject,
                Body=SentEmailBody(text_part=text, html_part=html),
            )
        )
        return SendEmailResponse(MessageId=message.id)


    # ------------------------------------------------------------------
    # Template CRUD — store on the v1 backend so v1 SendTemplatedEmail
    # and v2 SendEmail(Template) share the same template dictionary.
    # moto's sesv2 backend itself doesn't expose template ops, so the
    # fallback dispatcher can't help us here; the implementations all
    # piggyback on v1's ``backend.templates`` map.
    # ------------------------------------------------------------------
    def create_email_template(
        self,
        context: RequestContext,
        template_name,
        template_content,
        tags=None,
        **kwargs,
    ):
        backend = get_ses_backend(context)
        if template_name in backend.templates:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "AlreadyExistsException",
                f"Template {template_name!r} already exists.",
                status_code=400,
            )
        backend.templates[template_name] = template_v2_to_v1(
            template_name, template_content or {},
        )
        return {}

    def update_email_template(
        self,
        context: RequestContext,
        template_name,
        template_content,
        **kwargs,
    ):
        backend = get_ses_backend(context)
        if template_name not in backend.templates:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Template {template_name!r} does not exist.",
                status_code=404,
            )
        backend.templates[template_name] = template_v2_to_v1(
            template_name, template_content or {},
        )
        return {}

    def get_email_template(
        self, context: RequestContext, template_name, **kwargs,
    ):
        backend = get_ses_backend(context)
        template = backend.templates.get(template_name)
        if template is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Template {template_name!r} does not exist.",
                status_code=404,
            )
        return template_v1_to_v2(template)

    def delete_email_template(
        self, context: RequestContext, template_name, **kwargs,
    ):
        backend = get_ses_backend(context)
        backend.templates.pop(template_name, None)
        return {}

    def list_email_templates(
        self,
        context: RequestContext,
        next_token=None,
        page_size=None,
        **kwargs,
    ):
        backend = get_ses_backend(context)
        templates = [
            {
                "TemplateName": name,
                "CreatedTimestamp": None,  # moto v1 doesn't track this
            }
            for name in backend.templates.keys()
        ]
        return {"TemplatesMetadata": templates}

    def test_render_email_template(
        self,
        context: RequestContext,
        template_name,
        template_data,
        **kwargs,
    ):
        backend = get_ses_backend(context)
        template = backend.templates.get(template_name)
        if template is None:
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Template {template_name!r} does not exist.",
                status_code=404,
            )
        try:
            data = json.loads(template_data or "{}")
        except json.JSONDecodeError:
            data = {}
        rendered = "\r\n".join(
            filter(None, [
                _render(template.get("subject_part") or "", data),
                _render(template.get("text_part") or "", data),
                _render(template.get("html_part") or "", data),
            ])
        )
        return {"RenderedTemplate": rendered}


def _render(template_str: str, data: dict) -> str:
    """Render a Handlebars-style template using moto's ``parse_template``.

    Moto's helper handles ``{{var}}``, ``{{#each list}}``, and
    ``{{#if cond}}`` — the same subset SES uses on the real service.
    Missing variables resolve to empty strings (matches the AWS
    permissive contract; SES doesn't 4xx on a stray placeholder).
    """
    if not template_str:
        return ""
    try:
        from moto.ses.template import parse_template

        return parse_template(template_str, data)
    except Exception:
        LOG.debug("Template render failed; falling back to raw text", exc_info=True)
        return template_str


def _looks_like_b64(data: bytes) -> bool:
    """Cheap check: a base64-encoded payload contains only the b64
    alphabet. boto3 may hand us either already-decoded bytes or the
    base64 form depending on serialiser settings."""
    try:
        return all(
            chr(b) in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n "
            )
            for b in data[:64]
        )
    except Exception:
        return False
