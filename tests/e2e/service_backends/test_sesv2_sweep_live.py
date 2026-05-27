"""Extensive SESv2 regression — covers the surface beyond simple SendEmail.

  * SendEmail with malformed Content (no Simple/Raw/Template) → 4xx
  * Template SendEmail referencing unknown template → NotFoundException
  * CreateEmailTemplate duplicate → AlreadyExistsException
  * GetEmailTemplate / UpdateEmailTemplate / DeleteEmailTemplate happy path
  * ListEmailTemplates includes new entries
  * TestRenderEmailTemplate renders all three parts
  * SendEmail(Raw) with missing FromEmailAddress AND no From: header → 4xx
  * Identity surface still works via moto fallback
"""

import json
import sys
import uuid

import boto3
import botocore.exceptions
import requests

ENDPOINT = "http://localhost:4566"
KW = dict(endpoint_url=ENDPOINT, region_name="us-east-1",
          aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
          aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
ses = boto3.client("sesv2", **KW)
uid = uuid.uuid4().hex[:8]
failures = []
report = []


def t(name, fn):
    try:
        fn()
        report.append(f"  PASS: {name}")
    except AssertionError as e:
        report.append(f"  FAIL: {name} — {e}")
        failures.append((name, str(e)))
    except Exception as e:
        report.append(f"  ERROR: {name} — {type(e).__name__}: {e}")
        failures.append((name, f"{type(e).__name__}: {e}"))


_SENDER = None


def _ensure_sender():
    global _SENDER
    if _SENDER is None:
        _SENDER = f"send-{uid}@example.com"
        try:
            ses.create_email_identity(EmailIdentity=_SENDER)
        except ses.exceptions.AlreadyExistsException:
            pass
    return _SENDER


# ---------------------------------------------------------------------------
# 1. Malformed Content rejected
# ---------------------------------------------------------------------------
def send_email_no_simple_raw_or_template():
    """Either the boto3 client validates Content keys client-side
    (ParamValidationError) OR the server returns a 4xx — both are
    acceptable rejections. The bug we'd care about is silent acceptance."""
    sender = _ensure_sender()
    try:
        ses.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": ["x@y.com"]},
            Content={"Unknown": {}},
        )
    except botocore.exceptions.ParamValidationError:
        return  # client-side rejection — fine
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        assert code in ("BadRequestException", "ValidationException",
                        "MessageRejected"), f"wrong code: {code}"
        return
    raise AssertionError("malformed Content was accepted with 200")


def send_email_completely_empty_content():
    sender = _ensure_sender()
    try:
        ses.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": ["x@y.com"]},
            Content={},
        )
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] in (
            "BadRequestException", "ValidationException", "MessageRejected",
        )
        return
    raise AssertionError("empty Content was accepted with 200")


# ---------------------------------------------------------------------------
# 2. Template CRUD
# ---------------------------------------------------------------------------
def template_crud_round_trip():
    name = f"crud-{uid}"
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={
            "Subject": "S {{x}}",
            "Text": "T {{x}}",
            "Html": "<p>H {{x}}</p>",
        },
    )
    got = ses.get_email_template(TemplateName=name)
    assert got["TemplateName"] == name
    assert got["TemplateContent"]["Subject"] == "S {{x}}"
    # Update changes the body.
    ses.update_email_template(
        TemplateName=name,
        TemplateContent={
            "Subject": "S2 {{x}}", "Text": "T2 {{x}}", "Html": "<p>H2 {{x}}</p>",
        },
    )
    got = ses.get_email_template(TemplateName=name)
    assert got["TemplateContent"]["Subject"] == "S2 {{x}}"
    # List surfaces.
    listed = ses.list_email_templates()
    names = [t["TemplateName"] for t in listed.get("TemplatesMetadata", [])]
    assert name in names, f"{name} not in list"
    # Delete.
    ses.delete_email_template(TemplateName=name)
    try:
        ses.get_email_template(TemplateName=name)
        raise AssertionError("Get after Delete still succeeded")
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] == "NotFoundException"


def template_duplicate_create_rejected():
    name = f"dup-{uid}"
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={"Subject": "x", "Text": "x", "Html": "<p>x</p>"},
    )
    try:
        ses.create_email_template(
            TemplateName=name,
            TemplateContent={"Subject": "y", "Text": "y", "Html": "<p>y</p>"},
        )
        ses.delete_email_template(TemplateName=name)
        raise AssertionError("duplicate Create succeeded")
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] == "AlreadyExistsException"
    ses.delete_email_template(TemplateName=name)


def send_email_template_unknown_404():
    sender = _ensure_sender()
    try:
        ses.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": ["x@y.com"]},
            Content={"Template": {"TemplateName": f"nope-{uid}",
                                  "TemplateData": "{}"}},
        )
    except botocore.exceptions.ClientError as e:
        assert e.response["Error"]["Code"] == "NotFoundException"
        return
    raise AssertionError("SendEmail with unknown template returned 200")


# ---------------------------------------------------------------------------
# 3. TestRenderEmailTemplate renders all parts
# ---------------------------------------------------------------------------
def test_render_email_template_renders():
    name = f"render-{uid}"
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={
            "Subject": "Hello {{n}}",
            "Text": "T {{n}}",
            "Html": "<p>H {{n}}</p>",
        },
    )
    try:
        got = ses.test_render_email_template(
            TemplateName=name,
            TemplateData=json.dumps({"n": "World"}),
        )
        rendered = got.get("RenderedTemplate") or ""
        assert "Hello World" in rendered, f"subject not rendered: {rendered}"
        assert "T World" in rendered, f"text not rendered: {rendered}"
        assert "<p>H World</p>" in rendered, f"html not rendered: {rendered}"
    finally:
        ses.delete_email_template(TemplateName=name)


# ---------------------------------------------------------------------------
# 4. Raw email with no From: header AND no FromEmailAddress -> 4xx
# ---------------------------------------------------------------------------
def raw_without_any_source_4xx():
    try:
        ses.send_email(
            Destination={"ToAddresses": ["r@x.com"]},
            Content={"Raw": {"Data": b"To: r@x.com\r\nSubject: hi\r\n\r\nbody"}},
        )
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        assert code in (
            "BadRequestException", "ValidationException", "MessageRejected",
        ), f"wrong code: {code}"
        return
    raise AssertionError("Raw email with no From: header was accepted")


# ---------------------------------------------------------------------------
# 5. Mailbox snapshot contains every variant — re-confirm
# ---------------------------------------------------------------------------
def mailbox_endpoint_responds():
    r = requests.get(f"{ENDPOINT}/_aws/ses", timeout=5)
    assert r.status_code == 200, r.status_code
    body = r.json()
    assert "messages" in body, body
    assert isinstance(body["messages"], list)


TESTS = [
    ("validation: malformed Content rejected", send_email_no_simple_raw_or_template),
    ("validation: empty Content rejected", send_email_completely_empty_content),
    ("template: CRUD round-trip", template_crud_round_trip),
    ("template: duplicate Create -> AlreadyExists", template_duplicate_create_rejected),
    ("template: SendEmail unknown template -> NotFound", send_email_template_unknown_404),
    ("template: TestRender renders subject+text+html", test_render_email_template_renders),
    ("raw: no source anywhere -> 4xx", raw_without_any_source_4xx),
    ("surface: /_aws/ses mailbox endpoint responds", mailbox_endpoint_responds),
]
for n, fn in TESTS:
    t(n, fn)

print("\n".join(report))
print(f"\n{len(TESTS) - len(failures)}/{len(TESTS)} passed")
if failures:
    print("\nFAILURES:")
    for n, e in failures:
        print(f"  - {n}: {e}")
    sys.exit(1)
