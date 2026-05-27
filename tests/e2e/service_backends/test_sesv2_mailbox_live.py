"""Live E2E for SESv2 — Simple / Raw / Template all visible in /_aws/ses.

The previous moto-only stub silently lost the unused body half on
Simple sends, raised NotImplementedError for Template sends, and never
wrote anything to the retrospection mailbox. This test exercises the
new provider against a real LocalEmu and asserts each of the three
SendEmail variants produces a mailbox entry with the expected shape.
"""

import base64
import json
import sys
import uuid

import boto3
import requests

ENDPOINT = "http://localhost:4566"
KW = dict(
    endpoint_url=ENDPOINT,
    region_name="us-east-1",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

sesv2 = boto3.client("sesv2", **KW)

# 1. Verify the sender identity once
sender = f"sender-{uuid.uuid4().hex[:8]}@example.com"
try:
    sesv2.create_email_identity(EmailIdentity=sender)
except sesv2.exceptions.AlreadyExistsException:
    pass

# 2. Simple send — both text and html bodies
simple_subject = f"hello-{uuid.uuid4().hex[:8]}"
resp = sesv2.send_email(
    FromEmailAddress=sender,
    Destination={"ToAddresses": ["recip@example.com"]},
    Content={
        "Simple": {
            "Subject": {"Data": simple_subject},
            "Body": {
                "Text": {"Data": "plain-text-body"},
                "Html": {"Data": "<p>html-body</p>"},
            },
        },
    },
)
simple_id = resp["MessageId"]
print(f"Simple send -> {simple_id}")

# 3. Raw send — From header in the MIME body, no FromEmailAddress param
raw_subject = f"raw-{uuid.uuid4().hex[:8]}"
raw_body = (
    f"From: {sender}\r\n"
    f"To: r@x.com\r\n"
    f"Subject: {raw_subject}\r\n"
    f"\r\nraw body line\r\n"
).encode("utf-8")
resp = sesv2.send_email(
    Destination={"ToAddresses": ["r@x.com"]},
    Content={"Raw": {"Data": raw_body}},
)
raw_id = resp["MessageId"]
print(f"Raw send -> {raw_id}")

# 4. Template send — create a template, then SendEmail with TemplateData
tpl_name = f"tpl-{uuid.uuid4().hex[:8]}"
sesv2.create_email_template(
    TemplateName=tpl_name,
    TemplateContent={
        "Subject": "Hello {{name}}",
        "Html": "<p>Hi {{name}}, your code is {{code}}</p>",
        "Text": "Hi {{name}}, your code is {{code}}",
    },
)
resp = sesv2.send_email(
    FromEmailAddress=sender,
    Destination={"ToAddresses": ["dst@example.com"]},
    Content={
        "Template": {
            "TemplateName": tpl_name,
            "TemplateData": json.dumps({"name": "Alice", "code": "42"}),
        },
    },
)
tpl_id = resp["MessageId"]
print(f"Template send -> {tpl_id}")

# 5. Retrospection — pull /_aws/ses and check each landed
mailbox_url = f"{ENDPOINT}/_aws/ses"
got = requests.get(mailbox_url, timeout=5).json()
messages = got.get("messages") or []
by_id = {m.get("Id"): m for m in messages}
print(f"mailbox has {len(messages)} messages")

simple_msg = by_id.get(simple_id)
raw_msg = by_id.get(raw_id)
tpl_msg = by_id.get(tpl_id)

fail = []
if simple_msg is None:
    fail.append(f"Simple {simple_id} missing from mailbox")
else:
    if simple_msg.get("Subject") != simple_subject:
        fail.append(f"Simple subject mismatch: {simple_msg.get('Subject')!r}")
    body = simple_msg.get("Body") or {}
    if body.get("text_part") != "plain-text-body":
        fail.append(f"Simple text_part missing: {body!r}")
    if body.get("html_part") != "<p>html-body</p>":
        fail.append(f"Simple html_part missing: {body!r}")

if raw_msg is None:
    fail.append(f"Raw {raw_id} missing from mailbox")
else:
    raw_data = raw_msg.get("RawData", "")
    if raw_subject not in raw_data:
        fail.append("Raw subject not in RawData")
    if raw_msg.get("Source") != sender:
        fail.append(f"Raw Source not derived: {raw_msg.get('Source')!r}")

if tpl_msg is None:
    fail.append(f"Template {tpl_id} missing from mailbox")
else:
    if tpl_msg.get("Template") != tpl_name:
        fail.append(f"Template name not recorded: {tpl_msg.get('Template')!r}")
    subj = tpl_msg.get("Subject") or ""
    if subj != "Hello Alice":
        fail.append(f"Template subject not rendered: {subj!r}")
    body = tpl_msg.get("Body") or {}
    if body.get("html_part") != "<p>Hi Alice, your code is 42</p>":
        fail.append(f"Template html_part not rendered: {body!r}")

if fail:
    print("\nFAIL:")
    for f in fail:
        print(" -", f)
    sys.exit(1)
print("\nPASS: SESv2 SendEmail covers Simple / Raw / Template "
      "and each variant lands in the retrospection mailbox with the expected shape.")
