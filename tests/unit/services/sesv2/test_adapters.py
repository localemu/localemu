"""SESv2 → v1 wire-shape adapter — pure-function unit tests.

Every SendEmail variant (Simple / Raw / Template) must normalise to a
SendKind dataclass without losing fields. The negative paths (missing
``Content``, unknown branch) need to raise :class:`UnsupportedSendShape`
so the provider can surface an AWS-shaped ``BadRequestException`` to
the caller instead of swallowing the malformed request.
"""

from __future__ import annotations

import pytest

from localemu.services.sesv2.adapters import (
    RawSend,
    SimpleSend,
    TemplateSend,
    UnsupportedSendShape,
    normalize_send_request,
    template_v1_to_v2,
    template_v2_to_v1,
)


class TestSimpleSend:
    def test_subject_and_both_bodies_preserved(self):
        kind = normalize_send_request({
            "FromEmailAddress": "alice@example.com",
            "Destination": {"ToAddresses": ["bob@example.com"]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": "hi"},
                    "Body": {
                        "Text": {"Data": "plain"},
                        "Html": {"Data": "<p>html</p>"},
                    },
                }
            },
        })
        assert isinstance(kind, SimpleSend)
        assert kind.source == "alice@example.com"
        assert kind.subject_data == "hi"
        assert kind.text_data == "plain"
        assert kind.html_data == "<p>html</p>"
        assert kind.destination["ToAddresses"] == ["bob@example.com"]

    def test_simple_with_only_text(self):
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": "s"},
                    "Body": {"Text": {"Data": "only-text"}},
                }
            },
        })
        assert kind.text_data == "only-text"
        assert kind.html_data is None

    def test_simple_with_email_tags_passthrough(self):
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": "s"},
                    "Body": {"Text": {"Data": "t"}},
                }
            },
            "EmailTags": [{"Name": "campaign", "Value": "spring24"}],
        })
        assert kind.tags == [{"Name": "campaign", "Value": "spring24"}]


class TestRawSend:
    def test_raw_decodes_bytes_and_flattens_destinations(self):
        raw = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: hi\r\n\r\nbody"
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {
                "ToAddresses": ["c@d.com"],
                "CcAddresses": ["e@f.com"],
                "BccAddresses": ["g@h.com"],
            },
            "Content": {"Raw": {"Data": raw}},
        })
        assert isinstance(kind, RawSend)
        assert kind.raw_data == raw
        assert kind.destinations == ["c@d.com", "e@f.com", "g@h.com"]
        assert kind.source == "a@b.com"

    def test_raw_str_data_is_encoded(self):
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {"Raw": {"Data": "From: a@b.com\r\nSubject: x\r\n\r\nb"}},
        })
        assert isinstance(kind.raw_data, bytes)

    def test_raw_without_from_keeps_source_none(self):
        # The provider derives Source from MIME headers when this is the case.
        kind = normalize_send_request({
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {"Raw": {"Data": b"From: x@y.com\r\n\r\n"}},
        })
        assert isinstance(kind, RawSend)
        assert kind.source is None


class TestTemplateSend:
    def test_template_carries_name_and_data(self):
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {
                "Template": {
                    "TemplateName": "welcome",
                    "TemplateData": '{"name": "World"}',
                }
            },
        })
        assert isinstance(kind, TemplateSend)
        assert kind.template_name == "welcome"
        assert kind.template_data == '{"name": "World"}'

    def test_template_data_defaults_to_empty_object(self):
        kind = normalize_send_request({
            "FromEmailAddress": "a@b.com",
            "Destination": {"ToAddresses": ["c@d.com"]},
            "Content": {"Template": {"TemplateName": "t"}},
        })
        assert kind.template_data == "{}"


class TestErrors:
    def test_missing_content_raises(self):
        with pytest.raises(UnsupportedSendShape):
            normalize_send_request({"FromEmailAddress": "a@b.com"})

    def test_empty_content_raises(self):
        with pytest.raises(UnsupportedSendShape):
            normalize_send_request({"Content": {}})

    def test_unknown_branch_raises(self):
        with pytest.raises(UnsupportedSendShape):
            normalize_send_request({"Content": {"Unknown": {}}})


class TestTemplateShapeRoundTrip:
    def test_v1_to_v2(self):
        v1 = {
            "template_name": "t",
            "subject_part": "Hi {{name}}",
            "text_part": "Hello {{name}}",
            "html_part": "<p>{{name}}</p>",
        }
        v2 = template_v1_to_v2(v1)
        assert v2["TemplateName"] == "t"
        assert v2["TemplateContent"]["Subject"] == "Hi {{name}}"
        assert v2["TemplateContent"]["Text"] == "Hello {{name}}"
        assert v2["TemplateContent"]["Html"] == "<p>{{name}}</p>"

    def test_v2_to_v1(self):
        v1 = template_v2_to_v1("t", {
            "Subject": "Hi", "Text": "T", "Html": "<p>H</p>",
        })
        assert v1 == {
            "template_name": "t",
            "subject_part": "Hi",
            "text_part": "T",
            "html_part": "<p>H</p>",
        }
