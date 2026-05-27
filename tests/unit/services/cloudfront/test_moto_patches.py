"""Tests for the moto-patching module.

Confirms the Origin init patch attaches ``origin_access_control_id`` and
the template patch inserts the corresponding XML element. Defensive
behaviour on shape change is exercised by replacing the moto attributes
with stand-ins that don't match the expected anchor.
"""

from __future__ import annotations

import importlib
import logging


def test_origin_init_captures_oac_field():
    """Fresh Origin(config) must carry origin_access_control_id attribute."""
    # Import triggers apply() via services.cloudfront.__init__
    import localemu.services.cloudfront  # noqa: F401
    from moto.cloudfront.models import Origin

    origin = Origin({
        "Id": "o1",
        "DomainName": "bucket.s3.amazonaws.com",
        "OriginAccessControlId": "OACZ",
    })
    assert getattr(origin, "origin_access_control_id", None) == "OACZ"


def test_origin_init_defaults_to_empty_string_when_absent():
    import localemu.services.cloudfront  # noqa: F401
    from moto.cloudfront.models import Origin

    origin = Origin({
        "Id": "o2",
        "DomainName": "origin.example.com",
        "CustomOriginConfig": {"HTTPPort": 80},
    })
    # Present but empty, so template's `{% if %}` gate skips it cleanly.
    assert origin.origin_access_control_id == ""


def test_template_contains_oac_element_after_patch():
    import localemu.services.cloudfront  # noqa: F401
    from moto.cloudfront import responses

    assert "origin.origin_access_control_id" in responses.DIST_CONFIG_TEMPLATE, (
        "DIST_CONFIG_TEMPLATE was expected to have been patched to emit "
        "<OriginAccessControlId>; patch apparently did not apply."
    )
    # Sanity: the patched element is inside the <Origin> block (not at top level).
    idx_origin = responses.DIST_CONFIG_TEMPLATE.find("<Origin>")
    idx_end = responses.DIST_CONFIG_TEMPLATE.find("</Origin>", idx_origin)
    snippet = responses.DIST_CONFIG_TEMPLATE[idx_origin:idx_end]
    assert "origin_access_control_id" in snippet, (
        "OriginAccessControlId element was patched but outside the <Origin> block"
    )


def test_apply_is_idempotent():
    """Calling apply() twice must not duplicate the XML element."""
    from localemu.services.cloudfront import _moto_patches
    from moto.cloudfront import responses

    before = responses.DIST_CONFIG_TEMPLATE.count("origin.origin_access_control_id")
    _moto_patches.apply()
    _moto_patches.apply()
    after = responses.DIST_CONFIG_TEMPLATE.count("origin.origin_access_control_id")
    assert before == after, "re-applying the patch duplicated the template insertion"


def test_apply_logs_warning_if_no_templates_match(monkeypatch, caplog):
    """If a future moto version drops the expected ``<Id>`` anchor from
    every template we know about, apply() must not raise — just log and
    move on. The wrapper's request-payload binding still works.
    """
    from localemu.services.cloudfront import _moto_patches
    from moto.cloudfront import responses as cf_responses

    # Replace every template moto exposes with a body that lacks the anchor.
    bare = "<Origins><Items></Items></Origins>"
    for attr in (
        "DIST_CONFIG_TEMPLATE", "DISTRIBUTION_TEMPLATE",
        "CREATE_DISTRIBUTION_TEMPLATE", "GET_DISTRIBUTION_TEMPLATE",
        "GET_DISTRIBUTION_CONFIG_TEMPLATE", "LIST_TEMPLATE",
        "UPDATE_DISTRIBUTION_TEMPLATE",
    ):
        monkeypatch.setattr(cf_responses, attr, bare)
    monkeypatch.setattr(_moto_patches, "_applied", False)

    with caplog.at_level(logging.WARNING,
                         logger="localemu.services.cloudfront._moto_patches"):
        _moto_patches.apply()

    # Must not raise. Exactly one warning covering the no-op condition.
    assert any("no cloudfront templates were patched" in rec.message.lower()
               for rec in caplog.records), (
        "expected a no-templates-matched warning; got: "
        + repr([rec.message for rec in caplog.records])
    )
