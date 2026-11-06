"""Tests for the moto WAFv2 "at most one Web ACL per resource" patch.

Without this patch, re-associating a different Web ACL to the same
resource without an explicit DisassociateWebACL first leaves BOTH Web
ACLs' associated_resources lists containing that resource's ARN, making
get_web_acl_for_resource's answer depend on dict insertion order rather
than which association actually happened most recently."""
from __future__ import annotations

from moto import mock_aws

from localemu.services.wafv2.patches import apply_patches


@mock_aws
def test_reassociating_a_different_web_acl_replaces_the_old_one():
    apply_patches()
    from moto.wafv2.models import wafv2_backends

    backend = wafv2_backends["123456789012"]["us-east-1"]
    acl1 = backend.create_web_acl(
        name="acl-one", visibility_config={"SampledRequestsEnabled": False,
                                           "CloudWatchMetricsEnabled": False, "MetricName": "m1"},
        default_action={"Allow": {}}, scope="REGIONAL", description="", tags=[], rules=[],
        association_config=None, captcha_config=None, challenge_config=None,
        custom_response_bodies=None, token_domains=None,
    )
    acl2 = backend.create_web_acl(
        name="acl-two", visibility_config={"SampledRequestsEnabled": False,
                                           "CloudWatchMetricsEnabled": False, "MetricName": "m2"},
        default_action={"Block": {}}, scope="REGIONAL", description="", tags=[], rules=[],
        association_config=None, captcha_config=None, challenge_config=None,
        custom_response_bodies=None, token_domains=None,
    )
    resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc"

    backend.associate_web_acl(acl1.arn, resource_arn)
    assert resource_arn in acl1.associated_resources
    assert resource_arn not in acl2.associated_resources
    assert backend.get_web_acl_for_resource(resource_arn).arn == acl1.arn

    # Re-associate WITHOUT disassociating first - the patch must make
    # this behave like real AWS (replace), not moto's raw append.
    backend.associate_web_acl(acl2.arn, resource_arn)

    assert resource_arn not in acl1.associated_resources, (
        "old association must be removed when a new one is made"
    )
    assert resource_arn in acl2.associated_resources
    resolved = backend.get_web_acl_for_resource(resource_arn)
    assert resolved is not None and resolved.arn == acl2.arn


@mock_aws
def test_first_association_still_works_normally():
    apply_patches()
    from moto.wafv2.models import wafv2_backends

    backend = wafv2_backends["123456789012"]["us-east-1"]
    acl = backend.create_web_acl(
        name="only-acl", visibility_config={"SampledRequestsEnabled": False,
                                             "CloudWatchMetricsEnabled": False, "MetricName": "m"},
        default_action={"Allow": {}}, scope="REGIONAL", description="", tags=[], rules=[],
        association_config=None, captcha_config=None, challenge_config=None,
        custom_response_bodies=None, token_domains=None,
    )
    resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/xyz"
    backend.associate_web_acl(acl.arn, resource_arn)
    assert backend.get_web_acl_for_resource(resource_arn).arn == acl.arn


@mock_aws
def test_disassociate_then_associate_elsewhere_still_works():
    apply_patches()
    from moto.wafv2.models import wafv2_backends

    backend = wafv2_backends["123456789012"]["us-east-1"]
    acl1 = backend.create_web_acl(
        name="acl-a", visibility_config={"SampledRequestsEnabled": False,
                                          "CloudWatchMetricsEnabled": False, "MetricName": "m1"},
        default_action={"Allow": {}}, scope="REGIONAL", description="", tags=[], rules=[],
        association_config=None, captcha_config=None, challenge_config=None,
        custom_response_bodies=None, token_domains=None,
    )
    acl2 = backend.create_web_acl(
        name="acl-b", visibility_config={"SampledRequestsEnabled": False,
                                          "CloudWatchMetricsEnabled": False, "MetricName": "m2"},
        default_action={"Allow": {}}, scope="REGIONAL", description="", tags=[], rules=[],
        association_config=None, captcha_config=None, challenge_config=None,
        custom_response_bodies=None, token_domains=None,
    )
    resource_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123"
    backend.associate_web_acl(acl1.arn, resource_arn)
    backend.disassociate_web_acl(resource_arn)
    assert backend.get_web_acl_for_resource(resource_arn) is None
    backend.associate_web_acl(acl2.arn, resource_arn)
    assert backend.get_web_acl_for_resource(resource_arn).arn == acl2.arn
