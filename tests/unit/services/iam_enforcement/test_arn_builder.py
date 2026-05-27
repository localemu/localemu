"""Unit tests for localemu.services.iam_enforcement.arn_builder."""

import pytest

from localemu.services.iam_enforcement.arn_builder import build_resource_arn


REGION = "us-east-1"
ACCOUNT = "000000000000"


class TestRoute53Arn:
    """Route53 HostedZoneId accepts both '/hostedzone/X' and bare 'X'.

    Route53's APIs return zone IDs prefixed with '/hostedzone/'; users pass
    them back verbatim. The ARN form is 'arn:aws:route53:::hostedzone/X'.
    The builder must strip the prefix WITHOUT mangling zone IDs whose body
    happens to contain characters from the prefix alphabet.
    """

    @pytest.mark.parametrize(
        "hosted_zone_id, expected_body",
        [
            ("/hostedzone/Z1ABC123", "Z1ABC123"),
            ("Z1ABC123", "Z1ABC123"),
            # Regression: lstrip("/hostedzone/") would mangle these because
            # 'h', 'o', 's', 't', 'e', 'd', 'z', 'n' are in the set.
            ("/hostedzone/hosted-zone-x", "hosted-zone-x"),
            ("/hostedzone/one", "one"),
            ("hoste", "hoste"),
        ],
        ids=[
            "canonical-prefixed",
            "bare-id",
            "body-shares-prefix-chars",
            "body-is-subset-of-prefix",
            "pathological-prefix-chars-only",
        ],
    )
    def test_hosted_zone_id_prefix_stripped_correctly(self, hosted_zone_id, expected_body):
        arn = build_resource_arn(
            service="route53",
            operation="GetHostedZone",
            request_params={"HostedZoneId": hosted_zone_id},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == f"arn:aws:route53:::hostedzone/{expected_body}"

    def test_missing_hosted_zone_id_uses_wildcard(self):
        arn = build_resource_arn(
            service="route53",
            operation="ListHostedZones",
            request_params={},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == "arn:aws:route53:::hostedzone/*"

    def test_id_parameter_alternative(self):
        """Some Route53 operations use 'Id' instead of 'HostedZoneId'."""
        arn = build_resource_arn(
            service="route53",
            operation="GetHostedZone",
            request_params={"Id": "/hostedzone/Z9XYZ"},
            region=REGION,
            account_id=ACCOUNT,
        )
        assert arn == "arn:aws:route53:::hostedzone/Z9XYZ"
