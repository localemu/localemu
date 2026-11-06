"""Tests for the RAM moto-patching module.

Moto's RAM backend had CreateResourceShare (principals/resources inline)
but no AssociateResourceShare/DisassociateResourceShare at all. Confirmed
by an independent review that actually ran AssociateResourceShare against
unpatched moto and got a 404 - real customers call Create then Associate
as two separate steps, so the feature needs this patch to support that
real flow, not just the inline-at-create path.
"""
from __future__ import annotations

import localemu.services.ram  # noqa: F401 - triggers the patch at import


def _backend(account_id="111111111111", region="us-east-1"):
    from moto.ram.models import ram_backends

    return ram_backends[account_id][region]


class TestAssociateResourceShare:
    def test_associate_adds_a_new_principal(self):
        backend = _backend()
        share = backend.create_resource_share(name="s1")["resourceShare"]
        arn = share["resourceShareArn"]

        result = backend.associate_resource_share(arn, principals=["222222222222"])

        stored = next(r for r in backend.resource_shares if r.arn == arn)
        assert "222222222222" in stored.principals
        assert result["resourceShareAssociations"][0]["associatedEntity"] == "222222222222"
        assert result["resourceShareAssociations"][0]["associationType"] == "PRINCIPAL"
        assert result["resourceShareAssociations"][0]["status"] == "ASSOCIATED"

    def test_associate_adds_a_new_resource(self):
        backend = _backend()
        share = backend.create_resource_share(name="s2")["resourceShare"]
        arn = share["resourceShareArn"]
        subnet_arn = "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-abc123"

        backend.associate_resource_share(arn, resource_arns=[subnet_arn])

        stored = next(r for r in backend.resource_shares if r.arn == arn)
        assert subnet_arn in stored.resource_arns

    def test_associate_unknown_share_raises(self):
        from moto.ram.exceptions import UnknownResourceException

        backend = _backend()
        try:
            backend.associate_resource_share("arn:aws:ram:us-east-1:111111111111:resource-share/nope", principals=["222222222222"])
            assert False, "expected UnknownResourceException"
        except UnknownResourceException:
            pass


class TestDisassociateResourceShare:
    def test_disassociate_removes_a_principal(self):
        backend = _backend()
        share = backend.create_resource_share(name="s3", principals=["222222222222", "333333333333"])["resourceShare"]
        arn = share["resourceShareArn"]

        result = backend.disassociate_resource_share(arn, principals=["222222222222"])

        stored = next(r for r in backend.resource_shares if r.arn == arn)
        assert "222222222222" not in stored.principals
        assert "333333333333" in stored.principals  # the other principal is untouched
        assert result["resourceShareAssociations"][0]["status"] == "DISASSOCIATED"

    def test_disassociate_removes_a_resource(self):
        backend = _backend()
        subnet_arn = "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-abc123"
        share = backend.create_resource_share(name="s4", resourceArns=[subnet_arn])["resourceShare"]
        arn = share["resourceShareArn"]

        backend.disassociate_resource_share(arn, resource_arns=[subnet_arn])

        stored = next(r for r in backend.resource_shares if r.arn == arn)
        assert subnet_arn not in stored.resource_arns

    def test_disassociate_nonexistent_principal_is_a_no_op(self):
        backend = _backend()
        share = backend.create_resource_share(name="s5", principals=["222222222222"])["resourceShare"]
        arn = share["resourceShareArn"]

        backend.disassociate_resource_share(arn, principals=["999999999999"])

        stored = next(r for r in backend.resource_shares if r.arn == arn)
        assert "222222222222" in stored.principals


class TestUrlRoutesRegistered:
    def test_associate_and_disassociate_routes_exist(self):
        from moto.ram.urls import url_paths

        assert "{0}/associateresourceshare$" in url_paths
        assert "{0}/disassociateresourceshare$" in url_paths
