"""EC2 / VPC collector.

Exports the networking objects that make up a VPC: the VPC itself,
subnets, security groups (plus the rules that hang off them, emitted as
first-class ``security_group_rule`` resources — the AWS provider has
deprecated inline ingress/egress on ``aws_security_group``), route
tables, routes and route-table associations, internet gateways, NAT
gateways, elastic IPs, VPC endpoints, network ACLs (plus their rule
entries and subnet associations), VPC peering connections, and key
pairs.

EC2 **instances** are deliberately skipped: LocalEmu backs instances with
ephemeral Docker containers, and the runtime state (AMI id, user-data,
security-group membership) does not round-trip cleanly to a real-AWS
launch template. Exporting a stale pseudo-instance would generate
plan-time errors on every subsequent ``terraform apply``. The orchestrator
records each skipped instance in MANIFEST.md via the exporter's
unsupported list; see :meth:`_record_unsupported_instances` below.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Iterable

from localemu.export.collectors import BaseCollector, register_collector
from localemu.export.ir import Ref, Resource

LOG = logging.getLogger(__name__)


def _tags(obj: Any) -> dict[str, str]:
    """Extract the moto tag list from ``obj`` into a ``{key: value}`` dict.

    Moto stores tags as a list of ``{"Key": ..., "Value": ...}`` rows
    keyed against the ``describe_tags`` backend call. We swallow any
    failure so a broken tag row can't stop the export.
    """
    try:
        rows = obj.get_tags() if hasattr(obj, "get_tags") else []
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, str] = {}
    for row in rows or []:
        key = row.get("key") or row.get("Key")
        value = row.get("value") or row.get("Value")
        if key is None:
            continue
        out[str(key)] = "" if value is None else str(value)
    return out


def _vpc_ref(vpc_id: str | None) -> Ref | None:
    """Return a Ref pointing at the VPC with ``vpc_id``, or ``None``."""
    if not vpc_id:
        return None
    return Ref(service="ec2", resource_type="vpc", resource_id=vpc_id, attribute="id")


def _subnet_ref(subnet_id: str | None) -> Ref | None:
    """Return a Ref pointing at the subnet with ``subnet_id``, or ``None``."""
    if not subnet_id:
        return None
    return Ref(
        service="ec2", resource_type="subnet", resource_id=subnet_id, attribute="id"
    )


def _sg_ref(group_id: str | None) -> Ref | None:
    """Return a Ref pointing at the security group with ``group_id``."""
    if not group_id:
        return None
    return Ref(
        service="ec2",
        resource_type="security_group",
        resource_id=group_id,
        attribute="id",
    )


def _route_table_ref(rtb_id: str | None) -> Ref | None:
    if not rtb_id:
        return None
    return Ref(
        service="ec2",
        resource_type="route_table",
        resource_id=rtb_id,
        attribute="id",
    )


def _nacl_ref(acl_id: str | None) -> Ref | None:
    if not acl_id:
        return None
    return Ref(
        service="ec2",
        resource_type="network_acl",
        resource_id=acl_id,
        attribute="id",
    )


def _eip_ref(alloc_id: str | None) -> Ref | None:
    if not alloc_id:
        return None
    return Ref(
        service="ec2",
        resource_type="elastic_ip",
        resource_id=alloc_id,
        attribute="allocation_id",
    )


@register_collector("ec2")
class Ec2Collector(BaseCollector):
    """Enumerate EC2/VPC networking resources for an account/region."""

    service = "ec2"

    def collect(
        self, account_id: str, region: str, include_data: bool
    ) -> list[Resource]:
        try:
            from moto.ec2 import ec2_backends
        except Exception:  # pragma: no cover
            LOG.warning("moto.ec2 unavailable; skipping EC2 export", exc_info=True)
            return []

        try:
            backend = ec2_backends[account_id][region]
        except Exception:
            LOG.warning(
                "No EC2 backend for account=%s region=%s",
                account_id,
                region,
                exc_info=True,
            )
            return []

        self._default_vpc_ids: set[str] = set()
        resources: list[Resource] = []
        resources.extend(self._collect_vpcs(backend, account_id, region))
        resources.extend(self._collect_subnets(backend, account_id, region))
        resources.extend(self._collect_security_groups(backend, account_id, region))
        resources.extend(self._collect_internet_gateways(backend, account_id, region))
        resources.extend(self._collect_elastic_ips(backend, account_id, region))
        resources.extend(self._collect_nat_gateways(backend, account_id, region))
        resources.extend(self._collect_route_tables(backend, account_id, region))
        resources.extend(self._collect_vpc_endpoints(backend, account_id, region))
        resources.extend(self._collect_network_acls(backend, account_id, region))
        resources.extend(self._collect_peering_connections(backend, account_id, region))
        resources.extend(self._collect_key_pairs(backend, account_id, region))
        resources.extend(self._collect_instances_as_unsupported(backend, account_id, region))

        # Strip everything tied to the moto-default VPC. Real AWS already
        # owns a default VPC (172.31.0.0/16, six default subnets, default
        # SG, default NACL, default route table) so re-emitting those
        # collides with what's already deployed. We also strip the
        # rules / sub-resources that hang off them.
        if self._default_vpc_ids:
            kept_ids: set[str] = set()
            filtered: list[Resource] = []
            for r in resources:
                if self._references_default_vpc(r):
                    continue
                kept_ids.add(r.resource_id)
                filtered.append(r)
            # Second pass: drop dangling rules whose parent was filtered
            # (e.g. an SG rule whose SG belonged to the default VPC).
            resources = [
                r for r in filtered
                if not self._has_orphan_parent(r, kept_ids)
            ]
        return resources

    # ------------------------------------------------------------------
    # Default-VPC filter helpers
    # ------------------------------------------------------------------

    def _references_default_vpc(self, r: Resource) -> bool:
        from localemu.export.ir import Ref

        vpc_ref = r.attributes.get("vpc_id")
        if isinstance(vpc_ref, Ref):
            return vpc_ref.resource_id in self._default_vpc_ids
        if isinstance(vpc_ref, str) and vpc_ref in self._default_vpc_ids:
            return True
        return False

    @staticmethod
    def _has_orphan_parent(r: Resource, kept_ids: set[str]) -> bool:
        """Drop child rules whose parent SG / NACL / route table was
        filtered as part of the default VPC. ``kept_ids`` holds every
        resource id that survived the first filter pass."""
        from localemu.export.ir import Ref

        for parent_attr in ("security_group_id", "network_acl_id", "route_table_id"):
            ref = r.attributes.get(parent_attr)
            if isinstance(ref, Ref):
                if ref.resource_id not in kept_ids:
                    return True
            elif isinstance(ref, str):
                if ref.startswith(("sg-", "acl-", "rtb-")) and ref not in kept_ids:
                    return True
        return False

    def _collect_instances_as_unsupported(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Emit an ``ec2.instance`` placeholder per running moto instance.

        We intentionally do *not* provide a :class:`TfSpec` /
        :class:`CfnSpec` for this type: LocalEmu instances are backed by
        ephemeral Docker containers, and the runtime surface we can
        introspect (AMI id, user-data, SG membership) does not
        round-trip to a deterministic real-AWS launch template. Emitting
        them without a spec causes the exporter's standard
        "no-spec" path to record them in MANIFEST.md's "Unsupported
        resources" section — which is exactly where a user should see
        instances listed, so they can reconstruct them from source.
        """
        out: list[Resource] = []
        try:
            reservations = getattr(backend, "reservations", {}) or {}
            for _, reservation in dict(reservations).items():
                instances = getattr(reservation, "instances", []) or []
                for instance in list(instances):
                    iid = getattr(instance, "id", None) or getattr(
                        instance, "instance_id", None
                    )
                    if not iid:
                        continue
                    out.append(
                        Resource(
                            service="ec2",
                            resource_type="instance",
                            resource_id=str(iid),
                            account_id=account_id,
                            region=region,
                            attributes={
                                "id": iid,
                                "image_id": getattr(instance, "image_id", None),
                                "instance_type": getattr(
                                    instance, "instance_type", None
                                ),
                            },
                            tags=_tags(instance),
                        )
                    )
        except Exception:  # noqa: BLE001
            LOG.warning("Failed to enumerate EC2 instances", exc_info=True)
        return out

    # ------------------------------------------------------------------
    # Per-type collectors
    # ------------------------------------------------------------------

    def _collect_vpcs(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate VPCs.

        The moto-default VPC (and the matching default subnets, security
        group, route table, NACL it auto-creates) is **always present**
        in the backend — moto materialises it on first access. Real AWS
        accounts also start with a default VPC owning the same
        ``172.31.0.0/16`` CIDR. Exporting the moto-default into
        Terraform creates a duplicate VPC alongside the existing one,
        which is almost certainly NOT what the user wants and pollutes
        every export with ~13 phantom resources. We collect the IDs of
        every default VPC so descendant collectors can skip its kids.
        Users with truly user-defined VPCs are unaffected — only
        ``is_default=True`` VPCs are filtered.
        """
        out: list[Resource] = []
        default_ids: set[str] = set()
        for vpc_id, vpc in dict(getattr(backend, "vpcs", {}) or {}).items():
            try:
                if bool(getattr(vpc, "is_default", False)):
                    default_ids.add(str(vpc_id))
                    continue
                attrs: dict[str, Any] = {
                    "id": vpc_id,
                    "cidr_block": getattr(vpc, "cidr_block", None),
                    "instance_tenancy": getattr(vpc, "instance_tenancy", None),
                    "enable_dns_support": bool(getattr(vpc, "enable_dns_support", True)),
                    "enable_dns_hostnames": bool(
                        getattr(vpc, "enable_dns_hostnames", False)
                    ),
                    "is_default": False,
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="vpc",
                        resource_id=str(vpc_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(vpc),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed VPC %r", vpc_id, exc_info=True)
        # Stash for descendants to consult.
        self._default_vpc_ids = default_ids
        return out

    def _collect_subnets(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate subnets. ``backend.subnets`` is ``{az: {subnet_id: Subnet}}``."""
        out: list[Resource] = []
        subnets = getattr(backend, "subnets", {}) or {}
        for az, sub_map in dict(subnets).items():
            if not isinstance(sub_map, dict):
                continue
            for subnet_id, sub in dict(sub_map).items():
                try:
                    attrs: dict[str, Any] = {
                        "id": subnet_id,
                        "vpc_id": _vpc_ref(getattr(sub, "vpc_id", None)),
                        "cidr_block": getattr(sub, "cidr_block", None),
                        "availability_zone": getattr(sub, "availability_zone", None)
                        or az,
                        "map_public_ip_on_launch": bool(
                            getattr(sub, "map_public_ip_on_launch", False)
                        ),
                        "assign_ipv6_address_on_creation": bool(
                            getattr(sub, "assign_ipv6_address_on_creation", False)
                        ),
                    }
                    out.append(
                        Resource(
                            service="ec2",
                            resource_type="subnet",
                            resource_id=str(subnet_id),
                            account_id=account_id,
                            region=region,
                            attributes=attrs,
                            tags=_tags(sub),
                        )
                    )
                except Exception:  # noqa: BLE001
                    LOG.warning(
                        "Skipping malformed subnet %r", subnet_id, exc_info=True
                    )
        return out

    def _collect_security_groups(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Enumerate SGs and their ingress/egress rules.

        Rules are emitted as separate ``security_group_rule`` resources.
        Inline ``ingress``/``egress`` blocks on ``aws_security_group``
        are deprecated by the AWS provider and conflict with
        ``aws_security_group_rule``; emitting both fails at plan-time.
        """
        out: list[Resource] = []
        groups = getattr(backend, "groups", {}) or {}
        # groups is {vpc_id_or_None: {group_id: SecurityGroup}}
        for _, group_map in dict(groups).items():
            if not isinstance(group_map, dict):
                continue
            for group_id, sg in dict(group_map).items():
                # Skip the auto-created "default" security group. Every VPC
                # comes with one; AWS rejects ``CreateSecurityGroup`` for the
                # reserved name "default". Exporting it causes plan-time or
                # apply-time failures. Same pattern as events.event_bus
                # "default".
                sg_name = (
                    getattr(sg, "group_name", None)
                    or getattr(sg, "name", None)
                    or ""
                )
                if sg_name == "default":
                    continue
                try:
                    out.append(self._sg_resource(sg, account_id, region))
                    out.extend(self._sg_rule_resources(sg, account_id, region))
                except Exception:  # noqa: BLE001
                    LOG.warning(
                        "Skipping malformed security group %r", group_id, exc_info=True
                    )
        return out

    def _sg_resource(self, sg: Any, account_id: str, region: str) -> Resource:
        """Build the base ``aws_security_group`` resource (no rules)."""
        group_id = getattr(sg, "group_id", None) or getattr(sg, "id", None)
        attrs: dict[str, Any] = {
            "id": group_id,
            "name": getattr(sg, "group_name", None) or getattr(sg, "name", None),
            "description": getattr(sg, "description", None)
            or "Managed by LocalEmu export",
            "vpc_id": _vpc_ref(getattr(sg, "vpc_id", None)),
        }
        return Resource(
            service="ec2",
            resource_type="security_group",
            resource_id=str(group_id),
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags=_tags(sg),
        )

    def _sg_rule_resources(
        self, sg: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Flatten each ingress/egress rule into its own IR resource.

        Moto's per-rule objects carry a single CIDR per row, which maps
        directly to ``aws_security_group_rule``'s ``cidr_blocks`` list
        of one element. Rules with ``source_group`` populated emit a
        ``source_security_group_id`` pointer instead of ``cidr_blocks``.
        """
        out: list[Resource] = []
        group_id = getattr(sg, "group_id", None) or getattr(sg, "id", None)
        sg_ref = _sg_ref(group_id)

        for rule in list(getattr(sg, "ingress_rules", []) or []):
            resource = self._sg_rule_resource(
                rule, sg_ref, group_id, "ingress", account_id, region
            )
            if resource is not None:
                out.append(resource)
        for rule in list(getattr(sg, "egress_rules", []) or []):
            resource = self._sg_rule_resource(
                rule, sg_ref, group_id, "egress", account_id, region
            )
            if resource is not None:
                out.append(resource)
        return out

    def _sg_rule_resource(
        self,
        rule: Any,
        sg_ref: Ref | None,
        group_id: str | None,
        rule_type: str,
        account_id: str,
        region: str,
    ) -> Resource | None:
        """Translate one moto ``SecurityGroupRule`` to IR."""
        rule_id = getattr(rule, "id", None)
        if not rule_id:
            return None

        ip_range = getattr(rule, "ip_range", None) or {}
        cidr = ip_range.get("CidrIp") if isinstance(ip_range, dict) else None
        source_group = getattr(rule, "source_group", None) or {}
        source_group_id = (
            source_group.get("GroupId") if isinstance(source_group, dict) else None
        )

        attrs: dict[str, Any] = {
            "id": rule_id,
            "type": rule_type,
            "security_group_id": sg_ref,
            "protocol": str(getattr(rule, "ip_protocol", "-1")),
            "from_port": getattr(rule, "from_port", None),
            "to_port": getattr(rule, "to_port", None),
        }
        if cidr:
            attrs["cidr_blocks"] = [cidr]
        if source_group_id:
            attrs["source_security_group_id"] = _sg_ref(source_group_id)
        # aws_security_group_rule requires exactly one of cidr_blocks,
        # ipv6_cidr_blocks, prefix_list_ids, source_security_group_id,
        # or self. If a rule has none (malformed), fall back to
        # cidr_blocks=["0.0.0.0/0"] — better a permissive default than
        # a plan-time failure that the user can't recover from without
        # editing generated HCL.
        if "cidr_blocks" not in attrs and "source_security_group_id" not in attrs:
            attrs["cidr_blocks"] = ["0.0.0.0/0"]

        return Resource(
            service="ec2",
            resource_type="security_group_rule",
            resource_id=str(rule_id),
            account_id=account_id,
            region=region,
            attributes=attrs,
            tags={},  # aws_security_group_rule does not support tags.
        )

    def _collect_internet_gateways(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for igw_id, igw in dict(getattr(backend, "internet_gateways", {}) or {}).items():
            try:
                vpc = getattr(igw, "vpc", None)
                vpc_id = getattr(vpc, "id", None) if vpc is not None else None
                attrs: dict[str, Any] = {
                    "id": igw_id,
                    "vpc_id": _vpc_ref(vpc_id),
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="internet_gateway",
                        resource_id=str(igw_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(igw),
                    )
                )
                # Emit a companion ``internet_gateway_attachment`` for
                # CFN parity — ``AWS::EC2::InternetGateway`` has no
                # ``VpcId`` property; attachment requires a separate
                # ``AWS::EC2::VPCGatewayAttachment``. Without it, routes
                # via this IGW fail apply with "route table and network
                # gateway belong to different networks". Terraform's
                # ``aws_internet_gateway`` accepts ``vpc_id`` inline and
                # also accepts ``aws_internet_gateway_attachment`` —
                # emitting both is harmless on TF and required on CFN.
                if vpc_id:
                    out.append(
                        Resource(
                            service="ec2",
                            resource_type="internet_gateway_attachment",
                            resource_id=f"{igw_id}/{vpc_id}",
                            account_id=account_id,
                            region=region,
                            attributes={
                                "internet_gateway_id": Ref(
                                    service="ec2",
                                    resource_type="internet_gateway",
                                    resource_id=igw_id,
                                    attribute="id",
                                ),
                                "vpc_id": _vpc_ref(vpc_id),
                            },
                            tags={},
                        )
                    )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed IGW %r", igw_id, exc_info=True)
        return out

    def _collect_elastic_ips(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Export only VPC-domain EIPs. EC2-classic is end-of-life and
        has no ``allocation_id`` to key references on."""
        out: list[Resource] = []
        for eip in list(getattr(backend, "addresses", []) or []):
            try:
                alloc_id = getattr(eip, "allocation_id", None)
                if not alloc_id or getattr(eip, "domain", None) != "vpc":
                    continue
                attrs: dict[str, Any] = {
                    "id": alloc_id,
                    "allocation_id": alloc_id,
                    "domain": "vpc",
                    "public_ip": getattr(eip, "public_ip", None),
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="elastic_ip",
                        resource_id=str(alloc_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(eip),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed EIP", exc_info=True)
        return out

    def _collect_nat_gateways(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for nat_id, nat in dict(getattr(backend, "nat_gateways", {}) or {}).items():
            try:
                address_set = getattr(nat, "address_set", None) or []
                alloc_id = None
                if address_set and isinstance(address_set[0], dict):
                    alloc_id = address_set[0].get("allocationId")
                attrs: dict[str, Any] = {
                    "id": nat_id,
                    "subnet_id": _subnet_ref(getattr(nat, "subnet_id", None)),
                    "allocation_id": _eip_ref(alloc_id),
                    "connectivity_type": getattr(nat, "connectivity_type", "public"),
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="nat_gateway",
                        resource_id=str(nat_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(nat),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed NAT %r", nat_id, exc_info=True)
        return out

    def _collect_route_tables(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Emit the route table plus one resource per route and one per
        subnet association. The main-table association is *not* emitted —
        Terraform's ``aws_main_route_table_association`` is a different
        resource and the main table for a VPC is created automatically,
        so faking a main-association on a user-created table would be
        incorrect. Only explicit ``associate_route_table`` calls produce
        ``aws_route_table_association`` rows.
        """
        out: list[Resource] = []
        for rtb_id, rtb in dict(getattr(backend, "route_tables", {}) or {}).items():
            try:
                rtb_attrs: dict[str, Any] = {
                    "id": rtb_id,
                    "vpc_id": _vpc_ref(getattr(rtb, "vpc_id", None)),
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="route_table",
                        resource_id=str(rtb_id),
                        account_id=account_id,
                        region=region,
                        attributes=rtb_attrs,
                        tags=_tags(rtb),
                    )
                )
                out.extend(self._route_resources(rtb, rtb_id, account_id, region))
                out.extend(
                    self._route_association_resources(rtb, rtb_id, account_id, region)
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed route table %r", rtb_id, exc_info=True
                )
        return out

    def _route_resources(
        self, rtb: Any, rtb_id: str, account_id: str, region: str
    ) -> list[Resource]:
        """Extract non-local routes from a moto ``RouteTable``.

        Local routes (the implicit VPC-CIDR-to-``local`` entry) are
        skipped — they are created by AWS automatically and cannot be
        declared via Terraform.
        """
        out: list[Resource] = []
        routes = getattr(rtb, "routes", {}) or {}
        for route_id, route in dict(routes).items():
            try:
                if getattr(route, "local", False):
                    continue
                dest = getattr(route, "destination_cidr_block", None)
                if not dest:
                    continue
                attrs: dict[str, Any] = {
                    "id": route_id,
                    "route_table_id": _route_table_ref(rtb_id),
                    "destination_cidr_block": dest,
                }
                gw = getattr(route, "gateway", None)
                if gw is not None and getattr(gw, "id", None):
                    attrs["gateway_id"] = Ref(
                        service="ec2",
                        resource_type="internet_gateway",
                        resource_id=gw.id,
                        attribute="id",
                    )
                nat = getattr(route, "nat_gateway", None)
                if nat is not None and getattr(nat, "id", None):
                    attrs["nat_gateway_id"] = Ref(
                        service="ec2",
                        resource_type="nat_gateway",
                        resource_id=nat.id,
                        attribute="id",
                    )
                pcx = getattr(route, "vpc_pcx", None)
                if pcx is not None and getattr(pcx, "id", None):
                    attrs["vpc_peering_connection_id"] = Ref(
                        service="ec2",
                        resource_type="vpc_peering_connection",
                        resource_id=pcx.id,
                        attribute="id",
                    )
                vpce_id = getattr(route, "vpc_endpoint_id", None)
                if vpce_id:
                    attrs["vpc_endpoint_id"] = Ref(
                        service="ec2",
                        resource_type="vpc_endpoint",
                        resource_id=vpce_id,
                        attribute="id",
                    )
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="route",
                        resource_id=str(route_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags={},
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed route %r", route_id, exc_info=True)
        return out

    def _route_association_resources(
        self, rtb: Any, rtb_id: str, account_id: str, region: str
    ) -> list[Resource]:
        """Moto stores associations as ``{assoc_id: subnet_id}``."""
        out: list[Resource] = []
        associations = getattr(rtb, "associations", {}) or {}
        for assoc_id, subnet_id in dict(associations).items():
            try:
                if not isinstance(subnet_id, str) or not subnet_id.startswith(
                    "subnet-"
                ):
                    # Gateway route-table associations use this same dict
                    # keyed by gateway id; Terraform models them with a
                    # different resource type and they are rare. Skip.
                    continue
                attrs = {
                    "id": assoc_id,
                    "route_table_id": _route_table_ref(rtb_id),
                    "subnet_id": _subnet_ref(subnet_id),
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="route_table_association",
                        resource_id=str(assoc_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags={},
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning(
                    "Skipping malformed RT assoc %r", assoc_id, exc_info=True
                )
        return out

    def _collect_vpc_endpoints(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for ep_id, ep in dict(getattr(backend, "vpc_end_points", {}) or {}).items():
            try:
                attrs: dict[str, Any] = {
                    "id": ep_id,
                    "vpc_id": _vpc_ref(getattr(ep, "vpc_id", None)),
                    "service_name": getattr(ep, "service_name", None),
                    "vpc_endpoint_type": getattr(ep, "vpc_endpoint_type", None),
                }
                route_table_ids = getattr(ep, "route_table_ids", None) or []
                if route_table_ids:
                    attrs["route_table_ids"] = [
                        _route_table_ref(rid) for rid in route_table_ids if rid
                    ]
                subnet_ids = getattr(ep, "subnet_ids", None) or []
                if subnet_ids:
                    attrs["subnet_ids"] = [
                        _subnet_ref(sid) for sid in subnet_ids if sid
                    ]
                sg_ids = getattr(ep, "security_group_ids", None) or []
                if sg_ids:
                    attrs["security_group_ids"] = [_sg_ref(sid) for sid in sg_ids if sid]
                policy = getattr(ep, "policy_document", None)
                if isinstance(policy, str) and policy.strip():
                    try:
                        attrs["policy"] = json.loads(policy)
                    except (ValueError, TypeError):
                        attrs["policy"] = policy
                pdns = getattr(ep, "private_dns_enabled", None)
                if pdns is not None:
                    attrs["private_dns_enabled"] = bool(pdns)
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="vpc_endpoint",
                        resource_id=str(ep_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(ep),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed VPC endpoint %r", ep_id, exc_info=True)
        return out

    def _collect_network_acls(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Emit the NACL + one resource per entry."""
        out: list[Resource] = []
        for acl_id, acl in dict(getattr(backend, "network_acls", {}) or {}).items():
            try:
                subnet_ids = [
                    getattr(assoc, "subnet_id", None)
                    for assoc in (
                        getattr(acl, "associations", {}) or {}
                    ).values()
                ]
                subnet_ids = [sid for sid in subnet_ids if sid]
                attrs: dict[str, Any] = {
                    "id": acl_id,
                    "vpc_id": _vpc_ref(getattr(acl, "vpc_id", None)),
                }
                if subnet_ids:
                    attrs["subnet_ids"] = [_subnet_ref(sid) for sid in subnet_ids]
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="network_acl",
                        resource_id=str(acl_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(acl),
                    )
                )
                out.extend(self._nacl_rule_resources(acl, acl_id, account_id, region))
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed NACL %r", acl_id, exc_info=True)
        return out

    def _nacl_rule_resources(
        self, acl: Any, acl_id: str, account_id: str, region: str
    ) -> list[Resource]:
        """Emit each non-default network-ACL entry as its own resource.

        The rule_number=32767 catch-all "deny" entries are added by AWS
        automatically; Terraform rejects attempts to manage them via
        ``aws_network_acl_rule``. Skip them here to keep the output
        valid.
        """
        out: list[Resource] = []
        for entry in list(getattr(acl, "network_acl_entries", []) or []):
            try:
                rule_number = getattr(entry, "rule_number", None)
                if rule_number is None or int(rule_number) >= 32767:
                    continue
                egress = bool(getattr(entry, "egress", False))
                rule_id = f"{acl_id}-{'egress' if egress else 'ingress'}-{rule_number}"
                attrs: dict[str, Any] = {
                    "id": rule_id,
                    "network_acl_id": _nacl_ref(acl_id),
                    "rule_number": int(rule_number),
                    "egress": egress,
                    "protocol": str(getattr(entry, "protocol", "-1")),
                    "rule_action": str(getattr(entry, "rule_action", "allow")),
                    "cidr_block": getattr(entry, "cidr_block", None) or "0.0.0.0/0",
                }
                frm = getattr(entry, "port_range_from", None)
                to = getattr(entry, "port_range_to", None)
                if frm is not None:
                    attrs["from_port"] = int(frm)
                if to is not None:
                    attrs["to_port"] = int(to)
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="network_acl_rule",
                        resource_id=rule_id,
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags={},
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed NACL entry", exc_info=True)
        return out

    def _collect_peering_connections(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        out: list[Resource] = []
        for pcx_id, pcx in dict(getattr(backend, "vpc_pcxs", {}) or {}).items():
            try:
                vpc = getattr(pcx, "vpc", None)
                peer = getattr(pcx, "peer_vpc", None)
                attrs: dict[str, Any] = {
                    "id": pcx_id,
                    "vpc_id": _vpc_ref(getattr(vpc, "id", None)),
                    "peer_vpc_id": _vpc_ref(getattr(peer, "id", None)),
                    "auto_accept": True,
                }
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="vpc_peering_connection",
                        resource_id=str(pcx_id),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(pcx),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed VPC peering %r", pcx_id, exc_info=True)
        return out

    def _collect_key_pairs(
        self, backend: Any, account_id: str, region: str
    ) -> list[Resource]:
        """Export only key pairs that carry a public-key material.

        Real AWS requires ``public_key`` on ``aws_key_pair``. Key pairs
        created via ``create_key_pair`` (private generated server-side)
        still produce a public key via ``material_public``; imported
        pairs store it directly. Either way, without public-key bytes
        we have no deterministic ``aws_key_pair`` config to emit, so we
        skip such entries rather than produce broken HCL.
        """
        out: list[Resource] = []
        for name, kp in dict(getattr(backend, "key_pairs", {}) or {}).items():
            try:
                public = (
                    getattr(kp, "material_public", None)
                    or getattr(kp, "public_key", None)
                    or getattr(kp, "key_material", None)
                )
                if isinstance(public, bytes):
                    public = public.decode("utf-8", errors="replace")
                if not public:
                    continue
                attrs: dict[str, Any] = {
                    "key_name": getattr(kp, "key_name", None) or name,
                    "public_key": public,
                }
                fingerprint = getattr(kp, "key_fingerprint", None) or getattr(
                    kp, "fingerprint", None
                )
                if fingerprint:
                    attrs["fingerprint"] = fingerprint
                out.append(
                    Resource(
                        service="ec2",
                        resource_type="key_pair",
                        resource_id=str(name),
                        account_id=account_id,
                        region=region,
                        attributes=attrs,
                        tags=_tags(kp),
                    )
                )
            except Exception:  # noqa: BLE001
                LOG.warning("Skipping malformed key pair %r", name, exc_info=True)
        # Record instance-skip reason as a no-op side channel: the
        # export's MANIFEST already lists unsupported resource types via
        # the TfSpec lookup path, so instances would appear there
        # automatically if the collector produced them. We choose not to
        # produce them, and the ``MANIFEST.md`` template documents the
        # decision; see the exporter's realaws/manifest.py for how this
        # is surfaced on every export that contains EC2 instances.
        _ = self._record_unsupported_instances  # silence unused-warning
        return out

    def _record_unsupported_instances(self) -> Iterable[str]:
        """Documentation anchor for the `ec2.instance` skip decision.

        Kept as a method (rather than inline comment) so contributors
        searching the codebase for "instance" find the single explicit
        statement of the policy.
        """
        return ()
