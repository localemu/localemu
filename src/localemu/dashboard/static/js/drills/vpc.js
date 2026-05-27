// VPC drill: every related object the user expects on a VPC detail
// page on real AWS. Tabs: Overview, Subnets, Route tables, Gateways
// (IGW + NAT), Security groups, Network ACLs, VPC endpoints, Peering.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "vpc",
      title: function (r) { return r.vpc_id || r.name || "(vpc)"; },
      subtitle: function (r) {
        return [
          r.cidr,
          r.is_default ? "default" : null,
          r.docker_network || null,
          r.region,
        ].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/vpc/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { vpc_id: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            return H.kvTable([
              ["VPC ID", r.vpc_id],
              ["CIDR", r.cidr],
              ["State", r.state || "available"],
              ["Default VPC", r.is_default ? "yes" : "no"],
              ["Instance tenancy", r.instance_tenancy || "default"],
              ["DHCP options", r.dhcp_options_id || "-"],
              ["Subnets", (r.subnets || []).length],
              ["Route tables", (r.route_tables || []).length],
              ["Internet gateways", (r.internet_gateways || []).length],
              ["NAT gateways", (r.nat_gateways || []).length],
              ["Security groups", (r.security_groups || []).length],
              ["Network ACLs", (r.network_acls || []).length],
              ["VPC endpoints", (r.vpc_endpoints || []).length],
              ["Peering connections", (r.peerings || []).length],
              ["Docker network", r.docker_network || "(not materialised yet)"],
              ["Region", r.region],
            ]);
          }
        },
        {
          id: "subnets", label: "Subnets",
          render: function (r) {
            var rows = r.subnets || [];
            if (!rows.length) return '<div class="empty-state">No subnets in this VPC.</div>';
            return H.table(rows, [
              { key: "subnet_id",         label: "Subnet ID" },
              { key: "cidr",              label: "CIDR" },
              { key: "availability_zone", label: "AZ" },
              { key: "available_ips",     label: "Available IPs" },
              { key: "map_public_ip",     label: "Auto-assign public IP",
                render: function (s) { return s.map_public_ip ? "yes" : "no"; } },
              { key: "default_for_az",    label: "Default for AZ",
                render: function (s) { return s.default_for_az ? "yes" : "no"; } },
            ]);
          }
        },
        {
          id: "route-tables", label: "Route tables",
          render: function (r) {
            var rts = r.route_tables || [];
            if (!rts.length) return '<div class="empty-state">No route tables in this VPC.</div>';
            var html = "";
            rts.forEach(function (rt) {
              html += '<h3>' + u.esc(rt.route_table_id);
              if (rt.main) html += ' <span class="hint">main</span>';
              html += '</h3>';
              html += H.table(rt.routes || [], [
                { key: "destination", label: "Destination" },
                { key: "target",      label: "Target" },
                { key: "state",       label: "State" },
              ]);
              if ((rt.associations || []).length) {
                html += '<h4 style="margin-top:10px">Subnet associations</h4>';
                html += H.table(rt.associations, [
                  { key: "association_id", label: "Association ID" },
                  { key: "subnet_id",      label: "Subnet" },
                ]);
              }
            });
            return html;
          }
        },
        {
          id: "gateways", label: "Gateways",
          render: function (r) {
            var igws = r.internet_gateways || [];
            var nats = r.nat_gateways || [];
            var html = '<h3>Internet gateways</h3>';
            if (!igws.length) html += '<div class="empty-state">No internet gateway attached.</div>';
            else html += H.table(igws, [
              { key: "internet_gateway_id", label: "IGW ID" },
              { key: "state",               label: "State" },
            ]);
            html += '<h3 style="margin-top:18px">NAT gateways</h3>';
            if (!nats.length) html += '<div class="empty-state">No NAT gateways in this VPC.</div>';
            else html += H.table(nats, [
              { key: "nat_gateway_id",     label: "NAT ID" },
              { key: "subnet_id",          label: "Subnet" },
              { key: "state",              label: "State" },
              { key: "public_ip",          label: "Public IP" },
              { key: "connectivity_type",  label: "Connectivity" },
            ]);
            return html;
          }
        },
        {
          id: "security-groups", label: "Security groups",
          render: function (r) {
            var sgs = r.security_groups || [];
            if (!sgs.length) return '<div class="empty-state">No security groups in this VPC.</div>';
            var html = "";
            sgs.forEach(function (sg) {
              html += '<h3>' + u.esc(sg.name) + ' <span class="hint">' + u.esc(sg.group_id) + '</span></h3>';
              if (sg.description) html += '<p class="hint">' + u.esc(sg.description) + '</p>';
              html += '<h4 style="margin-top:10px">Ingress</h4>';
              html += (sg.ingress || []).length
                ? H.table(sg.ingress, [
                    { key: "protocol",  label: "Protocol" },
                    { key: "from_port", label: "From" },
                    { key: "to_port",   label: "To" },
                    { key: "cidr",      label: "CIDR" },
                  ])
                : '<div class="empty-state">No ingress rules.</div>';
              html += '<h4 style="margin-top:10px">Egress</h4>';
              html += (sg.egress || []).length
                ? H.table(sg.egress, [
                    { key: "protocol",  label: "Protocol" },
                    { key: "from_port", label: "From" },
                    { key: "to_port",   label: "To" },
                    { key: "cidr",      label: "CIDR" },
                  ])
                : '<div class="empty-state">No egress rules.</div>';
            });
            return html;
          }
        },
        {
          id: "nacls", label: "Network ACLs",
          render: function (r) {
            var nacls = r.network_acls || [];
            if (!nacls.length) return '<div class="empty-state">No network ACLs in this VPC.</div>';
            var html = "";
            nacls.forEach(function (nacl) {
              html += '<h3>' + u.esc(nacl.network_acl_id);
              if (nacl.default) html += ' <span class="hint">default</span>';
              html += '</h3>';
              html += H.table(nacl.entries || [], [
                { key: "rule_number", label: "Rule" },
                { key: "protocol",    label: "Protocol" },
                { key: "rule_action", label: "Action" },
                { key: "egress",      label: "Direction",
                  render: function (e) { return e.egress ? "egress" : "ingress"; } },
                { key: "cidr",        label: "CIDR" },
              ]);
              if ((nacl.associations || []).length) {
                html += '<h4 style="margin-top:10px">Associated subnets</h4>';
                html += H.table(nacl.associations, [
                  { key: "subnet_id", label: "Subnet" },
                ]);
              }
            });
            return html;
          }
        },
        {
          id: "endpoints", label: "VPC endpoints",
          render: function (r) {
            var eps = r.vpc_endpoints || [];
            if (!eps.length) return '<div class="empty-state">No VPC endpoints in this VPC.</div>';
            return H.table(eps, [
              { key: "endpoint_id",  label: "Endpoint ID" },
              { key: "service_name", label: "Service" },
              { key: "type",         label: "Type" },
              { key: "state",        label: "State" },
            ]);
          }
        },
        {
          id: "peerings", label: "Peering",
          render: function (r) {
            var pxs = r.peerings || [];
            if (!pxs.length) return '<div class="empty-state">No peering connections touching this VPC.</div>';
            return H.table(pxs, [
              { key: "peering_id",     label: "Peering ID" },
              { key: "requester_vpc",  label: "Requester VPC" },
              { key: "accepter_vpc",   label: "Accepter VPC" },
              { key: "status",         label: "Status" },
            ]);
          }
        },
      ],
      actions: [
        {
          id: "copy-vpc-id", label: "Copy VPC ID",
          run: function (row) {
            DASH.utils.copyToClipboard(row.vpc_id || "");
            DASH.utils.showToast("VPC ID copied", "ok");
          }
        },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("vpc", spec());
  }
})();
