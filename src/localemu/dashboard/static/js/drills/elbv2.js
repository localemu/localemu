// ELBv2 load balancer drill (ALB / NLB).
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "elbv2",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.type, row.scheme, row.state, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/elbv2/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn],
              ["Type", row.type],
              ["Scheme", row.scheme],
              ["State", row.state],
              ["DNS name", row.dns_name],
              ["VPC", row.vpc_id || "-"],
              ["Subnets", (row.subnets || []).join(", ") || "-"],
              ["Security groups", (row.security_groups || []).join(", ") || "-"],
              ["IP address type", row.ip_address_type],
              ["Created", row.created_time],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "listeners", label: "Listeners",
          render: function (row) {
            var ls = row.listeners || [];
            if (!ls.length) return '<div class="empty-state">No listeners.</div>';
            return H.table(ls, [
              { key: "port",     label: "Port" },
              { key: "protocol", label: "Protocol" },
              { key: "ssl_policy", label: "SSL policy" },
              { key: "default_actions", label: "Default actions",
                render: function (l) { return JSON.stringify(l.default_actions || []); } },
              { key: "certificates", label: "Certificates",
                render: function (l) { return JSON.stringify(l.certificates || []); } },
            ]);
          }
        },
        {
          id: "target-groups", label: "Target groups",
          render: function (row) {
            var tgs = row.target_groups || [];
            if (!tgs.length) return '<div class="empty-state">No target groups associated.</div>';
            var html = "";
            tgs.forEach(function (tg) {
              html += '<h3>' + DASH.utils.esc(tg.name) + ' <span class="hint">' + DASH.utils.esc(tg.protocol + ":" + (tg.port || "-")) + '</span></h3>';
              html += H.kvTable([
                ["ARN", tg.arn],
                ["Target type", tg.target_type],
                ["VPC", tg.vpc_id],
                ["Health check", tg.health_check_protocol],
              ]);
              if ((tg.targets || []).length) {
                html += '<h4 style="margin-top:10px">Targets</h4>';
                html += H.table(tg.targets, [
                  { key: "id",   label: "Target ID" },
                  { key: "port", label: "Port" },
                ]);
              }
            });
            return html;
          }
        },
      ],
      actions: [
        { id: "copy-dns", label: "Copy DNS name", run: function (row) {
          DASH.utils.copyToClipboard(row.dns_name || "");
          DASH.utils.showToast("DNS copied", "ok");
        } },
      ],
    };
  }
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("elbv2", spec());
  }
})();
