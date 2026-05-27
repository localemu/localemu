// WAFv2 drill: one detail page covering web ACLs, IP sets, and rule
// groups (kind is on the row). Regex pattern sets fall through to the
// generic spec because there is little to show beyond the regex list.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "wafv2",
      title: function (r) { return r.name || "(wafv2)"; },
      subtitle: function (r) {
        return [r.kind, r.scope, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/wafv2/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            if (r.kind === "web-acl")    return renderWebAcl(r);
            if (r.kind === "ip-set")     return renderIpSet(r);
            if (r.kind === "rule-group") return renderRuleGroup(r);
            return H.kvTable(Object.keys(r).map(function (k) { return [k, r[k]]; }));
          }
        },
        {
          id: "rules", label: "Rules",
          render: function (r) {
            if (r.kind === "ip-set") {
              var addrs = r.addresses || [];
              if (!addrs.length) return '<div class="empty-state">IP set is empty.</div>';
              return '<p class="hint">' + u.esc(r.ip_address_version) + ' addresses (' + addrs.length + ').</p>'
                + H.table(addrs.map(function (a) { return { address: a }; }), [
                    { key: "address", label: "Address" },
                  ]);
            }
            var rules = r.rules || [];
            if (!rules.length) return '<div class="empty-state">No rules defined.</div>';
            return H.table(rules, [
              { key: "Name",     label: "Name",     render: function (x) { return x.Name || "-"; } },
              { key: "Priority", label: "Priority", render: function (x) { return x.Priority; } },
              { key: "Action",   label: "Action",
                render: function (x) {
                  if (!x.Action) return "use group action";
                  return Object.keys(x.Action)[0] || "-";
                } },
              { key: "Statement", label: "Statement",
                render: function (x) { return summarizeStatement(x.Statement); } },
            ]);
          }
        },
        {
          id: "associated", label: "Associated",
          render: function (r) {
            if (r.kind !== "web-acl") return '<div class="empty-state">Not applicable for this resource.</div>';
            var rs = r.associated_resources || [];
            if (!rs.length) return '<div class="empty-state">No resources are using this web ACL.</div>';
            return H.table(rs.map(function (a) { return { arn: a }; }), [
              { key: "arn", label: "Resource ARN" },
            ]);
          }
        },
        {
          id: "json", label: "JSON",
          render: function (r) { return jsonOrPre(r); }
        },
      ],
      actions: [
        {
          id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          }
        },
      ],
    };
  }

  function renderWebAcl(r) {
    var H = DASH.drills.framework.helpers;
    var vc = r.visibility_config || {};
    var da = r.default_action || {};
    return H.kvTable([
      ["Name", r.name],
      ["ID", r.id],
      ["ARN", r.arn],
      ["Scope", r.scope],
      ["Description", r.description || "-"],
      ["Default action", Object.keys(da)[0] || "-"],
      ["Capacity (WCU)", r.capacity],
      ["Rules", (r.rules || []).length],
      ["Sampled requests", vc.SampledRequestsEnabled ? "yes" : "no"],
      ["CloudWatch metrics", vc.CloudWatchMetricsEnabled ? "yes" : "no"],
      ["Metric name", vc.MetricName || "-"],
      ["Associated resources", (r.associated_resources || []).length],
      ["Created", r.created_time],
      ["Region", r.region],
    ]);
  }

  function renderIpSet(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["ID", r.id],
      ["ARN", r.arn],
      ["Scope", r.scope],
      ["Description", r.description || "-"],
      ["IP version", r.ip_address_version],
      ["Addresses", (r.addresses || []).length],
      ["Region", r.region],
    ]);
  }

  function renderRuleGroup(r) {
    var H = DASH.drills.framework.helpers;
    var vc = r.visibility_config || {};
    return H.kvTable([
      ["Name", r.name],
      ["ID", r.id],
      ["ARN", r.arn],
      ["Scope", r.scope],
      ["Description", r.description || "-"],
      ["Capacity (WCU)", r.capacity],
      ["Rules", (r.rules || []).length],
      ["Sampled requests", vc.SampledRequestsEnabled ? "yes" : "no"],
      ["CloudWatch metrics", vc.CloudWatchMetricsEnabled ? "yes" : "no"],
      ["Region", r.region],
    ]);
  }

  function summarizeStatement(s) {
    if (!s) return "-";
    var keys = Object.keys(s);
    return keys[0] || "(empty)";
  }

  function jsonOrPre(v) {
    var H = DASH.drills.framework.helpers;
    if (H.jsonBlock) return H.jsonBlock(v);
    return '<pre>' + DASH.utils.esc(JSON.stringify(v, null, 2)) + '</pre>';
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("wafv2", spec());
  }
})();
