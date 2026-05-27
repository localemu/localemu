// Route 53 hosted zone drill.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "route53",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.private_zone ? "Private" : "Public", row.rrset_count + " records"].join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/route53/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { id: key, error: "not found" }; });
      },
      defaultTab: "records",
      tabs: [
        {
          id: "records", label: "Records",
          render: function (row) {
            var recs = row.records || [];
            if (!recs.length) return '<div class="empty-state">No records.</div>';
            return H.table(recs, [
              { key: "name", label: "Name" },
              { key: "type", label: "Type" },
              { key: "ttl",  label: "TTL" },
              { key: "values", label: "Values",
                render: function (r) {
                  if (r.alias_target) return "ALIAS \u2192 " + JSON.stringify(r.alias_target);
                  return (r.values || []).join(", ");
                } },
              { key: "set_identifier", label: "Set ID" },
            ]);
          }
        },
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Zone ID", row.id],
              ["Domain", row.name],
              ["Type", row.private_zone ? "Private" : "Public"],
              ["Records", row.rrset_count],
              ["Delegation set", row.delegation_set_id || "(default)"],
              ["VPCs", (row.vpcs || []).length],
              ["Comment", row.comment || "(none)"],
            ]);
          }
        },
        {
          id: "vpcs", label: "Associated VPCs",
          availableWhen: function (row) { return !!row.private_zone; },
          render: function (row) {
            var vpcs = row.vpcs || [];
            if (!vpcs.length) return '<div class="empty-state">No VPCs associated.</div>';
            return H.jsonBlock(vpcs);
          }
        },
      ],
      actions: [
        { id: "copy-id", label: "Copy zone ID", run: function (row) {
          DASH.utils.copyToClipboard(row.id || "");
          DASH.utils.showToast("Zone ID copied", "ok");
        } },
      ],
    };
  }
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("route53", spec());
  }
})();
