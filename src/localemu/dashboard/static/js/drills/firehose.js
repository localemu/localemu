// Firehose delivery stream drill.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "firehose",
      title: function (r) { return r.name; },
      subtitle: function (r) { return [r.type, r.status, r.region].filter(Boolean).join(" \u00b7 "); },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/firehose/" + encodeURIComponent(k),
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { name: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          return H.kvTable([
            ["Name", r.name], ["ARN", r.arn], ["Status", r.status],
            ["Type", r.type], ["Created", r.created], ["Last updated", r.last_updated],
            ["Version", r.version_id], ["Region", r.region],
          ]);
        }},
        { id: "destinations", label: "Destinations", render: function (r) {
          var d = r.destinations || [];
          if (!d.length) return '<div class="empty-state">No destinations configured.</div>';
          return H.jsonBlock(d);
        }},
        { id: "encryption", label: "Encryption", render: function (r) {
          return H.jsonBlock(r.encryption || {});
        }},
        { id: "tags", label: "Tags", render: function (r) {
          var t = r.tags || [];
          if (!t.length) return '<div class="empty-state">No tags.</div>';
          return H.table(t, [{ key: "Key", label: "Key" }, { key: "Value", label: "Value" }]);
        }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("firehose", spec());
})();
