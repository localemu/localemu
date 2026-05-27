// Kinesis stream drill.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "kinesis",
      title: function (r) { return r.name; },
      subtitle: function (r) { return [r.stream_mode, r.status, r.region].filter(Boolean).join(" \u00b7 "); },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/kinesis/" + encodeURIComponent(k) + "/detail",
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { name: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          return H.kvTable([
            ["Name", r.name], ["ARN", r.arn], ["Status", r.status],
            ["Mode", r.stream_mode], ["Retention (h)", r.retention_hours],
            ["Encryption", r.encryption_type], ["KMS key", r.key_id || "-"],
            ["Shards", (r.shards || []).length], ["Region", r.region],
          ]);
        }},
        { id: "shards", label: "Shards", render: function (r) {
          var s = r.shards || [];
          if (!s.length) return '<div class="empty-state">No shards.</div>';
          return H.table(s, [
            { key: "id", label: "Shard ID" },
            { key: "starting_sequence_number", label: "Start seq" },
            { key: "ending_sequence_number", label: "End seq" },
            { key: "ending_hash_key", label: "End hash" },
            { key: "parent_shard_id", label: "Parent" },
          ]);
        }},
        { id: "consumers", label: "Consumers", render: function (r) {
          var c = r.consumers || [];
          if (!c.length) return '<div class="empty-state">No enhanced-fan-out consumers.</div>';
          return H.table(c, [
            { key: "name", label: "Name" }, { key: "status", label: "Status" },
            { key: "arn", label: "ARN" }, { key: "creation_timestamp", label: "Created" },
          ]);
        }},
      ],
      actions: [
        { id: "put-record", label: "Put record (CLI)", run: function (r) {
          DASH.utils.copyToClipboard("awsemu kinesis put-record --stream-name " + r.name + " --partition-key x --data $(echo hello | base64)");
          DASH.utils.showToast("Copied put-record", "ok");
        }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("kinesis", spec());
})();
