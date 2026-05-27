// EFS file system drill.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "efs",
      title: function (r) { return r.name || r.file_system_id; },
      subtitle: function (r) { return [r.life_cycle_state, r.performance_mode, r.region].filter(Boolean).join(" \u00b7 "); },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/efs/" + encodeURIComponent(k),
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { file_system_id: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          return H.kvTable([
            ["File system ID", r.file_system_id],
            ["Name", r.name || "(unnamed)"],
            ["Performance mode", r.performance_mode],
            ["Throughput mode", r.throughput_mode],
            ["Encrypted", r.encrypted ? "Yes" : "No"],
            ["KMS key", r.kms_key_id || "(none)"],
            ["State", r.life_cycle_state],
            ["Size", JSON.stringify(r.size_in_bytes || {})],
            ["Backup policy", r.backup_policy_status],
            ["Created", r.creation_time],
            ["Region", r.region],
          ]);
        }},
        { id: "lifecycle", label: "Lifecycle policies", render: function (r) {
          var lp = r.lifecycle_policies || [];
          if (!lp.length) return '<div class="empty-state">No lifecycle policies.</div>';
          return H.jsonBlock(lp);
        }},
        { id: "tags", label: "Tags", render: function (r) {
          var t = r.tags || [];
          if (!t.length) return '<div class="empty-state">No tags.</div>';
          return H.table(t, [{ key: "Key", label: "Key" }, { key: "Value", label: "Value" }]);
        }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("efs", spec());
})();
