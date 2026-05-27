// EventBridge Pipes drill: source / target / transform / runtime worker.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "pipes",
      title: function (r) { return r.name || "(pipe)"; },
      subtitle: function (r) {
        return [
          shortArn(r.source),
          "\u2192",
          shortArn(r.target),
          r.region,
        ].filter(Boolean).join(" ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/pipes/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            return H.kvTable([
              ["Name", r.name],
              ["ARN", r.arn],
              ["Description", r.description || "-"],
              ["Source", r.source],
              ["Target", r.target],
              ["Role ARN", r.role_arn],
              ["Desired state", r.desired_state],
              ["Current state", r.current_state],
              ["Worker state", r.worker_state || "(not started)"],
              ["Poller thread", r.poller_thread_alive === null ? "-" : (r.poller_thread_alive ? "alive" : "stopped")],
              ["State reason", r.state_reason || "-"],
              ["Created", r.creation_time],
              ["Modified", r.last_modified_time],
              ["KMS key", r.kms_key_identifier || "-"],
              ["Region", r.region],
            ]);
          }
        },
        {
          id: "source-params", label: "Source parameters",
          render: function (r) {
            var p = r.source_parameters || {};
            if (!Object.keys(p).length) return '<div class="empty-state">No source parameters (defaults apply).</div>';
            return jsonOrPre(p);
          }
        },
        {
          id: "target-params", label: "Target parameters",
          render: function (r) {
            var p = r.target_parameters || {};
            if (!Object.keys(p).length) return '<div class="empty-state">No target parameters (event passes through unchanged).</div>';
            return jsonOrPre(p);
          }
        },
        {
          id: "enrichment", label: "Enrichment",
          render: function (r) {
            if (!r.enrichment) return '<div class="empty-state">No enrichment step (source events go straight to target).</div>';
            return H.kvTable([
              ["Enrichment ARN", r.enrichment],
            ]) + jsonOrPre(r.enrichment_parameters || {});
          }
        },
        {
          id: "logs", label: "Logging",
          render: function (r) {
            var lc = r.log_configuration || {};
            if (!Object.keys(lc).length) return '<div class="empty-state">No log destination configured.</div>';
            return jsonOrPre(lc);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (r) {
            var tags = r.tags || {};
            var keys = Object.keys(tags);
            if (!keys.length) return '<div class="empty-state">No tags.</div>';
            return H.table(keys.map(function (k) { return { key: k, value: tags[k] }; }), [
              { key: "key",   label: "Key" },
              { key: "value", label: "Value" },
            ]);
          }
        },
      ],
      actions: [
        {
          id: "copy-arn", label: "Copy pipe ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("Pipe ARN copied", "ok");
          }
        },
      ],
    };
  }

  function shortArn(a) {
    if (!a) return "-";
    var parts = String(a).split(":");
    return parts.length > 5 ? parts[2] + ":" + parts[parts.length - 1] : a;
  }
  function jsonOrPre(v) {
    var H = DASH.drills.framework.helpers;
    if (H.jsonBlock) return H.jsonBlock(v);
    return '<pre>' + DASH.utils.esc(JSON.stringify(v, null, 2)) + '</pre>';
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("pipes", spec());
  }
})();
