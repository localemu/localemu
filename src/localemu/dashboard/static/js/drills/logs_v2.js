// CloudWatch Logs group drill via the framework. Hierarchical:
// Group overview, Streams, Metric filters, Subscription filters,
// Tags, plus the existing flat events viewer on a sub-tab.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "logs",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        var parts = [];
        if (row.retention_in_days) parts.push(row.retention_in_days + "d retention");
        if (row.stored_bytes != null) parts.push(_humanBytes(row.stored_bytes));
        if (row.region) parts.push(row.region);
        return parts.join(" \u00b7 ");
      },
      fetch: function (key) {
        // Logs hash carries the canonical "/aws/..." form with the
        // leading slash. The backend handler strips and re-adds it.
        var clean = key.charAt(0) === "/" ? key.substring(1) : key;
        var path = clean.split("/").map(encodeURIComponent).join("/");
        return Promise.all([
          DASH.api.fetchJSON("/_localemu/api/resources/logs/" + path + "/detail", { etag: false, timeoutMs: 6000 })
            .then(function (r) { return (r && r.data) || null; })
            .catch(function () { return null; }),
          DASH.api.fetchJSON("/_localemu/api/resources/logs/" + path, { etag: false, timeoutMs: 8000 })
            .then(function (r) { return (r && r.data && r.data.events) || []; })
            .catch(function () { return []; }),
        ]).then(function (parts) {
          var detail = parts[0] || { name: key, error: "not found" };
          detail.events_preview = parts[1];
          return detail;
        });
      },
      defaultTab: "events",
      tabs: [
        {
          id: "events", label: "Events",
          render: function (row) {
            var evs = row.events_preview || [];
            if (!evs.length) return '<div class="empty-state">No log events yet.</div>';
            return H.table(evs, [
              { key: "timestamp", label: "Timestamp",
                render: function (e) { return e.timestamp ? DASH.utils.formatTimestamp(e.timestamp) : "-"; } },
              { key: "stream", label: "Stream" },
              { key: "message", label: "Message",
                render: function (e) { return (e.message || "").slice(0, 500); } },
            ]);
          }
        },
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn || "-"],
              ["Retention (days)", row.retention_in_days || "Never expire"],
              ["Stored bytes", _humanBytes(row.stored_bytes || 0)],
              ["KMS key", row.kms_key_id || "(default)"],
              ["Log class", row.log_class || "STANDARD"],
              ["Region", row.region],
              ["Streams (count)", (row.streams || []).length],
            ]);
          }
        },
        {
          id: "streams", label: "Streams",
          render: function (row) {
            var streams = row.streams || [];
            if (!streams.length) return '<div class="empty-state">No streams.</div>';
            return H.table(streams, [
              { key: "name",                label: "Stream name" },
              { key: "events",              label: "Events" },
              { key: "stored_bytes",        label: "Bytes",
                render: function (s) { return _humanBytes(s.stored_bytes || 0); } },
              { key: "last_ingestion_time", label: "Last ingestion",
                render: function (s) { return s.last_ingestion_time ? DASH.utils.formatTimestamp(s.last_ingestion_time) : "-"; } },
            ]);
          }
        },
        {
          id: "metric-filters", label: "Metric filters",
          render: function (row) {
            var mfs = row.metric_filters || [];
            if (!mfs.length) return '<div class="empty-state">No metric filters configured.</div>';
            return H.table(mfs, [
              { key: "name",    label: "Name" },
              { key: "pattern", label: "Filter pattern" },
              { key: "transformations", label: "Transformations",
                render: function (m) { return JSON.stringify(m.transformations || []); } },
            ]);
          }
        },
        {
          id: "sub-filters", label: "Subscription filters",
          render: function (row) {
            var subs = row.subscription_filters || [];
            if (!subs.length) return '<div class="empty-state">No subscription filters.</div>';
            return H.table(subs, [
              { key: "name",        label: "Name" },
              { key: "pattern",     label: "Filter pattern" },
              { key: "destination", label: "Destination ARN" },
              { key: "role",        label: "Role ARN" },
            ]);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || {};
            var keys = Object.keys(tags);
            if (!keys.length) return '<div class="empty-state">No tags.</div>';
            return H.table(keys.map(function (k) { return { key: k, value: tags[k] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
      ],
      actions: [
        { id: "copy-name", label: "Copy log group name",
          run: function (row) {
            DASH.utils.copyToClipboard(row.name || "");
            DASH.utils.showToast("Name copied", "ok");
          } },
        { id: "tail", label: "Tail command",
          run: function (row) {
            var cmd = "awsemu logs tail " + (row.name || "") + " --follow";
            DASH.utils.copyToClipboard(cmd);
            DASH.utils.showToast("Copied tail command", "ok");
          } },
      ],
    };
  }

  function _humanBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MiB";
    return (n / (1024 * 1024 * 1024)).toFixed(1) + " GiB";
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("logs", spec());
  }
})();
