// Athena workgroup drill. Surfaces recent queries from the LocalEmu
// DuckDB engine with the actual result rows inline -- unique to
// LocalEmu since real AWS only writes the CSV to S3.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "athena",
      title: function (row) { return (row.workgroup && row.workgroup.name) || "primary"; },
      subtitle: function (row) {
        return [row.region, row.executions_total + " executions"].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/athena/" + encodeURIComponent(key || "primary"),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { workgroup: { name: key }, error: "not found" }; });
      },
      defaultTab: "executions",
      tabs: [
        {
          id: "executions", label: "Recent queries",
          render: function (row) {
            var execs = row.executions || [];
            if (!execs.length) return '<div class="empty-state">No queries yet. Run with <code>awsemu athena start-query-execution</code>.</div>';
            return H.table(execs, [
              { key: "id",         label: "Execution ID",
                render: function (e) { return (e.id || "").slice(0, 8); } },
              { key: "state",      label: "State" },
              { key: "query",      label: "Query",
                render: function (e) { return (e.query || "").slice(0, 80); } },
              { key: "start_time", label: "Started" },
              { key: "engine_execution_time_ms", label: "Runtime (ms)" },
              { key: "data_scanned_bytes",       label: "Data scanned" },
              { key: "output_location",          label: "Output" },
            ]);
          }
        },
        {
          id: "preview", label: "Preview rows",
          availableWhen: function (row) { return (row.preview_rows || []).length > 0; },
          render: function (row) {
            var u = DASH.utils;
            var html = '<p class="hint">First 50 rows of execution '
              + u.esc(row.preview_exec_id || "") + ' (read live from LocalEmu DuckDB).</p>';
            html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
            (row.preview_columns || []).forEach(function (c) { html += '<th>' + u.esc(c) + '</th>'; });
            html += '</tr></thead><tbody>';
            (row.preview_rows || []).forEach(function (r) {
              html += '<tr>';
              r.forEach(function (v) {
                html += '<td>' + u.esc(v == null ? "NULL" : String(v)) + '</td>';
              });
              html += '</tr>';
            });
            html += '</tbody></table></div>';
            return html;
          }
        },
        {
          id: "workgroup", label: "Workgroup",
          render: function (row) {
            var wg = row.workgroup || {};
            return H.kvTable([
              ["Name", wg.name],
              ["Description", wg.description || "(none)"],
              ["State", wg.state],
              ["Created", wg.creation_time || "-"],
            ]) + H.jsonBlock(wg.configuration || {});
          }
        },
      ],
      actions: [
        { id: "copy-id", label: "Copy workgroup ARN", run: function (row) {
          var wg = row.workgroup || {};
          DASH.utils.copyToClipboard(wg.name || "primary");
          DASH.utils.showToast("Workgroup copied", "ok");
        } },
      ],
    };
  }
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("athena", spec());
  }
})();
