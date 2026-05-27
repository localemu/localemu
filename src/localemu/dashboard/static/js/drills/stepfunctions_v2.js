// Step Functions state machine drill -- registry-driven via the
// shared tabbed framework. Replaces the older 44-line stub at
// drills/stepfunctions.js for state machines that arrive via the
// framework dispatcher.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "stepfunctions",
      title: function (row) { return row.name || row.key || ""; },
      subtitle: function (row) {
        return [row.type || "STANDARD", row.region || ""].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (arn) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/stepfunctions/" + encodeURIComponent(arn),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: arn, error: "not found" }; });
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
              ["Role ARN", row.role_arn],
              ["Created", row.create_date || "-"],
              ["Region", row.region || "-"],
              ["Revision", row.revision_id || "-"],
              ["Executions (total)", row.executions_total || 0],
            ]);
          }
        },
        {
          id: "definition", label: "Definition",
          render: function (row) {
            return '<p class="hint">Amazon States Language definition.</p>' + H.jsonBlock(row.definition || {});
          }
        },
        {
          id: "graph", label: "Visual graph",
          render: function (row) {
            var states = (row.definition && row.definition.States) || {};
            var start = (row.definition && row.definition.StartAt) || "";
            var html = '<div style="display:flex;flex-wrap:wrap;gap:10px;padding:12px">';
            Object.keys(states).forEach(function (name) {
              var s = states[name] || {};
              var t = s.Type || "?";
              var isStart = (name === start) ? " (Start)" : "";
              html += '<div style="background:var(--base02);border:1px solid var(--base01);padding:8px 12px;border-radius:4px;font-family:Menlo,Monaco,Consolas,monospace;font-size:11px;min-width:160px">'
                + '<div><strong>' + DASH.utils.esc(name) + '</strong>' + DASH.utils.esc(isStart) + '</div>'
                + '<div class="hint">' + DASH.utils.esc(t) + '</div>'
                + (s.Next ? '<div class="hint">\u2192 ' + DASH.utils.esc(s.Next) + '</div>' : '')
                + (s.End ? '<div class="hint">end</div>' : '')
                + '</div>';
            });
            html += '</div>';
            return html;
          }
        },
        {
          id: "executions", label: "Executions",
          render: function (row) {
            var execs = row.executions || [];
            if (!execs.length) return '<div class="empty-state">No executions yet.</div>';
            return H.table(execs, [
              { key: "name",       label: "Name" },
              { key: "status",     label: "Status" },
              { key: "start_date", label: "Started" },
              { key: "stop_date",  label: "Stopped" },
              { key: "error",      label: "Error", render: function (e) { return e.error || ""; } },
            ]);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || [];
            if (!tags.length) return '<div class="empty-state">No tags.</div>';
            return H.table(tags, [
              { key: "key",   label: "Key" },
              { key: "value", label: "Value" },
            ]);
          }
        },
      ],
      actions: [
        {
          id: "start", label: "Start execution", primary: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu stepfunctions start-execution --state-machine-arn " + row.arn + " --input '{}'");
            DASH.utils.showToast("Copied start-execution command", "ok");
          }
        },
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

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("stepfunctions", spec());
  }
})();
