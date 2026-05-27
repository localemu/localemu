// CloudFormation stack drill.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "cloudformation",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.status, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/cloudformation/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 8000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["Stack ID", row.stack_id || "-"],
              ["Status", row.status || "-"],
              ["Status reason", row.status_reason || "-"],
              ["Description", row.description || "(none)"],
              ["Created", row.creation_time || "-"],
              ["Last updated", row.last_updated_time || "-"],
              ["Capabilities", (row.capabilities || []).join(", ") || "-"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "resources", label: "Resources",
          render: function (row) {
            var res = row.resources || [];
            if (!res.length) return '<div class="empty-state">No resources tracked.</div>';
            return H.table(res, [
              { key: "logical_id",  label: "Logical ID" },
              { key: "physical_id", label: "Physical ID" },
              { key: "type",        label: "Type" },
              { key: "status",      label: "Status" },
            ]);
          }
        },
        {
          id: "events", label: "Events",
          render: function (row) {
            var events = row.events || [];
            if (!events.length) return '<div class="empty-state">No events recorded.</div>';
            return H.table(events.slice().reverse(), [
              { key: "timestamp",                label: "Time" },
              { key: "logical_resource_id",      label: "Logical ID" },
              { key: "resource_type",            label: "Type" },
              { key: "resource_status",          label: "Status" },
              { key: "resource_status_reason",   label: "Reason" },
            ]);
          }
        },
        {
          id: "outputs", label: "Outputs",
          render: function (row) {
            var outs = row.outputs || [];
            if (!outs.length) return '<div class="empty-state">No outputs.</div>';
            return H.table(outs, [
              { key: "OutputKey",   label: "Key" },
              { key: "OutputValue", label: "Value" },
              { key: "Description", label: "Description" },
              { key: "ExportName",  label: "Export name" },
            ]);
          }
        },
        {
          id: "parameters", label: "Parameters",
          render: function (row) {
            var params = row.parameters || {};
            var keys = Array.isArray(params)
              ? params.map(function (p) { return [p.ParameterKey || p.key, p.ParameterValue || p.value]; })
              : Object.keys(params).map(function (k) { return [k, params[k]]; });
            if (!keys.length) return '<div class="empty-state">No parameters.</div>';
            return H.table(keys.map(function (p) { return { key: p[0], value: p[1] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
        {
          id: "template", label: "Template",
          render: function (row) {
            return '<pre class="drill-json" style="max-height:520px">'
              + DASH.utils.esc(row.template_body || "(no template body retained)") + '</pre>';
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || {};
            var entries = Array.isArray(tags)
              ? tags.map(function (t) { return [t.Key || t.key, t.Value || t.value]; })
              : Object.keys(tags).map(function (k) { return [k, tags[k]]; });
            if (!entries.length) return '<div class="empty-state">No tags.</div>';
            return H.table(entries.map(function (e) { return { key: e[0], value: e[1] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
      ],
      actions: [
        { id: "copy-id", label: "Copy stack ID", run: function (row) {
          DASH.utils.copyToClipboard(row.stack_id || row.name);
          DASH.utils.showToast("Stack ID copied", "ok");
        } },
        { id: "delete", label: "Delete stack", destructive: true, run: function (row) {
          DASH.utils.copyToClipboard("awsemu cloudformation delete-stack --stack-name " + row.name);
          DASH.utils.showToast("Copied delete-stack", "ok");
        } },
      ],
    };
  }
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("cloudformation", spec());
  }
})();
