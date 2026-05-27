// DynamoDB table drill via the framework.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "dynamodb",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.status, row.billing_mode, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        var name = encodeURIComponent(key);
        return Promise.all([
          DASH.api.fetchJSON("/_localemu/api/resources/dynamodb/" + name + "/detail", { etag: false, timeoutMs: 6000 })
            .then(function (r) { return (r && r.data) || null; })
            .catch(function () { return null; }),
          DASH.api.fetchJSON("/_localemu/api/resources/dynamodb/" + name, { etag: false, timeoutMs: 6000 })
            .then(function (r) { return (r && r.data && r.data.items) || []; })
            .catch(function () { return []; }),
        ]).then(function (parts) {
          var detail = parts[0] || { name: key, error: "not found" };
          detail.items_preview = parts[1];
          return detail;
        });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn || "-"],
              ["Status", row.status],
              ["Item count", row.item_count],
              ["Table size (bytes)", row.table_size_bytes],
              ["Billing mode", row.billing_mode],
              ["Throughput", row.throughput ? JSON.stringify(row.throughput) : "-"],
              ["Deletion protection", row.deletion_protection ? "On" : "Off"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "schema", label: "Schema",
          render: function (row) {
            var html = '<h3>Key schema</h3>';
            html += H.table(row.key_schema || [], [
              { key: "AttributeName", label: "Attribute" },
              { key: "KeyType",       label: "Key type" },
            ]);
            html += '<h3 style="margin-top:18px">Attribute definitions</h3>';
            html += H.jsonBlock(row.attribute_definitions || []);
            return html;
          }
        },
        {
          id: "indexes", label: "Indexes",
          render: function (row) {
            var html = '<h3>Global secondary indexes</h3>';
            var gsi = row.global_secondary_indexes || [];
            if (!gsi.length) {
              html += '<div class="empty-state">No global secondary indexes.</div>';
            } else {
              gsi.forEach(function (g) {
                html += '<div style="margin-bottom:12px"><strong>' + DASH.utils.esc(g.name) + '</strong>'
                  + ' <span class="hint">' + DASH.utils.esc(g.status || "ACTIVE") + '</span>'
                  + H.jsonBlock({ schema: g.schema, projection: g.projection, throughput: g.throughput })
                  + '</div>';
              });
            }
            html += '<h3 style="margin-top:18px">Local secondary indexes</h3>';
            var lsi = row.local_secondary_indexes || [];
            if (!lsi.length) {
              html += '<div class="empty-state">No local secondary indexes.</div>';
            } else {
              lsi.forEach(function (l) {
                html += '<div style="margin-bottom:12px"><strong>' + DASH.utils.esc(l.name) + '</strong>'
                  + H.jsonBlock({ schema: l.schema, projection: l.projection })
                  + '</div>';
              });
            }
            return html;
          }
        },
        {
          id: "items", label: "Items (preview)",
          render: function (row) {
            var items = row.items_preview || [];
            if (!items.length) return '<div class="empty-state">No items. Use the action panel to PutItem.</div>';
            var cols = {};
            items.forEach(function (it) { Object.keys(it).forEach(function (k) { cols[k] = true; }); });
            var keys = Object.keys(cols);
            return H.table(items, keys.map(function (k) {
              return { key: k, label: k, render: function (it) {
                var v = it[k];
                if (v && typeof v === "object") return JSON.stringify(v);
                return String(v == null ? "" : v);
              } };
            }));
          }
        },
        {
          id: "streams", label: "Streams",
          render: function (row) {
            if (!row.stream_specification || !row.stream_specification.enabled) {
              return '<div class="empty-state">Streams not enabled on this table.</div>';
            }
            return H.kvTable([
              ["Enabled", "Yes"],
              ["View type", row.stream_specification.view_type || "-"],
            ]);
          }
        },
        {
          id: "settings", label: "Settings",
          render: function (row) {
            return H.kvTable([
              ["TTL", row.ttl ? JSON.stringify(row.ttl) : "(disabled)"],
              ["SSE", row.sse_description ? JSON.stringify(row.sse_description) : "(default AWS-managed)"],
              ["Deletion protection", row.deletion_protection ? "On" : "Off"],
            ]);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || [];
            if (!tags.length) return '<div class="empty-state">No tags.</div>';
            return H.table(tags, [
              { key: "Key", label: "Key" },
              { key: "Value", label: "Value" },
            ]);
          }
        },
      ],
      actions: [
        { id: "items", label: "Items", primary: true,
          run: function (row) { DASH.actions.dynamoDb.open({ name: row.name }); } },
        { id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          } },
        { id: "delete", label: "Delete", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu dynamodb delete-table --table-name " + row.name);
            DASH.utils.showToast("Copied delete-table", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("dynamodb", spec());
  }
})();
