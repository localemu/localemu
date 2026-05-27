// Lambda function drill via the framework. Replaces the narrow
// "Configuration + invocations" page in drills/lambda.js with a full
// tabbed view backed by the new /api/resources/lambda/<name> endpoint.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "lambda",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.runtime, row.handler, row.state, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/lambda/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "config",
      tabs: [
        {
          id: "config", label: "Configuration",
          render: function (row) {
            return H.kvTable([
              ["Function ARN", row.function_arn],
              ["Runtime", row.runtime],
              ["Handler", row.handler],
              ["Memory (MB)", row.memory_size],
              ["Timeout (s)", row.timeout],
              ["Package type", row.package_type],
              ["Architectures", (row.architectures || []).join(", ") || "-"],
              ["Ephemeral storage (MB)", row.ephemeral_storage || 512],
              ["Tracing", row.tracing_config_mode || "-"],
              ["SnapStart", row.snap_start ? JSON.stringify(row.snap_start) : "Off"],
              ["Role", row.role || "-"],
              ["DLQ", row.dead_letter_arn || "(none)"],
              ["VPC config", row.vpc_config ? JSON.stringify(row.vpc_config) : "(none)"],
              ["State", row.state || "-"],
              ["Last modified", row.last_modified || "-"],
              ["Revision id", row.revision_id || "-"],
              ["Region", row.region || "-"],
            ]);
          }
        },
        {
          id: "env", label: "Environment",
          render: function (row) {
            var env = row.environment || {};
            var keys = Object.keys(env);
            if (!keys.length) return '<div class="empty-state">No environment variables.</div>';
            return H.table(keys.map(function (k) { return { key: k, value: env[k] }; }), [
              { key: "key", label: "Key" },
              { key: "value", label: "Value" },
            ]);
          }
        },
        {
          id: "triggers", label: "Triggers",
          render: function (row) {
            var esms = row.event_source_mappings || [];
            if (!esms.length) return '<div class="empty-state">No event source mappings.</div>';
            return H.table(esms, [
              { key: "uuid",       label: "UUID" },
              { key: "source",     label: "Source ARN" },
              { key: "state",      label: "State" },
              { key: "batch_size", label: "Batch size" },
            ]);
          }
        },
        {
          id: "permissions", label: "Permissions",
          render: function (row) {
            var perms = row.permissions || [];
            if (!perms.length) return '<div class="empty-state">No resource-based policy attached.</div>';
            return perms.map(function (p) {
              return '<div style="margin-bottom:12px"><div class="hint">Qualifier: ' + DASH.utils.esc(p.qualifier) + '</div>'
                + H.jsonBlock(p.policy) + '</div>';
            }).join("");
          }
        },
        {
          id: "url", label: "Function URL",
          render: function (row) {
            var urls = row.url_configs || [];
            if (!urls.length) return '<div class="empty-state">No Function URL configured.</div>';
            return H.table(urls, [
              { key: "qualifier", label: "Qualifier" },
              { key: "url",       label: "URL" },
              { key: "auth_type", label: "Auth type" },
            ]);
          }
        },
        {
          id: "layers", label: "Layers",
          render: function (row) {
            var layers = row.layers || [];
            if (!layers.length) return '<div class="empty-state">No layers attached.</div>';
            return H.table(layers, [
              { key: "name",    label: "Layer" },
              { key: "version", label: "Version" },
              { key: "arn",     label: "ARN" },
            ]);
          }
        },
        {
          id: "versions", label: "Versions and aliases",
          render: function (row) {
            var html = '<h3>Aliases</h3>';
            html += H.table(row.aliases || [], [
              { key: "name", label: "Alias" },
              { key: "version", label: "Version" },
              { key: "description", label: "Description" },
            ]);
            html += '<h3 style="margin-top:18px">Versions</h3>';
            html += H.table((row.versions || []).map(function (v) { return { version: v }; }), [
              { key: "version", label: "Version" },
            ]);
            return html;
          }
        },
        {
          id: "logs", label: "Logs",
          render: function (row) {
            var u = DASH.utils;
            var lg = "/aws/lambda/" + row.name;
            // /aws/lambda/<name> -> 'aws/lambda/<name>' on the wire.
            var path = lg.replace(/^\//, "").split("/").map(encodeURIComponent).join("/");
            var head = '<p class="hint">Live tail of the Lambda CloudWatch log group <code>'
              + u.esc(lg) + '</code>.</p>'
              + '<p><a class="row-action primary" href="#/logs/' + encodeURIComponent(lg)
              + '">Open full Log group page</a></p>';
            return DASH.api.fetchJSON("/_localemu/api/resources/logs/" + path,
                                      { etag: false, timeoutMs: 8000 })
              .then(function (r) {
                var events = (r && r.data && r.data.events) || [];
                if (!events.length) {
                  return head + '<div class="empty-state">No log events yet for this function. Invoke it (button above) to populate the group.</div>';
                }
                var html = head + '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>'
                  + '<th>Timestamp</th><th>Stream</th><th>Message</th>'
                  + '</tr></thead><tbody>';
                events.slice(0, 100).forEach(function (e) {
                  var ts = e.timestamp ? u.formatTimestamp(e.timestamp) : "-";
                  html += '<tr>'
                    + '<td>' + u.esc(ts) + '</td>'
                    + '<td>' + u.esc(e.stream || "") + '</td>'
                    + '<td><pre style="margin:0;font-family:inherit;font-size:12px;white-space:pre-wrap;max-width:720px">'
                    + u.esc(e.message || "") + '</pre></td>'
                    + '</tr>';
                });
                html += '</tbody></table></div>';
                return html;
              })
              .catch(function () {
                return head + '<div class="empty-state">Could not load log events. The log group may not exist yet.</div>';
              });
          }
        },
        {
          id: "invocations", label: "Invocations",
          render: function (row) {
            var u = DASH.utils;
            // CloudTrail-derived, filtered to Lambda Invoke/InvokeAsync
            // for THIS function name (substring match against the
            // requestParameters JSON catches both bare-name and full-ARN
            // forms moto records).
            return DASH.api.fetchJSON(
              "/_localemu/api/cloudtrail?limit=200&service=lambda",
              { etag: false, timeoutMs: 6000 }
            ).then(function (r) {
              var events = (r && r.data && r.data.events) || [];
              var fnName = row.name;
              var invocations = events.filter(function (e) {
                if (e.eventName !== "Invoke" && e.eventName !== "InvokeAsync") return false;
                var req = e.requestParameters || {};
                var fn = String(req.functionName || "");
                if (!fn) return false;
                if (fn === fnName) return true;
                var bare = fn.split(":function:").pop().split(":")[0];
                return bare === fnName;
              });
              if (!invocations.length) {
                return '<div class="empty-state">No invocations of <code>' + u.esc(fnName) + '</code> recorded yet.</div>';
              }
              var html = '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>'
                + '<th>Time</th><th>Operation</th><th>Status</th><th>Error</th><th>Request ID</th>'
                + '</tr></thead><tbody>';
              invocations.slice(0, 100).forEach(function (e) {
                var rid = e.requestId || e.requestID || "";
                var code = e.responseCode || 0;
                var cls = u.statusClass(code);
                var when = u.formatTimestamp(e.eventTime);
                html += '<tr>'
                  + '<td>' + u.esc(when) + '</td>'
                  + '<td>' + u.esc(e.eventName || "") + '</td>'
                  + '<td><span class="activity-status ' + cls + '">' + u.esc(code) + '</span></td>'
                  + '<td>' + u.esc(e.errorCode || "") + '</td>'
                  + '<td>' + u.esc(rid) + '</td>'
                  + '</tr>';
              });
              html += '</tbody></table></div>';
              return html;
            }).catch(function () {
              return '<div class="empty-state">Could not load CloudTrail events.</div>';
            });
          }
        },
      ],
      actions: [
        {
          id: "invoke", label: "Invoke", primary: true,
          run: function (row) { DASH.actions.lambdaInvoke.open({ name: row.name }); }
        },
        {
          id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.function_arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          }
        },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("lambda", spec());
  }
})();
