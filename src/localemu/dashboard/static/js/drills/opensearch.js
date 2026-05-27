// OpenSearch domain drill. Surfaces moto domain config + the real
// LocalEmu container info (container name, host port, OpenSearch
// Dashboards URL).
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "opensearch",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.engine, row.endpoint, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/opensearch/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            var cfg = row.cluster_config || {};
            return H.kvTable([
              ["Domain name", row.name],
              ["ARN", row.arn || "-"],
              ["Engine version", row.engine || "-"],
              ["Endpoint", row.endpoint || "-"],
              ["Status", row.processing ? "Processing" : "Active"],
              ["Instance type", cfg.InstanceType || "-"],
              ["Instance count", cfg.InstanceCount || 1],
              ["Dedicated master", cfg.DedicatedMasterEnabled ? "Yes" : "No"],
              ["Zone awareness", cfg.ZoneAwarenessEnabled ? "Yes" : "No"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "container", label: "Container",
          availableWhen: function (row) { return !!row.container; },
          render: function (row) {
            var u = DASH.utils;
            var c = row.container || {};
            var html = H.kvTable([
              ["Container name", c.container_name || "-"],
              ["Image", c.image || "-"],
              ["Host port", c.host_port || "-"],
              ["Direct URL", c.host_port ? "http://localhost:" + c.host_port : "-"],
              ["Dashboards URL", c.dashboards_url || "-"],
            ]);
            html += '<h3 style="margin-top:18px">Useful commands</h3>';
            var cmds = [];
            if (c.host_port) {
              cmds.push(["Cluster health", "curl http://localhost:" + c.host_port + "/_cluster/health"]);
              cmds.push(["List indices",  "curl http://localhost:" + c.host_port + "/_cat/indices"]);
            }
            if (c.container_name) {
              cmds.push(["Tail container logs", "docker logs -f " + c.container_name]);
            }
            cmds.forEach(function (pair) {
              html += '<p><strong>' + u.esc(pair[0]) + '</strong>:</p>'
                + '<pre class="drill-json">' + u.esc(pair[1]) + '</pre>'
                + '<p><button class="row-action" data-copy="' + u.esc(pair[1]) + '">Copy</button></p>';
            });
            if (c.dashboards_url) {
              html += '<p><a class="row-action primary" href="' + u.esc(c.dashboards_url) + '" target="_blank" rel="noopener">Open OpenSearch Dashboards</a></p>';
            }
            html += '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
            return html;
          }
        },
        {
          id: "storage", label: "Storage",
          render: function (row) { return H.jsonBlock(row.ebs_options || {}); }
        },
        {
          id: "security", label: "Security",
          render: function (row) {
            return H.jsonBlock({
              encryption_at_rest: row.encryption_at_rest_options || {},
              node_to_node_encryption: row.node_to_node_encryption_options || {},
              advanced_security: row.advanced_security_options || {},
              vpc: row.vpc_options || {},
            });
          }
        },
        {
          id: "snapshot", label: "Snapshots",
          render: function (row) { return H.jsonBlock(row.snapshot_options || {}); }
        },
        {
          id: "logging", label: "Logging",
          render: function (row) { return H.jsonBlock(row.log_publishing_options || {}); }
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
        { id: "copy-endpoint", label: "Copy endpoint",
          run: function (row) {
            DASH.utils.copyToClipboard(row.endpoint || "");
            DASH.utils.showToast("Endpoint copied", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("opensearch", spec());
  }
})();
