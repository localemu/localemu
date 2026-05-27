// RDS DB instance drill. The headline tab is Connection info -- it
// surfaces the host, port, username, master password (read from the
// Docker container label), the database name, a copyable psql or
// mysql shell command, a URL-form connection string for SDK callers,
// and the Docker container name with a `docker logs` command for log
// tailing.
//
// No JDBC. JDBC is a Java-only string format; this dashboard caters
// to whatever language the user is actually running.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "rds",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        var bits = [];
        if (row.kind === "cluster") bits.push("Aurora cluster");
        else bits.push(row.engine + " " + (row.engine_version || ""));
        bits.push(row.status || "-");
        if (row.region) bits.push(row.region);
        return bits.filter(Boolean).join(" \u00b7 ").trim();
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/rds/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "connect",
      tabs: [
        {
          id: "connect", label: "Connection info",
          render: function (row) {
            if (row.kind === "cluster") return renderClusterConnect(row);
            return renderInstanceConnect(row);
          }
        },
        {
          id: "config", label: "Configuration",
          render: function (row) {
            return H.kvTable([
              ["Engine", row.engine + " " + (row.engine_version || "")],
              ["Instance class", row.instance_class || "-"],
              ["Storage", (row.storage_gb || 0) + " GB " + (row.storage_type || "")],
              ["IOPS", row.iops || "-"],
              ["Multi-AZ", row.multi_az ? "Yes" : "No"],
              ["Publicly accessible", row.publicly_accessible ? "Yes" : "No"],
              ["Backup retention (days)", row.backup_retention_period || 0],
              ["Backup window", row.preferred_backup_window || "-"],
              ["Maintenance window", row.preferred_maintenance_window || "-"],
              ["CA cert", row.ca_certificate_identifier || "-"],
              ["Encryption at rest", row.storage_encrypted ? "Yes (KMS: " + (row.kms_key_id || "default") + ")" : "No"],
              ["Deletion protection", row.deletion_protection ? "On" : "Off"],
              ["Auto minor version upgrade", row.auto_minor_version_upgrade ? "On" : "Off"],
              ["Subnet group", row.subnet_group || "-"],
              ["Parameter groups", (row.parameter_groups || []).join(", ") || "-"],
              ["VPC security groups", (row.vpc_security_groups || []).join(", ") || "-"],
              ["Region", row.region || "-"],
            ]);
          }
        },
        {
          id: "docker", label: "Container",
          availableWhen: function (row) { return row.docker_available; },
          render: function (row) {
            var u = DASH.utils;
            var rows = [
              ["Container name", row.docker_container_name || "-"],
              ["Image", row.docker_container_image || "-"],
              ["Container IP", row.docker_container_ip || "-"],
            ];
            var html = H.kvTable(rows);
            if (row.docker_logs_command) {
              html += '<p style="margin-top:14px"><strong>Tail logs:</strong></p>'
                + '<pre class="drill-json">' + u.esc(row.docker_logs_command) + '</pre>'
                + '<p><button class="row-action" data-copy="' + u.esc(row.docker_logs_command) + '">Copy</button></p>';
            }
            return html
              + '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
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
        {
          id: "copy-host", label: "Copy host:port",
          run: function (row) {
            var host = row.host || row.endpoint || "";
            var port = row.port || "";
            DASH.utils.copyToClipboard(host + (port ? ":" + port : ""));
            DASH.utils.showToast("host:port copied", "ok");
          }
        },
        {
          id: "copy-shell", label: "Copy shell command",
          run: function (row) {
            if (!row.shell_command) {
              DASH.utils.showToast("Engine not recognised for shell command", "error");
              return;
            }
            DASH.utils.copyToClipboard(row.shell_command);
            DASH.utils.showToast("Shell command copied", "ok");
          }
        },
        {
          id: "copy-url", label: "Copy connection URL",
          run: function (row) {
            if (!row.connection_url) {
              DASH.utils.showToast("Engine not recognised for URL form", "error");
              return;
            }
            DASH.utils.copyToClipboard(row.connection_url);
            DASH.utils.showToast("Connection URL copied", "ok");
          }
        },
      ],
    };
  }

  function renderInstanceConnect(row) {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    var hasDocker = row.docker_available && row.master_password;

    var head = "";
    if (!hasDocker) {
      head += '<div class="tier-banner tier-banner-metadata">'
        + 'Set <code>RDS_DOCKER_BACKEND=1</code> for a reachable endpoint. Without it, the endpoint here is metadata only and connection attempts will fail. Master password is not retrievable when Docker is off.'
        + '</div>';
    }

    var kv = [
      ["Host",             row.host || "-"],
      ["Port",             row.port || "-"],
      ["Master username",  row.master_username || "-"],
      ["Master password",  hasDocker ? row.master_password : "(set RDS_DOCKER_BACKEND=1 to recover)"],
      ["Default database", row.database_name || "(none)"],
    ];

    var html = head + H.kvTable(kv);

    if (row.shell_command) {
      html += '<h3 style="margin-top:18px">Connect via shell</h3>';
      html += '<pre class="drill-json">' + u.esc(row.shell_command) + '</pre>';
      html += '<p><button class="row-action" data-copy="' + u.esc(row.shell_command) + '">Copy shell command</button></p>';
    }
    if (row.connection_url) {
      html += '<h3 style="margin-top:18px">Connect via SDK (URL form)</h3>';
      html += '<p class="hint">Works directly with Python (SQLAlchemy / psycopg2), Node (pg / mysql2), Go (sqlx), Rust (sqlx), Ruby (Sequel), and most ORMs.</p>';
      html += '<pre class="drill-json">' + u.esc(row.connection_url) + '</pre>';
      html += '<p><button class="row-action" data-copy="' + u.esc(row.connection_url) + '">Copy URL</button></p>';
    }
    html += '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
    return html;
  }

  function renderClusterConnect(row) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Writer endpoint", row.endpoint || "-"],
      ["Reader endpoint", row.reader_endpoint || "-"],
      ["Port", row.port || "-"],
      ["Master username", row.master_username || "-"],
      ["Default database", row.database_name || "(none)"],
      ["Cluster members", (row.members || []).join(", ") || "-"],
    ]);
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("rds", spec());
  }
})();
