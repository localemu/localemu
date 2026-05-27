// EC2 instance drill via the framework. Surfaces the moto metadata
// PLUS the unique-to-LocalEmu Docker container info (container name,
// SSH host port, IMDS host port, console output). Without these the
// dashboard would look identical to a pure metadata emulator.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "ec2",
      title: function (row) { return row.instance_id; },
      subtitle: function (row) {
        return [row.instance_type, row.state, row.availability_zone, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/ec2/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { instance_id: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Instance ID", row.instance_id],
              ["State", row.state],
              ["Instance type", row.instance_type],
              ["AMI", row.image_id],
              ["Availability zone", row.availability_zone],
              ["Launched", row.launch_time || "-"],
              ["IAM instance profile", row.iam_instance_profile ? JSON.stringify(row.iam_instance_profile) : "(none)"],
              ["Monitoring", row.monitoring || "default"],
              ["EBS optimized", row.ebs_optimized ? "Yes" : "No"],
              ["Tenancy", row.tenancy || "default"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "networking", label: "Networking",
          render: function (row) {
            return H.kvTable([
              ["VPC", row.vpc_id || "-"],
              ["Subnet", row.subnet_id || "-"],
              ["Private IP", row.private_ip || "-"],
              ["Public IP", row.public_ip || "-"],
              ["Private DNS", row.private_dns || "-"],
              ["Public DNS", row.public_dns || "-"],
              ["Security groups",
                (row.security_groups || []).map(function (s) { return s.id + " (" + s.name + ")"; }).join(", ") || "-"],
            ]);
          }
        },
        {
          id: "container", label: "Docker container",
          availableWhen: function (row) { return !!row.container; },
          render: function (row) {
            var u = DASH.utils;
            var c = row.container || {};
            var sshCmd = (c.ssh_port && c.key_name)
              ? "ssh -p " + c.ssh_port + " -i ~/.ssh/" + c.key_name + ".pem ec2-user@localhost"
              : (c.ssh_port ? "ssh -p " + c.ssh_port + " ec2-user@localhost" : null);
            var imdsCmd = c.imds_port ? "curl http://localhost:" + c.imds_port + "/latest/meta-data/instance-id" : null;
            var logsCmd = c.container_name ? "docker logs -f " + c.container_name : null;
            var execCmd = c.container_name ? "docker exec -it " + c.container_name + " /bin/bash" : null;

            var html = H.kvTable([
              ["Container name", c.container_name || "-"],
              ["Image", c.image || "-"],
              ["SSH host port", c.ssh_port || "(not exposed)"],
              ["IMDS host port", c.imds_port || "(not exposed)"],
              ["Private IP", c.private_ip || "-"],
              ["Key pair", c.key_name || "(none)"],
              ["VPC", c.vpc_id || "-"],
            ]);
            html += '<h3 style="margin-top:18px">Copyable commands</h3>';
            [
              ["Tail logs",      logsCmd],
              ["Exec a shell",   execCmd],
              ["SSH in",         sshCmd],
              ["Hit IMDS",       imdsCmd],
            ].forEach(function (pair) {
              if (!pair[1]) return;
              html += '<p><strong>' + u.esc(pair[0]) + '</strong>:</p>'
                + '<pre class="drill-json">' + u.esc(pair[1]) + '</pre>'
                + '<p><button class="row-action" data-copy="' + u.esc(pair[1]) + '">Copy</button></p>';
            });
            html += '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
            return html;
          }
        },
        {
          id: "storage", label: "Storage",
          render: function (row) {
            var bds = row.block_devices || [];
            if (!bds.length) return '<div class="empty-state">No block devices attached.</div>';
            return H.table(bds, [
              { key: "device_name",          label: "Device" },
              { key: "volume_id",            label: "Volume" },
              { key: "status",               label: "Status" },
              { key: "delete_on_termination",label: "DeleteOnTerm" },
            ]);
          }
        },
        {
          id: "user-data", label: "User data",
          render: function (row) {
            if (!row.user_data) return '<div class="empty-state">No user data was provided at launch.</div>';
            return '<pre class="drill-json">' + DASH.utils.esc(String(row.user_data)) + '</pre>';
          }
        },
        {
          id: "console", label: "Console output",
          availableWhen: function (row) { return !!(row.console_output && row.console_output.length); },
          render: function (row) {
            return '<p class="hint">Tail of the container stdout/stderr (last ~64 KiB).</p>'
              + '<pre class="drill-json" style="max-height:520px">' + DASH.utils.esc(row.console_output) + '</pre>';
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
        { id: "copy-id", label: "Copy instance ID",
          run: function (row) {
            DASH.utils.copyToClipboard(row.instance_id);
            DASH.utils.showToast("Instance ID copied", "ok");
          } },
        { id: "stop", label: "Stop",
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu ec2 stop-instances --instance-ids " + row.instance_id);
            DASH.utils.showToast("Copied stop command", "ok");
          } },
        { id: "start", label: "Start",
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu ec2 start-instances --instance-ids " + row.instance_id);
            DASH.utils.showToast("Copied start command", "ok");
          } },
        { id: "terminate", label: "Terminate", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu ec2 terminate-instances --instance-ids " + row.instance_id);
            DASH.utils.showToast("Copied terminate command", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("ec2", spec());
  }
})();
