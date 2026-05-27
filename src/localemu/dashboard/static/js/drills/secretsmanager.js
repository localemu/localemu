// Secrets Manager drill.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "secretsmanager",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.kms_key_id || "AWS-managed KMS", row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/secretsmanager/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn],
              ["Description", row.description || "(none)"],
              ["KMS key", row.kms_key_id || "AWS-managed KMS"],
              ["Last changed", row.last_changed_date || "-"],
              ["Region", row.region || "-"],
              ["Deletion scheduled", row.deletion_date || "-"],
              ["Replicas", (row.replicas || []).length],
              ["Versions", (row.versions || []).length],
            ]);
          }
        },
        {
          id: "value", label: "Secret value",
          render: function (row) {
            var u = DASH.utils;
            return '<div class="tier-banner tier-banner-metadata">Secret values are never auto-revealed. Click below to copy a command that prints the current value.</div>'
              + '<p>' + '<code>awsemu secretsmanager get-secret-value --secret-id ' + u.esc(row.name) + ' --query SecretString --output text</code></p>'
              + '<p><button class="row-action primary" id="sm-copy-cmd">Copy command</button></p>'
              + '<script>(function(){var b=document.getElementById("sm-copy-cmd");if(b)b.addEventListener("click",function(){DASH.utils.copyToClipboard("awsemu secretsmanager get-secret-value --secret-id ' + u.esc(row.name) + ' --query SecretString --output text");DASH.utils.showToast("Copied","ok");});})();</script>';
          }
        },
        {
          id: "versions", label: "Versions",
          render: function (row) {
            var versions = row.versions || [];
            if (!versions.length) return '<div class="empty-state">No versions.</div>';
            return H.table(versions, [
              { key: "version_id", label: "Version ID" },
              { key: "stages",     label: "Stages",
                render: function (r) { return (r.stages || []).join(", "); } },
              { key: "created",    label: "Created" },
            ]);
          }
        },
        {
          id: "rotation", label: "Rotation",
          render: function (row) {
            return H.kvTable([
              ["Rotation enabled", row.rotation_enabled ? "Yes" : "No"],
              ["Rotation Lambda ARN", row.rotation_lambda_arn || "-"],
              ["Last rotated", row.last_rotated_date || "-"],
              ["Next rotation", row.next_rotation_date || "-"],
              ["Rules", row.rotation_rules ? JSON.stringify(row.rotation_rules) : "-"],
            ]);
          }
        },
        {
          id: "replication", label: "Replication",
          render: function (row) {
            var replicas = row.replicas || [];
            if (!replicas.length) return '<div class="empty-state">Single-region secret. Use <code>awsemu secretsmanager replicate-secret-to-regions</code> to mirror.</div>';
            return H.table(replicas, [
              { key: "region", label: "Region" },
              { key: "status", label: "Status" },
              { key: "kms_key_id", label: "KMS key" },
            ]);
          }
        },
        {
          id: "policy", label: "Resource policy",
          render: function (row) {
            if (!row.resource_policy || (typeof row.resource_policy === "object" && !Object.keys(row.resource_policy).length)) {
              return '<div class="empty-state">No resource policy attached. Default IAM rules apply.</div>';
            }
            return H.jsonBlock(row.resource_policy);
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
          id: "rotate", label: "Rotate now", primary: true,
          run: function (row) { DASH.actions.secretRotate.open({ name: row.name }); }
        },
        {
          id: "copy-name", label: "Copy name",
          run: function (row) {
            DASH.utils.copyToClipboard(row.name || "");
            DASH.utils.showToast("Secret name copied", "ok");
          }
        },
        {
          id: "delete", label: "Delete", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu secretsmanager delete-secret --secret-id " + row.name);
            DASH.utils.showToast("Copied delete-secret command", "ok");
          }
        },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("secretsmanager", spec());
  }
})();
