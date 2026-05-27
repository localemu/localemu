// KMS key drill -- tabbed drill via DASH.drills.framework.
// Implements the design from /tmp/le-audit2-15-crypto-secrets.md.
//
// Tabs: General | Key policy | Cryptographic config | Aliases |
// Grants | Rotation | Public key (asymmetric only) |
// Multi-Region (MultiRegion=true only) | Tags | Recent activity.
(function () {
  "use strict";

  function open(key) {
    DASH.drills.framework.open(spec(), key, {});
  }

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "kms",
      title: function (row) {
        var aliases = (row.aliases || []).join(", ");
        return aliases ? (aliases + "  (" + row.key_id + ")") : row.key_id;
      },
      subtitle: function (row) {
        var md = row.metadata || {};
        return [md.KeyState || "-", md.KeySpec || "-", md.Origin || "-", row.region || ""]
          .filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (keyId) {
        return DASH.api.fetchJSON("/_localemu/api/resources/kms/" + encodeURIComponent(keyId), { etag: false, timeoutMs: 6000 })
          .then(function (r) { return (r && r.data) || { key_id: keyId, error: "not found" }; });
      },
      defaultTab: "general",
      tabs: [
        {
          id: "general", label: "General",
          render: function (row) {
            var md = row.metadata || {};
            var multi = md.MultiRegion ? "Yes (" + (md.MultiRegionConfiguration && md.MultiRegionConfiguration.MultiRegionKeyType || "PRIMARY") + ")" : "No";
            return H.kvTable([
              ["Key ID", row.key_id],
              ["ARN", md.Arn || "-"],
              ["Description", md.Description || "(none)"],
              ["State", md.KeyState || "-"],
              ["Enabled", md.Enabled === false ? "No" : "Yes"],
              ["Key spec", md.KeySpec || "-"],
              ["Key usage", md.KeyUsage || "-"],
              ["Origin", md.Origin || "-"],
              ["Key manager", md.KeyManager || "-"],
              ["Multi-Region", multi],
              ["Account", md.AWSAccountId || "-"],
              ["Region", row.region || "-"],
              ["Created", md.CreationDate ? String(md.CreationDate) : "-"],
              ["Deletion date", md.DeletionDate ? String(md.DeletionDate) : "-"],
            ]);
          }
        },
        {
          id: "policy", label: "Key policy",
          render: function (row) {
            return '<p class="hint">Policy document attached to the key. Edit with <code>awsemu kms put-key-policy</code>.</p>'
              + H.jsonBlock(row.policy || {});
          }
        },
        {
          id: "crypto", label: "Cryptographic config",
          render: function (row) {
            var md = row.metadata || {};
            var algos = md.EncryptionAlgorithms || md.SigningAlgorithms || md.KeyAgreementAlgorithms || [];
            return H.kvTable([
              ["Key spec", md.KeySpec || "-"],
              ["Key usage", md.KeyUsage || "-"],
              ["Encryption algorithms", (md.EncryptionAlgorithms || []).join(", ") || "-"],
              ["Signing algorithms", (md.SigningAlgorithms || []).join(", ") || "-"],
              ["MAC algorithms", (md.MacAlgorithms || []).join(", ") || "-"],
              ["Key agreement algorithms", (md.KeyAgreementAlgorithms || []).join(", ") || "-"],
              ["Current key material id", md.CurrentKeyMaterialId || "-"],
              ["Origin", md.Origin || "-"],
              ["Custom key store", md.CustomKeyStoreId || "(default AWS-managed)"],
            ]);
          }
        },
        {
          id: "aliases", label: "Aliases",
          render: function (row) {
            if (!row.aliases || !row.aliases.length) {
              return '<div class="empty-state">No aliases. Create one with: '
                + '<code>awsemu kms create-alias --alias-name alias/my-key --target-key-id '
                + DASH.utils.esc(row.key_id) + '</code></div>';
            }
            return H.table(row.aliases.map(function (n) { return { name: n }; }), [
              { key: "name", label: "Alias name" },
            ]);
          }
        },
        {
          id: "grants", label: "Grants",
          render: function (row) {
            if (!row.grants || !row.grants.length) {
              return '<div class="empty-state">No grants on this key.</div>';
            }
            return H.table(row.grants, [
              { key: "grant_id",          label: "Grant ID" },
              { key: "name",              label: "Name" },
              { key: "grantee_principal", label: "Grantee" },
              { key: "retiring_principal",label: "Retiring principal" },
              { key: "operations",        label: "Operations",
                render: function (r) { return (r.operations || []).join(", "); } },
              { key: "constraints",       label: "Constraints",
                render: function (r) {
                  var c = r.constraints || {};
                  return Object.keys(c).length ? JSON.stringify(c) : "(none)";
                } },
            ]);
          }
        },
        {
          id: "rotation", label: "Rotation",
          render: function (row) {
            return H.kvTable([
              ["Automatic rotation", row.rotation_enabled ? "Enabled" : "Disabled"],
              ["Rotation period (days)", row.rotation_period_in_days],
              ["Next rotation date", row.next_rotation_date || "-"],
              ["Manual rotation", "Run <code>awsemu kms rotate-key-on-demand --key-id " + row.key_id + "</code>"],
            ]);
          }
        },
        {
          id: "public-key", label: "Public key",
          availableWhen: function (row) {
            var spec = (row.metadata || {}).KeySpec || "";
            return spec && spec !== "SYMMETRIC_DEFAULT";
          },
          render: function (row) {
            return '<p class="hint">Public key PEM (asymmetric keys only).</p>'
              + '<p>Fetch with: <code>awsemu kms get-public-key --key-id ' + DASH.utils.esc(row.key_id) + '</code></p>';
          }
        },
        {
          id: "multi-region", label: "Multi-Region",
          availableWhen: function (row) { return (row.metadata || {}).MultiRegion === true; },
          render: function (row) {
            var mrc = (row.metadata || {}).MultiRegionConfiguration || {};
            return H.kvTable([
              ["Type",      mrc.MultiRegionKeyType || "-"],
              ["Primary",   JSON.stringify(mrc.PrimaryKey || {})],
              ["Replicas",  JSON.stringify(mrc.ReplicaKeys || [])],
            ]);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var md = row.metadata || {};
            var tags = md.Tags || [];
            if (!tags.length) return '<div class="empty-state">No tags.</div>';
            return H.table(tags, [
              { key: "TagKey", label: "Key" },
              { key: "TagValue", label: "Value" },
            ]);
          }
        },
      ],
      actions: [
        { id: "enable", label: "Enable",
          run: function (row) {
            DASH.utils.showToast("Run: awsemu kms enable-key --key-id " + row.key_id, "ok");
            DASH.utils.copyToClipboard("awsemu kms enable-key --key-id " + row.key_id);
          }
        },
        { id: "disable", label: "Disable",
          run: function (row) {
            DASH.utils.showToast("Run: awsemu kms disable-key --key-id " + row.key_id, "ok");
            DASH.utils.copyToClipboard("awsemu kms disable-key --key-id " + row.key_id);
          }
        },
        { id: "rotate", label: "Rotate on demand",
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu kms rotate-key-on-demand --key-id " + row.key_id);
            DASH.utils.showToast("Copied: awsemu kms rotate-key-on-demand", "ok");
          }
        },
        { id: "schedule-deletion", label: "Schedule deletion", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu kms schedule-key-deletion --key-id " + row.key_id + " --pending-window-in-days 7");
            DASH.utils.showToast("Copied schedule-key-deletion to clipboard", "ok");
          }
        },
      ],
    };
  }

  // Register so app.openDrill routes via the framework.
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("kms", spec());
  }
  // Legacy callable so DASH.drills.kms.open still works.
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.kms = { open: open };
})();
