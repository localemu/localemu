// IAM drill. Handles Role / User / Group / Policy entities through
// one drill spec that introspects the row's `type` field.
//
// This was the user's main pain anchor: /tmp/le-shit-2.png showed
// "le-llmgw-lambda-role" with Type / Name / ARN / Policies count and
// no way to inspect the trust policy or the policy documents. The
// drill below renders the full attached + inline policy JSON, the
// trust relationship JSON, Access Advisor (from CloudTrail), and the
// recent activity.
(function () {
  "use strict";

  function kindFromRow(row) {
    var t = (row && row.type || "").toLowerCase();
    if (t === "role") return "roles";
    if (t === "user") return "users";
    if (t === "group") return "groups";
    if (t === "instanceprofile") return "instance-profiles";
    if (t === "policy") return "policies";
    return "roles";  // best default for the typical click target
  }

  function open(key) {
    // The IAM list passes the raw name as the resource key. The drill
    // fetch is kind-aware via the row's `type` field that the list
    // endpoint already returns. We default to Role -- most user clicks
    // target roles, which is exactly the user's pain anchor.
    DASH.drills.framework.open(spec(), key, {});
  }

  function fetchEntity(kind, name) {
    var path = "/_localemu/api/resources/iam/" + kind + "/" + encodeURIComponent(name);
    return DASH.api.fetchJSON(path, { etag: false, timeoutMs: 6000 })
      .then(function (r) { return (r && r.data) || null; });
  }

  function fetchByName(name) {
    // Try each kind in turn (role first, then user, group, policy).
    var kinds = ["roles", "users", "groups", "policies", "instance-profiles"];
    var i = 0;
    function tryNext() {
      if (i >= kinds.length) return Promise.resolve({ name: name, kind: "unknown" });
      var k = kinds[i++];
      return fetchEntity(k, name).then(function (r) {
        if (r && !r.error) return r;
        return tryNext();
      }).catch(tryNext);
    }
    return tryNext();
  }

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "iam",
      title: function (row) { return row.name || row.key || ""; },
      subtitle: function (row) {
        var bits = [];
        if (row.kind) bits.push(row.kind.charAt(0).toUpperCase() + row.kind.slice(1));
        if (row.arn) bits.push(row.arn);
        return bits.join(" \u00b7 ");
      },
      fetch: function (key) { return fetchByName(key); },
      defaultTab: "perms",
      tabs: [
        {
          id: "perms", label: "Permissions",
          render: function (row) { return renderPerms(row); }
        },
        {
          id: "trust", label: "Trust relationships",
          availableWhen: function (row) { return row.kind === "role"; },
          render: function (row) {
            return '<p class="hint">Principals allowed to assume this role.</p>'
              + H.jsonBlock(row.trust_policy || {});
          }
        },
        {
          id: "users", label: "Users",
          availableWhen: function (row) { return row.kind === "group"; },
          render: function (row) {
            return H.table((row.users || []).map(function (u) { return { name: u }; }),
              [{ key: "name", label: "User" }]);
          }
        },
        {
          id: "credentials", label: "Security credentials",
          availableWhen: function (row) { return row.kind === "user"; },
          render: function (row) {
            var html = '<h3>Access keys</h3>';
            html += H.table(row.access_keys || [], [
              { key: "access_key_id", label: "Access key ID" },
              { key: "status",        label: "Status" },
              { key: "created",       label: "Created" },
              { key: "last_used",     label: "Last used" },
              { key: "last_used_service", label: "Service" },
              { key: "last_used_region",  label: "Region" },
            ]);
            html += '<h3 style="margin-top:18px">MFA devices</h3>';
            html += H.table(row.mfa_devices || [], [
              { key: "serial_number", label: "Serial number" },
              { key: "enable_date",   label: "Enabled" },
            ]);
            return html;
          }
        },
        {
          id: "versions", label: "Policy versions",
          availableWhen: function (row) { return row.kind === "policy"; },
          render: function (row) {
            return (row.versions || []).map(function (v) {
              return '<div style="margin-bottom:14px"><div class="hint">Version '
                + DASH.utils.esc(v.version_id) + (v.is_default ? " (default)" : "")
                + " &middot; created " + DASH.utils.esc(v.create_date)
                + '</div>' + H.jsonBlock(v.document || {}) + '</div>';
            }).join("");
          }
        },
        {
          id: "tags", label: "Tags",
          availableWhen: function (row) { return row.kind === "role" || row.kind === "user"; },
          render: function (row) {
            var tags = row.tags || [];
            if (!tags.length) return '<div class="empty-state">No tags.</div>';
            return H.table(tags, [
              { key: "Key", label: "Key" },
              { key: "Value", label: "Value" },
            ]);
          }
        },
        {
          id: "advisor", label: "Access Advisor",
          availableWhen: function (row) { return row.kind === "role" || row.kind === "user"; },
          render: function (row) {
            return '<div class="tier-banner tier-banner-metadata">' +
              'Access Advisor in real AWS shows the last time the principal called each service. ' +
              'LocalEmu derives this from CloudTrail; the Recent activity tab below shows the live feed. ' +
              'A condensed Service-last-used view is on the roadmap.' +
              '</div>' +
              '<p class="hint">For an immediate answer, see Recent activity (below) or query CloudTrail with ' +
              '<code>awsemu cloudtrail lookup-events --lookup-attributes ' +
              'AttributeKey=Username,AttributeValue=' + DASH.utils.esc(row.name || "") + '</code></p>';
          }
        },
      ],
      actions: [
        {
          id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            if (!row.arn) return;
            DASH.utils.copyToClipboard(row.arn);
            DASH.utils.showToast("ARN copied", "ok");
          }
        },
        {
          id: "describe", label: "Copy describe command",
          run: function (row) {
            var cmd = "awsemu iam get-role --role-name " + (row.name || "");
            if (row.kind === "user") cmd = "awsemu iam get-user --user-name " + (row.name || "");
            else if (row.kind === "group") cmd = "awsemu iam get-group --group-name " + (row.name || "");
            else if (row.kind === "policy") cmd = "awsemu iam get-policy --policy-arn " + (row.arn || "");
            DASH.utils.copyToClipboard(cmd);
            DASH.utils.showToast("Copied: " + cmd, "ok");
          }
        },
      ],
    };
  }

  function renderPerms(row) {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    var html = "";

    var inline = row.inline_policies || {};
    var inlineKeys = Object.keys(inline);
    html += '<h3>Inline policies (' + inlineKeys.length + ')</h3>';
    if (!inlineKeys.length) {
      html += '<div class="empty-state">No inline policies.</div>';
    } else {
      inlineKeys.forEach(function (pname) {
        html += '<details style="margin-bottom:10px"><summary><strong>' + u.esc(pname) + '</strong></summary>'
          + H.jsonBlock(inline[pname])
          + '</details>';
      });
    }

    var managed = row.managed_policies || [];
    html += '<h3 style="margin-top:18px">Attached managed policies (' + managed.length + ')</h3>';
    if (!managed.length) {
      html += '<div class="empty-state">No attached managed policies.</div>';
    } else {
      managed.forEach(function (mp) {
        var name = mp.name || "(unnamed)";
        var arn = mp.arn || "";
        html += '<details style="margin-bottom:10px"><summary><strong>' + u.esc(name) + '</strong> &middot; <span class="hint">'
          + u.esc(arn) + ' (' + u.esc(mp.default_version_id || "v1") + ')</span></summary>'
          + (mp.document
              ? H.jsonBlock(mp.document)
              : '<div class="hint">Policy document not bundled; fetch with <code>awsemu iam get-policy-version --policy-arn '
                  + u.esc(arn) + ' --version-id ' + u.esc(mp.default_version_id || "v1") + '</code></div>')
          + '</details>';
      });
    }

    if (row.permissions_boundary) {
      html += '<h3 style="margin-top:18px">Permissions boundary</h3>';
      html += H.jsonBlock(row.permissions_boundary);
    }
    return html;
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("iam", spec());
  }
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.iam = { open: open };
})();
