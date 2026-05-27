// Cognito User Pool drill.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "cognito-idp",
      title: function (row) { return row.name || row.id; },
      subtitle: function (row) {
        return [(row.users || []).length + " users", (row.groups || []).length + " groups", row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/cognito-idp/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { id: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Pool ID", row.id],
              ["Name", row.name],
              ["ARN", row.arn],
              ["Created", row.creation_date],
              ["MFA configuration", row.mfa_configuration],
              ["Username attributes", (row.username_attributes || []).join(", ") || "-"],
              ["Auto-verified attributes", (row.auto_verified_attributes || []).join(", ") || "-"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "users", label: "Users",
          render: function (row) {
            var users = row.users || [];
            if (!users.length) return '<div class="empty-state">No users.</div>';
            return H.table(users, [
              { key: "username", label: "Username" },
              { key: "status",   label: "Status" },
              { key: "enabled",  label: "Enabled",
                render: function (u) { return u.enabled ? "Yes" : "No"; } },
              { key: "attributes", label: "Attributes",
                render: function (u) {
                  return (u.attributes || []).map(function (a) { return a.name + "=" + a.value; }).join(", ");
                } },
              { key: "created", label: "Created" },
            ]);
          }
        },
        {
          id: "groups", label: "Groups",
          render: function (row) {
            var groups = row.groups || [];
            if (!groups.length) return '<div class="empty-state">No groups.</div>';
            return H.table(groups, [
              { key: "name",        label: "Name" },
              { key: "precedence",  label: "Precedence" },
              { key: "role_arn",    label: "Role ARN" },
              { key: "description", label: "Description" },
            ]);
          }
        },
        {
          id: "clients", label: "App clients",
          render: function (row) {
            var clients = row.clients || [];
            if (!clients.length) return '<div class="empty-state">No app clients.</div>';
            return H.table(clients, [
              { key: "id",            label: "Client ID" },
              { key: "name",          label: "Name" },
              { key: "auth_flows",    label: "Auth flows",
                render: function (c) { return (c.auth_flows || []).join(", "); } },
              { key: "callback_urls", label: "Callback URLs",
                render: function (c) { return (c.callback_urls || []).join(", "); } },
            ]);
          }
        },
        {
          id: "triggers", label: "Lambda triggers",
          render: function (row) {
            var triggers = row.lambda_config || {};
            var keys = Object.keys(triggers);
            if (!keys.length) return '<div class="empty-state">No Lambda triggers configured.</div>';
            return H.table(keys.map(function (k) { return { trigger: k, lambda: triggers[k] }; }), [
              { key: "trigger", label: "Trigger" },
              { key: "lambda",  label: "Lambda ARN",
                render: function (e) {
                  return typeof e.lambda === "string" ? e.lambda : JSON.stringify(e.lambda);
                } },
            ]);
          }
        },
        {
          id: "schema", label: "Schema",
          render: function (row) { return H.jsonBlock(row.schema_attributes || []); }
        },
        {
          id: "policies", label: "Policies",
          render: function (row) { return H.jsonBlock(row.policies || {}); }
        },
      ],
      actions: [
        { id: "copy-id", label: "Copy pool ID", run: function (row) {
          DASH.utils.copyToClipboard(row.id || "");
          DASH.utils.showToast("Pool ID copied", "ok");
        } },
      ],
    };
  }
  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("cognito-idp", spec());
  }
})();
