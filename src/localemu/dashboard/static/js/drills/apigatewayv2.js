// API Gateway HTTP/WebSocket API drill via the framework.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;

    return {
      service: "apigatewayv2",
      title: function (row) { return (row.name || "") + "  (" + row.api_id + ")"; },
      subtitle: function (row) {
        return [row.protocol_type, row.api_endpoint, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/apigatewayv2/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { api_id: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["API ID", row.api_id],
              ["Name", row.name],
              ["Protocol", row.protocol_type],
              ["Invoke endpoint", row.api_endpoint],
              ["ARN", row.arn],
              ["Description", row.description || "(none)"],
              ["Version", row.version || "-"],
              ["Route selection expression", row.route_selection_expression || "$request.method $request.path"],
              ["API key selection expression", row.api_key_selection_expression || "-"],
              ["Disable execute-api endpoint", row.disable_execute_api_endpoint ? "Yes" : "No"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "routes", label: "Routes",
          render: function (row) {
            var routes = row.routes || [];
            if (!routes.length) return '<div class="empty-state">No routes defined.</div>';
            return H.table(routes, [
              { key: "route_key",          label: "Route key" },
              { key: "target",             label: "Target integration" },
              { key: "authorization_type", label: "Auth" },
              { key: "authorizer_id",      label: "Authorizer ID" },
              { key: "api_key_required",   label: "API key" },
            ]);
          }
        },
        {
          id: "integrations", label: "Integrations",
          render: function (row) {
            var ints = row.integrations || [];
            if (!ints.length) return '<div class="empty-state">No integrations.</div>';
            return H.table(ints, [
              { key: "id",     label: "ID" },
              { key: "type",   label: "Type" },
              { key: "method", label: "Method" },
              { key: "uri",    label: "URI" },
              { key: "payload_format_version", label: "Payload version" },
              { key: "timeout_ms", label: "Timeout (ms)" },
            ]);
          }
        },
        {
          id: "stages", label: "Stages",
          render: function (row) {
            var stages = row.stages || [];
            if (!stages.length) return '<div class="empty-state">No stages.</div>';
            return H.table(stages, [
              { key: "name", label: "Stage" },
              { key: "auto_deploy", label: "Auto-deploy",
                render: function (s) { return s.auto_deploy ? "Yes" : "No"; } },
              { key: "deployment_id", label: "Deployment ID" },
              { key: "description", label: "Description" },
            ]);
          }
        },
        {
          id: "authorizers", label: "Authorizers",
          render: function (row) {
            var auths = row.authorizers || [];
            if (!auths.length) return '<div class="empty-state">No authorizers.</div>';
            return H.table(auths, [
              { key: "name", label: "Name" },
              { key: "type", label: "Type" },
              { key: "identity_source", label: "Identity source",
                render: function (a) { return (a.identity_source || []).join(", "); } },
              { key: "authorizer_uri", label: "Authorizer URI" },
            ]);
          }
        },
        {
          id: "cors", label: "CORS",
          render: function (row) {
            var cors = row.cors_configuration || {};
            if (!Object.keys(cors).length) return '<div class="empty-state">CORS is not configured.</div>';
            return H.jsonBlock(cors);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || {};
            var keys = Object.keys(tags);
            if (!keys.length) return '<div class="empty-state">No tags.</div>';
            return H.table(keys.map(function (k) { return { key: k, value: tags[k] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
      ],
      actions: [
        { id: "copy-endpoint", label: "Copy invoke endpoint",
          run: function (row) {
            DASH.utils.copyToClipboard(row.api_endpoint || "");
            DASH.utils.showToast("Invoke endpoint copied", "ok");
          } },
        { id: "copy-id", label: "Copy API ID",
          run: function (row) {
            DASH.utils.copyToClipboard(row.api_id || "");
            DASH.utils.showToast("API ID copied", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("apigatewayv2", spec());
  }
})();
