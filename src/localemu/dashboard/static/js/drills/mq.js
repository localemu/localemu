// MQ broker drill. Surfaces real container info (management URL,
// connection endpoints) when MQ_DOCKER_BACKEND=1.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "mq",
      title: function (r) { return r.name || r.broker_id; },
      subtitle: function (r) { return [r.engine_type, r.engine_version, r.broker_state, r.region].filter(Boolean).join(" \u00b7 "); },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/mq/" + encodeURIComponent(k),
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { broker_id: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          return H.kvTable([
            ["Broker ID", r.broker_id], ["Name", r.name], ["Engine", r.engine_type + " " + (r.engine_version || "")],
            ["Deployment mode", r.deployment_mode], ["Instance type", r.host_instance_type],
            ["State", r.broker_state], ["Created", r.created], ["Region", r.region],
          ]);
        }},
        { id: "container", label: "Container", availableWhen: function (r) { return !!r.container; },
          render: function (r) {
            var c = r.container || {};
            var u = DASH.utils;
            var html = H.kvTable([
              ["Container name", c.container_name || "-"],
              ["Image", c.image || "-"],
              ["Host port (broker protocol)", c.host_port || "-"],
              ["Management port", c.management_port || "-"],
              ["Management URL", c.management_url || "-"],
            ]);
            if (c.management_url) {
              html += '<p style="margin-top:14px"><a class="row-action primary" href="' + u.esc(c.management_url) + '" target="_blank" rel="noopener">Open Web Console</a></p>';
            }
            return html;
          }
        },
        { id: "instances", label: "Endpoints", render: function (r) {
          var inst = r.broker_instances || [];
          if (!inst.length) return '<div class="empty-state">No broker instances reported.</div>';
          return H.jsonBlock(inst);
        }},
        { id: "users", label: "Users", render: function (r) {
          var u = r.users || [];
          if (!u.length) return '<div class="empty-state">No users.</div>';
          return H.table(u.map(function (n) { return { name: n }; }), [{ key: "name", label: "Username" }]);
        }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("mq", spec());
})();
