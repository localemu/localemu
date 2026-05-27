// MSK (Kafka) cluster drill. Surfaces the bootstrap brokers and
// container info when MSK_DOCKER_BACKEND=1 is on.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "kafka",
      title: function (r) { return r.name; },
      subtitle: function (r) { return [r.type, "Kafka " + (r.kafka_version || ""), r.state, r.region].filter(Boolean).join(" \u00b7 "); },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/kafka/" + encodeURIComponent(k),
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { name: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          return H.kvTable([
            ["Cluster", r.name], ["ARN", r.arn], ["Type", r.type], ["State", r.state],
            ["Kafka version", r.kafka_version], ["Broker count", r.broker_count],
            ["Region", r.region],
          ]);
        }},
        { id: "broker", label: "Bootstrap brokers", availableWhen: function (r) { return !!r.broker_info; },
          render: function (r) {
            var b = r.broker_info || {};
            var html = H.kvTable([
              ["Container name", b.container_name || "-"],
              ["Host port", b.host_port || "-"],
              ["Bootstrap brokers", b.bootstrap_brokers || "-"],
            ]);
            if (b.bootstrap_brokers) {
              html += '<p style="margin-top:14px"><button class="row-action primary" data-copy="' + DASH.utils.esc(b.bootstrap_brokers) + '">Copy bootstrap brokers</button></p>';
              html += '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
            }
            return html;
          }
        },
        { id: "broker-config", label: "Broker config", render: function (r) {
          return H.jsonBlock(r.broker_node_group_info || {});
        }},
        { id: "encryption", label: "Encryption", render: function (r) {
          return H.jsonBlock(r.encryption_info || {});
        }},
        { id: "tags", label: "Tags", render: function (r) {
          var t = r.tags || {};
          var keys = Object.keys(t);
          if (!keys.length) return '<div class="empty-state">No tags.</div>';
          return H.table(keys.map(function (k) { return { key: k, value: t[k] }; }),
            [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
        }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("kafka", spec());
})();
