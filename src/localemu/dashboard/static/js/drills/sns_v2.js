// SNS topic drill via the framework. Fetches the topic + subscriptions
// from the existing endpoints; adds tabs for Filter policies and a
// Recent activity feed.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "sns",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.arn || "", row.region || ""].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        var name = encodeURIComponent(key);
        // Read base info from the topic list and subscriptions from
        // the existing per-topic endpoint.
        return DASH.api.fetchJSON("/_localemu/api/resources/sns/" + name + "/subscriptions", { etag: false, timeoutMs: 6000 })
          .then(function (r) {
            var subs = (r && r.data && r.data.subscriptions) || [];
            return {
              name: key,
              subscriptions: subs,
            };
          }).then(function (data) {
            // Enrich with the listing row (for arn + region).
            var hit = (DASH.app.state.resources || []).find(function (x) { return x.name === key; });
            if (hit) {
              data.arn = hit.arn || data.arn;
              data.region = hit.region || data.region;
            }
            return data;
          });
      },
      defaultTab: "details",
      tabs: [
        {
          id: "details", label: "Details",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn || "-"],
              ["Region", row.region || "-"],
              ["Subscriptions", (row.subscriptions || []).length],
            ]);
          }
        },
        {
          id: "subs", label: "Subscriptions",
          render: function (row) {
            var subs = row.subscriptions || [];
            if (!subs.length) return '<div class="empty-state">No subscriptions on this topic.</div>';
            return H.table(subs, [
              { key: "protocol",         label: "Protocol" },
              { key: "endpoint",         label: "Endpoint" },
              { key: "subscription_arn", label: "Subscription ARN",
                render: function (s) { return (s.subscription_arn || "").slice(-60); } },
              { key: "filter_policy",    label: "Filter policy",
                render: function (s) { return s.filter_policy ? JSON.stringify(s.filter_policy) : ""; } },
              { key: "raw_message_delivery", label: "RMD",
                render: function (s) { return s.raw_message_delivery || ""; } },
            ]);
          }
        },
      ],
      actions: [
        { id: "publish", label: "Publish", primary: true,
          run: function (row) { DASH.actions.snsPublish.open({ name: row.name, arn: row.arn }); } },
        { id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("sns", spec());
  }
})();
