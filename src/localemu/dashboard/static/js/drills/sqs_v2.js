// SQS queue drill via the framework. Replaces the narrow message-peek
// page in drills/sqs.js with a richer tabbed view.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "sqs",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.type, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        var name = encodeURIComponent(key);
        return Promise.all([
          DASH.api.fetchJSON("/_localemu/api/resources/sqs/" + name + "/detail", { etag: false, timeoutMs: 6000 })
            .then(function (r) { return (r && r.data) || null; })
            .catch(function () { return null; }),
          DASH.api.fetchJSON("/_localemu/api/resources/sqs/" + name, { etag: false, timeoutMs: 6000 })
            .then(function (r) { return (r && r.data && r.data.messages) || []; })
            .catch(function () { return []; }),
        ]).then(function (parts) {
          var detail = parts[0] || { name: key, error: "not found" };
          detail.messages = parts[1];
          return detail;
        });
      },
      defaultTab: "details",
      tabs: [
        {
          id: "details", label: "Details",
          render: function (row) {
            return H.kvTable([
              ["Name", row.name],
              ["ARN", row.arn],
              ["URL", row.url],
              ["Type", row.type],
              ["Region", row.region],
              ["Visibility timeout (s)", row.visibility_timeout],
              ["Delivery delay (s)", row.delay_seconds],
              ["Message retention (s)", row.message_retention_period],
              ["Max message size (bytes)", row.maximum_message_size],
              ["Receive wait time (s)", row.receive_message_wait_time_seconds],
              ["SQS-managed SSE", row.sqs_managed_sse],
              ["KMS master key", row.kms_master_key_id || "(none)"],
              ["FIFO dedup scope", row.deduplication_scope || "-"],
              ["FIFO throughput limit", row.fifo_throughput_limit || "-"],
              ["Content-based dedup", row.content_based_deduplication],
              ["Created", row.created_timestamp || "-"],
              ["Last modified", row.last_modified_timestamp || "-"],
            ]);
          }
        },
        {
          id: "messages", label: "Messages",
          render: function (row) {
            var msgs = row.messages || [];
            if (!msgs.length) return '<div class="empty-state">Queue is empty (or every message is in flight).</div>';
            return H.table(msgs, [
              { key: "message_id", label: "Message ID" },
              { key: "body",       label: "Body",
                render: function (m) { return (m.body || "").slice(0, 200); } },
              { key: "attributes", label: "Attributes",
                render: function (m) { return JSON.stringify(m.attributes || {}); } },
            ]);
          }
        },
        {
          id: "dlq", label: "Dead-letter queue",
          render: function (row) {
            if (!row.redrive_policy) return '<div class="empty-state">No DLQ configured. Set with <code>awsemu sqs set-queue-attributes</code> RedrivePolicy.</div>';
            return H.kvTable([
              ["maxReceiveCount", row.redrive_policy.maxReceiveCount],
              ["deadLetterTargetArn", row.redrive_policy.deadLetterTargetArn],
            ]);
          }
        },
        {
          id: "policy", label: "Access policy",
          render: function (row) {
            if (!row.policy || (typeof row.policy === "object" && !Object.keys(row.policy).length)) {
              return '<div class="empty-state">No resource policy attached. Default IAM rules apply.</div>';
            }
            return H.jsonBlock(row.policy);
          }
        },
        {
          id: "monitoring", label: "Live counts",
          render: function (row) {
            return H.kvTable([
              ["Approximate # messages",                row.approximate_number_of_messages],
              ["Approximate # delayed",                 row.approximate_number_of_messages_delayed],
              ["Approximate # in flight (not visible)", row.approximate_number_of_messages_not_visible],
            ]);
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
        { id: "send", label: "Send message", primary: true,
          run: function (row) { DASH.actions.sqsSend.open({ name: row.name }); } },
        { id: "purge", label: "Purge", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu sqs purge-queue --queue-url " + (row.url || row.name));
            DASH.utils.showToast("Copied purge-queue", "ok");
          } },
        { id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("sqs", spec());
  }
})();
