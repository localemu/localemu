// EventBridge Scheduler drill: expression + target + LocalEmu runtime
// state (next_fire, fired_once, currently_dispatching) sourced from
// SchedulerJobScheduler so the user can confirm the polling thread
// actually sees the schedule.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "scheduler",
      title: function (r) { return r.name || "(schedule)"; },
      subtitle: function (r) {
        return [r.group, r.expression, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        // Key can be "group/name" or just "name" — the backend handles both.
        var path = "/_localemu/api/resources/scheduler/" + key.split("/").map(encodeURIComponent).join("/");
        return DASH.api.fetchJSON(path, { etag: false, timeoutMs: 6000 })
          .then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            var rt = r.runtime || {};
            var ftw = r.flexible_time_window || {};
            return H.kvTable([
              ["Name", r.name],
              ["Group", r.group],
              ["ARN", r.arn],
              ["Description", r.description || "-"],
              ["Schedule expression", r.schedule_expression],
              ["Timezone", r.schedule_expression_timezone],
              ["State", rt.state || r.state],
              ["Next fire", rt.next_fire || "-"],
              ["Currently dispatching", rt.currently_dispatching ? "yes" : "no"],
              ["Fired once (at-expr)", rt.fired_once ? "yes" : "no"],
              ["Flexible window mode", ftw.Mode || "OFF"],
              ["Flexible minutes", ftw.MaximumWindowInMinutes || 0],
              ["Start date", r.start_date || "-"],
              ["End date", r.end_date || "-"],
              ["Action after completion", r.action_after_completion || "NONE"],
              ["KMS key", r.kms_key_arn || "-"],
              ["Region", r.region],
            ]);
          }
        },
        {
          id: "target", label: "Target",
          render: function (r) {
            var t = r.target || {};
            return H.kvTable([
              ["Target ARN", t.Arn || "-"],
              ["Role ARN", t.RoleArn || "-"],
              ["DLQ ARN", (t.DeadLetterConfig || {}).Arn || "-"],
              ["Retry policy", t.RetryPolicy],
              ["Input", t.Input || "-"],
              ["Input transformer", t.InputTransformer],
              ["Service-specific params", extractServiceParams(t)],
            ]);
          }
        },
        {
          id: "json", label: "JSON",
          render: function (r) { return jsonOrPre(r); }
        },
      ],
      actions: [
        {
          id: "copy-arn", label: "Copy schedule ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("Schedule ARN copied", "ok");
          }
        },
      ],
    };
  }

  // EventBridge Scheduler target keys for per-service overrides (one of
  // these may be present depending on the target type).
  var SVC_PARAM_KEYS = [
    "SqsParameters", "KinesisParameters", "EventBridgeParameters",
    "EcsParameters", "SageMakerPipelineParameters",
  ];
  function extractServiceParams(t) {
    if (!t) return "-";
    var out = {};
    SVC_PARAM_KEYS.forEach(function (k) { if (t[k]) out[k] = t[k]; });
    return Object.keys(out).length ? out : "-";
  }

  function jsonOrPre(v) {
    var H = DASH.drills.framework.helpers;
    if (H.jsonBlock) return H.jsonBlock(v);
    return '<pre>' + DASH.utils.esc(JSON.stringify(v, null, 2)) + '</pre>';
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("scheduler", spec());
  }
})();
