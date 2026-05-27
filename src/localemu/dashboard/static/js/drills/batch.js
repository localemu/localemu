// Batch drill: the response carries ``kind`` so we pick the right layout
// for compute envs, job queues, job definitions, and jobs.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "batch",
      title: function (r) { return r.name || "(batch)"; },
      subtitle: function (r) {
        return [r.kind, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/batch/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            if (r.kind === "compute-env")   return renderComputeEnv(r);
            if (r.kind === "job-queue")     return renderJobQueue(r);
            if (r.kind === "job-def")       return renderJobDef(r);
            if (r.kind === "job")           return renderJob(r);
            return H.kvTable(Object.keys(r).map(function (k) { return [k, r[k]]; }));
          }
        },
        {
          id: "json", label: "JSON",
          render: function (r) { return H.jsonBlock ? H.jsonBlock(r) : '<pre>' + u.esc(JSON.stringify(r, null, 2)) + '</pre>'; }
        },
      ],
      actions: [
        {
          id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          }
        },
      ],
    };
  }

  function renderComputeEnv(r) {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    var cr = r.compute_resources || {};
    var html = H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Type", r.type],
      ["State", r.state],
      ["Service role", r.service_role || "-"],
      ["ECS cluster", r.ecs_cluster_arn || "-"],
      ["Compute type", cr.type || "-"],
      ["Min vCPUs", cr.minvCpus],
      ["Max vCPUs", cr.maxvCpus],
      ["Desired vCPUs", cr.desiredvCpus],
      ["Instance role", cr.instanceRole || "-"],
      ["Instance types", (cr.instanceTypes || []).join(", ") || "-"],
      ["Subnets", (cr.subnets || []).join(", ") || "-"],
      ["Security groups", (cr.securityGroupIds || []).join(", ") || "-"],
      ["Region", r.region],
    ]);
    if ((r.instances || []).length) {
      html += '<h3 style="margin-top:14px">Active instances</h3>';
      html += '<ul>' + r.instances.map(function (i) { return '<li><code>' + u.esc(i) + '</code></li>'; }).join("") + '</ul>';
    }
    return html;
  }

  function renderJobQueue(r) {
    var H = DASH.drills.framework.helpers;
    var html = H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["State", r.state],
      ["Priority", r.priority],
      ["Scheduling policy", r.schedule_policy || "-"],
      ["Region", r.region],
    ]);
    if ((r.compute_environments || []).length) {
      html += '<h3 style="margin-top:14px">Compute environment order</h3>';
      html += H.table(r.compute_environments, [
        { key: "order",              label: "Order" },
        { key: "computeEnvironment", label: "Compute environment" },
      ]);
    }
    return html;
  }

  function renderJobDef(r) {
    var H = DASH.drills.framework.helpers;
    var cp = r.container_properties || {};
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Type", r.type],
      ["Revision", r.revision],
      ["Image", cp.image || "-"],
      ["vCPUs", cp.vcpus],
      ["Memory (MiB)", cp.memory],
      ["Command", (cp.command || []).join(" ") || "-"],
      ["Job role ARN", cp.jobRoleArn || "-"],
      ["Execution role ARN", cp.executionRoleArn || "-"],
      ["Platform capabilities", (r.platform_capabilities || []).join(", ") || "EC2"],
      ["Propagate tags", r.propagate_tags ? "yes" : "no"],
      ["Retry strategy", r.retry_strategy],
      ["Timeout", r.timeout],
      ["Parameters", r.parameters],
      ["Region", r.region],
    ]);
  }

  function renderJob(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["Job ID", r.job_id],
      ["Status", r.status],
      ["Status reason", r.status_reason || "-"],
      ["Job queue", r.job_queue || "-"],
      ["Job definition", r.job_definition || "-"],
      ["Started", r.started_at ? new Date(r.started_at).toISOString() : "-"],
      ["Stopped", r.stopped_at ? new Date(r.stopped_at).toISOString() : "-"],
      ["Container overrides", r.container_overrides],
      ["Depends on", (r.depends_on || []).map(function (d) { return d.jobId; }).join(", ") || "-"],
      ["Region", r.region],
    ]);
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("batch", spec());
  }
})();
