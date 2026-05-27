// ECS cluster drill via the framework.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "ecs",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.status, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/ecs/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Cluster", row.name],
              ["ARN", row.arn || "-"],
              ["Status", row.status],
              ["Active services", row.active_services_count],
              ["Running tasks", row.running_tasks_count],
              ["Pending tasks", row.pending_tasks_count],
              ["Container instances", row.registered_container_instances_count],
              ["Capacity providers", (row.capacity_providers || []).join(", ") || "-"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "services", label: "Services",
          render: function (row) {
            var svcs = row.services || [];
            if (!svcs.length) return '<div class="empty-state">No services in this cluster.</div>';
            return H.table(svcs, [
              { key: "name",            label: "Service" },
              { key: "task_definition", label: "Task definition" },
              { key: "desired_count",   label: "Desired" },
              { key: "running_count",   label: "Running" },
              { key: "pending_count",   label: "Pending" },
              { key: "launch_type",     label: "Launch type" },
              { key: "status",          label: "Status" },
            ]);
          }
        },
        {
          id: "tasks", label: "Tasks",
          render: function (row) {
            var tasks = row.tasks || [];
            if (!tasks.length) return '<div class="empty-state">No tasks. Use <code>awsemu ecs run-task</code> to launch one.</div>';
            return H.table(tasks, [
              { key: "arn",             label: "Task ARN",
                render: function (t) { return (t.arn || "").split("/").pop(); } },
              { key: "task_definition", label: "Task def",
                render: function (t) { return (t.task_definition || "").split("/").pop(); } },
              { key: "last_status",     label: "Status" },
              { key: "desired_status",  label: "Desired" },
              { key: "started_by",      label: "Started by" },
              { key: "started_at",      label: "Started" },
              { key: "launch_type",     label: "Launch type" },
            ]);
          }
        },
        {
          id: "instances", label: "Container instances",
          render: function (row) {
            var ci = row.container_instances || [];
            if (!ci.length) return '<div class="empty-state">No container instances registered.</div>';
            return H.table(ci, [
              { key: "ec2_instance_id",     label: "EC2 instance" },
              { key: "status",              label: "Status" },
              { key: "agent_connected",     label: "Agent",
                render: function (c) { return c.agent_connected ? "Connected" : "Disconnected"; } },
              { key: "running_tasks_count", label: "Running tasks" },
              { key: "pending_tasks_count", label: "Pending tasks" },
            ]);
          }
        },
        {
          id: "config", label: "Configuration",
          render: function (row) {
            return H.kvTable([
              ["Settings", JSON.stringify(row.settings || [])],
              ["Configuration", JSON.stringify(row.configuration || {})],
              ["Default capacity provider strategy", JSON.stringify(row.default_capacity_provider_strategy || [])],
            ]);
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || {};
            var keys = Array.isArray(tags) ? tags.map(function (t) { return [t.key || t.Key, t.value || t.Value]; }) : Object.keys(tags).map(function (k) { return [k, tags[k]]; });
            if (!keys.length) return '<div class="empty-state">No tags.</div>';
            return H.table(keys.map(function (p) { return { key: p[0], value: p[1] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
      ],
      actions: [
        { id: "copy-arn", label: "Copy ARN",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || "");
            DASH.utils.showToast("ARN copied", "ok");
          } },
        { id: "list-tasks", label: "Copy list-tasks command",
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu ecs list-tasks --cluster " + row.name);
            DASH.utils.showToast("Copied", "ok");
          } },
        { id: "delete", label: "Delete cluster", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu ecs delete-cluster --cluster " + row.name);
            DASH.utils.showToast("Copied delete-cluster", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("ecs", spec());
  }
})();
