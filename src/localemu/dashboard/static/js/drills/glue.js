// Glue drill: one entry point that routes by kind to the right
// per-resource layout (database / table / crawler / job / job-run /
// trigger / workflow / connection / registry / schema).
//
// The drill key is the URL fragment after "glue/" and is shaped as
// "<kind>/<rest>". The first segment picks the route, the rest is
// the resource key (which may contain its own "/" -- e.g. tables
// keyed as "<db>/<table>").
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "glue",
      title: function (r) {
        if (r.kind === "table") return r.database_name + "." + r.name;
        if (r.kind === "schema") return r.registry_name + "." + r.name;
        if (r.kind === "job-run") return r.job_name + " \u2192 " + r.id;
        return r.name || "(glue)";
      },
      subtitle: function (r) {
        return [r.kind, r.status, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        // key is "<kind>/<rest>" -- split on the first slash only,
        // the rest may contain its own slashes (e.g. "table/db/name").
        var firstSlash = key.indexOf("/");
        if (firstSlash < 0) {
          return Promise.reject(new Error("Glue drill expects kind/key, got: " + key));
        }
        var kind = key.slice(0, firstSlash);
        var rest = key.slice(firstSlash + 1);
        // The backend route is /resources/glue/<kind>/<path:key>.
        // The path converter accepts slashes in rest, so encode each
        // segment individually to preserve them.
        var path = "/_localemu/api/resources/glue/" + encodeURIComponent(kind) + "/"
                 + rest.split("/").map(encodeURIComponent).join("/");
        return DASH.api.fetchJSON(path, { etag: false, timeoutMs: 8000 })
          .then(function (r) { return (r && r.data) || { kind: kind, name: rest, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            if (r.kind === "database")   return renderDatabase(r);
            if (r.kind === "table")      return renderTable(r);
            if (r.kind === "crawler")    return renderCrawler(r);
            if (r.kind === "job")        return renderJob(r);
            if (r.kind === "job-run")    return renderJobRun(r);
            if (r.kind === "trigger")    return renderTrigger(r);
            if (r.kind === "workflow")   return renderWorkflow(r);
            if (r.kind === "connection") return renderConnection(r);
            if (r.kind === "registry")   return renderRegistry(r);
            if (r.kind === "schema")     return renderSchema(r);
            return H.kvTable(Object.keys(r).map(function (k) { return [k, r[k]]; }));
          }
        },
        {
          id: "tables", label: "Tables",
          availableWhen: function (r) { return r.kind === "database"; },
          render: function (r) {
            var tables = r.tables || [];
            if (!tables.length) return '<div class="empty-state">No tables in this database yet.<br>'
              + '<span class="hint">Add one with: <code>awsemu glue create-table --database-name '
              + u.esc(r.name) + ' --table-input Name=orders,StorageDescriptor={Location=s3://...,Columns=[...]}</code></span></div>';
            return H.table(tables, [
              { key: "name",         label: "Name" },
              { key: "columns",      label: "Columns" },
              { key: "partitions",   label: "Partitions" },
              { key: "created_time", label: "Created" },
              { key: "updated_time", label: "Updated" },
            ]);
          }
        },
        {
          id: "columns", label: "Schema",
          availableWhen: function (r) { return r.kind === "table"; },
          render: function (r) {
            var cols = r.columns || [];
            if (!cols.length) return '<div class="empty-state">No columns recorded for this table.</div>';
            return H.table(cols, [
              { key: "Name",    label: "Column" },
              { key: "Type",    label: "Type" },
              { key: "Comment", label: "Comment" },
            ]);
          }
        },
        {
          id: "partitions", label: "Partitions",
          availableWhen: function (r) { return r.kind === "table"; },
          render: function (r) {
            var keys = r.partition_keys || [];
            var parts = r.partitions || [];
            var html = '';
            if (keys.length) {
              html += '<h3>Partition keys</h3>';
              html += H.table(keys, [
                { key: "Name", label: "Key" },
                { key: "Type", label: "Type" },
              ]);
            }
            html += '<h3 style="margin-top:14px">Materialised partitions</h3>';
            if (!parts.length) {
              html += '<div class="empty-state">No partitions registered for this table.</div>';
            } else {
              html += H.table(parts, [
                { key: "values",           label: "Values",
                  render: function (p) { return (p.values || []).join(" / "); } },
                { key: "creation_time",    label: "Created" },
                { key: "last_access_time", label: "Last access" },
              ]);
            }
            return html;
          }
        },
        {
          id: "storage", label: "Storage",
          availableWhen: function (r) { return r.kind === "table"; },
          render: function (r) {
            var s = r.storage || {};
            var serde = s.serde_info || {};
            return H.kvTable([
              ["Table type", r.table_type],
              ["Location", s.location || "-"],
              ["Input format", s.input_format || "-"],
              ["Output format", s.output_format || "-"],
              ["Compressed", s.compressed ? "yes" : "no"],
              ["SerDe library", serde.SerializationLibrary || "-"],
              ["SerDe parameters", serde.Parameters || {}],
              ["Table parameters", r.parameters || {}],
            ]);
          }
        },
        {
          id: "runs", label: "Job runs",
          availableWhen: function (r) { return r.kind === "job"; },
          render: function (r) {
            var runs = r.job_runs || [];
            if (!runs.length) return '<div class="empty-state">This job has never run.<br>'
              + '<span class="hint">Start one: <code>awsemu glue start-job-run --job-name '
              + u.esc(r.name) + '</code></span></div>';
            return H.table(runs, [
              { key: "id",                label: "Run ID",
                render: function (x) { return (x.id || "").slice(0, 24) + "..."; } },
              { key: "status",            label: "Status" },
              { key: "worker_type",       label: "Worker type" },
              { key: "number_of_workers", label: "Workers" },
              { key: "started_on",        label: "Started" },
              { key: "completed_on",      label: "Completed" },
              { key: "timeout",           label: "Timeout (min)" },
            ]);
          }
        },
        {
          id: "schemas", label: "Schemas",
          availableWhen: function (r) { return r.kind === "registry"; },
          render: function (r) {
            var schemas = r.schemas || [];
            if (!schemas.length) return '<div class="empty-state">No schemas registered yet.</div>';
            return H.table(schemas, [
              { key: "name",           label: "Name" },
              { key: "data_format",    label: "Data format" },
              { key: "compatibility",  label: "Compatibility" },
              { key: "latest_version", label: "Latest version" },
              { key: "status",         label: "Status" },
            ]);
          }
        },
        {
          id: "versions", label: "Versions",
          availableWhen: function (r) { return r.kind === "schema"; },
          render: function (r) {
            var versions = r.versions || [];
            if (!versions.length) return '<div class="empty-state">No versions recorded.</div>';
            return H.table(versions, [
              { key: "id",             label: "Version ID" },
              { key: "version_number", label: "Version #" },
              { key: "status",         label: "Status" },
            ]);
          }
        },
        {
          id: "actions", label: "Actions",
          availableWhen: function (r) { return r.kind === "trigger"; },
          render: function (r) {
            var actions = r.actions || [];
            if (!actions.length) return '<div class="empty-state">No actions wired to this trigger.</div>';
            return H.table(actions, [
              { key: "job_name",      label: "Job" },
              { key: "crawler_name",  label: "Crawler" },
              { key: "timeout",       label: "Timeout (min)" },
              { key: "arguments",     label: "Arguments",
                render: function (a) { return Object.keys(a.arguments || {}).length + " keys"; } },
            ]);
          }
        },
        {
          id: "wf-runs", label: "Workflow runs",
          availableWhen: function (r) { return r.kind === "workflow"; },
          render: function (r) {
            var runs = r.runs || [];
            if (!runs.length) return '<div class="empty-state">No workflow runs.</div>';
            return H.table(runs, [
              { key: "id",           label: "Run ID",
                render: function (x) { return (x.id || "").slice(0, 24) + "..."; } },
              { key: "status",       label: "Status" },
              { key: "started_on",   label: "Started" },
              { key: "completed_on", label: "Completed" },
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
          id: "copy-key", label: "Copy ARN/name",
          run: function (row) {
            DASH.utils.copyToClipboard(row.arn || row.schema_arn || row.registry_arn || row.name || "");
            DASH.utils.showToast("Copied", "ok");
          }
        },
      ],
    };
  }

  // -------------------- Per-kind overview renderers --------------------
  function renderDatabase(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["Catalog ID", r.catalog_id],
      ["Tables", (r.tables || []).length],
      ["Created", r.created_time],
      ["Description", (r.input || {}).Description || "-"],
      ["Location URI", (r.input || {}).LocationUri || "-"],
      ["Parameters", (r.input || {}).Parameters || {}],
      ["Region", r.region],
    ]);
  }

  function renderTable(r) {
    var H = DASH.drills.framework.helpers;
    var s = r.storage || {};
    return H.kvTable([
      ["Database", r.database_name],
      ["Table", r.name],
      ["Table type", r.table_type],
      ["Catalog ID", r.catalog_id],
      ["Current version", r.current_version],
      ["Total versions", r.version_count],
      ["Columns", (r.columns || []).length],
      ["Partition keys", (r.partition_keys || []).length],
      ["Materialised partitions", (r.partitions || []).length],
      ["Location", s.location || "-"],
      ["Created", r.created_time],
      ["Updated", r.updated_time || "-"],
      ["Region", r.region],
    ]);
  }

  function renderCrawler(r) {
    var H = DASH.drills.framework.helpers;
    var last = r.last_crawl;
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["IAM role", r.role],
      ["Target database", r.database_name || "-"],
      ["Description", r.description || "-"],
      ["Schedule", r.schedule],
      ["Table prefix", r.table_prefix || "-"],
      ["Status", r.status],
      ["Classifiers", (r.classifiers || []).join(", ") || "-"],
      ["Targets", r.targets],
      ["Schema change policy", r.schema_change_policy],
      ["Recrawl policy", r.recrawl_policy],
      ["Lineage configuration", r.lineage_configuration],
      ["Last crawl", last == null ? "(never)" : last.status + " \u00b7 " + last.start_time + " \u2192 " + last.end_time],
      ["Version", r.version],
      ["Created", r.creation_time],
      ["Last updated", r.last_updated],
      ["Region", r.region],
    ]);
  }

  function renderJob(r) {
    var H = DASH.drills.framework.helpers;
    var cmd = r.command || {};
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Description", r.description || "-"],
      ["IAM role", r.role],
      ["Command name", cmd.Name || "-"],
      ["Script location", cmd.ScriptLocation || "-"],
      ["Python version", cmd.PythonVersion || "-"],
      ["Glue version", r.glue_version || "-"],
      ["Worker type", r.worker_type || "-"],
      ["Workers", r.number_of_workers],
      ["Max capacity", r.max_capacity],
      ["Allocated capacity", r.allocated_capacity],
      ["Max retries", r.max_retries],
      ["Timeout (min)", r.timeout],
      ["Execution class", r.execution_class || "-"],
      ["Execution property", r.execution_property],
      ["Default arguments", r.default_arguments],
      ["Non-overridable arguments", r.non_overridable_arguments],
      ["Connections", r.connections],
      ["Security configuration", r.security_configuration || "-"],
      ["Log URI", r.log_uri || "-"],
      ["Job runs", (r.job_runs || []).length],
      ["Created", r.created_on],
      ["Last modified", r.last_modified_on],
      ["Region", r.region],
    ]);
  }

  function renderJobRun(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Job", r.job_name],
      ["Run ID", r.id],
      ["Previous run ID", r.previous_run_id || "-"],
      ["Status", r.status],
      ["Worker type", r.worker_type || "-"],
      ["Workers", r.number_of_workers],
      ["Max capacity", r.max_capacity],
      ["Allocated capacity", r.allocated_capacity],
      ["Timeout (min)", r.timeout],
      ["Started", r.started_on],
      ["Modified", r.modified_on],
      ["Completed", r.completed_on],
      ["Arguments", r.arguments],
      ["Security configuration", r.security_configuration || "-"],
      ["Notification property", r.notification_property],
      ["Region", r.region],
    ]);
  }

  function renderTrigger(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Workflow", r.workflow_name || "-"],
      ["Type", r.trigger_type],
      ["State", r.state],
      ["Schedule", r.schedule || "-"],
      ["Description", r.description || "-"],
      ["Predicate", r.predicate || "(none)"],
      ["Actions", (r.actions || []).length],
      ["Event batching", r.event_batching_condition],
      ["Region", r.region],
    ]);
  }

  function renderWorkflow(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["Description", r.description || "-"],
      ["Max concurrent runs", r.max_concurrent_runs == null ? "-" : r.max_concurrent_runs],
      ["Default run properties", r.default_run_properties],
      ["Tags", r.tags],
      ["Runs", (r.runs || []).length],
      ["Created", r.created_on],
      ["Last modified", r.last_modified_on],
      ["Region", r.region],
    ]);
  }

  function renderConnection(r) {
    var H = DASH.drills.framework.helpers;
    var cp = r.connection_properties || {};
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Catalog ID", r.catalog_id],
      ["Description", r.description || "-"],
      ["Status", r.status],
      ["Connection type", cp.CONNECTION_TYPE || "-"],
      ["JDBC URL", cp.JDBC_CONNECTION_URL || "-"],
      ["Username", cp.USERNAME || "-"],
      ["Connection properties", cp],
      ["Spark properties", r.spark_properties],
      ["Athena properties", r.athena_properties],
      ["Python properties", r.python_properties],
      ["Created", r.created_time],
      ["Updated", r.updated_time],
      ["Region", r.region],
    ]);
  }

  function renderRegistry(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Name", r.name],
      ["ARN", r.arn],
      ["Description", r.description || "-"],
      ["Status", r.status],
      ["Schemas", (r.schemas || []).length],
      ["Tags", r.tags],
      ["Created", r.created_time],
      ["Updated", r.updated_time],
      ["Region", r.region],
    ]);
  }

  function renderSchema(r) {
    var H = DASH.drills.framework.helpers;
    return H.kvTable([
      ["Schema name", r.name],
      ["Registry", r.registry_name],
      ["Schema ARN", r.schema_arn],
      ["Registry ARN", r.registry_arn],
      ["Description", r.description || "-"],
      ["Data format", r.data_format],
      ["Compatibility", r.compatibility],
      ["Latest version", r.latest_schema_version],
      ["Next version", r.next_schema_version],
      ["Checkpoint", r.schema_checkpoint],
      ["Schema status", r.schema_status],
      ["Latest version ID", r.schema_version_id],
      ["Total versions", (r.versions || []).length],
      ["Created", r.created_time],
      ["Updated", r.updated_time],
      ["Region", r.region],
    ]);
  }

  function jsonOrPre(v) {
    var H = DASH.drills.framework.helpers;
    if (H.jsonBlock) return H.jsonBlock(v);
    return '<pre>' + DASH.utils.esc(JSON.stringify(v, null, 2)) + '</pre>';
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("glue", spec());
  }
})();
