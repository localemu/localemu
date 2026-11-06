// Service page: header, awsemu command line, resource table with row
// actions, empty state, and the service's call volume.
//
// Rows come from /_localemu/api/resources/<service>?account=<id> (the same
// lister the per-resource drills are built on), scoped to the account
// selected in the top bar. The table refreshes on SSE ``resource`` events
// for the service; a 30 s poll is the fallback when SSE is down.
(function () {
  "use strict";

  var ROW_ACTIONS = {
    lambda: [
      { label: "Invoke", primary: true, run: function (row) { DASH.actions.lambdaInvoke.open(row); } },
      { label: "Logs", run: function (row) { DASH.app.navigate({ service: "logs", resource: "/aws/lambda/" + (row.name || "") }); } }
    ],
    sqs: [
      { label: "Send message", primary: true, run: function (row) { DASH.actions.sqsSend.open(row); } },
      { label: "Purge", danger: true, run: function (row) { purgeQueue(row); } }
    ],
    sns: [{ label: "Publish", primary: true, run: function (row) { DASH.actions.snsPublish.open(row); } }],
    events: [{ label: "Put event", primary: true, run: function (row) { DASH.actions.eventsPut.open(row); } }],
    secretsmanager: [{ label: "Rotate", primary: true, run: function (row) { DASH.actions.secretRotate.open(row); } }],
    dynamodb: [{ label: "Items", primary: true, run: function (row) { DASH.actions.dynamoDb.open(row); } }],
    s3: [{ label: "Browse", primary: true, run: function (row) { dispatchDrill("s3", row); } }],
    ec2: [{ label: "Connect", primary: true, run: function (row) { dispatchDrill("ec2", row); } }],
    rds: [{ label: "Connect", primary: true, run: function (row) { dispatchDrill("rds", row); } }]
  };

  // Drill-down navigation per service (row -> drill key).
  var DRILL_DOWNS = {
    s3:           function (row) { DASH.app.navigate({ service: "s3",            resource: row.name }); },
    sqs:          function (row) { DASH.app.navigate({ service: "sqs",           resource: row.name }); },
    dynamodb:     function (row) { DASH.app.navigate({ service: "dynamodb",      resource: row.name }); },
    logs:         function (row) { DASH.app.navigate({ service: "logs",          resource: row.name }); },
    sns:          function (row) { DASH.app.navigate({ service: "sns",           resource: row.name }); },
    events:       function (row) { DASH.app.navigate({ service: "events",        resource: row.bus, meta: { highlight: row.name } }); },
    lambda:       function (row) { DASH.app.navigate({ service: "lambda",        resource: row.name }); },
    stepfunctions:function (row) { DASH.app.navigate({ service: "stepfunctions", resource: row.arn || row.name }); },
    kms:          function (row) { DASH.app.navigate({ service: "kms",           resource: row.key_id || row.name }); },
    iam:          function (row) { if (DASH.drills.iam && DASH.drills.iam.hint) DASH.drills.iam.hint(row.name, row.type); DASH.app.navigate({ service: "iam", resource: row.name }); },
    ec2:          function (row) { DASH.app.navigate({ service: "ec2",           resource: row.instance_id || row.name }); },
    vpc:          function (row) { DASH.app.navigate({ service: "vpc",           resource: row.name }); },
    glue:         function (row) {
      var k = row.kind || "database";
      var key = row.key || row.name || "";
      if (key) DASH.app.navigate({ service: "glue", resource: k + "/" + key });
    },
    rds:          function (row) { DASH.app.navigate({ service: "rds",           resource: row.name }); },
    secretsmanager:function (row) { DASH.app.navigate({ service: "secretsmanager", resource: row.name }); },
    apigatewayv2: function (row) { DASH.app.navigate({ service: "apigatewayv2",  resource: row.api_id || row.name }); },
    apigateway:   function (row) { DASH.app.navigate({ service: "apigateway",    resource: row.api_id || row.name }); },
    ecs:          function (row) { DASH.app.navigate({ service: "ecs",           resource: row.name }); },
    eks:          function (row) { DASH.app.navigate({ service: "eks",           resource: row.cluster || row.name }); },
    opensearch:   function (row) { DASH.app.navigate({ service: "opensearch",    resource: row.name }); },
    athena:       function (row) { DASH.app.navigate({ service: "athena",        resource: row.name || "primary" }); },
    cloudformation:function (row) { DASH.app.navigate({ service: "cloudformation", resource: row.name }); },
    elbv2:        function (row) { DASH.app.navigate({ service: "elbv2",         resource: row.name }); },
    route53:      function (row) { DASH.app.navigate({ service: "route53",       resource: row.id || row.name }); },
    "cognito-idp":function (row) { DASH.app.navigate({ service: "cognito-idp",   resource: row.id || row.name }); },
    kinesis:      function (row) { DASH.app.navigate({ service: "kinesis",       resource: row.name }); },
    firehose:     function (row) { DASH.app.navigate({ service: "firehose",      resource: row.name }); },
    kafka:        function (row) { DASH.app.navigate({ service: "kafka",         resource: row.arn || row.name }); },
    mq:           function (row) { DASH.app.navigate({ service: "mq",            resource: row.broker_id || row.name }); },
    acm:          function (row) { DASH.app.navigate({ service: "acm",           resource: row.arn || row.name }); },
    efs:          function (row) { DASH.app.navigate({ service: "efs",           resource: row.file_system_id || row.name }); }
  };

  function dispatchDrill(svc, row) {
    if (DRILL_DOWNS[svc]) return DRILL_DOWNS[svc](row);
    if (DASH.registry && DASH.registry.get && DASH.registry.get(svc)) {
      var key = row.name || row.key_id || row.id || row.arn || row.key || "";
      if (key) DASH.app.navigate({ service: svc, resource: key });
    }
  }

  function purgeQueue(row) {
    var name = row.name || "";
    if (!window.confirm("Purge every message from " + name + "?\n\nThis calls sqs:PurgeQueue and cannot be undone.")) return;
    DASH.api.post("/_localemu/api/actions/sqs/purge-queue", { queue_name: name, region: row.region }, { timeoutMs: 15000 }).then(function () {
      DASH.utils.showToast("Purged " + name);
      refresh(true);
    }).catch(function (err) { DASH.utils.showApiError(err, "purge " + name); });
  }

  var lastFetched = null;
  var searchFilter = "";
  var pollTimer = null;
  var fetchError = null;

  function open() {
    searchFilter = "";
    lastFetched = null;
    fetchError = null;
    DASH.app.state.resources = [];
    DASH.app.state.resourcesService = null;
    refresh(true);
    startPolling();
  }
  function close() { stopPolling(); searchFilter = ""; lastFetched = null; }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(function () {
      if (DASH.bus.connectionStatus() === "connected") return;
      if (DASH.app.state.route.resource) return;
      refresh(false);
    }, 30000);
  }
  function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  function listUrl(svc) {
    return "/_localemu/api/resources/" + encodeURIComponent(svc) + "?account=" + encodeURIComponent(DASH.app.state.account);
  }

  function refresh(force) {
    var svc = DASH.app.state.route.service;
    if (!svc || DASH.app.state.route.resource) return;
    var acct = DASH.app.state.account;
    var cacheKey = "resources:" + svc;
    if (force) DASH.cache.invalidateKey(cacheKey);
    DASH.api.get(listUrl(svc), { cacheKey: cacheKey, ttlMs: 30000, tags: ["resources:" + svc], etag: true }).then(function (r) {
      if (DASH.app.state.route.service !== svc || DASH.app.state.route.resource || DASH.app.state.account !== acct) return;
      var data = r.value || {};
      fetchError = data.error || null;
      DASH.app.state.resources = data.resources || [];
      DASH.app.state.resourcesService = svc;
      lastFetched = Date.now();
      render();
    }).catch(function (err) {
      if (DASH.app.state.route.service !== svc || DASH.app.state.route.resource) return;
      fetchError = (err && err.message) || "request failed";
      DASH.app.state.resources = [];
      DASH.app.state.resourcesService = svc;
      render();
    });
  }

  var ALT_KEYS = {
    name: ["name", "Name", "table_name", "TableName", "queue_name", "QueueName", "function_name", "FunctionName", "topic_name", "TopicName", "bucket_name", "BucketName", "cluster_name", "ClusterName"],
    instance_id: ["instance_id", "InstanceId", "id"],
    state: ["state", "State", "status", "Status"],
    status: ["status", "Status", "state", "State"],
    type: ["type", "Type", "instance_type", "InstanceType"],
    region: ["region", "Region"], runtime: ["runtime", "Runtime"], handler: ["handler", "Handler"],
    memory: ["memory", "Memory"], role: ["role", "Role"], objects: ["objects", "Objects"],
    items: ["items", "Items", "item_count", "ItemCount"], messages: ["messages", "Messages"],
    subscriptions: ["subscriptions", "Subscriptions"], cluster: ["cluster", "Cluster", "name", "Name"],
    arn: ["arn", "Arn", "ARN"], shards: ["shards", "Shards"], bus: ["bus", "Bus"], targets: ["targets", "Targets"],
    endpoint: ["endpoint", "Endpoint"], api_id: ["api_id", "ApiId", "id", "Id"],
    protocol: ["protocol", "Protocol", "protocol_type", "ProtocolType"], routes: ["routes", "Routes"],
    stages: ["stages", "Stages"], id: ["id", "Id"], key_id: ["key_id", "KeyId"], alias: ["alias", "Alias", "aliases"],
    usage: ["usage", "Usage", "key_usage", "KeyUsage"], account: ["account", "Account", "account_id", "AccountId"],
    kind: ["kind", "Kind"], operation: ["operation", "Operation", "op"], principal: ["principal", "Principal"],
    dns: ["dns", "Dns", "dns_name", "DNSName"], scheme: ["scheme", "Scheme"],
    source: ["source", "Source", "event_source", "EventSource"], user: ["user", "User", "username", "Username"],
    request_id: ["request_id", "RequestId", "requestId"], time: ["time", "Time", "event_time", "EventTime", "timestamp"],
    records: ["records", "Records", "record_count", "RecordCount"],
    last_modified: ["last_modified", "LastModified", "LastModifiedDate"], version: ["version", "Version"]
  };
  function cellValue(row, key) {
    var v = row[key];
    if (v !== undefined) return v;
    var alts = ALT_KEYS[key] || [];
    for (var j = 0; j < alts.length; j++) if (row[alts[j]] !== undefined) return row[alts[j]];
    return undefined;
  }
  var OK_STATES = /^(running|available|active|enabled|in-service|issued|ready|deployed|create_complete|update_complete|succeeded|healthy)$/i;
  var NEUTRAL_STATES = /^(stopped|stopping|terminated|disabled|inactive|deleted|shutting-down)$/i;
  var WARN_STATES = /^(pending|creating|starting|modifying|updating|provisioning|in_progress|rebooting|backing-up)$/i;
  var ERR_STATES = /^(failed|error|.*_failed|unhealthy|incompatible.*)$/i;
  function cellHtml(v, q) {
    var u = DASH.utils;
    if (v == null || v === "") return { cls: "dim", html: "-" };
    var s = String(v);
    if (OK_STATES.test(s)) return { cls: "", html: '<span class="chip ok">' + u.esc(s) + "</span>" };
    if (NEUTRAL_STATES.test(s)) return { cls: "", html: '<span class="chip neutral">' + u.esc(s) + "</span>" };
    if (WARN_STATES.test(s)) return { cls: "", html: '<span class="chip warn">' + u.esc(s) + "</span>" };
    if (ERR_STATES.test(s)) return { cls: "", html: '<span class="chip err">' + u.esc(s) + "</span>" };
    if (typeof v === "number" || /^\d[\d,]*$/.test(s)) return { cls: "r num", html: u.highlight(s, q) };
    return { cls: "dim", html: u.highlight(s, q) };
  }

  function rowKey(row) { return row.name || row.instance_id || row.id || row.key_id || row.cluster || row.arn || ""; }

  function cmdFor(svc, rows) {
    var cmd = rows.length ? DASH.services.copyCommand(svc, rows[0]) : null;
    if (!cmd && DASH.registry.copyCmd && rows.length) cmd = DASH.registry.copyCmd(svc, rows[0]);
    if (!cmd) cmd = DASH.registry.emptyStateText(svc) || DASH.services.emptyStateText(svc);
    return cmd || "";
  }

  function spark(arr, w, h) {
    var max = Math.max.apply(null, arr.concat([1])), n = arr.length;
    var pts = arr.map(function (v, i) { return [(i / (n - 1)) * w, h - 2 - (v / max) * (h - 8)]; });
    var line = pts.map(function (p) { return p[0].toFixed(1) + "," + p[1].toFixed(1); }).join(" ");
    return '<svg viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" style="width:100%;height:100%" role="img" aria-label="calls per minute">' +
      '<path d="M0,' + h + " L" + line.replace(/ /g, " L") + " L" + w + "," + h + ' Z" fill="var(--accent)" fill-opacity=".12"/>' +
      '<polyline points="' + line + '" fill="none" stroke="var(--accent)" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';
  }

  function render() {
    var state = DASH.app.state;
    var svc = state.route.service;
    if (!svc || state.route.resource) return;
    var u = DASH.utils, c = DASH.catalog;
    var el = document.getElementById("main-content");
    if (!el) return;
    var loaded = state.resourcesService === svc && lastFetched !== null;
    var all = loaded ? (state.resources || []) : [];
    var q = searchFilter.toLowerCase();
    var rows = all.filter(function (r) {
      if (!q) return true;
      for (var k in r) { var v = r[k]; if (v != null && String(v).toLowerCase().indexOf(q) !== -1) return true; }
      return false;
    });
    var labelText = c.label(svc);
    var groupId = c.group(svc);
    var groupLabel = (DASH.services.GROUPS.filter(function (g) { return g.id === groupId; })[0] || {}).label || groupId;
    var n = c.count(svc), isCounted = c.counted(svc);
    var cont = c.containers(svc);
    var docker = c.isDockerBacked(svc);
    var be = docker ? c.dockerBackends()[svc] : null;
    var badge = DASH.registry.tierBadge(svc);
    var docsUrl = DASH.services.docsUrl(svc);
    var arr = c.calls(svc) || [];
    var actions = ROW_ACTIONS[svc] || [];
    var drillable = !!(DRILL_DOWNS[svc] || DASH.registry.get(svc));
    var cmd = cmdFor(svc, all);

    var html = '<div><div class="crumbs"><button type="button" data-route="overview">Overview</button><span>/</span><span>' +
      u.esc(groupLabel) + "</span><span>/</span><span>" + u.esc(labelText) + "</span></div></div>";
    html += '<div class="drill-head">' + u.tile(svc, "lg", n > 0) + '<div class="t"><h1>' + u.esc(labelText) + '</h1><div class="sub">' +
      '<span class="chip ' + (all.length ? "ok" : "neutral") + '">' + (all.length ? "active" : "no resources") + "</span>" +
      '<span class="tier-badge ' + badge.cls + '">' + u.esc(badge.label) + "</span>" +
      (docker ? '<span class="chip box" title="' + u.esc(be.switch) + '">Docker-backed' + (be.enabled ? "" : " (off)") + "</span>" : '<span class="chip neutral">in-process</span>') +
      (cont ? "<span>" + cont.running + " container" + (cont.running === 1 ? "" : "s") + " running</span><span>&middot;</span>" : "") +
      "<span>" + (loaded ? all.length + " resource" + (all.length === 1 ? "" : "s") + " in " + u.esc(state.account) : "loading") + "</span>" +
      "<span>&middot;</span><span>" + c.calls5m(svc) + (c.calls5m(svc) === 1 ? " call" : " calls") + " in 5 min</span></div></div>" +
      '<div class="head-actions">' +
        (docsUrl ? '<a class="btn ghost" href="' + u.esc(docsUrl) + '" target="_blank" rel="noopener noreferrer">' + u.ICON.doc + "LocalEmu Docs</a>" : "") +
        '<button class="btn" type="button" id="resRefresh">' + u.ICON.refresh + "Refresh</button>" +
        '<button class="btn primary" type="button" id="resCreate">' + u.ICON.plus + "Create</button></div></div>";
    if (cmd) {
      var ep = (state.system && state.system.endpoint) || window.location.origin;
      html += u.cmdBlock([{ label: "awsemu", cmd: cmd }, { label: "aws cli", cmd: u.toAwsCli(cmd, ep) }]);
    }
    var bnr = DASH.registry.banner(svc);
    if (bnr) html += '<div class="banner ' + u.esc(DASH.registry.tier(svc)) + '">' + u.esc(bnr) + "</div>";
    if (!isCounted && loaded && !all.length) {
      html += '<div class="banner">The console has no resource lister for ' + u.esc(labelText) +
        " yet, so this page cannot show its resources. Calls to it still appear in the live panel and in CloudTrail.</div>";
    }

    if (!loaded) {
      html += '<div class="loading">Loading ' + u.esc(labelText) + " resources...</div>";
    } else if (fetchError) {
      html += '<section class="panel"><div class="panel-empty"><h3>Could not list ' + u.esc(labelText) + ' resources</h3><p>' + u.esc(fetchError) + "</p></div></section>";
    } else if (!all.length) {
      var crossRef = DASH.services.crossRef ? DASH.services.crossRef(svc, state.overview && state.overview.services) : "";
      if (crossRef) html += '<div class="cross-ref-banner">' + crossRef + "</div>";
      html += '<section class="panel"><div class="panel-empty"><h3>No ' + u.esc(labelText) + " resources in account " + u.esc(state.account) + ' yet</h3>' +
        "<p>Create one from your usual tooling pointed at " + u.esc((state.system && state.system.endpoint) || window.location.origin) +
        ", or use Create above. It appears here the moment the event stream reports it.</p></div></section>";
    } else {
      var columns = DASH.services.columns(svc);
      var colKeys = columns.map(function (col) { return col.toLowerCase().replace(/\s+/g, "_"); });
      var hasCopy = DASH.services.hasCopyCommand(svc);
      html += '<section class="panel"><div class="panel-head"><h3>Resources</h3><span class="chip neutral num">' + rows.length +
        (q ? " of " + all.length : "") + '</span><span class="sp"></span>' +
        '<label class="tbl-filter">' + u.ICON.search + '<input id="resource-search" type="text" placeholder="Filter rows" autocomplete="off" value="' + u.esc(searchFilter) + '"></label></div>' +
        '<div class="tbl-wrap"><table class="tbl"><thead><tr>' + columns.map(function (col) { return "<th>" + u.esc(col) + "</th>"; }).join("") +
        ((actions.length || hasCopy) ? '<th class="r">Actions</th>' : "") + "</tr></thead><tbody>";
      rows.forEach(function (row) {
        var key = rowKey(row);
        html += "<tr>";
        colKeys.forEach(function (k, i) {
          var v = cellValue(row, k);
          if (i === 0) {
            var label = v == null ? key : v;
            html += '<td class="res">' + (drillable && key ? '<button class="link mono" type="button" data-drill="' + u.esc(key) + '">' + u.highlight(String(label), searchFilter) + "</button>" : u.highlight(String(label), searchFilter)) +
              (row.arn && k !== "arn" ? '<span class="arn">' + u.esc(row.arn) + "</span>" : "") + "</td>";
          } else {
            var cell = cellHtml(v, searchFilter);
            html += '<td class="' + cell.cls + '">' + cell.html + "</td>";
          }
        });
        if (actions.length || hasCopy) {
          html += '<td class="r"><span class="row-actions">';
          actions.forEach(function (a, i) {
            html += '<button class="btn sm' + (a.primary ? "" : " ghost") + (a.danger ? " danger" : "") + '" type="button" data-row-action="' + i + '" data-key="' + u.esc(key) + '">' + u.esc(a.label) + "</button>";
          });
          if (hasCopy) {
            var cc = DASH.services.copyCommand(svc, row);
            if (cc) html += '<button class="btn sm ghost" type="button" data-copy="' + u.esc(cc) + '" title="Copy: ' + u.esc(cc) + '" aria-label="Copy CLI command">' + u.ICON.copy + "</button>";
          }
          html += "</span></td>";
        }
        html += "</tr>";
      });
      html += "</tbody></table></div></section>";
    }

    html += '<section class="panel"><div class="panel-head"><h3>Call volume</h3><span class="sp"></span><span class="chip neutral">last 24 min &middot; 1 min buckets &middot; account ' +
      u.esc(state.account) + '</span></div><div style="height:96px;padding:10px 14px">' +
      (arr.some(function (x) { return x > 0; }) ? spark(arr, 600, 76) : '<div class="note">No calls to ' + u.esc(labelText) + " in the last 24 minutes.</div>") +
      "</div></section>";

    el.innerHTML = html;
    var rb = document.getElementById("resRefresh");
    if (rb) rb.addEventListener("click", function () { refresh(true); });
    var cb = document.getElementById("resCreate");
    if (cb) cb.addEventListener("click", function () { DASH.palette.openCreate(svc); });
    var search = document.getElementById("resource-search");
    if (search) {
      search.addEventListener("input", DASH.utils.debounce(function () {
        var caret = search.selectionStart;
        searchFilter = search.value;
        render();
        var again = document.getElementById("resource-search");
        if (again) { again.focus(); try { again.setSelectionRange(caret, caret); } catch (_) {} }
      }, 120));
    }
  }

  function findRow(key) {
    var rows = DASH.app.state.resources || [];
    return rows.filter(function (r) {
      return r.name === key || r.instance_id === key || r.id === key || r.key_id === key || r.cluster === key || r.arn === key;
    })[0] || { name: key };
  }

  function onClick(e) {
    var svc = DASH.app.state.route.service;
    if (!svc || DASH.app.state.route.resource) return;
    var act = e.target.closest("[data-row-action]");
    if (act) {
      var a = (ROW_ACTIONS[svc] || [])[+act.getAttribute("data-row-action")];
      if (a) a.run(findRow(act.getAttribute("data-key")));
      return;
    }
    var drill = e.target.closest("[data-drill]");
    if (drill) dispatchDrill(svc, findRow(drill.getAttribute("data-drill")));
  }

  function init() {
    var el = document.getElementById("main-content");
    if (el) el.addEventListener("click", onClick);
    DASH.bus.subscribe("resource", function (data) {
      var svc = DASH.app.state.route.service;
      if (!svc || !data || data.service !== svc) return;
      DASH.cache.invalidateKey("resources:" + svc);
      if (!DASH.app.state.route.resource) refresh(false);
    });
  }

  window.DASH.resources = {
    init: init, open: open, close: close, render: render, refresh: refresh, stopPolling: stopPolling,
    openRow: function (svc, row) { dispatchDrill(svc, row); }
  };
})();
