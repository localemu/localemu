// Resource list panel for a single service.
//
// Owns:
//   - The detail header (icon, name, Docs ↗, Refresh, Last refreshed)
//   - Per-service search box
//   - The resource table (columns from services.SERVICE_COLUMNS)
//   - Row actions: Copy-as-awsemu + primary actions (Invoke, Send, etc.)
//   - Empty-state guidance with awsemu suggestion
//   - 30 s safety polling while open (skipped while SSE is connected)
(function () {
  "use strict";

  var ROW_ACTIONS = {
    lambda: { label: "Invoke", open: function (row) { DASH.actions.lambdaInvoke.open(row); } },
    sqs:    { label: "Send",   open: function (row) { DASH.actions.sqsSend.open(row); } },
    sns:    { label: "Publish",open: function (row) { DASH.actions.snsPublish.open(row); } },
    events: { label: "Put event", open: function (row) { DASH.actions.eventsPut.open(row); } },
    secretsmanager: { label: "Rotate", open: function (row) { DASH.actions.secretRotate.open(row); } },
    dynamodb: { label: "Items", open: function (row) { DASH.actions.dynamoDb.open(row); } }
  };

  // Drill-down handlers per service. Every click routes through
  // DASH.app.navigate() so the URL hash updates, history pushes an
  // entry (so Back returns to the list), and the resources poll-timer
  // shuts down via the navigate() lifecycle hook.
  //
  // EventBridge: the rows on the resource list are RULES. The drill-down
  // takes the rule's BUS (not the rule name) and uses an optional
  // `highlight` meta to scroll the clicked row into view.
  var DRILL_DOWNS = {
    s3:           function (row) { DASH.app.navigate({ service: "s3",            resource: row.name }); },
    sqs:          function (row) { DASH.app.navigate({ service: "sqs",           resource: row.name }); },
    dynamodb:     function (row) { DASH.app.navigate({ service: "dynamodb",      resource: row.name }); },
    logs:         function (row) { DASH.app.navigate({ service: "logs",          resource: row.name }); },
    sns:          function (row) { DASH.app.navigate({ service: "sns",           resource: row.name }); },
    events:       function (row) { DASH.app.navigate({ service: "events",        resource: row.bus, meta: { highlight: row.name } }); },
    lambda:       function (row) { DASH.app.navigate({ service: "lambda",        resource: row.name }); },
    stepfunctions:function (row) { DASH.app.navigate({ service: "stepfunctions", resource: row.arn || row.name }); },
    // Registry-driven drills (KMS, IAM, ...) navigate by registry key.
    kms:          function (row) { DASH.app.navigate({ service: "kms",           resource: row.key_id || row.name }); },
    iam:          function (row) { DASH.app.navigate({ service: "iam",           resource: row.name }); },
    ec2:          function (row) { DASH.app.navigate({ service: "ec2",           resource: row.instance_id || row.name }); },
    vpc:          function (row) { DASH.app.navigate({ service: "vpc",           resource: row.name }); },
    glue:         function (row) {
      // Glue rows carry kind + key; the drill route is /resources/glue/<kind>/<key>
      // so we encode "<kind>/<key>" into the URL fragment.
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
    efs:          function (row) { DASH.app.navigate({ service: "efs",           resource: row.file_system_id || row.name }); },
  };

  // Fall back: when the row's service has a registered drill in the
  // registry but no entry above, OR when the registry knows the
  // service at all (the generic drill handles that case in openDrill),
  // navigate by row.name.
  function dispatchDrill(svc, row) {
    if (DRILL_DOWNS[svc]) return DRILL_DOWNS[svc](row);
    if (DASH.registry && DASH.registry.get && DASH.registry.get(svc)) {
      var key = row.name || row.key_id || row.id || row.arn || row.key || "";
      if (key) DASH.app.navigate({ service: svc, resource: key });
    }
  }

  var lastFetched = null;
  var searchFilter = "";
  var pollTimer = null;

  function setSearch(v) {
    searchFilter = String(v || "");
    render();
  }

  function open(serviceName) {
    searchFilter = "";
    lastFetched = null;
    refresh(true);
    startPolling();
  }
  function close() {
    stopPolling();
    searchFilter = "";
    lastFetched = null;
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(function () {
      // Skip polling when SSE is connected -- the cache invalidates on
      // `resource` events and the user will see updates pushed instantly.
      if (DASH.bus.connectionStatus() === "connected") return;
      // A drill-down has taken over #main-content; never overwrite it
      // with a stale list render. The drill owns its own refresh path.
      if (DASH.app.state.route.resource) return;
      refresh(false);
    }, 30000);
  }
  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  function refresh(force) {
    var svc = DASH.app.state.route.service;
    if (!svc) return;
    // Drill-down owns #main-content. Don't paint the list table on top.
    if (DASH.app.state.route.resource) return;
    var url = "/_localemu/api/resources/" + encodeURIComponent(svc);
    var cacheKey = "resources:" + svc;
    if (force) DASH.cache.invalidateKey(cacheKey);
    DASH.api.get(url, {
      cacheKey: cacheKey,
      ttlMs: 30000,
      tags: ["resources:" + svc],
      etag: true
    }).then(function (r) {
      // Late response for a service the user has already navigated away
      // from: discard so we don't paint A's data into B's panel.
      if (DASH.app.state.route.service !== svc) return;
      if (DASH.app.state.route.resource) return;
      var data = r.value;
      DASH.app.state.resources = (data && data.resources) || [];
      DASH.app.state.resourcesService = svc;
      lastFetched = Date.now();
      render();
    }).catch(function () {
      if (DASH.app.state.route.service !== svc) return;
      if (DASH.app.state.route.resource) return;
      DASH.app.state.resources = [];
      render();
    });
  }

  function render() {
    var state = DASH.app.state;
    var svc = state.route.service;
    if (!svc) return;
    var u = DASH.utils, s = DASH.services;
    var elMain = document.getElementById("main-content");
    if (!elMain) return;

    var docsUrl = s.docsUrl(svc);
    var labelText = s.label(svc);
    var hasCopy = s.hasCopyCommand(svc);
    var rowAction = ROW_ACTIONS[svc];
    // Every registry-known service is drillable via the generic
    // framework spec, even when there is no custom DRILL_DOWNS entry.
    // The list cell renders first-column-clickable accordingly.
    var drillDown = DRILL_DOWNS[svc]
      || (DASH.registry && DASH.registry.get && DASH.registry.get(svc) ? true : null);
    var hasActions = !!(hasCopy || rowAction);

    var rows = (state.resources || []).filter(function (r) {
      if (!searchFilter) return true;
      var q = searchFilter.toLowerCase();
      for (var k in r) {
        var v = r[k];
        if (v == null) continue;
        if (String(v).toLowerCase().indexOf(q) !== -1) return true;
      }
      return false;
    });

    var lastTxt = lastFetched ? "last refreshed " + Math.max(0, Math.round((Date.now() - lastFetched) / 1000)) + "s ago" : "loading...";

    var html = "";
    html += '<div class="detail-header">';
    html += u.iconHtml(svc, 28);
    html += '<h2>' + u.esc(labelText) + '</h2>';
    // Tier badge from the registry: Live (green), Metadata only
    // (yellow), Not emulated (red). Falls back silently when the
    // registry has not loaded yet.
    if (DASH.registry && DASH.registry.tierBadge) {
      var badge = DASH.registry.tierBadge(svc);
      if (badge && badge.label) {
        html += '<span class="tier-badge ' + badge.cls + '">' + u.esc(badge.label) + '</span>';
      }
    }
    if (docsUrl) {
      html += '<a class="docs-link" href="' + u.esc(docsUrl) + '" target="_blank" rel="noopener noreferrer">Docs</a>';
    }
    html += '<span class="last-refreshed" id="last-refreshed">' + u.esc(lastTxt) + '</span>';
    html += '<button class="refresh-btn" id="refresh-btn">Refresh</button>';
    html += '<button class="back-link" id="back-overview-btn">← Overview</button>';
    html += '</div>';

    // Honesty banner from the registry (Metadata only / Not emulated /
    // stub explanations). Lets the user know up front what they can
    // expect from the page.
    if (DASH.registry && DASH.registry.banner && DASH.registry.tier) {
      var bnr = DASH.registry.banner(svc);
      if (bnr) {
        var t = DASH.registry.tier(svc);
        html += '<div class="tier-banner tier-banner-' + t + '">' + u.esc(bnr) + '</div>';
      }
    }

    if (!state.resources || state.resources.length === 0) {
      var hint = s.emptyStateText(svc);
      var crossRef = s.crossRef ? s.crossRef(svc, state.overview && state.overview.services) : "";
      if (crossRef) {
        html += '<div class="cross-ref-banner">' + crossRef + '</div>';
      }
      if (hint) {
        html += '<div class="empty-state-guidance">';
        html += '<div class="empty-title">No resources yet. Get started:</div>';
        html += '<pre>' + u.esc(hint) + '</pre>';
        html += '<div class="hint">Every awsemu command is the AWS CLI v1 with the LocalEmu endpoint baked in.</div>';
        html += '</div>';
      } else {
        html += '<div class="empty-state">No resources</div>';
      }
      // Set innerHTML directly so subsequent render() preserves nothing.
      elMain.innerHTML = html;
      elMain.dataset.lastKey = "empty:" + svc;
      wireDetailHeader();
      return;
    }

    html += '<div class="detail-toolbar">';
    html += '<input type="text" class="search-input" id="resource-search" placeholder="Filter ' + u.esc(labelText) + '..." value="' + u.esc(searchFilter) + '" autocomplete="off">';
    html += '<span class="row-count">' + rows.length + (searchFilter ? ' of ' + state.resources.length : '') + ' result' + (rows.length === 1 ? '' : 's') + '</span>';
    html += '</div>';

    var columns = s.columns(svc);
    var colKeys = columns.map(function (c) { return c.toLowerCase().replace(/\s+/g, "_"); });
    var altKeys = {
      name: ["name", "Name", "table_name", "TableName", "queue_name", "QueueName", "function_name", "FunctionName", "topic_name", "TopicName", "bucket_name", "BucketName", "cluster_name", "ClusterName"],
      instance_id: ["instance_id", "InstanceId", "id"],
      state: ["state", "State", "status", "Status"],
      status: ["status", "Status", "state", "State"],
      type: ["type", "Type", "instance_type", "InstanceType"],
      region: ["region", "Region"],
      runtime: ["runtime", "Runtime"],
      handler: ["handler", "Handler"],
      memory: ["memory", "Memory"],
      role: ["role", "Role"],
      objects: ["objects", "Objects"],
      items: ["items", "Items", "item_count", "ItemCount"],
      messages: ["messages", "Messages"],
      subscriptions: ["subscriptions", "Subscriptions"],
      cluster: ["cluster", "Cluster", "name", "Name"],
      arn: ["arn", "Arn", "ARN"],
      shards: ["shards", "Shards"],
      bus: ["bus", "Bus"],
      targets: ["targets", "Targets"],
      endpoint: ["endpoint", "Endpoint"],
      api_id: ["api_id", "ApiId", "id", "Id"],
      protocol: ["protocol", "Protocol", "protocol_type", "ProtocolType"],
      routes: ["routes", "Routes"],
      stages: ["stages", "Stages"],
      id: ["id", "Id"],
      key_id: ["key_id", "KeyId"],
      alias: ["alias", "Alias", "aliases"],
      usage: ["usage", "Usage", "key_usage", "KeyUsage"],
      account: ["account", "Account", "account_id", "AccountId"],
      kind: ["kind", "Kind"],
      operation: ["operation", "Operation", "op"],
      principal: ["principal", "Principal"],
      dns: ["dns", "Dns", "dns_name", "DNSName"],
      scheme: ["scheme", "Scheme"],
      source: ["source", "Source", "event_source", "EventSource"],
      user: ["user", "User", "username", "Username"],
      request_id: ["request_id", "RequestId", "requestId"],
      time: ["time", "Time", "event_time", "EventTime", "timestamp"],
      records: ["records", "Records", "record_count", "RecordCount"],
      last_modified: ["last_modified", "LastModified", "LastModifiedDate"],
      version: ["version", "Version"]
    };

    html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
    columns.forEach(function (c) { html += '<th>' + u.esc(c) + '</th>'; });
    if (hasActions) html += '<th></th>';
    html += '</tr></thead><tbody>';

    rows.forEach(function (row) {
      html += '<tr>';
      colKeys.forEach(function (key, i) {
        var val = row[key];
        if (val === undefined) {
          var alts = altKeys[key] || [];
          for (var j = 0; j < alts.length; j++) {
            if (row[alts[j]] !== undefined) { val = row[alts[j]]; break; }
          }
        }
        var content = (val == null) ? "-" : val;
        if (i === 0 && drillDown && (row.name || row.instance_id || row.id)) {
          var rowKey = row.name || row.instance_id || row.id;
          html += '<td><span class="clickable-name" data-drill="' + u.esc(rowKey) + '">' + u.highlight(content, searchFilter) + '</span></td>';
        } else {
          html += '<td>' + u.highlight(content, searchFilter) + '</td>';
        }
      });
      if (hasActions) {
        html += '<td class="actions-cell">';
        if (rowAction) {
          var key = row.name || row.instance_id || row.id || row.cluster || "";
          html += '<button class="row-action primary" data-row-action="' + u.esc(key) + '">' + u.esc(rowAction.label) + '</button>';
        }
        if (hasCopy) {
          var cmd = s.copyCommand(svc, row);
          if (cmd) html += '<button class="row-action" data-copy-cmd="' + u.esc(cmd) + '">Copy</button>';
        }
        html += '</td>';
      }
      html += '</tr>';
    });
    html += '</tbody></table></div>';

    elMain.innerHTML = html;
    elMain.dataset.lastKey = "detail:" + svc + ":" + rows.length + ":" + searchFilter;
    wireDetailHeader();
    wireRowActions(svc, rows, rowAction, drillDown);
  }

  function wireDetailHeader() {
    var refresh = document.getElementById("refresh-btn");
    if (refresh) refresh.addEventListener("click", function () { module.refresh(true); });
    var back = document.getElementById("back-overview-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: null, resource: null }); });
    var search = document.getElementById("resource-search");
    if (search) {
      search.addEventListener("input", DASH.utils.debounce(function () {
        var caret = search.selectionStart;
        setSearch(search.value);
        var restored = document.getElementById("resource-search");
        if (restored) { restored.focus(); try { restored.setSelectionRange(caret, caret); } catch (_) {} }
      }, 120));
    }
  }

  // Delegated click handler attached ONCE in init(); inspects the
  // current resources state to dispatch row actions and drill-downs.
  function delegatedRowClick(e) {
    var cpy = e.target.closest("[data-copy-cmd]");
    if (cpy) {
      DASH.utils.copyToClipboard(cpy.dataset.copyCmd);
      return;
    }
    var svc = DASH.app.state.route.service;
    if (!svc) return;
    var rows = DASH.app.state.resources || [];
    var act = e.target.closest("[data-row-action]");
    if (act && ROW_ACTIONS[svc]) {
      var k = act.dataset.rowAction;
      var row = rows.find(function (r) {
        return (r.name === k) || (r.instance_id === k) || (r.id === k) || (r.cluster === k);
      }) || { name: k };
      ROW_ACTIONS[svc].open(row);
      return;
    }
    var drill = e.target.closest("[data-drill]");
    if (drill) {
      var dk = drill.dataset.drill;
      var drow = rows.find(function (r) {
        return (r.name === dk) || (r.instance_id === dk) || (r.id === dk) || (r.key_id === dk);
      }) || { name: dk };
      dispatchDrill(svc, drow);
      return;
    }
  }
  function wireRowActions(/* args unused: delegation in init() */) { /* no-op */ }

  function init() {
    // Delegated click handler -- attached once, alive for the lifetime
    // of the page. Re-renders that replace innerHTML do NOT remove
    // listeners attached to the parent #main-content.
    var elMain = document.getElementById("main-content");
    if (elMain) elMain.addEventListener("click", delegatedRowClick);

    // Refresh "Last refreshed" timestamp every 5 s for the human eye.
    setInterval(function () {
      var el = document.getElementById("last-refreshed");
      if (el && lastFetched) {
        el.textContent = "last refreshed " + Math.max(0, Math.round((Date.now() - lastFetched) / 1000)) + "s ago";
      }
    }, 5000);

    // Bus: invalidate cache + refresh whenever a `resource` event for
    // the current service comes through. This is what makes the panel
    // feel live with no polling.
    DASH.bus.subscribe("resource", function (data) {
      var svc = DASH.app.state.route.service;
      if (!svc) return;
      // Drill-down active: do NOT overwrite #main-content with the list.
      // The drill module owns its panel and is responsible for its own
      // refresh. Still invalidate the list cache so a future back-to-list
      // navigation sees fresh data.
      if (DASH.app.state.route.resource) {
        if (data && data.service === svc) {
          DASH.cache.invalidateKey("resources:" + svc);
        }
        return;
      }
      if (data && data.service === svc) {
        DASH.cache.invalidateKey("resources:" + svc);
        refresh(false);
      }
    });
  }

  var module = {
    init: init,
    open: open,
    close: close,
    render: render,
    refresh: refresh,
    stopPolling: stopPolling
  };
  window.DASH.resources = module;
})();
