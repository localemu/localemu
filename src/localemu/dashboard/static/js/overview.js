// Overview page. Every number on it comes from the running instance:
//   endpoint band  /_localemu/api/system (+ the URL the browser used)
//   rate chart     /_localemu/api/metrics/requests (per-second buckets
//                  recorded by the gateway telemetry handler)
//   totals         /_localemu/api/overview?account=, /system, /metrics
//   service grid   registry + per-account counts + /metrics/services
//   recent changes /_localemu/api/changes?account=, refreshed on SSE
(function () {
  "use strict";

  var filterKey = "localemu-console-grid-filter";
  var gridFilter = "inuse";
  try { gridFilter = localStorage.getItem(filterKey) || "inuse"; } catch (_) {}

  var metrics = null;       // last /metrics/requests payload
  var changes = null;       // last /changes payload
  var metricsTimer = null;
  var activityTimer = null;
  var uptimeTimer = null;
  var active = false;

  function u() { return DASH.utils; }
  function st() { return DASH.app.state; }
  function onPage() { return active && !st().route.service; }

  // ── data ──
  function fetchMetrics() {
    return DASH.api.fetchJSON("/_localemu/api/metrics/requests?window=300", { etag: false, timeoutMs: 6000 })
      .then(function (r) { metrics = r.data; if (onPage()) paintRate(); paintStats(); })
      .catch(function () {});
  }
  function fetchActivity() {
    var url = "/_localemu/api/metrics/services?minutes=24&account=" + encodeURIComponent(st().account);
    return DASH.api.fetchJSON(url, { etag: false, timeoutMs: 6000 }).then(function (r) {
      DASH.catalog.setActivity((r.data && r.data.services) || {});
      DASH.sidebar.schedule();
      if (onPage()) paintGrid();
    }).catch(function () {});
  }
  function fetchChanges() {
    var url = "/_localemu/api/changes?limit=25&account=" + encodeURIComponent(st().account);
    return DASH.api.fetchJSON(url, { etag: false, timeoutMs: 6000 }).then(function (r) {
      changes = (r.data && r.data.changes) || [];
      if (onPage()) paintChanges();
    }).catch(function () {});
  }
  var scheduleChanges = null;
  var scheduleActivity = null;

  // ── render ──
  function render() {
    active = true;
    var el = document.getElementById("main-content");
    if (!el) return;
    var acct = st().account;
    var rec = DASH.accounts.find(acct);
    var sys = st().system || {};
    el.innerHTML =
      '<div><div class="crumbs"><span>Account ' + u().esc(acct) + (rec && rec.Name ? " &middot; " + u().esc(rec.Name) : "") +
        '</span><span>/</span><span>' + u().esc(sys.default_region || "us-east-1") + '</span></div>' +
      '<div class="page-head"><div><h1>Overview</h1><p>Everything running on this LocalEmu instance, updated live from the event stream.</p></div>' +
      '<div class="head-actions"><button class="btn" type="button" id="ovCreate">' + u().ICON.plus + 'Create resource</button></div></div></div>' +
      '<section class="endpoint" aria-label="Endpoint" id="ovEndpoint"></section>' +
      '<section class="stats" aria-label="Totals" id="ovStats"></section>' +
      '<section class="svc-section" aria-label="Services" id="ovGrid"></section>' +
      '<section class="panel" aria-label="Recently changed resources" id="ovChanges"></section>';
    document.getElementById("ovCreate").addEventListener("click", function () { DASH.palette.open("create "); });
    paintEndpoint();
    paintStats();
    paintGrid();
    paintChanges();
    fetchMetrics();
    fetchActivity();
    fetchChanges();
    if (!metricsTimer) metricsTimer = setInterval(function () { if (onPage() && !document.hidden) fetchMetrics(); }, 2000);
    if (!uptimeTimer) uptimeTimer = setInterval(tickUptime, 1000);
  }

  function leave() { active = false; }

  function envSnippet() {
    var sys = st().system || {};
    var ep = sys.endpoint || window.location.origin;
    // A 12-digit access key selects that account in LocalEmu; "test" maps
    // to the default account 000000000000.
    var key = st().account === "000000000000" ? "test" : st().account;
    return "export AWS_ENDPOINT_URL=" + ep + " AWS_ACCESS_KEY_ID=" + key +
      " AWS_SECRET_ACCESS_KEY=test AWS_REGION=" + (sys.default_region || "us-east-1");
  }

  function uptimeText() {
    var sys = st().system;
    if (!sys || !sys.started_at) return "...";
    return u().formatUptime(Date.now() / 1000 - sys.started_at);
  }
  function tickUptime() {
    var e = document.getElementById("ovUptime");
    if (e) e.textContent = uptimeText();
  }

  function iamChip(mode) {
    if (mode === "enforce") return '<span class="chip warn" title="IAM_ENFORCEMENT=1: unauthorized calls are denied">enforce</span>';
    if (mode === "audit") return '<span class="chip accent" title="IAM_ENFORCEMENT=soft: denials are logged, calls proceed">audit</span>';
    if (mode === "off") return '<span class="chip neutral" title="Set IAM_ENFORCEMENT=1 to evaluate IAM policies">off</span>';
    return '<span class="chip neutral">...</span>';
  }
  function dockerChip(d) {
    if (!d) return '<span class="chip neutral">checking</span>';
    if (!d.available) return '<span class="chip err" title="' + u().esc(d.error || "") + '">unreachable</span>';
    return '<span class="chip box" title="' + u().esc(d.operating_system || "") + '">' + u().esc(d.server_version || "?") + " &middot; ok</span>";
  }
  function bedrockText(b) {
    if (!b) return "...";
    if (!b.configured) return '<span title="BEDROCK_BACKEND=' + u().esc(b.backend) + '">' + u().esc(b.backend) + "</span>";
    if (b.reachable) return '<span class="chip ok" title="' + u().esc((b.models || []).join(", ")) + '">ollama :' + u().esc(b.port) + " &middot; " + (b.models || []).length + " models</span>";
    if (b.running) return '<span class="chip warn" title="' + u().esc(b.detail || "") + '">ollama :' + u().esc(b.port || "?") + " &middot; down</span>";
    return '<span class="chip neutral" title="' + u().esc(b.detail || "") + '">ollama &middot; idle</span>';
  }

  function paintEndpoint() {
    var box = document.getElementById("ovEndpoint");
    if (!box) return;
    var sys = st().system || {};
    var ep = sys.endpoint || window.location.origin;
    var m = /^(.*:)(\d+)$/.exec(ep);
    var urlHtml = m ? u().esc(m[1]) + "<em>" + u().esc(m[2]) + "</em>" : u().esc(ep);
    var snip = envSnippet();
    box.innerHTML =
      '<div class="ep-left"><span class="eyebrow">Your cloud is listening on</span>' +
        '<div class="ep-url"><span class="url">' + urlHtml + '</span><button class="btn sm" type="button" data-copy="' + u().esc(ep) + '">' + u().ICON.copy + "Copy</button></div>" +
        '<div class="snippet"><code>' + u().esc(snip).replace("AWS_ENDPOINT_URL", "<b>AWS_ENDPOINT_URL</b>") + '</code>' +
          '<button class="icon-btn" type="button" aria-label="Copy shell exports" data-copy="' + u().esc(snip) + '">' + u().ICON.copy + "</button></div>" +
        '<div class="ep-facts">' +
          fact("Version", u().esc(sys.version || "...")) +
          fact("Uptime", '<span class="num" id="ovUptime">' + uptimeText() + "</span>") +
          fact("IAM enforcement", iamChip(sys.iam_enforcement)) +
          fact("Persistence", sys.persistence == null ? "..." : (sys.persistence ? '<span class="chip ok">on</span>' : "off")) +
          fact("Docker", dockerChip(sys.docker)) +
          fact("Bedrock backend", bedrockText(sys.bedrock)) +
        "</div></div>" +
      '<div class="ep-right"><span class="eyebrow">Requests per second &middot; all accounts &middot; last 5 min</span>' +
        '<div class="rate-head"><span class="rate-big" id="ovRate">&ndash;<small>req/s</small></span>' +
        '<div class="rate-sub" id="ovRateSub"></div></div>' +
        '<div class="rate-chart" id="ovChart"></div>' +
        '<div class="rate-axis"><span>&minus;5m</span><span>&minus;2m30s</span><span>now</span></div>' +
        '<div class="rate-legend"><span><i style="background:var(--accent)"></i>requests</span><span><i style="background:var(--err)"></i>4xx/5xx or IAM denial in that second</span></div>' +
      "</div>";
    if (st().system) box.dataset.painted = "1";
    paintRate();
  }
  function fact(k, v) { return '<div class="fact"><span class="k">' + k + '</span><span class="v">' + v + "</span></div>"; }

  function paintRate() {
    var chart = document.getElementById("ovChart");
    if (!chart) return;
    var big = document.getElementById("ovRate");
    var sub = document.getElementById("ovRateSub");
    if (!metrics) { chart.innerHTML = '<div class="note">Loading request metrics...</div>'; return; }
    var series = metrics.series || [];
    big.innerHTML = (metrics.rps_10s_avg || 0).toFixed(metrics.rps_10s_avg >= 10 ? 0 : 1) + "<small>req/s, 10 s avg</small>";
    sub.innerHTML = "<span>p50 <b>" + u().fmtLatency(metrics.p50_ms) + "</b></span><span>p99 <b>" + u().fmtLatency(metrics.p99_ms) +
      '</b></span><span class="e">errors <b>' + u().fmtInt(metrics.errors_15m) + "</b> in 15 min</span>";
    chart.innerHTML = rateSvg(series);
  }

  // 5-second bins keep the line readable at 300 s; error markers stay per second.
  function rateSvg(series) {
    var w = 600, h = 110, bin = 5;
    var bins = [];
    for (var i = 0; i < series.length; i += bin) {
      var s = 0;
      for (var j = i; j < i + bin && j < series.length; j++) s += series[j].n;
      bins.push(s / bin);
    }
    var n = bins.length;
    if (n < 2) return "";
    var max = Math.max(1, Math.max.apply(null, bins));
    var top = niceMax(max);
    var pts = bins.map(function (v, i) { return [(i / (n - 1)) * w, h - 2 - (v / top) * (h - 10)]; });
    var line = pts.map(function (p) { return p[0].toFixed(1) + "," + p[1].toFixed(1); }).join(" ");
    var grid = [0.25, 0.5, 0.75].map(function (f) {
      var y = (h - 2 - f * (h - 10)).toFixed(1);
      return '<line x1="0" x2="' + w + '" y1="' + y + '" y2="' + y + '" stroke="var(--line)" stroke-width="1" vector-effect="non-scaling-stroke" stroke-dasharray="3 4"/>';
    }).join("");
    var marks = "";
    series.forEach(function (p, i) {
      if (p.e4 || p.e5 || p.denied) {
        var x = ((i / (series.length - 1)) * w).toFixed(1);
        marks += '<line x1="' + x + '" x2="' + x + '" y1="' + (h - 16) + '" y2="' + h + '" stroke="var(--err)" stroke-width="2" vector-effect="non-scaling-stroke"><title>' +
          new Date(p.t * 1000).toLocaleTimeString() + ": " + (p.e4 + p.e5) + " error(s)" + (p.denied ? ", " + p.denied + " denied" : "") + "</title></line>";
      }
    });
    var last = pts[n - 1];
    return '<svg viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" role="img" aria-label="Requests per second, last 5 minutes, peak ' +
      max.toFixed(1) + ' per second">' + grid +
      '<path d="M0,' + h + " L" + line.replace(/ /g, " L") + " L" + w + "," + h + ' Z" fill="var(--accent)" fill-opacity=".14"/>' +
      '<polyline points="' + line + '" fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke"/>' + marks +
      '<circle cx="' + (last[0] - 3).toFixed(1) + '" cy="' + last[1].toFixed(1) + '" r="4" fill="var(--accent)" stroke="var(--surface)" stroke-width="2" vector-effect="non-scaling-stroke"/>' +
      '<text x="4" y="12" font-size="10" fill="var(--muted)" font-family="var(--font-mono)">' + fmtAxis(top) + "/s</text></svg>";
  }
  function niceMax(v) {
    var steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000];
    for (var i = 0; i < steps.length; i++) if (v <= steps[i]) return steps[i];
    return Math.ceil(v);
  }
  function fmtAxis(v) { return v >= 1000 ? (v / 1000) + "k" : String(v); }

  function paintStats() {
    var box = document.getElementById("ovStats");
    if (!box || !onPage()) return;
    var c = DASH.catalog;
    var ov = st().overview || {};
    var totals = ov.totals;
    var svcs = c.services();
    var inUse = svcs.filter(c.inUse).length;
    var pinnedN = svcs.filter(c.pinned).length;
    var sys = st().system || {};
    var d = sys.docker;
    var running = d && d.containers ? d.containers.running : null;
    var breakdown = "";
    if (d && d.containers && d.containers.by_service) {
      breakdown = Object.keys(d.containers.by_service).sort().map(function (k) {
        var x = d.containers.by_service[k];
        return u().esc(c.label(k)) + " " + x.running + (x.total !== x.running ? "/" + x.total : "");
      }).join(" &middot; ");
    }
    var denied = metrics ? metrics.denied_15m : null;
    var ld = metrics && metrics.last_denial;
    var deniedLabel = sys.iam_enforcement === "audit" ? "Denied by IAM (audit), 15 min" : "Denied by IAM, 15 min";
    box.innerHTML =
      stat("accent", "Resources in this account",
        totals ? u().fmtInt(totals.resources) : "&ndash;",
        totals ? "counted across " + totals.services_counted + " of " + totals.services_total + " services" : "loading") +
      stat("", "Services in use", inUse + "<small> / " + DASH.registry.aws().length + "</small>",
        "with resources or calls in the last 30 min &middot; " + pinnedN + " pinned") +
      stat("box", "Docker containers", running == null ? "&ndash;" : String(running),
        !d ? "checking Docker" : !d.available ? "Docker unreachable" :
          (breakdown || "none running") + " &middot; all accounts") +
      stat("warn", deniedLabel, denied == null ? "&ndash;" : String(denied),
        ld ? "<b>" + u().esc(ld.operation) + "</b> by " + u().esc(u().shortPrincipal(ld.principal)) + " " + u().relTime(ld.ts) :
          (sys.iam_enforcement === "off" ? "IAM enforcement is off (IAM_ENFORCEMENT=1 to enable)" : "no denials"));
  }
  function stat(cls, k, v, d) {
    return '<div class="stat ' + cls + '"><span class="k">' + k + '</span><span class="v num">' + v + '</span><span class="d">' + d + "</span></div>";
  }

  function visible(name) {
    var c = DASH.catalog;
    if (gridFilter === "inuse") return c.pinned(name) || c.inUse(name);
    if (gridFilter === "docker") return c.isDockerBacked(name);
    return true;
  }

  function spark(arr, w, h) {
    var max = Math.max.apply(null, arr.concat([1])), n = arr.length;
    var pts = arr.map(function (v, i) { return [(i / (n - 1)) * w, h - 2 - (v / max) * (h - 5)]; });
    var line = pts.map(function (p) { return p[0].toFixed(1) + "," + p[1].toFixed(1); }).join(" ");
    var area = "M0," + h + " L" + line.replace(/ /g, " L") + " L" + w + "," + h + " Z";
    var last = pts[n - 1];
    return '<svg viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" aria-hidden="true">' +
      '<path d="' + area + '" fill="var(--accent)" fill-opacity=".12"/>' +
      '<polyline points="' + line + '" fill="none" stroke="var(--accent)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>' +
      '<circle cx="' + last[0].toFixed(1) + '" cy="' + last[1].toFixed(1) + '" r="2.4" fill="var(--accent)"/></svg>';
  }

  function card(name) {
    var c = DASH.catalog;
    var n = c.count(name), isCounted = c.counted(name);
    var used = c.inUse(name);
    var cont = c.containers(name);
    var cpm = c.calls5m(name);
    var stateHtml;
    if (cont && cont.running) {
      stateHtml = '<span class="dot box"></span>' + cont.running + " container" + (cont.running === 1 ? "" : "s") + " up";
    } else if (!used) {
      stateHtml = '<span class="dot idle"></span>' + (isCounted ? "No resources" : "No calls yet");
    } else {
      stateHtml = '<span class="dot ok"></span>' + (cpm ? cpm + " call" + (cpm === 1 ? "" : "s") + " in 5 min" : "idle 5 min");
    }
    var arr = c.calls(name);
    var hasCalls = arr && arr.some(function (x) { return x > 0; });
    var countHtml = isCounted
      ? '<span class="count">' + n + "<small>resource" + (n === 1 ? "" : "s") + "</small></span>"
      : '<span class="count nc" title="LocalEmu has no resource counter for this service yet">&ndash;<small>not counted</small></span>';
    return '<button class="card' + (used ? "" : " idle") + '" type="button" data-go-svc="' + u().esc(name) + '" id="card-' + u().esc(name) + '">' +
      u().tile(name, "md", n > 0) + '<span class="name">' + u().esc(c.label(name)) + "</span>" + countHtml +
      '<span class="state">' + stateHtml + "</span>" +
      (hasCalls ? '<span class="spark" title="calls per minute, last 24 min">' + spark(arr, 200, 26) + "</span>" : "") + "</button>";
  }

  function paintGrid() {
    var box = document.getElementById("ovGrid");
    if (!box) return;
    var c = DASH.catalog;
    var all = c.services();
    var nInUse = all.filter(function (s) { return c.pinned(s) || c.inUse(s); }).length;
    var nDocker = all.filter(c.isDockerBacked).length;
    var html = '<div class="section-head"><h2>Services</h2><div class="seg" role="tablist" aria-label="Service filter">' +
      seg("inuse", "Pinned and in use", nInUse) + seg("docker", "Docker-backed", nDocker) + seg("all", "All", DASH.registry.aws().length) + "</div></div>";
    if (gridFilter === "docker") {
      var be = c.dockerBackends();
      html += '<p class="note">Services whose resources run as real Docker containers. ' +
        Object.keys(be).sort().map(function (k) {
          return u().esc(c.label(k)) + ": " + (be[k].enabled ? "on" : "off") + " (" + u().esc(be[k].switch) + ")";
        }).join("; ") + ".</p>";
    }
    var byGroup = {};
    all.filter(visible).forEach(function (s) { (byGroup[c.group(s)] = byGroup[c.group(s)] || []).push(s); });
    var any = false;
    DASH.services.GROUPS.forEach(function (g) {
      var ids = byGroup[g.id];
      if (!ids || !ids.length) return;
      any = true;
      ids.sort(function (a, b) { return c.label(a).localeCompare(c.label(b)); });
      var res = ids.reduce(function (s, id) { return s + c.count(id); }, 0);
      html += '<div class="cat"><div class="cat-head"><h3>' + u().esc(g.label) + "</h3><span>" + res + " resource" + (res === 1 ? "" : "s") +
        '</span></div><div class="grid">' + ids.map(card).join("") + "</div></div>";
    });
    if (!any) html += '<p class="note">Loading the service registry...</p>';
    box.innerHTML = html;
    box.querySelectorAll("[data-filter]").forEach(function (b) {
      b.addEventListener("click", function () {
        gridFilter = b.getAttribute("data-filter");
        try { localStorage.setItem(filterKey, gridFilter); } catch (_) {}
        paintGrid();
      });
    });
  }
  function seg(key, labelText, n) {
    return '<button type="button" role="tab" data-filter="' + key + '" class="' + (gridFilter === key ? "on" : "") +
      '" aria-selected="' + (gridFilter === key) + '">' + labelText + '<span class="n">' + n + "</span></button>";
  }

  function paintChanges() {
    var box = document.getElementById("ovChanges");
    if (!box) return;
    var c = DASH.catalog;
    var head = '<div class="panel-head"><h3>Recently changed resources</h3><span class="sp"></span><span class="chip neutral">account ' +
      u().esc(st().account) + "</span></div>";
    if (changes === null) { box.innerHTML = head + '<div class="panel-body note">Loading...</div>'; return; }
    if (!changes.length) {
      box.innerHTML = head + '<div class="panel-empty"><h3>No changes recorded yet</h3><p>Create, update or delete something with your usual tooling pointed at ' +
        u().esc((st().system && st().system.endpoint) || window.location.origin) +
        ". It appears here the moment the gateway handles the call. Changes made before this LocalEmu process started are not listed.</p></div>";
      return;
    }
    box.innerHTML = head + '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Resource</th><th>Service</th><th>Account</th><th>Last change</th><th>When</th><th class="r">Action</th></tr></thead><tbody>' +
      changes.map(function (ch) {
        var res = ch.resource || {};
        var openable = DASH.registry.get(ch.service);
        return "<tr><td class=\"res\">" + u().esc(res.name) + (res.arn ? '<span class="arn">' + u().esc(res.arn) + "</span>" : "") + "</td>" +
          '<td><span class="svc-cell">' + u().tile(ch.service, "sm") + u().esc(c.label(ch.service)) + "</span></td>" +
          '<td class="dim mono">' + u().esc(ch.account_id) + '</td><td class="mono" style="font-size:12.5px">' + u().esc(ch.operation) +
          '</td><td class="dim" title="' + u().esc(new Date(ch.ts * 1000).toLocaleString()) + '">' + u().relTime(ch.ts) + "</td>" +
          '<td class="r">' + (openable ? '<button class="btn sm" type="button" data-go-svc="' + u().esc(ch.service) + '">Open</button>' : "") + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  // Called by app.js after each overview fetch, with the previous counts.
  function onCounts(prev) {
    if (!onPage()) { DASH.sidebar.schedule(); return; }
    paintStats();
    paintGrid();
    prev = prev || {};
    var now = (st().overview && st().overview.services) || {};
    Object.keys(now).forEach(function (k) {
      if (prev[k] && now[k].resources > prev[k].resources) {
        var cardEl = document.getElementById("card-" + k);
        if (cardEl) { cardEl.classList.remove("bump"); void cardEl.offsetWidth; cardEl.classList.add("bump"); }
      }
    });
  }
  function onSystem() {
    if (!onPage()) return;
    // Don't rebuild the band while the user may be selecting text in it;
    // just refresh the parts that change.
    var box = document.getElementById("ovEndpoint");
    if (box && !box.dataset.painted) { paintEndpoint(); box.dataset.painted = "1"; }
    else if (box) {
      var facts = box.querySelector(".ep-facts");
      if (facts) {
        var sys = st().system || {};
        facts.innerHTML = fact("Version", u().esc(sys.version || "...")) +
          fact("Uptime", '<span class="num" id="ovUptime">' + uptimeText() + "</span>") +
          fact("IAM enforcement", iamChip(sys.iam_enforcement)) +
          fact("Persistence", sys.persistence ? '<span class="chip ok">on</span>' : "off") +
          fact("Docker", dockerChip(sys.docker)) +
          fact("Bedrock backend", bedrockText(sys.bedrock));
      }
    }
    paintStats();
    paintGrid();
  }

  function init() {
    scheduleChanges = u().debounce(fetchChanges, 400);
    scheduleActivity = u().debounce(fetchActivity, 1500);
    fetchActivity();
    activityTimer = setInterval(function () { if (!document.hidden) fetchActivity(); }, 15000);
    DASH.bus.subscribe("call", function (call) {
      if (!call) return;
      if (call.mutating && call.status >= 200 && call.status < 300 && call.resource && onPage()) scheduleChanges();
      scheduleActivity();
    });
  }

  window.DASH.overview = {
    init: init, render: render, leave: leave, onCounts: onCounts, onSystem: onSystem,
    refreshActivity: fetchActivity
  };
})();
