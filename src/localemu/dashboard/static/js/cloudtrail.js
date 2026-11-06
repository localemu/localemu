// CloudTrail events page (#/cloudtrail).
//
// Reads the CloudTrail event store (/_localemu/api/cloudtrail, the same
// records `aws cloudtrail lookup-events` returns), with server-side
// service / account filters and paging over the whole store. Rows expand
// to the full CloudTrailEvent JSON (/_localemu/api/cloudtrail/<request id>).
(function () {
  "use strict";

  var data = [];
  var totalEvents = 0;
  var lastFetched = null;
  var pollTimer = null;
  var filterService = "";
  var scope = "account";     // "account" (selected account) | "all"
  var pageOffset = 0;
  var pageLimit = 100;
  var detailOpenId = null;
  var detailCache = {};
  var detailLoading = {};
  var fetchFailed = null;

  function u() { return DASH.utils; }
  function onPage() { return DASH.app.state.route.service === "cloudtrail"; }

  function open() { refresh(true); startPoll(); }
  function close() {
    stopPoll();
    if (!onPage()) detailOpenId = null;
  }
  function startPoll() {
    stopPoll();
    pollTimer = setInterval(function () {
      if (DASH.bus.connectionStatus() === "connected") return;
      refresh(false);
    }, 60000);
  }
  function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

  function refresh(force) {
    var url = "/_localemu/api/cloudtrail?limit=" + pageLimit + "&offset=" + pageOffset;
    if (filterService) url += "&service=" + encodeURIComponent(filterService);
    if (scope === "account") url += "&account=" + encodeURIComponent(DASH.app.state.account);
    var cacheKey = "cloudtrail:" + url;
    if (force) DASH.cache.invalidateKey(cacheKey);
    DASH.api.get(url, { cacheKey: cacheKey, ttlMs: 30000, tags: ["cloudtrail"] }).then(function (r) {
      data = (r.value && r.value.events) || [];
      totalEvents = (r.value && typeof r.value.total === "number") ? r.value.total : data.length;
      lastFetched = Date.now();
      fetchFailed = null;
      render();
    }).catch(function (err) { data = []; totalEvents = 0; fetchFailed = (err && err.message) || "request failed"; render(); });
  }

  function openDetail(reqId) {
    detailOpenId = reqId;
    scope = "all";
    pageOffset = 0;
    filterService = "";
    loadDetail(reqId);
    if (!onPage()) DASH.app.navigate({ service: "cloudtrail", resource: null });
    else refresh(true);
    setTimeout(function () {
      var row = document.querySelector('[data-event-id="' + cssEsc(reqId) + '"]');
      if (row && row.scrollIntoView) row.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 400);
  }
  function cssEsc(s) { return (window.CSS && CSS.escape) ? CSS.escape(String(s)) : String(s).replace(/"/g, '\\"'); }

  function parseCloudTrailEvent(envelope) {
    if (!envelope || typeof envelope.CloudTrailEvent !== "string") return null;
    try { return JSON.parse(envelope.CloudTrailEvent); } catch (e) { return null; }
  }

  function loadDetail(rid) {
    if (!rid || detailCache[rid] || detailLoading[rid]) return;
    detailLoading[rid] = true;
    DASH.api.fetchJSON("/_localemu/api/cloudtrail/" + encodeURIComponent(rid), { etag: false, timeoutMs: 6000 })
      .then(function (resp) { if (resp && resp.data) detailCache[rid] = resp.data; })
      .catch(function () {})
      .then(function () { detailLoading[rid] = false; if (detailOpenId === rid) render(); });
  }

  function resultChip(evt) {
    var code = evt.responseCode || 0;
    if (code === 403 && /AccessDenied/.test(evt.errorCode || "")) return '<span class="chip err">403 denied</span>';
    if (code >= 500) return '<span class="chip err" title="' + u().esc(evt.errorCode || "") + '">' + code + "</span>";
    if (code >= 400) return '<span class="chip warn" title="' + u().esc(evt.errorCode || "") + '">' + code + "</span>";
    return '<span class="chip ok">' + (code || "-") + "</span>";
  }
  function principalText(evt) {
    if (evt.principalArn) return u().shortPrincipal({ arn: evt.principalArn });
    if (evt.accessKeyId) return "key " + evt.accessKeyId;
    return "-";
  }
  function resourceText(evt) {
    var p = evt.requestParameters || {};
    var keys = Object.keys(p);
    if (keys.length) return keys.map(function (k) { return k + "=" + p[k]; }).join("  ");
    if (evt.resources && evt.resources.length) return evt.resources.map(function (r) { return r.ResourceName; }).join(", ");
    return "";
  }
  function jsonHtml(obj) {
    return u().esc(JSON.stringify(obj, null, 2)).replace(/^(\s*)(&quot;[^&]*?&quot;)(:)/gm, '$1<span class="k">$2</span>$3');
  }

  function render() {
    if (!onPage()) return;
    var el = document.getElementById("main-content");
    if (!el) return;
    var c = DASH.catalog;
    var acct = DASH.app.state.account;
    var startIdx = totalEvents === 0 ? 0 : pageOffset + 1;
    var endIdx = Math.min(totalEvents, pageOffset + data.length);
    var svcOptions = c.services().slice().sort(function (a, b) { return c.label(a).localeCompare(c.label(b)); });

    var html = '<div><div class="crumbs"><button type="button" data-route="overview">Overview</button><span>/</span><span>CloudTrail events</span></div>' +
      '<div class="page-head"><div><h1>CloudTrail events</h1><p>The persisted history behind the live panel: the same records LookupEvents returns, searchable after the fact.</p></div>' +
      '<div class="head-actions"><button class="btn" type="button" id="ctRefresh">' + u().ICON.refresh + "Refresh</button></div></div></div>";
    html += '<section class="panel"><div class="panel-head"><h3>Events</h3><span class="chip neutral num">' + u().fmtInt(totalEvents) + " stored" +
      (filterService || scope === "account" ? " (filtered)" : "") + '</span><span class="sp"></span>' +
      '<select class="select" id="ctScope" aria-label="Account"><option value="account"' + (scope === "account" ? " selected" : "") + ">Account " + u().esc(acct) +
      '</option><option value="all"' + (scope === "all" ? " selected" : "") + ">All accounts</option></select>" +
      '<select class="select" id="ctFilter" aria-label="Service"><option value="">All services</option>' +
      svcOptions.map(function (s) { return '<option value="' + u().esc(s) + '"' + (s === filterService ? " selected" : "") + ">" + u().esc(c.label(s)) + "</option>"; }).join("") +
      "</select></div>";

    if (fetchFailed) {
      html += '<div class="panel-empty"><h3>Could not read the event store</h3><p>' + u().esc(fetchFailed) + "</p></div></section>";
    } else if (!data.length) {
      html += '<div class="panel-empty"><h3>' + (lastFetched ? "No events match" : "Loading events...") + "</h3>" +
        (lastFetched ? "<p>Every AWS call LocalEmu handles is recorded here unless a trail's event selectors exclude it.</p>" : "") + "</div></section>";
    } else {
      html += '<div class="tbl-wrap"><table class="tbl compact"><thead><tr><th>Time</th><th>Event</th><th>Service</th><th>Principal</th><th>Account</th><th class="r">Result</th></tr></thead><tbody>';
      data.forEach(function (evt) {
        var rid = evt.requestId || evt.requestID || "";
        var src = (evt.eventSource || "").replace(".amazonaws.com", "");
        var isOpen = detailOpenId === rid;
        var res = resourceText(evt);
        if (evt.errorCode) res = evt.errorCode + (res ? "  " + res : "");
        html += '<tr class="clickable' + (isOpen ? " open" : "") + '" data-event-id="' + u().esc(rid) + '" tabindex="0">' +
          '<td class="dim mono" title="' + u().esc(evt.eventTime || "") + '">' + u().esc(u().formatTimestamp(evt.eventTime)) + "</td>" +
          '<td class="res">' + u().esc(evt.eventName || "") + (res ? '<span class="arn">' + u().esc(res) + "</span>" : "") + "</td>" +
          '<td><span class="svc-cell">' + u().tile(src, "sm") + u().esc(c.label(src)) + "</span></td>" +
          '<td class="dim mono" title="' + u().esc(evt.principalArn || evt.accessKeyId || "") + '">' + u().esc(principalText(evt)) + "</td>" +
          '<td class="dim mono" title="' + u().esc(evt.accountId || "") + '">' + u().esc(u().shortAcct(evt.accountId || "")) + '</td><td class="r">' + resultChip(evt) + "</td></tr>";
        if (isOpen) {
          var full = detailCache[rid];
          var inner = full ? (parseCloudTrailEvent(full) || full) : null;
          html += '<tr><td colspan="6" class="detail">' + (inner ? '<pre class="json">' + jsonHtml(inner) + "</pre>" :
            detailLoading[rid] ? '<div class="note">Loading the full event...</div>' : '<pre class="json">' + jsonHtml(evt) + "</pre>") + "</td></tr>";
        }
      });
      html += "</tbody></table></div>" +
        '<div class="pager"><span>Showing ' + startIdx + "&ndash;" + endIdx + " of " + u().fmtInt(totalEvents) + '</span><span class="sp"></span>' +
        '<button class="btn sm" type="button" id="ctPrev"' + (pageOffset > 0 ? "" : " disabled") + ">&larr; Newer</button>" +
        '<button class="btn sm" type="button" id="ctNext"' + (pageOffset + data.length < totalEvents ? "" : " disabled") + ">Older &rarr;</button></div></section>";
    }
    el.innerHTML = html;

    document.getElementById("ctRefresh").addEventListener("click", function () { refresh(true); });
    document.getElementById("ctFilter").addEventListener("change", function (e) { filterService = e.target.value; pageOffset = 0; refresh(true); });
    document.getElementById("ctScope").addEventListener("change", function (e) { scope = e.target.value; pageOffset = 0; refresh(true); });
    var prev = document.getElementById("ctPrev"), next = document.getElementById("ctNext");
    if (prev) prev.addEventListener("click", function () { pageOffset = Math.max(0, pageOffset - pageLimit); refresh(true); });
    if (next) next.addEventListener("click", function () { pageOffset += pageLimit; refresh(true); });
    el.querySelectorAll("tr[data-event-id]").forEach(function (row) {
      function toggle() {
        var rid = row.getAttribute("data-event-id");
        if (detailOpenId === rid) { detailOpenId = null; applyPending(); }
        else { detailOpenId = rid; loadDetail(rid); }
        render();
      }
      row.addEventListener("click", toggle);
      row.addEventListener("keydown", function (e) { if (e.key === "Enter") toggle(); });
    });
  }

  // New calls refresh the first page (coalesced), unless a row is open.
  var coalesce = null, pendingWhileOpen = false;
  function bump() {
    if (!onPage() || pageOffset !== 0) return;
    if (detailOpenId !== null) { pendingWhileOpen = true; return; }
    if (coalesce) return;
    coalesce = setTimeout(function () { coalesce = null; if (onPage() && detailOpenId === null) refresh(true); }, 1000);
  }
  function applyPending() { if (pendingWhileOpen) { pendingWhileOpen = false; refresh(true); } }

  function init() { DASH.bus.subscribe("call", bump); }

  window.DASH.cloudtrail = {
    init: init, open: open, close: close, render: render,
    refresh: refresh, openDetail: openDetail, parse: parseCloudTrailEvent
  };
})();
