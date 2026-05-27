// CloudTrail event history viewer. Renders when route.service ===
// "cloudtrail". One-off fetch on open; 60 s safety poll afterwards.
(function () {
  "use strict";

  var data = [];
  // Total stored in the backend, separate from data.length (which is the
  // size of the latest fetched window). Used to honestly say "showing N
  // of TOTAL" instead of pretending the window is the whole set.
  var totalEvents = 0;
  var lastFetched = null;
  var pollTimer = null;
  var filterService = "";
  var pageOffset = 0;
  var pageLimit = 200;
  var detailOpenId = null;
  // Cache of full per-event payloads (requestParameters + responseElements),
  // keyed by request_id. The list endpoint strips these to keep the payload
  // small; we lazy-fetch the detail when a row is expanded.
  var detailCache = {};
  var detailLoading = {};

  function open() { refresh(true); startPoll(); }
  // Only clear detailOpenId when leaving the cloudtrail route entirely.
  // Re-entering the same route (e.g. navigate() called from openDetail)
  // must preserve the row the user just expanded.
  function close() {
    stopPoll();
    if (DASH.app.state.route.service !== "cloudtrail") {
      detailOpenId = null;
    }
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
    // Push the service filter and offset down to the server so
    // filtering operates over the whole event store, not just the
    // last 200 events the dashboard happened to fetch.
    var url = "/_localemu/api/cloudtrail?limit=" + encodeURIComponent(pageLimit)
            + "&offset=" + encodeURIComponent(pageOffset);
    if (filterService) url += "&service=" + encodeURIComponent(filterService);
    var cacheKey = "cloudtrail:" + pageLimit + ":" + pageOffset + ":" + filterService;
    if (force) DASH.cache.invalidateKey(cacheKey);
    DASH.api.get(url, { cacheKey: cacheKey, ttlMs: 30000, tags: ["cloudtrail"] }).then(function (r) {
      data = (r.value && r.value.events) || [];
      totalEvents = (r.value && typeof r.value.total === "number") ? r.value.total : data.length;
      lastFetched = Date.now();
      render();
    }).catch(function () { data = []; totalEvents = 0; render(); });
  }

  function openDetail(reqId) {
    detailOpenId = reqId;
    if (DASH.app.state.route.service !== "cloudtrail") {
      DASH.app.navigate({ service: "cloudtrail", resource: null });
    } else {
      render();
    }
    // Scroll to row.
    setTimeout(function () {
      var row = document.querySelector('.cloudtrail-event-row[data-event-id="' + cssEsc(reqId) + '"]');
      if (row && row.scrollIntoView) row.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 50);
  }

  function cssEsc(s) {
    if (window.CSS && CSS.escape) return CSS.escape(String(s));
    return String(s).replace(/"/g, "\\\"");
  }

  // The detail endpoint follows the AWS LookupEvents envelope and nests
  // the full event payload (requestParameters, responseElements,
  // userIdentity, etc.) inside ``CloudTrailEvent`` as a JSON string.
  // Return the parsed inner event, or null on shape mismatch.
  function parseCloudTrailEvent(envelope) {
    if (!envelope || typeof envelope.CloudTrailEvent !== "string") return null;
    try { return JSON.parse(envelope.CloudTrailEvent); }
    catch (e) { return null; }
  }
  // (Parser is exported below under DASH.cloudtrail.parse so other
  // drills can reuse it.)

  function render() {
    var state = DASH.app.state;
    if (state.route.service !== "cloudtrail") return;
    var u = DASH.utils, s = DASH.services;
    var elMain = document.getElementById("main-content");
    if (!elMain) return;

    // Backend now applies the service filter, so the response is
    // already pre-filtered. Just render whatever it returned.
    var filtered = data;

    var serviceFacets = {};
    data.forEach(function (e) {
      var src = (e.eventSource || "").replace(".amazonaws.com", "");
      if (src) serviceFacets[src] = (serviceFacets[src] || 0) + 1;
    });
    var facetKeys = Object.keys(serviceFacets).sort();

    var lastTxt = lastFetched ? "last refreshed " + Math.max(0, Math.round((Date.now() - lastFetched) / 1000)) + "s ago" : "loading...";

    var html = "";
    html += '<div class="detail-header">';
    html += u.iconHtml("cloudtrail", 28);
    html += '<h2>CloudTrail Event History</h2>';
    html += '<span class="last-refreshed">' + u.esc(lastTxt) + '</span>';
    html += '<button class="refresh-btn" id="ct-refresh-btn">Refresh</button>';
    html += '<button class="back-link" id="back-overview-btn">← Overview</button>';
    html += '</div>';

    // Honest count line: backend gives the true filter-aware total in
    // `totalEvents`; the rows on screen are at most `pageLimit` of
    // that, starting at `pageOffset`.
    var startIdx = totalEvents === 0 ? 0 : pageOffset + 1;
    var endIdx = Math.min(totalEvents, pageOffset + filtered.length);
    var rangeNote = totalEvents > 0
      ? ' <span class="row-window-note">(showing ' + startIdx + '\u2013' + endIdx + ' of ' + totalEvents + ')</span>'
      : '';
    var hasPrev = pageOffset > 0;
    var hasNext = pageOffset + filtered.length < totalEvents;

    html += '<div class="detail-toolbar">';
    html += '<select id="ct-filter">';
    html += '<option value="">All services</option>';
    facetKeys.forEach(function (k) {
      var sel = (k === filterService) ? " selected" : "";
      html += '<option value="' + u.esc(k) + '"' + sel + '>' + u.esc(s.label(k) || k) + ' (' + serviceFacets[k] + ' shown)</option>';
    });
    html += '</select>';
    html += '<span class="row-count">' + filtered.length + ' events' + rangeNote + '</span>';
    html += '<button class="row-action" id="ct-prev"' + (hasPrev ? '' : ' disabled') + '>\u2190 Prev</button>';
    html += '<button class="row-action" id="ct-next"' + (hasNext ? '' : ' disabled') + '>Next \u2192</button>';
    html += '</div>';

    if (filtered.length === 0) {
      html += '<div class="empty-state">No CloudTrail events.</div>';
      elMain.innerHTML = html;
      elMain.dataset.lastKey = "cloudtrail:empty";
      wireHeader();
      return;
    }

    html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
    html += '<th>Time</th><th>Event Source</th><th>Event Name</th><th>Region</th><th>Status</th>';
    html += '</tr></thead><tbody>';
    filtered.forEach(function (evt) {
      var code = evt.responseCode || 0;
      var cls = u.statusClass(code);
      var ts = u.formatTimestamp(evt.eventTime);
      var src = (evt.eventSource || "").replace(".amazonaws.com", "");
      var rid = evt.requestId || evt.requestID || "";
      var isOpen = detailOpenId === rid;
      html += '<tr class="cloudtrail-event-row clickable-row" data-event-id="' + u.esc(rid) + '">';
      html += '<td>' + u.esc(ts) + '</td>';
      html += '<td>' + u.esc(src) + '</td>';
      html += '<td>' + u.esc(evt.eventName || "") + '</td>';
      html += '<td>' + u.esc(evt.awsRegion || "") + '</td>';
      html += '<td><span class="activity-status ' + cls + '">' + u.esc(code) + '</span></td>';
      html += '</tr>';
      if (isOpen) {
        var full = detailCache[rid];
        var body;
        if (full) {
          // ``/_localemu/api/cloudtrail/<rid>`` returns the LookupEvents
          // envelope. The full payload (including requestParameters and
          // responseElements) is nested inside ``CloudTrailEvent`` as a
          // JSON string. Render the parsed inner event when present,
          // falling back to the envelope.
          var inner = parseCloudTrailEvent(full);
          body = u.esc(JSON.stringify(inner || full, null, 2));
        } else if (detailLoading[rid]) {
          body = "loading full request / response body...";
        } else {
          // Fall back to the summary row until the detail fetch completes.
          body = u.esc(JSON.stringify(evt, null, 2));
        }
        html += '<tr><td colspan="5"><pre class="cloudtrail-detail">' + body + '</pre></td></tr>';
      }
    });
    html += '</tbody></table></div>';

    elMain.innerHTML = html;
    elMain.dataset.lastKey = "cloudtrail:" + data.length + ":" + filterService + ":" + (detailOpenId || "");
    wireHeader();

    var sel = document.getElementById("ct-filter");
    if (sel) sel.addEventListener("change", function () {
      filterService = sel.value;
      pageOffset = 0;
      refresh(true);
    });
    var prev = document.getElementById("ct-prev");
    if (prev) prev.addEventListener("click", function () {
      if (pageOffset === 0) return;
      pageOffset = Math.max(0, pageOffset - pageLimit);
      refresh(true);
    });
    var next = document.getElementById("ct-next");
    if (next) next.addEventListener("click", function () {
      if (pageOffset + filtered.length >= totalEvents) return;
      pageOffset = pageOffset + pageLimit;
      refresh(true);
    });
    elMain.querySelectorAll(".cloudtrail-event-row").forEach(function (row) {
      row.addEventListener("click", function () {
        var rid = row.dataset.eventId;
        if (detailOpenId === rid) {
          detailOpenId = null;
          maybeApplyPendingRefresh();
        } else {
          detailOpenId = rid;
          // Lazy-load the full event body (requestParameters +
          // responseElements) once per request_id. The list endpoint
          // returns the summary shape; this fetch widens it.
          if (rid && !detailCache[rid] && !detailLoading[rid]) {
            detailLoading[rid] = true;
            DASH.api.fetchJSON(
              "/_localemu/api/cloudtrail/" + encodeURIComponent(rid),
              { etag: false, timeoutMs: 6000 }
            ).then(function (resp) {
              detailLoading[rid] = false;
              if (resp && resp.data) detailCache[rid] = resp.data;
              if (detailOpenId === rid) render();
            }).catch(function () {
              detailLoading[rid] = false;
              if (detailOpenId === rid) render();
            });
          }
        }
        render();
      });
    });
  }

  function wireHeader() {
    var refresh = document.getElementById("ct-refresh-btn");
    if (refresh) refresh.addEventListener("click", function () { module.refresh(true); });
    var back = document.getElementById("back-overview-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: null, resource: null }); });
  }

  function init() {
    setInterval(function () {
      if (DASH.app.state.route.service === "cloudtrail") {
        var el = document.querySelector(".last-refreshed");
        if (el && lastFetched) {
          el.textContent = "last refreshed " + Math.max(0, Math.round((Date.now() - lastFetched) / 1000)) + "s ago";
        }
      }
    }, 5000);
  }

  // Refresh CloudTrail data whenever new activity is recorded (via SSE).
  // Coalesce: only refresh once per second.
  //
  // Suppressed while an event row is expanded -- a full re-render would
  // race the user's click and the in-flight detail fetch, briefly
  // collapsing the row they just opened. We rely on the user closing
  // the row or pressing Refresh to pull newer events.
  var coalesce = null;
  var pendingWhileOpen = false;
  function bumpRefresh() {
    if (DASH.app.state.route.service !== "cloudtrail") return;
    if (detailOpenId !== null) { pendingWhileOpen = true; return; }
    if (coalesce) return;
    coalesce = setTimeout(function () {
      coalesce = null;
      if (DASH.app.state.route.service !== "cloudtrail") return;
      if (detailOpenId !== null) { pendingWhileOpen = true; return; }
      refresh(true);
    }, 1000);
  }
  // When the user collapses the detail row, apply any deferred refresh
  // so the freshly-collapsed list isn't stale.
  function maybeApplyPendingRefresh() {
    if (pendingWhileOpen && detailOpenId === null) {
      pendingWhileOpen = false;
      refresh(true);
    }
  }
  // Late-init: subscribe once DASH.bus is up.
  setTimeout(function () {
    if (DASH.bus && DASH.bus.subscribe) {
      DASH.bus.subscribe("activity", bumpRefresh);
    }
  }, 0);

  var module = {
    init: init, open: open, close: close, render: render,
    refresh: refresh, openDetail: openDetail, parse: parseCloudTrailEvent
  };
  window.DASH.cloudtrail = module;
})();
