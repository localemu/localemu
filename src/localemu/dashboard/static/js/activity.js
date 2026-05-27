// Live activity feed. Subscribes to SSE `activity` events and
// renders them in the bottom footer. Capped at 200 visible rows.
// Auto-scroll until the user scrolls up; then shows "X new" indicator.
(function () {
  "use strict";

  var MAX_ROWS = 200;
  var ringBuffer = [];        // most-recent first
  var filterService = "";
  var paused = false;

  function setFilter(svc) {
    filterService = svc || "";
    repopulate();
    syncFilterOptions();
  }
  function togglePause() {
    paused = !paused;
    var btn = document.getElementById("activity-pause-btn");
    if (btn) {
      btn.textContent = paused ? "Resume" : "Pause";
      btn.classList.toggle("paused", paused);
    }
  }
  function clearLocal() {
    ringBuffer = [];
    var list = document.getElementById("activity-list");
    if (list) list.innerHTML = "";
  }

  function record(evt) {
    if (!evt || paused) return;
    var entry = {
      ts: evt.timestamp || Date.now() / 1000,
      service: evt.service || "?",
      operation: evt.operation || "?",
      status: evt.status || 0,
      request_id: evt.request_id || "",
      region: evt.region || ""
    };
    ringBuffer.unshift(entry);
    while (ringBuffer.length > MAX_ROWS) ringBuffer.pop();
    if (!filterService || filterService === entry.service) {
      prependRow(entry);
    }
    syncFilterOptions();
  }

  function prependRow(entry) {
    var u = DASH.utils;
    var list = document.getElementById("activity-list");
    if (!list) return;
    var cls = u.statusClass(entry.status);
    var html =
      '<div class="activity-row clickable" data-req-id="' + u.esc(entry.request_id) + '">' +
        '<span class="activity-ts">' + u.esc(u.formatTimestamp(entry.ts)) + '</span>' +
        '<span class="activity-op">' + u.esc(entry.service) + '.' + u.esc(entry.operation) + '</span>' +
        '<span class="activity-status ' + cls + '">' + u.esc(entry.status) + '</span>' +
        '<span class="activity-req">' + u.esc(entry.region) + ' ' + u.esc((entry.request_id || "").slice(0, 8)) + '</span>' +
      '</div>';
    var holder = document.createElement("div");
    holder.innerHTML = html;
    var node = holder.firstChild;
    list.insertBefore(node, list.firstChild);
    while (list.children.length > MAX_ROWS) list.removeChild(list.lastChild);
  }

  function repopulate() {
    var list = document.getElementById("activity-list");
    if (!list) return;
    list.innerHTML = "";
    ringBuffer.forEach(function (entry) {
      if (!filterService || filterService === entry.service) prependRow(entry);
    });
  }

  // Keep the activity-filter <select> in sync with overview-known services.
  // Called whenever a new service shows up in the feed.
  var lastFilterServices = "";
  function syncFilterOptions() {
    var sel = document.getElementById("activity-filter");
    if (!sel) return;
    var services = (DASH.app.state.overview && DASH.app.state.overview.services) || {};
    var keys = Object.keys(services).sort();
    var fingerprint = keys.join(",");
    if (fingerprint === lastFilterServices) return;
    lastFilterServices = fingerprint;
    var u = DASH.utils, s = DASH.services;
    var html = '<option value="">All services</option>';
    keys.forEach(function (name) {
      var sel = (name === filterService) ? " selected" : "";
      html += '<option value="' + u.esc(name) + '"' + sel + '>' + u.esc(s.label(name)) + '</option>';
    });
    sel.innerHTML = html;
  }

  function init() {
    // SSE -> ring buffer + DOM append.
    DASH.bus.subscribe("activity", function (data) { record(data); });

    var sel = document.getElementById("activity-filter");
    if (sel) sel.addEventListener("change", function () { setFilter(sel.value); });
    var pauseBtn = document.getElementById("activity-pause-btn");
    if (pauseBtn) pauseBtn.addEventListener("click", togglePause);
    var clearBtn = document.getElementById("activity-clear-btn");
    if (clearBtn) clearBtn.addEventListener("click", clearLocal);

    // Click a row -> open the CloudTrail detail for that request id.
    var list = document.getElementById("activity-list");
    if (list) {
      list.addEventListener("click", function (e) {
        var row = e.target.closest(".activity-row");
        if (!row) return;
        var rid = row.dataset.reqId;
        if (rid) DASH.cloudtrail.openDetail(rid);
      });
    }

    // Hydrate with an initial fetch of the last 50 events.
    DASH.api.fetchJSON("/_localemu/api/activity?limit=50", { etag: false }).then(function (r) {
      var events = (r.data && r.data.events) || [];
      // Server returns most-recent-first; ringBuffer is also most-recent-first.
      events.forEach(function (evt) {
        ringBuffer.push({
          ts: evt.eventTime || evt.timestamp,
          service: (evt.eventSource || "").replace(".amazonaws.com", "") || evt.service || "?",
          operation: evt.eventName || evt.operation || "?",
          status: evt.responseCode || evt.status || 0,
          request_id: evt.requestId || evt.request_id || "",
          region: evt.awsRegion || evt.region || ""
        });
      });
      repopulate();
      syncFilterOptions();
    }).catch(function (err) {
      // Initial activity hydrate -- if it fails the live SSE feed
      // will still fill the strip, so just surface the error and
      // move on.
      if (DASH.utils && DASH.utils.showApiError) DASH.utils.showApiError(err, "activity feed");
    });
  }

  window.DASH.activity = {
    init: init,
    setFilter: setFilter,
    togglePause: togglePause,
    clear: clearLocal
  };
})();
