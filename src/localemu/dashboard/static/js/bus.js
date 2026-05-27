// Client-side event bus. Wraps an EventSource subscription to the
// server's /_localemu/api/stream endpoint and re-broadcasts every
// event to local subscribers. Falls back to a polling loop if SSE is
// unavailable (browser doesn't support EventSource, server unreachable,
// repeated reconnect failures).
//
// Local API:
//   DASH.bus.subscribe(kind, handler)         -> unsubscribe fn
//   DASH.bus.connectionStatus()               -> "connected" | "polling" | "offline"
//   DASH.bus.lastEventId()                    -> last seen event id
//   DASH.bus.start()                          -> open the SSE connection
//   DASH.bus.stop()                           -> close everything (tab unload)
(function () {
  "use strict";

  var URL_STREAM = "/_localemu/api/stream";
  var URL_ACTIVITY = "/_localemu/api/activity";

  var listeners = Object.create(null); // kind -> Array<fn>
  var status = "offline";
  var statusListeners = [];
  var es = null;
  var pollingTimer = null;
  var reconnectAttempt = 0;
  var lastId = null;
  var lastActivityCursor = null;
  var stopped = false;

  function setStatus(next) {
    if (status === next) return;
    status = next;
    statusListeners.forEach(function (l) { try { l(next); } catch (_) {} });
  }

  function emit(kind, payload, id) {
    if (id != null) lastId = id;
    (listeners[kind] || []).forEach(function (fn) {
      try { fn(payload, id); } catch (e) { /* swallow listener failures */ }
    });
    (listeners["*"] || []).forEach(function (fn) {
      try { fn({ kind: kind, payload: payload, id: id }); } catch (e) {}
    });
  }

  function subscribe(kind, handler) {
    if (!listeners[kind]) listeners[kind] = [];
    listeners[kind].push(handler);
    return function unsubscribe() {
      listeners[kind] = (listeners[kind] || []).filter(function (h) { return h !== handler; });
    };
  }

  function onStatus(handler) {
    statusListeners.push(handler);
    handler(status);
    return function () {
      statusListeners = statusListeners.filter(function (h) { return h !== handler; });
    };
  }

  function openSSE() {
    if (typeof EventSource === "undefined") {
      startPolling();
      return;
    }
    try {
      es = new EventSource(URL_STREAM);
    } catch (e) {
      startPolling();
      return;
    }
    es.onopen = function () {
      reconnectAttempt = 0;
      setStatus("connected");
      stopPolling();
    };
    es.onerror = function () {
      // EventSource auto-reconnects, but if errors persist we should
      // switch to polling. Exponential back-off counter.
      reconnectAttempt++;
      if (es && es.readyState === EventSource.CLOSED) {
        try { es.close(); } catch (_) {}
        es = null;
        if (reconnectAttempt < 5) {
          setTimeout(function () { if (!stopped) openSSE(); }, Math.min(1000 * Math.pow(2, reconnectAttempt), 30000));
        } else {
          setStatus("polling");
          startPolling();
        }
      } else {
        setStatus("offline");
      }
    };
    // Server-side event kinds (see dashboard/bus.py).
    ["activity", "count", "resource", "state", "hello", "dropped", "ping"].forEach(function (kind) {
      es.addEventListener(kind, function (msg) {
        var data = null;
        try { data = msg.data ? JSON.parse(msg.data) : {}; } catch (e) { data = {}; }
        emit(kind, data, msg.lastEventId ? parseInt(msg.lastEventId, 10) : null);
      });
    });
  }

  // ── Polling fallback ──
  // When SSE is unavailable we keep two timers:
  //   activity poll: every 3 s (delta via ?since=<last_request_id>)
  //   no overview poll here -- app.js handles that on its own 60 s timer
  function startPolling() {
    if (pollingTimer) return;
    setStatus("polling");
    pollingTimer = setInterval(pollOnce, 3000);
    pollOnce();
  }
  function stopPolling() {
    if (pollingTimer) { clearInterval(pollingTimer); pollingTimer = null; }
  }

  function pollOnce() {
    var url = URL_ACTIVITY + (lastActivityCursor ? "?since=" + encodeURIComponent(lastActivityCursor) : "?limit=50");
    DASH.api.fetchJSON(url, { etag: false, timeoutMs: 5000 }).then(function (r) {
      var events = (r.data && r.data.events) ? r.data.events : [];
      // The server returns most-recent-first. Replay in chronological order
      // so subscribers see them in the same order as SSE would deliver.
      for (var i = events.length - 1; i >= 0; i--) {
        var evt = events[i];
        emit("activity", {
          service: evt.service || (evt.eventSource || "").replace(".amazonaws.com", ""),
          operation: evt.operation || evt.eventName,
          status: evt.status || evt.responseCode,
          request_id: evt.request_id || evt.requestId,
          account_id: evt.account_id || evt.accountId,
          region: evt.region || evt.awsRegion,
          timestamp: evt.timestamp || evt.eventTime
        }, null);
        if (i === 0) lastActivityCursor = evt.request_id || evt.requestId;
      }
    }).catch(function () {
      // network error -- keep status "polling", do not flip to offline
      // unless the gateway is also down. The next /api/overview tick
      // (driven by app.js) will catch the offline transition.
    });
  }

  function start() {
    if (stopped) stopped = false;
    openSSE();
  }
  function stop() {
    stopped = true;
    if (es) { try { es.close(); } catch (_) {} es = null; }
    stopPolling();
  }

  window.DASH.bus = {
    subscribe: subscribe,
    onStatus: onStatus,
    connectionStatus: function () { return status; },
    lastEventId: function () { return lastId; },
    start: start,
    stop: stop
  };
})();
