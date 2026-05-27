// Bootstrap, router, top-level state. Loaded last.
//
// Owns the single DASH.app.state object that every component reads
// from. Wires the SSE bus, opens/closes drill-downs and resource
// panels in response to hash navigation, and drives the 60 s overview
// safety poll.
(function () {
  "use strict";

  var state = {
    route: { service: null, resource: null, tab: null, sub: null },
    overview: { services: {}, version: "", port: 0, uptime: 0, features: {} },
    resources: [],
    resourcesService: null,
    sse: { connected: false },
    overviewLastFetched: null
  };

  // Per-navigation context the drill framework reads (``meta.tab``,
  // ``meta.highlight``, etc.). Populated from either a navigate() call
  // or the parsed hash on history events, and consumed by the next
  // openDrill(). The router-side ``tab`` / ``sub`` segments DO persist
  // through history, so Back/Forward and bookmarks restore them.
  var pendingMeta = null;

  var overviewPollTimer = null;

  // ── Routing ──
  // Hash forms (4 positional segments, trailing empties trimmed):
  //   #/                              overview
  //   #/<service>                     service list
  //   #/<service>/<resource>          drill-down
  //   #/<service>/<resource>/<tab>    drill-down, specific tab
  //   #/<service>/<resource>/<tab>/<sub>
  //                                   drill-down, tab, with sub-id
  //                                   (e.g. EventBridge rule under a bus)
  //
  // The 3rd + 4th segments make tab switches and cross-resource
  // highlights bookmarkable / shareable / browser-back friendly. They
  // surface in the route as ``route.tab`` and ``route.sub``; the drill
  // framework reads ``meta.tab`` / ``meta.highlight`` which navigate()
  // synthesizes from those.
  function parseHash() {
    var raw = (window.location.hash || "").replace(/^#\/?/, "");
    if (!raw) return { service: null, resource: null, tab: null, sub: null };
    var parts = raw.split("/");
    return {
      service: parts[0] ? decodeURIComponent(parts[0]) : null,
      resource: parts[1] ? decodeURIComponent(parts[1]) : null,
      tab: parts[2] ? decodeURIComponent(parts[2]) : null,
      sub: parts.length > 3 ? decodeURIComponent(parts.slice(3).join("/")) : null
    };
  }
  function writeHash(route) {
    var segs = [];
    if (route.service) {
      segs.push(encodeURIComponent(route.service));
      if (route.resource) {
        segs.push(encodeURIComponent(route.resource));
        if (route.tab || route.sub) {
          // tab may be empty when only sub is set (rare but legal);
          // encode as "" so the positional slot is preserved.
          segs.push(route.tab ? encodeURIComponent(route.tab) : "");
          if (route.sub) {
            segs.push(encodeURIComponent(route.sub));
          }
        }
      }
    }
    var hash = segs.length ? "#/" + segs.join("/") : "";
    if ((window.location.hash || "") === hash) return;
    suppressHashRouter = true;
    if (hash) {
      history.pushState(null, "", hash);
    } else {
      history.pushState(null, "", window.location.pathname + window.location.search);
    }
    suppressHashRouter = false;
  }
  var suppressHashRouter = false;

  function navigate(route) {
    var prev = state.route;
    state.route = {
      service: route.service || null,
      resource: route.resource || null,
      tab: route.tab || null,
      sub: route.sub || null
    };
    // Synthesize the meta the drill framework reads. The router-side
    // ``tab`` / ``sub`` win over anything in ``route.meta`` so a
    // browser back/forward correctly restores the URL-encoded state.
    var meta = Object.assign({}, route.meta || {});
    if (state.route.tab) meta.tab = state.route.tab;
    if (state.route.sub && !meta.highlight) meta.highlight = state.route.sub;
    pendingMeta = (Object.keys(meta).length ? meta : null);
    writeHash(state.route);
    // Component lifecycle: close the previous, open the new.
    if (prev.service !== state.route.service) {
      // closing previous service panel.
      DASH.resources.close();
      DASH.cloudtrail.close();
    } else if (prev.resource && !state.route.resource) {
      // Same service, leaving the drill-down (Back to <Service>). The
      // resources panel is about to be re-opened; force a clean
      // poll-timer reset so the leftover timer from before the drill
      // entered does not double-fire.
      DASH.resources.close();
    } else if (!prev.resource && state.route.resource) {
      // Same service, entering a drill-down. Stop the list-panel poll
      // so it does not run in the background while the drill is up.
      DASH.resources.stopPolling();
    }
    // When the only thing that changed is the tab inside the same
    // drill, skip re-rendering the whole drill — the framework's
    // tab-click handler already updated the DOM. Saves a network
    // round-trip and keeps form state alive.
    if (
      prev.service === state.route.service
      && prev.resource === state.route.resource
      && state.route.resource
      && (prev.tab !== state.route.tab || prev.sub !== state.route.sub)
    ) {
      return;
    }
    renderCurrent();
  }

  function renderCurrent() {
    var elMain = document.getElementById("main-content");
    var r = state.route;

    // Drill-down takes precedence over service detail.
    if (r.service && r.resource) {
      var meta = pendingMeta;
      pendingMeta = null;
      openDrill(r.service, r.resource, meta);
      DASH.sidebar.render();
      return;
    }

    pendingMeta = null;

    if (r.service === "cloudtrail") {
      DASH.cloudtrail.open();
      DASH.cloudtrail.render();
      DASH.sidebar.render();
      return;
    }
    if (r.service) {
      DASH.resources.open(r.service);
      DASH.resources.render();
      DASH.sidebar.render();
      return;
    }
    // Overview
    DASH.overview.render();
    DASH.sidebar.render();
  }

  function openDrill(service, key, meta) {
    // Registry-driven framework drill takes precedence so new IAM /
    // KMS / SF / etc. drills route through the tabbed framework.
    if (DASH.registry && DASH.registry.getDrill) {
      var spec = DASH.registry.getDrill(service);
      if (spec) {
        DASH.drills.framework.open(spec, key, meta || {});
        return;
      }
    }
    var d = DASH.drills;
    if (service === "s3" && d.s3)             return d.s3.open(key);
    if (service === "dynamodb" && d.ddb)      return d.ddb.open(key);
    if (service === "sqs" && d.sqs)           return d.sqs.open(key);
    if (service === "logs" && d.logs)         return d.logs.open(key);
    if (service === "sns" && d.sns)           return d.sns.open(key);
    if (service === "events" && d.events)     return d.events.open(key, meta && meta.highlight);
    if (service === "lambda" && d.lambda)     return d.lambda.open(key);
    if (service === "stepfunctions" && d.stepfunctions) return d.stepfunctions.open(key);
    // Generic framework fallback: any service with a row in the list
    // gets a clickable Overview + JSON + Recent activity drill. This
    // is the registry's promise that 132 services have a useful page,
    // even when there is no hand-tuned drill yet.
    if (DASH.registry && DASH.registry.get && DASH.registry.get(service)) {
      DASH.drills.framework.openGeneric(service, key, meta || {});
      return;
    }
    // No drill registered for this service: render an honest "drill
    // not yet implemented" panel so the user sees the gap instead of
    // bouncing back to the list (which used to feel like a broken
    // click).
    var u = DASH.utils, s = DASH.services;
    var el = document.getElementById("main-content");
    if (el) {
      var html = '<div class="detail-header">';
      html += u.iconHtml(service, 28);
      html += '<h2>' + u.esc(s.label(service)) + ' &middot; ' + u.esc(key) + '</h2>';
      html += '<button class="back-link" id="back-svc-btn">&larr; Back to ' + u.esc(s.label(service)) + '</button>';
      html += '</div>';
      html += '<div class="empty-state-guidance">';
      html += '<div class="empty-title">Drill-down not yet implemented</div>';
      html += '<div class="hint">The list page shows this resource, but no per-resource detail view exists for ' + u.esc(s.label(service)) + ' yet.</div>';
      html += '</div>';
      el.innerHTML = html;
      var back = document.getElementById("back-svc-btn");
      if (back) back.addEventListener("click", function () {
        DASH.app.navigate({ service: service, resource: null });
      });
    }
  }

  // ── Overview polling ──
  // 60 s safety poll; SSE pushes invalidation in between.
  function refreshOverview(force) {
    var url = "/_localemu/api/overview";
    var cacheKey = "overview";
    if (force) DASH.cache.invalidateKey(cacheKey);
    DASH.api.get(url, { cacheKey: cacheKey, ttlMs: 60000, tags: ["overview"] }).then(function (r) {
      if (r.value) {
        state.overview = r.value;
        state.overviewLastFetched = Date.now();
      }
      renderTopbar();
      DASH.sidebar.render();
      if (!state.route.service) DASH.overview.render();
    }).catch(function (err) { DASH.utils.showApiError(err, "overview"); });
  }

  function renderTopbar() {
    var u = DASH.utils;
    var ov = state.overview || {};
    var elV = document.getElementById("topbar-version");
    var elP = document.getElementById("topbar-port");
    var elU = document.getElementById("topbar-uptime");
    if (elV) elV.innerHTML = '<span class="badge-label">v</span>' + u.esc(ov.version || "...");
    if (elP) elP.innerHTML = '<span class="badge-label">port</span>' + u.esc(ov.port || "...");
    if (elU) elU.innerHTML = '<span class="badge-label">up</span>' + u.esc(u.formatUptime(ov.uptime_seconds || ov.uptime));
  }

  function setConnectionStatus(status) {
    var dot = document.getElementById("conn-dot");
    var lbl = document.getElementById("conn-label");
    if (!dot || !lbl) return;
    dot.classList.remove("connected", "polling", "offline");
    if (status === "connected") {
      dot.classList.add("connected");
      lbl.textContent = "live";
    } else if (status === "polling") {
      dot.classList.add("polling");
      lbl.textContent = "polling";
    } else {
      dot.classList.add("offline");
      lbl.textContent = "offline";
    }
  }

  function init() {
    var hamburger = document.getElementById("hamburger-btn");
    if (hamburger) hamburger.addEventListener("click", function () {
      var sb = document.getElementById("sidebar");
      if (sb) sb.classList.toggle("mobile-open");
    });

    var brand = document.getElementById("brand-home");
    if (brand) brand.addEventListener("click", function (e) {
      e.preventDefault();
      navigate({ service: null, resource: null });
    });

    // SSE bus.
    DASH.bus.onStatus(setConnectionStatus);
    DASH.bus.subscribe("count", function () { refreshOverview(true); });
    DASH.bus.subscribe("resource", function () { refreshOverview(true); });
    DASH.bus.subscribe("hello", function () { /* connected ack */ });
    DASH.bus.subscribe("dropped", function () { refreshOverview(true); });
    DASH.bus.start();

    // Component init.
    // Preload the service registry first; it drives tier badges,
    // labels, columns and banners. The fetch is async; legacy
    // services.js maps remain functional while it lands.
    if (DASH.registry && DASH.registry.load) {
      DASH.registry.load().then(function () {
        DASH.sidebar.render();
      });
    }
    DASH.sidebar.init();
    DASH.overview.init();
    DASH.resources.init();
    DASH.activity.init();
    DASH.cloudtrail.init();
    if (DASH.actions && DASH.actions._modal) DASH.actions._modal.init();
    if (DASH.drills && DASH.drills.s3) DASH.drills.s3.init && DASH.drills.s3.init();
    if (DASH.drills && DASH.drills.ddb) DASH.drills.ddb.init && DASH.drills.ddb.init();
    if (DASH.drills && DASH.drills.sqs) DASH.drills.sqs.init && DASH.drills.sqs.init();
    if (DASH.drills && DASH.drills.logs) DASH.drills.logs.init && DASH.drills.logs.init();
    if (DASH.drills && DASH.drills.sns) DASH.drills.sns.init && DASH.drills.sns.init();
    if (DASH.drills && DASH.drills.events) DASH.drills.events.init && DASH.drills.events.init();
    if (DASH.drills && DASH.drills.lambda) DASH.drills.lambda.init && DASH.drills.lambda.init();
    if (DASH.drills && DASH.drills.stepfunctions) DASH.drills.stepfunctions.init && DASH.drills.stepfunctions.init();

    // Router. On hashchange (back/forward, paste-in-URL), sync
    // pendingMeta from the parsed tab/sub so the drill framework
    // opens to the right tab.
    function _syncPendingMetaFromRoute() {
      var r = state.route || {};
      var m = {};
      if (r.tab) m.tab = r.tab;
      if (r.sub) m.highlight = r.sub;
      pendingMeta = (Object.keys(m).length ? m : null);
    }
    state.route = parseHash();
    _syncPendingMetaFromRoute();
    window.addEventListener("hashchange", function () {
      if (suppressHashRouter) return;
      state.route = parseHash();
      _syncPendingMetaFromRoute();
      renderCurrent();
    });

    // First fetch.
    refreshOverview(true);
    renderCurrent();

    // Safety overview poll every 60 s. SSE pushes count events in
    // between; this backstop catches any missed update.
    overviewPollTimer = setInterval(function () {
      refreshOverview(false);
    }, 60000);

    // Tab visibility: pause overview polling when tab hidden.
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        // Nothing to do: SSE keeps running but render layer is idle.
      } else {
        refreshOverview(true);
      }
    });

    // Beforeunload: close the SSE connection cleanly.
    window.addEventListener("beforeunload", function () { DASH.bus.stop(); });
  }

  window.DASH.app = {
    state: state,
    navigate: navigate,
    refreshOverview: refreshOverview,
    init: init
  };

  document.addEventListener("DOMContentLoaded", init);
})();
