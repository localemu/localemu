// Bootstrap, router, top-level state. Loaded last.
//
// Owns DASH.app.state, which every component reads:
//   route     parsed URL hash
//   account   AWS account the console is scoped to (top-bar switcher)
//   overview  /_localemu/api/overview?account=<id> (per-service counts)
//   system    /_localemu/api/system (version, uptime, IAM, Docker, Ollama)
//   accounts  /_localemu/api/accounts records
// and wires the SSE bus, the router and the top bar.
(function () {
  "use strict";

  var ACCOUNT_KEY = "localemu-console-account";
  var DEFAULT_ACCOUNT = "000000000000";

  function savedAccount() {
    try {
      var v = localStorage.getItem(ACCOUNT_KEY);
      if (v && /^\d{12}$/.test(v)) return v;
    } catch (_) {}
    return DEFAULT_ACCOUNT;
  }

  var state = {
    route: { service: null, resource: null, tab: null, sub: null },
    account: savedAccount(),
    accounts: [],
    overview: { services: {}, totals: null },
    system: null,
    resources: [],
    resourcesService: null,
    sse: { status: "offline" },
    overviewLastFetched: null
  };

  // Per-navigation context the drill framework reads (meta.tab,
  // meta.highlight). Consumed by the next openDrill().
  var pendingMeta = null;
  var suppressHashRouter = false;

  // ── Routing ──
  //   #/                         overview
  //   #/cloudtrail, #/accounts   console pages
  //   #/<service>                service page
  //   #/<service>/<resource>[/<tab>[/<sub>]]   drill-down
  function parseHash() {
    var raw = (window.location.hash || "").replace(/^#\/?/, "");
    if (!raw || raw === "overview") return { service: null, resource: null, tab: null, sub: null };
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
          segs.push(route.tab ? encodeURIComponent(route.tab) : "");
          if (route.sub) segs.push(encodeURIComponent(route.sub));
        }
      }
    }
    var hash = segs.length ? "#/" + segs.join("/") : "";
    if ((window.location.hash || "") === hash) return;
    suppressHashRouter = true;
    if (hash) history.pushState(null, "", hash);
    else history.pushState(null, "", window.location.pathname + window.location.search);
    suppressHashRouter = false;
  }

  function navigate(route) {
    var prev = state.route;
    state.route = {
      service: route.service || null,
      resource: route.resource || null,
      tab: route.tab || null,
      sub: route.sub || null
    };
    var meta = Object.assign({}, route.meta || {});
    if (state.route.tab) meta.tab = state.route.tab;
    if (state.route.sub && !meta.highlight) meta.highlight = state.route.sub;
    pendingMeta = (Object.keys(meta).length ? meta : null);
    writeHash(state.route);
    if (prev.service !== state.route.service) {
      DASH.resources.close();
      DASH.cloudtrail.close();
    } else if (prev.resource && !state.route.resource) {
      DASH.resources.close();
    } else if (!prev.resource && state.route.resource) {
      DASH.resources.stopPolling();
    }
    if (prev.service === state.route.service && prev.resource === state.route.resource &&
        state.route.resource && (prev.tab !== state.route.tab || prev.sub !== state.route.sub)) {
      return;
    }
    renderCurrent(true);
  }

  function resetScroll() {
    var w = document.getElementById("work");
    var m = document.getElementById("scrollMerge");
    if (w) w.scrollTop = 0;
    if (m) m.scrollTop = 0;
  }

  function renderCurrent(scrollTop) {
    var r = state.route;
    var el = document.getElementById("main-content");
    if (el) delete el.dataset.lastKey;
    DASH.overlay.close();
    if (scrollTop) resetScroll();
    DASH.overview.leave();

    if (r.service && r.resource) {
      var meta = pendingMeta;
      pendingMeta = null;
      openDrill(r.service, r.resource, meta);
    } else if (r.service === "cloudtrail") {
      pendingMeta = null;
      DASH.cloudtrail.open();
      DASH.cloudtrail.render();
    } else if (r.service === "accounts") {
      pendingMeta = null;
      DASH.accounts.render();
    } else if (r.service) {
      pendingMeta = null;
      DASH.resources.open(r.service);
      DASH.resources.render();
    } else {
      pendingMeta = null;
      DASH.overview.render();
    }
    DASH.sidebar.render();
  }

  function openDrill(service, key, meta) {
    if (DASH.registry && DASH.registry.getDrill) {
      var spec = DASH.registry.getDrill(service);
      if (spec) { DASH.drills.framework.open(spec, key, meta || {}); return; }
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
    if (DASH.registry && DASH.registry.get && DASH.registry.get(service)) {
      DASH.drills.framework.openGeneric(service, key, meta || {});
      return;
    }
    var u = DASH.utils, s = DASH.services;
    var el = document.getElementById("main-content");
    if (el) {
      el.innerHTML = '<div class="detail-header">' + u.iconHtml(service, 28) +
        '<h2>' + u.esc(s.label(service)) + ' &middot; ' + u.esc(key) + '</h2>' +
        '<button class="back-link" type="button" data-go-svc="' + u.esc(service) + '">&larr; Back to ' + u.esc(s.label(service)) + '</button></div>' +
        '<div class="empty-state-guidance"><div class="empty-title">No detail view for this resource type</div>' +
        '<div class="hint">The list page shows this resource, but ' + u.esc(s.label(service)) + ' has no per-resource page yet.</div></div>';
    }
  }

  // ── Data ──
  function overviewUrl() {
    return "/_localemu/api/overview?account=" + encodeURIComponent(state.account);
  }
  var overviewInflight = false, overviewQueued = false;
  function refreshOverview(force) {
    if (overviewInflight) { overviewQueued = true; return; }
    overviewInflight = true;
    var cacheKey = "overview:" + state.account;
    if (force) DASH.cache.invalidateKey(cacheKey);
    var acct = state.account;
    DASH.api.get(overviewUrl(), { cacheKey: cacheKey, ttlMs: 60000, tags: ["overview"] }).then(function (r) {
      if (r.value && acct === state.account) {
        var prev = state.overview && state.overview.services;
        state.overview = r.value;
        state.overviewLastFetched = Date.now();
        DASH.overview.onCounts(prev);
        if (!prev || !Object.keys(prev).length) rerenderServicePage();
      }
      renderTopbar();
      DASH.sidebar.render();
    }).catch(function (err) { DASH.utils.showApiError(err, "overview"); })
      .then(function () {
        overviewInflight = false;
        if (overviewQueued) { overviewQueued = false; refreshOverview(true); }
      });
  }
  var scheduleOverview = DASH.utils.debounce(function () { refreshOverview(true); }, 250);

  // A service list page shows counts / Docker state from the overview and
  // system payloads; repaint it when those land, unless the user is typing
  // in its filter box.
  function rerenderServicePage() {
    var r = state.route;
    if (!r.service || r.resource || r.service === "cloudtrail" || r.service === "accounts") return;
    var a = document.activeElement;
    if (a && a.id === "resource-search") return;
    DASH.resources.render();
  }

  function refreshSystem() {
    return DASH.api.fetchJSON("/_localemu/api/system", { etag: false, timeoutMs: 8000 }).then(function (r) {
      var first = !state.system;
      state.system = r.data;
      state.systemFetchedAt = Date.now();
      renderTopbar();
      DASH.overview.onSystem();
      if (first) rerenderServicePage();
    }).catch(function () { /* the live chip reports connectivity */ });
  }

  // ── Top bar ──
  function renderTopbar() {
    var sys = state.system || {};
    var ver = sys.version || (state.overview && state.overview.version) || "";
    var v = document.getElementById("brandVer");
    if (v) v.textContent = ver ? "v" + ver : "";
    var rg = document.getElementById("regionBadge");
    if (rg) rg.textContent = sys.default_region || "us-east-1";
    var hint = document.getElementById("searchHint");
    if (hint && DASH.registry.isReady()) {
      hint.textContent = "Search " + DASH.registry.aws().length + " services, resources, actions";
    }
    var badge = document.getElementById("ctBadge");
    var ct = state.overview && state.overview.services && state.overview.services.cloudtrail;
    if (badge && ct) badge.textContent = DASH.utils.fmtInt(ct.resources);
    var ab = document.getElementById("acctBadge");
    if (ab) ab.textContent = String((state.accounts || []).length || "");
    DASH.accounts.renderButton();
  }

  function setAccount(id) {
    if (!/^\d{12}$/.test(id) || id === state.account) return;
    state.account = id;
    try { localStorage.setItem(ACCOUNT_KEY, id); } catch (_) {}
    DASH.cache.invalidateTag("overview");
    state.overview = { services: {}, totals: null };
    DASH.accounts.renderButton();
    refreshOverview(true);
    renderCurrent(false);
    DASH.wire.onAccountChange();
    var rec = DASH.accounts.find(id);
    DASH.utils.showToast("Switched to " + id + (rec && rec.Name ? " (" + rec.Name + ")" : ""));
  }

  function setLive(status) {
    state.sse.status = status;
    var btn = document.getElementById("liveBtn");
    var txt = document.getElementById("liveText");
    var paused = DASH.wire && DASH.wire.isPaused();
    if (btn) {
      btn.classList.remove("connected", "polling", "offline", "paused");
      btn.classList.add(paused ? "paused" : status);
    }
    if (txt) txt.textContent = paused ? "Paused" : status === "connected" ? "Live" : status === "polling" ? "Polling" : "Offline";
    if (DASH.wire) DASH.wire.onStatus(status);
  }

  // ── Global delegated clicks ──
  function onDocClick(e) {
    var t = e.target;
    if (!t.closest) return;
    var el;
    if ((el = t.closest("[data-copy]"))) { DASH.utils.copyToClipboard(el.getAttribute("data-copy")); return; }
    if ((el = t.closest("[data-route]"))) {
      var r = el.getAttribute("data-route");
      navigate({ service: r === "overview" ? null : r, resource: null });
      return;
    }
    if ((el = t.closest("[data-go-svc]"))) {
      navigate({ service: el.getAttribute("data-go-svc"), resource: el.getAttribute("data-go-res") || null });
      return;
    }
  }

  function init() {
    document.addEventListener("click", onDocClick);
    document.getElementById("brandLink").addEventListener("click", function (e) {
      e.preventDefault();
      navigate({ service: null, resource: null });
    });
    document.getElementById("themeBtn").addEventListener("click", function () { DASH.theme.toggle(); });
    document.getElementById("menuBtn").addEventListener("click", function () {
      if (window.matchMedia && window.matchMedia("(max-width: 780px)").matches) {
        DASH.overlay.open('<div class="scrim" data-close="1" style="z-index:44"></div>');
        document.getElementById("nav").classList.add("open");
      } else {
        DASH.layout.toggleNav();
      }
    });
    document.getElementById("liveBtn").addEventListener("click", function () { DASH.wire.togglePause(); });
    document.getElementById("wireHideBtn").addEventListener("click", function () { DASH.layout.setWireCollapsed(true); });
    document.getElementById("wireShowBtn").addEventListener("click", function () { DASH.layout.setWireCollapsed(false); });
    DASH.layout.syncButtons();

    DASH.bus.onStatus(setLive);
    DASH.bus.subscribe("resource", scheduleOverview);
    DASH.bus.subscribe("count", scheduleOverview);
    DASH.bus.subscribe("dropped", scheduleOverview);
    // Each recorded call is also a CloudTrail event; keep the nav badge
    // current between overview refreshes (which resync the exact count).
    DASH.bus.subscribe("call", function (c) {
      var ct = state.overview && state.overview.services && state.overview.services.cloudtrail;
      if (!c || !ct || c.account_id !== state.account) return;
      ct.resources = (ct.resources || 0) + 1;
      var b = document.getElementById("ctBadge");
      if (b) b.textContent = DASH.utils.fmtInt(ct.resources);
    });
    DASH.bus.start();

    DASH.registry.load().then(function () {
      renderTopbar();
      DASH.sidebar.render();
      if (!state.route.service) DASH.overview.render();
    });
    DASH.sidebar.init();
    DASH.overview.init();
    DASH.resources.init();
    DASH.wire.init();
    DASH.cloudtrail.init();
    DASH.accounts.init();
    DASH.palette.init();
    if (DASH.actions && DASH.actions._modal) DASH.actions._modal.init();
    ["s3", "ddb", "sqs", "logs", "sns", "events", "lambda", "stepfunctions"].forEach(function (k) {
      var d = DASH.drills && DASH.drills[k];
      if (d && d.init) d.init();
    });

    function syncPendingMetaFromRoute() {
      var r = state.route || {};
      var m = {};
      if (r.tab) m.tab = r.tab;
      if (r.sub) m.highlight = r.sub;
      pendingMeta = (Object.keys(m).length ? m : null);
    }
    state.route = parseHash();
    syncPendingMetaFromRoute();
    window.addEventListener("hashchange", function () {
      if (suppressHashRouter) return;
      state.route = parseHash();
      syncPendingMetaFromRoute();
      renderCurrent(true);
    });

    refreshOverview(true);
    refreshSystem();
    DASH.accounts.refresh();
    renderCurrent(true);

    // Backstops: SSE pushes changes between these.
    setInterval(function () { refreshOverview(false); }, 60000);
    setInterval(refreshSystem, 10000);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) { refreshOverview(true); refreshSystem(); }
    });
    window.addEventListener("beforeunload", function () { DASH.bus.stop(); });
  }

  window.DASH.app = {
    state: state,
    navigate: navigate,
    refreshOverview: refreshOverview,
    refreshSystem: refreshSystem,
    setAccount: setAccount,
    renderTopbar: renderTopbar,
    init: init
  };

  document.addEventListener("DOMContentLoaded", init);
})();
