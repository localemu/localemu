// Client-side dashboard service registry.
//
// Fetches /_localemu/api/registry once at boot, exposes
// DASH.registry.get(name), DASH.registry.all(), DASH.registry.byTier(),
// DASH.registry.label(name), DASH.registry.tier(name), and seeds the
// legacy DASH.services maps for backwards compatibility while the
// migration to the registry pattern lands per service.
//
// Honesty tier:
//   live           -- a real engine emulates behaviour
//   metadata       -- moto stores Create/Get state but no real behaviour
//   not_emulated   -- stub services with canned responses
//
// Per-service drills register via DASH.registry.registerDrill(name, drillSpec).
// Per-service actions register via DASH.registry.registerAction(spec).
(function () {
  "use strict";

  var SERVICES = {};        // name -> spec from /api/registry
  var DRILLS = {};          // name -> drill descriptor
  var ACTIONS = {};         // id -> action descriptor
  var READY_PROMISE = null;
  var READY = false;

  function load() {
    if (READY_PROMISE) return READY_PROMISE;
    READY_PROMISE = DASH.api.fetchJSON("/_localemu/api/registry",
                                      { etag: false, timeoutMs: 8000 })
      .then(function (resp) {
        var data = (resp && resp.data) || {};
        (data.services || []).forEach(function (s) { SERVICES[s.name] = s; });
        READY = true;
        return SERVICES;
      })
      .catch(function (err) {
        if (DASH.utils && DASH.utils.showApiError) {
          DASH.utils.showApiError(err, "service registry");
        }
        READY = true;
        return SERVICES;
      });
    return READY_PROMISE;
  }

  function get(name) { return SERVICES[name] || null; }
  function all() {
    return Object.keys(SERVICES).map(function (k) { return SERVICES[k]; });
  }
  function byTier(tier) {
    return all().filter(function (s) { return s.tier === tier; });
  }
  function isReady() { return READY; }

  function label(name) {
    var s = get(name);
    if (s && s.label) return s.label;
    // Fall back to services.js if the legacy map has it.
    if (DASH.services && DASH.services.label) return DASH.services.label(name);
    return name;
  }
  function tier(name) {
    var s = get(name);
    return (s && s.tier) || "metadata";
  }
  function banner(name) {
    var s = get(name);
    if (s && s.banner) return s.banner;
    // Default banners per tier so every service is honest about what
    // it does and doesn't emulate. Live services with no specific
    // banner show nothing (the green badge already says "Live").
    if (s && s.tier === "metadata") {
      return "Metadata only: Create/Get state persists, but no real behaviour is emulated. Use this page to inspect what your code created; do not expect AWS-grade runtime semantics.";
    }
    if (s && s.tier === "not_emulated") {
      return "Not emulated: list endpoints return empty arrays and mutating endpoints return canned responses. This page is here so the sidebar count stays consistent.";
    }
    return "";
  }
  function columns(name) {
    var s = get(name);
    if (s && s.columns && s.columns.length) return s.columns;
    if (DASH.services && DASH.services.columns) return DASH.services.columns(name);
    return ["Name", "Region"];
  }

  // Build a copy-command snippet for a row, when the registry provides a
  // template like "awsemu lambda get-function --function-name {name}".
  function copyCmd(name, row) {
    var s = get(name);
    if (!s || !s.copy_cmd_template) {
      if (DASH.services && DASH.services.copyCommand) return DASH.services.copyCommand(name, row);
      return null;
    }
    return s.copy_cmd_template.replace(/\{(\w+)\}/g, function (_, key) {
      var v = (row && row[key]);
      if (v === undefined || v === null) return "";
      return String(v);
    });
  }

  function emptyStateText(name) {
    var s = get(name);
    if (s && s.empty_state) return s.empty_state;
    if (DASH.services && DASH.services.emptyStateText) return DASH.services.emptyStateText(name);
    return "";
  }

  function registerDrill(name, drillSpec) { DRILLS[name] = drillSpec; }
  function getDrill(name) { return DRILLS[name] || null; }

  function registerAction(spec) { ACTIONS[spec.id] = spec; }
  function getAction(id) { return ACTIONS[id] || null; }
  function actionsForService(name) {
    var out = [];
    Object.keys(ACTIONS).forEach(function (id) {
      var a = ACTIONS[id];
      if (a.service === name) out.push(a);
    });
    return out;
  }

  // Pretty tier badge: shown in drill page headers.
  function tierBadge(name) {
    var t = tier(name);
    if (t === "live")          return { label: "Live",            cls: "tier-live" };
    if (t === "not_emulated")  return { label: "Not emulated",    cls: "tier-stub" };
    return { label: "Metadata only", cls: "tier-meta" };
  }

  window.DASH.registry = {
    load: load,
    isReady: isReady,
    get: get, all: all, byTier: byTier,
    label: label, tier: tier, banner: banner, columns: columns,
    copyCmd: copyCmd, emptyStateText: emptyStateText,
    tierBadge: tierBadge,
    registerDrill: registerDrill, getDrill: getDrill,
    registerAction: registerAction, getAction: getAction,
    actionsForService: actionsForService
  };
})();
