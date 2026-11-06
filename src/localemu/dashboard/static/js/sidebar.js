// Service catalog + left navigation.
//
// DASH.catalog joins the three real sources every service view needs:
//   - the service registry (/_localemu/api/registry, 132 services: label,
//     group, tier),
//   - the per-account counts (/_localemu/api/overview?account=),
//   - per-service call volume from request telemetry
//     (/_localemu/api/metrics/services, polled by overview.js),
// plus which services can run Docker containers (/_localemu/api/system).
//
// The nav shows the pinned anchors and anything in use; typing in the
// filter matches across every registered service.
(function () {
  "use strict";

  // ── catalog ──
  var activity = {};   // service -> [calls per minute, oldest first]

  function services() {
    var reg = DASH.registry.all();
    if (reg.length) return reg.map(function (s) { return s.name; });
    // Registry not loaded yet: fall back to what the overview reported.
    var ov = (DASH.app.state.overview && DASH.app.state.overview.services) || {};
    return Object.keys(ov).filter(function (n) { return n !== "accounts"; });
  }
  function label(name) { return DASH.registry.label(name); }
  function group(name) {
    var spec = DASH.registry.get(name);
    return (spec && spec.group) || DASH.services.group(name) || "other";
  }
  function info(name) {
    var ov = (DASH.app.state.overview && DASH.app.state.overview.services) || {};
    return ov[name] || null;
  }
  function count(name) { var i = info(name); return i ? (i.resources || 0) : 0; }
  function counted(name) { var i = info(name); return !!(i && i.counted); }
  function calls(name) { return activity[name] || null; }
  function recentCalls(name) {
    var a = activity[name];
    if (!a) return 0;
    return a.reduce(function (x, y) { return x + y; }, 0);
  }
  // Calls in the last 5 one-minute buckets (the current one is partial).
  function calls5m(name) {
    var a = activity[name];
    if (!a || !a.length) return 0;
    return a.slice(-5).reduce(function (x, y) { return x + y; }, 0);
  }
  function pinned(name) { return DASH.services.alwaysShow(name) && name !== "accounts"; }
  function inUse(name) { return count(name) > 0 || recentCalls(name) > 0; }
  function dockerBackends() {
    var sys = DASH.app.state.system;
    return (sys && sys.docker_backends) || {};
  }
  function isDockerBacked(name) { return !!dockerBackends()[name]; }
  function containers(name) {
    var sys = DASH.app.state.system;
    var by = sys && sys.docker && sys.docker.containers && sys.docker.containers.by_service;
    return (by && by[name]) || null;
  }
  function setActivity(map) { activity = map || {}; }

  window.DASH.catalog = {
    services: services, label: label, group: group, info: info, count: count,
    counted: counted, calls: calls, calls5m: calls5m, recentCalls: recentCalls,
    pinned: pinned, inUse: inUse, isDockerBacked: isDockerBacked, containers: containers,
    dockerBackends: dockerBackends, setActivity: setActivity
  };

  // ── nav ──
  var CLOSED_KEY = "localemu-console-closed-groups";
  var closed = { devtools: 1, media: 1, iot: 1, migration: 1, billing: 1 };
  try {
    var raw = localStorage.getItem(CLOSED_KEY);
    if (raw) closed = JSON.parse(raw) || closed;
  } catch (_) {}
  function persist() { try { localStorage.setItem(CLOSED_KEY, JSON.stringify(closed)); } catch (_) {} }

  var filter = "";
  var lastCounts = {};

  function render() {
    var u = DASH.utils, c = DASH.catalog;
    var box = document.getElementById("navGroups");
    if (!box) return;
    var q = filter.trim().toLowerCase();
    var sel = DASH.app.state.route.service;
    var byGroup = {};
    services().forEach(function (name) {
      if (q) {
        if (label(name).toLowerCase().indexOf(q) === -1 && name.indexOf(q) === -1) return;
      } else if (!pinned(name) && !inUse(name)) {
        return;
      }
      var g = group(name);
      (byGroup[g] = byGroup[g] || []).push(name);
    });

    var html = "";
    DASH.services.GROUPS.forEach(function (g) {
      var items = byGroup[g.id];
      if (!items || !items.length) return;
      items.sort(function (a, b) { return label(a).localeCompare(label(b)); });
      var used = items.filter(inUse).length;
      var isClosed = !q && closed[g.id];
      html += '<div class="group' + (isClosed ? " closed" : "") + '"><button class="group-head" type="button" data-group="' +
        u.esc(g.id) + '" aria-expanded="' + (!isClosed) + '">' + u.ICON.chev + u.esc(g.label) +
        '<span class="gcount">' + used + "/" + items.length + "</span></button><div class=\"group-items\">";
      items.forEach(function (name) {
        var n = count(name), isCounted = counted(name);
        var running = c.containers(name);
        var flash = lastCounts[name] !== undefined && n > lastCounts[name];
        html += '<button class="svc-link' + (inUse(name) ? "" : " idle") + (sel === name ? " on" : "") +
          '" type="button" data-go-svc="' + u.esc(name) + '">' + u.tile(name, "sm") +
          '<span class="lbl">' + (q ? u.highlight(label(name), q) : u.esc(label(name))) + "</span>" +
          (running && running.running ? '<span class="box-dot" title="' + running.running + ' Docker container(s) running"></span>' : "") +
          '<span class="badge num' + (n ? "" : " zero") + (flash ? " flash" : "") + '" title="' +
          (isCounted ? n + " resources" : "resource count not available for this service") + '">' +
          (isCounted ? n : "&ndash;") + "</span></button>";
      });
      html += "</div></div>";
    });
    services().forEach(function (n) { lastCounts[n] = count(n); });
    box.innerHTML = html || '<div class="nav-hint">No service matches "' + u.esc(q) + '". ' +
      DASH.registry.aws().length + " services are registered.</div>";
    var hint = document.getElementById("navHint");
    if (hint) hint.textContent = q ? "Matching across all " + DASH.registry.aws().length + " services" :
      "Pinned and in-use services. Type to find the rest.";
    document.querySelectorAll(".nav-link").forEach(function (b) {
      var r = b.getAttribute("data-route");
      b.classList.toggle("on", (r === "overview" && !sel) || r === sel);
    });
  }

  var pending = false;
  function schedule() {
    if (pending) return;
    pending = true;
    (window.requestAnimationFrame || setTimeout)(function () { pending = false; render(); });
  }

  function init() {
    var box = document.getElementById("navGroups");
    box.addEventListener("click", function (e) {
      var h = e.target.closest(".group-head");
      if (!h) return;
      var g = h.getAttribute("data-group");
      if (closed[g]) delete closed[g]; else closed[g] = 1;
      persist();
      render();
    });
    var f = document.getElementById("navFilter");
    f.addEventListener("input", DASH.utils.debounce(function () { filter = f.value; render(); }, 80));
    f.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        var first = document.querySelector("#navGroups .svc-link");
        if (first) first.click();
      }
    });
  }

  window.DASH.sidebar = { init: init, render: render, schedule: schedule };
})();
