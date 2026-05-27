// Sidebar: discovers all services from overview, groups them, renders
// collapsible categories. Hooks into SSE `count` and `resource` events
// to update badge counts without re-fetching overview.
(function () {
  "use strict";

  var collapsed = {};
  try {
    var raw = localStorage.getItem("localemu-collapsed-groups");
    if (raw) collapsed = JSON.parse(raw) || {};
  } catch (_) { collapsed = {}; }
  function persistCollapsed() {
    try { localStorage.setItem("localemu-collapsed-groups", JSON.stringify(collapsed)); } catch (_) {}
  }

  var search = "";
  function setSearch(v) {
    search = String(v || "");
    render();
  }

  function render() {
    var state = DASH.app.state;
    var services = (state.overview && state.overview.services) || {};
    var u = DASH.utils, s = DASH.services;
    var elList = document.getElementById("sidebar-list");
    if (!elList) return;

    var filter = search.toLowerCase();

    // Bucket services by group.
    var byGroup = {};
    Object.keys(services).forEach(function (name) {
      var info = services[name] || { status: "available", resources: 0 };
      var count = info.resources || 0;
      // Visibility rule: the curated 21 anchors are always shown so
      // first-time users land on a populated sidebar. Anything else
      // appears as soon as it has at least one resource.
      var visible = s.alwaysShow(name) || count > 0;
      if (!visible) return;
      if (filter) {
        var lbl = s.label(name).toLowerCase();
        if (lbl.indexOf(filter) === -1 && name.indexOf(filter) === -1) return;
      }
      var gid = s.group(name);
      if (!byGroup[gid]) byGroup[gid] = [];
      byGroup[gid].push({ name: name, count: count, status: info.status });
    });

    var key = JSON.stringify({
      sel: state.route.service,
      groups: Object.keys(byGroup).sort().map(function (g) {
        return g + ":" + byGroup[g].map(function (e) { return e.name + ":" + e.count; }).join(",");
      }),
      collapsed: collapsed,
      filter: filter
    });

    var html = "";
    s.GROUPS.forEach(function (g) {
      var items = (byGroup[g.id] || []).sort(function (a, b) { return a.name.localeCompare(b.name); });
      if (items.length === 0) return;
      var isClosed = !!collapsed[g.id];
      html += '<div class="sidebar-group' + (isClosed ? " collapsed" : "") + '">';
      html += '<button class="sidebar-group-header" type="button" data-group="' + u.esc(g.id) + '">';
      html += '<span>' + u.esc(g.label) + '</span>';
      html += '<span class="sidebar-group-caret">▾</span></button>';
      html += '<div class="sidebar-group-body">';
      items.forEach(function (svc) {
        var sel = state.route.service === svc.name ? " selected" : "";
        var labelHtml = filter ? u.highlight(s.label(svc.name), filter) : u.esc(s.label(svc.name));
        var countCls = svc.count > 0 ? "" : " zero";
        html += '<div class="service-item' + sel + '" data-service="' + u.esc(svc.name) + '" role="button" tabindex="0">';
        html += u.iconHtml(svc.name, 22);
        html += '<span class="service-name">' + labelHtml + '</span>';
        html += '<span class="count-badge' + countCls + '">' + u.esc(svc.count) + '</span>';
        html += '</div>';
      });
      html += '</div></div>';
    });

    DASH.render.renderInto(elList, key, html);
  }

  function init() {
    var elList = document.getElementById("sidebar-list");
    var elSearch = document.getElementById("sidebar-search");

    elList.addEventListener("click", function (e) {
      var hdr = e.target.closest(".sidebar-group-header");
      if (hdr) {
        var g = hdr.dataset.group;
        collapsed[g] = !collapsed[g];
        persistCollapsed();
        render();
        return;
      }
      var item = e.target.closest(".service-item");
      if (item) {
        DASH.app.navigate({ service: item.dataset.service, resource: null });
      }
    });
    elList.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var item = e.target.closest(".service-item");
      if (item) {
        e.preventDefault();
        DASH.app.navigate({ service: item.dataset.service, resource: null });
      }
    });

    if (elSearch) {
      elSearch.addEventListener("input", DASH.utils.debounce(function () {
        setSearch(elSearch.value);
      }, 120));
    }

    // Listen for SSE count updates so badges refresh without polling.
    // Debounced via rAF: count + resource events can fire several
    // times per second under load (every mutating AWS call publishes
    // a resource event), and each render() JSON-serialises the whole
    // sidebar state for cache-key comparison.
    var pendingRender = false;
    function scheduleRender() {
      if (pendingRender) return;
      pendingRender = true;
      var fire = function () { pendingRender = false; render(); };
      if (typeof requestAnimationFrame === "function") requestAnimationFrame(fire);
      else setTimeout(fire, 16);
    }
    DASH.bus.subscribe("count", scheduleRender);
    DASH.bus.subscribe("resource", scheduleRender);
  }

  window.DASH.sidebar = {
    init: init,
    render: render,
    setSearch: setSearch
  };
})();
