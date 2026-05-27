// Overview panel: grid of service cards. Renders when route.service
// is null. Clicking a card navigates to the service detail view.
(function () {
  "use strict";

  function render() {
    var state = DASH.app.state;
    if (state.route.service) return; // not on overview
    var u = DASH.utils, s = DASH.services;
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    var services = (state.overview && state.overview.services) || {};

    var cards = [];
    Object.keys(services).sort().forEach(function (name) {
      var info = services[name] || { status: "available", resources: 0 };
      var count = info.resources || 0;
      // Same rule as the sidebar: 21 curated anchors + anything with
      // at least one resource.
      if (!s.alwaysShow(name) && count === 0) return;
      cards.push({ name: name, count: count, status: info.status || "available" });
    });

    var key = "overview:" + cards.map(function (c) { return c.name + ":" + c.count + ":" + c.status; }).join(",");
    var html = '<div class="overview-grid">';
    cards.forEach(function (c) {
      var statusCls = c.status === "running" ? "running" : "available";
      html += '<div class="overview-card" data-service="' + u.esc(c.name) + '" role="button" tabindex="0">';
      html += u.iconHtml(c.name, 28);
      html += '<div class="overview-card-body">';
      html += '<div class="overview-card-name"><span class="status-dot ' + statusCls + '"></span>' + u.esc(s.label(c.name)) + '</div>';
      html += '<div class="overview-card-count">' + u.esc(c.count) + '</div>';
      html += '<div class="overview-card-label">resource' + (c.count === 1 ? '' : 's') + '</div>';
      html += '</div></div>';
    });
    html += '</div>';
    DASH.render.renderInto(elMain, key, html);
  }

  function init() {
    var elMain = document.getElementById("main-content");
    elMain.addEventListener("click", function (e) {
      var card = e.target.closest(".overview-card");
      if (card) {
        DASH.app.navigate({ service: card.dataset.service, resource: null });
      }
    });
    elMain.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var card = e.target.closest(".overview-card");
      if (card) {
        e.preventDefault();
        DASH.app.navigate({ service: card.dataset.service, resource: null });
      }
    });
  }

  window.DASH.overview = { init: init, render: render };
})();
