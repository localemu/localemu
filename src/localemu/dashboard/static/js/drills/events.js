// EventBridge bus drill-down: rules + targets.
(function () {
  "use strict";

  // The drill-down takes a BUS name. Optional second arg is the name of
  // a specific RULE the user clicked from the list page; we use it to
  // scroll-into-view and highlight that row.
  //
  // Defensive: if `bus` is falsy (e.g. older callers passed a rule name
  // through here) fall back to "default" so the user does not see a
  // 400 error on the underlying ListRules call.
  function open(bus, highlightRule) {
    var busName = bus || "default";
    var url = "/_localemu/api/resources/events/" + encodeURIComponent(busName) + "/rules";
    DASH.api.get(url, { cacheKey: "events:" + busName, ttlMs: 15000 }).then(function (r) {
      render(busName, (r.value && r.value.rules) || [], highlightRule);
    }).catch(function () { render(busName, [], highlightRule); });
  }

  function cssEsc(s) {
    if (window.CSS && CSS.escape) return CSS.escape(String(s));
    return String(s).replace(/"/g, "\\\"");
  }

  function render(bus, rules, highlightRule) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("events", 28);
    html += '<h2>' + u.esc(bus) + ' — rules</h2>';
    html += '<button class="row-action primary" id="evb-put-btn">Put event</button>';
    html += '<button class="back-link" id="back-events-btn">← Back to EventBridge</button>';
    html += '</div>';
    if (!rules || rules.length === 0) {
      html += '<div class="empty-state">No rules on this bus.</div>';
    } else {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>Name</th><th>State</th><th>Schedule</th><th>Pattern</th><th>Targets</th>';
      html += '</tr></thead><tbody>';
      rules.forEach(function (r) {
        var isHi = highlightRule && r.name === highlightRule;
        html += '<tr class="eb-rule-row' + (isHi ? ' row-highlighted' : '') + '" data-rule-name="' + u.esc(r.name || "") + '">';
        html += '<td>' + u.esc(r.name || "-") + '</td>';
        html += '<td>' + u.esc(r.state || "-") + '</td>';
        html += '<td>' + u.esc(r.schedule_expression || "-") + '</td>';
        html += '<td><pre style="margin:0;font-family:inherit;font-size:11px;white-space:pre-wrap;max-width:340px;color:var(--base01)">' + u.esc(r.event_pattern || "") + '</pre></td>';
        html += '<td><pre style="margin:0;font-family:inherit;font-size:11px;white-space:pre-wrap;max-width:260px">' + u.esc(JSON.stringify(r.targets || [], null, 1)) + '</pre></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "events:" + bus + ":" + (rules ? rules.length : 0);
    var back = document.getElementById("back-events-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "events", resource: null }); });
    var put = document.getElementById("evb-put-btn");
    if (put) put.addEventListener("click", function () { DASH.actions.eventsPut.open({ bus: bus, name: bus }); });

    if (highlightRule) {
      setTimeout(function () {
        var row = elMain.querySelector('.eb-rule-row[data-rule-name="' + cssEsc(highlightRule) + '"]');
        if (row && row.scrollIntoView) row.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 50);
    }
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.events = { open: open, init: init };
})();
