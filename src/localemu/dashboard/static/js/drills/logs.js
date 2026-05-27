// CloudWatch Logs drill-down: log events for a single group.
(function () {
  "use strict";
  function open(group) {
    var clean = group.charAt(0) === "/" ? group.substring(1) : group;
    // Display form is canonical AWS: log groups start with "/".
    var displayGroup = "/" + clean;
    var url = "/_localemu/api/resources/logs/" + clean.split("/").map(encodeURIComponent).join("/");
    DASH.api.get(url, { cacheKey: "logs:" + displayGroup, ttlMs: 10000 }).then(function (r) {
      render(displayGroup, (r.value && r.value.events) || []);
    }).catch(function () { render(displayGroup, []); });
  }
  function render(group, events) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("logs", 28);
    html += '<h2>' + u.esc(group) + '</h2>';
    html += '<button class="back-link" id="back-logs-btn">← Back to Log Groups</button>';
    html += '</div>';
    if (!events || events.length === 0) {
      html += '<div class="empty-state">No log events yet.</div>';
    } else {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>Timestamp</th><th>Stream</th><th>Message</th>';
      html += '</tr></thead><tbody>';
      events.forEach(function (e) {
        var ts = e.timestamp ? u.formatTimestamp(e.timestamp) : "-";
        html += '<tr>';
        html += '<td>' + u.esc(ts) + '</td>';
        html += '<td>' + u.esc(e.stream || "") + '</td>';
        html += '<td><pre style="margin:0;font-family:inherit;font-size:12px;white-space:pre-wrap;max-width:720px">' + u.esc(e.message || "") + '</pre></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "logs:" + group + ":" + (events ? events.length : 0);
    var back = document.getElementById("back-logs-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "logs", resource: null }); });
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.logs = { open: open, init: init };
})();
