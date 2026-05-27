// DynamoDB table drill-down: item list.
(function () {
  "use strict";
  function open(table) {
    var url = "/_localemu/api/resources/dynamodb/" + encodeURIComponent(table);
    DASH.api.get(url, { cacheKey: "ddb:" + table, ttlMs: 15000 }).then(function (r) {
      render(table, (r.value && r.value.items) || []);
    }).catch(function (err) {
      DASH.utils.showApiError(err, "dynamodb items");
      render(table, []);
    });
  }
  function render(table, items) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("dynamodb", 28);
    html += '<h2>' + u.esc(table) + '</h2>';
    html += '<button class="back-link" id="back-ddb-btn">← Back to DynamoDB tables</button>';
    html += '</div>';
    if (!items || items.length === 0) {
      html += '<div class="empty-state">No items in this table.</div>';
    } else {
      var cols = {};
      items.forEach(function (it) { Object.keys(it).forEach(function (k) { cols[k] = true; }); });
      var columns = Object.keys(cols);
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      columns.forEach(function (c) { html += '<th>' + u.esc(c) + '</th>'; });
      html += '</tr></thead><tbody>';
      items.forEach(function (it) {
        html += '<tr>';
        columns.forEach(function (c) {
          var v = it[c];
          if (v !== undefined && v !== null && typeof v === "object") v = JSON.stringify(v);
          html += '<td>' + u.esc(v == null ? "-" : v) + '</td>';
        });
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "ddb:" + table + ":" + (items ? items.length : 0);
    var back = document.getElementById("back-ddb-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "dynamodb", resource: null }); });
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.ddb = { open: open, init: init };
})();
