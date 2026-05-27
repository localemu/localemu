// SNS topic drill-down: subscriptions + Publish button.
(function () {
  "use strict";
  function open(topic) {
    var url = "/_localemu/api/resources/sns/" + encodeURIComponent(topic) + "/subscriptions";
    DASH.api.get(url, { cacheKey: "sns:" + topic, ttlMs: 15000 }).then(function (r) {
      render(topic, (r.value && r.value.subscriptions) || []);
    }).catch(function () { render(topic, []); });
  }
  function render(topic, subs) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("sns", 28);
    html += '<h2>' + u.esc(topic) + ' — subscriptions</h2>';
    html += '<button class="row-action primary" id="sns-publish-btn">Publish</button>';
    html += '<button class="back-link" id="back-sns-btn">← Back to SNS</button>';
    html += '</div>';
    if (!subs || subs.length === 0) {
      html += '<div class="empty-state">No subscriptions on this topic.</div>';
    } else {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>Protocol</th><th>Endpoint</th><th>Subscription ARN</th><th>Filter Policy</th>';
      html += '</tr></thead><tbody>';
      subs.forEach(function (s) {
        html += '<tr>';
        html += '<td>' + u.esc(s.protocol || "-") + '</td>';
        html += '<td>' + u.esc(s.endpoint || "-") + '</td>';
        html += '<td>' + u.esc((s.subscription_arn || "").slice(-40)) + '</td>';
        html += '<td>' + u.esc(s.filter_policy || "-") + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "sns:" + topic + ":" + (subs ? subs.length : 0);
    var back = document.getElementById("back-sns-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "sns", resource: null }); });
    var pub = document.getElementById("sns-publish-btn");
    if (pub) pub.addEventListener("click", function () { DASH.actions.snsPublish.open({ name: topic }); });
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.sns = { open: open, init: init };
})();
