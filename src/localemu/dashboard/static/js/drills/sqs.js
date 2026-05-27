// SQS queue drill-down: non-destructive message peek + send button.
(function () {
  "use strict";
  function open(queue) {
    var url = "/_localemu/api/resources/sqs/" + encodeURIComponent(queue);
    DASH.api.get(url, { cacheKey: "sqs:" + queue, ttlMs: 8000 }).then(function (r) {
      render(queue, (r.value && r.value.messages) || []);
    }).catch(function (err) {
      DASH.utils.showApiError(err, "sqs messages");
      render(queue, []);
    });
  }
  function render(queue, messages) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("sqs", 28);
    html += '<h2>' + u.esc(queue) + ' — message peek</h2>';
    html += '<button class="row-action primary" id="sqs-send-btn">Send</button>';
    html += '<button class="refresh-btn" id="sqs-refresh-btn">Refresh</button>';
    html += '<button class="back-link" id="back-sqs-btn">← Back to SQS</button>';
    html += '</div>';
    if (!messages || messages.length === 0) {
      html += '<div class="empty-state">Queue is empty (or every message is currently in flight).</div>';
    } else {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>MessageId</th><th>Body</th><th>Attributes</th>';
      html += '</tr></thead><tbody>';
      messages.forEach(function (m) {
        html += '<tr>';
        html += '<td>' + u.esc(m.message_id || "-") + '</td>';
        html += '<td><pre style="margin:0;font-family:inherit;font-size:12px;white-space:pre-wrap;max-width:520px">' + u.esc(m.body || "") + '</pre></td>';
        html += '<td><pre style="margin:0;font-family:inherit;font-size:11px;color:var(--base01);white-space:pre-wrap">' + u.esc(JSON.stringify(m.attributes || {}, null, 2)) + '</pre></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "sqs:" + queue + ":" + (messages ? messages.length : 0);
    var back = document.getElementById("back-sqs-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "sqs", resource: null }); });
    var refresh = document.getElementById("sqs-refresh-btn");
    if (refresh) refresh.addEventListener("click", function () {
      DASH.cache.invalidateKey("sqs:" + queue);
      open(queue);
    });
    var sendBtn = document.getElementById("sqs-send-btn");
    if (sendBtn) sendBtn.addEventListener("click", function () { DASH.actions.sqsSend.open({ name: queue }); });
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.sqs = { open: open, init: init };
})();
