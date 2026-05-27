// Lambda function drill-down: recent invocations + per-invocation
// drill-in + Invoke button + link to /aws/lambda/<name> log group.
//
// Each row in the recent-invocations list is clickable; expanding it
// fetches the full CloudTrail detail (requestParameters /
// responseElements, error fields) so the developer can see the
// payload, the response, and the error code without leaving the page.
(function () {
  "use strict";

  // Cache full per-event payloads keyed by request_id so reopening a
  // row doesn't refetch.
  var detailCache = {};
  var detailLoading = {};
  // request_id of the currently-expanded invocation row, or null.
  var expandedId = null;

  function open(name) {
    expandedId = null;
    var elMain = document.getElementById("main-content");
    elMain.innerHTML = '<div class="loading-state">Loading...</div>';
    refresh(name);
  }

  function refresh(name) {
    var u = DASH.utils;
    Promise.all([
      DASH.api.fetchJSON("/_localemu/api/resources/lambda", { etag: false, timeoutMs: 6000 })
        .catch(function (err) { DASH.utils.showApiError(err, "lambda list"); return { data: { resources: [] } }; }),
      DASH.api.fetchJSON("/_localemu/api/cloudtrail?limit=100&service=lambda", { etag: false, timeoutMs: 6000 })
        .catch(function () { return { data: { events: [] } }; })
    ]).then(function (results) {
      var fns = (results[0].data && results[0].data.resources) || [];
      var ev = (results[1].data && results[1].data.events) || [];
      var fn = fns.find(function (x) { return x.name === name; }) || { name: name };
      var invocations = ev.filter(function (e) {
        var src = (e.eventSource || "").replace(".amazonaws.com", "");
        var hits = src === "lambda" && (e.eventName === "Invoke" || e.eventName === "InvokeAsync");
        if (!hits) return false;
        // CloudTrail's lambda:Invoke requestParameters carries functionName
        // as a full ARN ("arn:aws:lambda:<region>:<acct>:function:<name>")
        // or the bare name. Accept both. Reject Invokes whose functionName
        // is absent -- attributing them to every drill-down would lie.
        var req = e.requestParameters || {};
        var fnName = String(req.functionName || "");
        if (!fnName) return false;
        if (fnName === name) return true;
        // Strip the optional :alias / :version qualifier first.
        var bare = fnName.split(":function:").pop().split(":")[0];
        return bare === name;
      });
      render(name, fn, invocations);
    });
  }

  function render(name, fn, invocations) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");

    var html = '<div class="detail-header">';
    html += u.iconHtml("lambda", 28);
    html += '<h2>' + u.esc(name) + '</h2>';
    html += '<a class="docs-link" href="https://localemu.cloud/docs/lambda" target="_blank">Docs</a>';
    html += '<button class="row-action primary" id="lam-invoke-btn">Invoke</button>';
    html += '<button class="back-link" id="back-lambda-btn">← Back to Lambda</button>';
    html += '</div>';

    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">';
    html += '<div class="empty-state-guidance" style="margin:0">';
    html += '<div class="empty-title">Configuration</div>';
    html += '<pre>Runtime:  ' + u.esc(fn.runtime || "-")
         + '\nHandler:  ' + u.esc(fn.handler || "-")
         + '\nMemory:   ' + u.esc(fn.memory || "-") + ' MB'
         + '\nTimeout:  ' + u.esc(fn.timeout || "-") + ' s'
         + '\nState:    ' + u.esc(fn.state || "-") + '</pre>';
    html += '<div class="hint"><a href="#/logs/' + encodeURIComponent("aws/lambda/" + name) + '">View log group</a> for invocation logs.</div>';
    html += '</div>';

    html += '<div class="empty-state-guidance" style="margin:0">';
    html += '<div class="empty-title">Recent invocations (' + invocations.length + ')</div>';
    if (invocations.length === 0) {
      html += '<pre>No invocations recorded yet. Run:\nawsemu lambda invoke --function-name '
           + u.esc(name) + ' --payload \'{}\' /tmp/r.json</pre>';
    } else {
      html += '<div class="hint">Click any row to see the full request payload and response.</div>';
    }
    html += '</div>';
    html += '</div>';  // grid

    if (invocations.length > 0) {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>Time</th><th>Op</th><th>Status</th><th>Error</th>';
      html += '</tr></thead><tbody>';
      invocations.slice(0, 50).forEach(function (e) {
        var rid = e.requestId || e.requestID || "";
        var ts = u.formatTimestamp(e.eventTime);
        var code = e.responseCode || 0;
        var cls = u.statusClass(code);
        var isOpen = expandedId === rid;
        html += '<tr class="lambda-inv-row clickable-row" data-rid="' + u.esc(rid) + '">';
        html += '<td>' + u.esc(ts) + '</td>';
        html += '<td>' + u.esc(e.eventName || "") + '</td>';
        html += '<td><span class="activity-status ' + cls + '">' + u.esc(code) + '</span></td>';
        html += '<td>' + u.esc(e.errorCode || "") + '</td>';
        html += '</tr>';
        if (isOpen) {
          var body = renderDetail(rid, e);
          html += '<tr><td colspan="4"><pre class="cloudtrail-detail">' + body + '</pre></td></tr>';
        }
      });
      html += '</tbody></table></div>';
    }

    elMain.innerHTML = html;

    var back = document.getElementById("back-lambda-btn");
    if (back) back.addEventListener("click", function () {
      DASH.app.navigate({ service: "lambda", resource: null });
    });
    var inv = document.getElementById("lam-invoke-btn");
    if (inv) inv.addEventListener("click", function () { DASH.actions.lambdaInvoke.open(fn); });

    elMain.querySelectorAll(".lambda-inv-row").forEach(function (row) {
      row.addEventListener("click", function () {
        var rid = row.dataset.rid;
        if (expandedId === rid) {
          expandedId = null;
          refresh(name);
          return;
        }
        expandedId = rid;
        // Single refresh per click. The detail fetch is async and
        // schedules its own re-render when it resolves so the panel
        // doesn't re-fetch the lambda list twice.
        if (rid && !detailCache[rid] && !detailLoading[rid]) {
          detailLoading[rid] = true;
          DASH.api.fetchJSON(
            "/_localemu/api/cloudtrail/" + encodeURIComponent(rid),
            { etag: false, timeoutMs: 6000 }
          ).then(function (resp) {
            detailLoading[rid] = false;
            if (resp && resp.data) detailCache[rid] = resp.data;
            if (expandedId === rid) refresh(name);
          }).catch(function (err) {
            detailLoading[rid] = false;
            DASH.utils.showApiError(err, "lambda invocation detail");
            if (expandedId === rid) refresh(name);
          });
        } else {
          refresh(name);
        }
      });
    });
  }

  function renderDetail(rid, summary) {
    var u = DASH.utils;
    var envelope = detailCache[rid];
    if (envelope) {
      // ``/_localemu/api/cloudtrail/<rid>`` returns the AWS LookupEvents
      // envelope; requestParameters / responseElements live inside
      // ``CloudTrailEvent`` as a JSON string. Reuse the shared parser.
      var parsed = (DASH.cloudtrail && DASH.cloudtrail.parse && DASH.cloudtrail.parse(envelope)) || envelope;
      var head = "";
      if (parsed.errorCode || parsed.errorMessage) {
        head += "Error: " + (parsed.errorCode || "") + "\n"
             + (parsed.errorMessage ? "  " + parsed.errorMessage + "\n" : "")
             + "\n";
      }
      var req = parsed.requestParameters;
      var res = parsed.responseElements;
      if (req) head += "Request payload:\n" + safeJson(req) + "\n\n";
      if (res) head += "Response:\n" + safeJson(res) + "\n\n";
      head += "Full event:\n" + safeJson(parsed);
      return u.esc(head);
    }
    if (detailLoading[rid]) return "loading full request / response body...";
    return u.esc(safeJson(summary));
  }

  function safeJson(obj) {
    try { return JSON.stringify(obj, null, 2); }
    catch (e) { return "[unserializable]"; }
  }

  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.lambda = { open: open, init: init };
})();
