// Lambda Invoke modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    var name = row.name || "";
    M.open(
      '<h2>Invoke Lambda: ' + u.esc(name) + '</h2>' +
      '<div class="subtitle">Calls <code>Invoke</code> via the local gateway. Response payload + tail logs appear below.</div>' +
      '<div class="row">' +
        '<div><label>Invocation type</label><select id="lam-type"><option value="RequestResponse">RequestResponse</option><option value="Event">Event (async)</option><option value="DryRun">DryRun</option></select></div>' +
        '<div><label>Qualifier</label><input id="lam-qual" type="text" value="$LATEST"></div>' +
      '</div>' +
      '<label>Payload (JSON)</label><textarea id="lam-payload">{}</textarea>' +
      '<div class="action-modal-error" id="lam-err"></div>' +
      '<div id="lam-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="lam-close">Close</button>' +
        '<button type="button" class="primary" id="lam-invoke">Invoke</button>' +
      '</div>'
    );

    document.getElementById("lam-close").addEventListener("click", M.close);
    document.getElementById("lam-invoke").addEventListener("click", function (e) {
      var err = document.getElementById("lam-err"); err.textContent = "";
      var raw = (document.getElementById("lam-payload").value || "{}").trim();
      var payload; try { payload = JSON.parse(raw); }
      catch (ex) { err.textContent = "Payload is not valid JSON: " + ex.message; return; }
      var body = {
        function_name: name,
        invocation_type: document.getElementById("lam-type").value,
        qualifier: document.getElementById("lam-qual").value || "$LATEST",
        payload: payload
      };
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/lambda/invoke", body, { timeoutMs: 60000 }).then(function (r) {
        document.getElementById("lam-result").innerHTML = renderResultWithLogs(r);
        // Logs and CloudTrail learn about the invocation. Invalidate
        // both so the drill-down + activity feed see the new event
        // without the user manually pressing Refresh.
        M.invalidate(["resources:lambda", "resources:logs", "logs:/aws/lambda/" + name]);
        M.showToast("Lambda invoked", "ok");
      }).catch(function (ex) {
        document.getElementById("lam-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }

  // Pull `log_tail` and `response` out of the result envelope and
  // render each in its own <pre> so newlines render correctly. The
  // generic JSON-stringify renderer would escape \n inside log_tail
  // and hide the lines from the user.
  function renderResultWithLogs(r) {
    var u = DASH.utils;
    var result = (r && r.data && r.data.result) || (r && r.data) || r;
    var html = '<div class="action-modal-result"><div class="ok-line">OK</div>';
    if (result && typeof result === "object" && "log_tail" in result) {
      var tail = result.log_tail;
      var resp = result.response;
      var rest = {};
      Object.keys(result).forEach(function (k) {
        if (k !== "log_tail" && k !== "response") rest[k] = result[k];
      });
      if (resp !== undefined && resp !== null) {
        html += '<div class="result-section">Response</div>';
        html += '<pre>' + u.esc(typeof resp === "string" ? resp : JSON.stringify(resp, null, 2)) + '</pre>';
      }
      if (tail) {
        html += '<div class="result-section">Log tail</div>';
        html += '<pre>' + u.esc(String(tail)) + '</pre>';
      }
      html += '<div class="result-section">Envelope</div>';
      html += '<pre>' + u.esc(JSON.stringify(rest, null, 2)) + '</pre>';
    } else {
      html += '<pre>' + u.esc(JSON.stringify(result, null, 2)) + '</pre>';
    }
    html += '</div>';
    return html;
  }

  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.lambdaInvoke = { open: open };
})();
