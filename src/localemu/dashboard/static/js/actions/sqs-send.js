// SQS Send Message modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    var queue = row.name || "";
    M.open(
      '<h2>Send to SQS: ' + u.esc(queue) + '</h2>' +
      '<div class="subtitle">Calls <code>SendMessage</code> via the local gateway.</div>' +
      '<label>Message body</label><textarea id="sqs-body">{"hello":"world"}</textarea>' +
      '<div class="row">' +
        '<div><label>Delay (s)</label><input id="sqs-delay" type="number" min="0" max="900" value="0"></div>' +
        '<div><label>MessageGroupId (FIFO)</label><input id="sqs-group" type="text" placeholder="(optional)"></div>' +
      '</div>' +
      '<div class="action-modal-error" id="sqs-err"></div>' +
      '<div id="sqs-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="sqs-close">Close</button>' +
        '<button type="button" class="primary" id="sqs-send">Send</button>' +
      '</div>'
    );
    document.getElementById("sqs-close").addEventListener("click", M.close);
    document.getElementById("sqs-send").addEventListener("click", function (e) {
      var body = {
        queue_name: queue,
        body: document.getElementById("sqs-body").value,
        delay_seconds: Number(document.getElementById("sqs-delay").value || 0)
      };
      var g = (document.getElementById("sqs-group").value || "").trim();
      if (g) body.message_group_id = g;
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/sqs/send-message", body, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("sqs-result").innerHTML = M.renderResult(r);
        M.invalidate(["resources:sqs", "sqs:" + queue]);
        M.showToast("Message sent", "ok");
      }).catch(function (ex) {
        document.getElementById("sqs-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }
  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.sqsSend = { open: open };
})();
