// SNS Publish modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    var name = row.name || "";
    // Prefer the row's real ARN -- the backend list returns it. Using
    // the topic name forces actions.py to synthesize an ARN from the
    // default region/account, which silently breaks for cross-region
    // topics.
    var arn = row.arn || "";
    M.open(
      '<h2>Publish to SNS: ' + u.esc(name) + '</h2>' +
      '<div class="subtitle">Calls <code>Publish</code> via the local gateway.</div>' +
      '<label>Topic ARN</label><input id="sns-arn" type="text" value="' + u.esc(arn) + '" placeholder="(leave blank to use default region)">' +
      '<label>Subject</label><input id="sns-subject" type="text" placeholder="(optional)">' +
      '<label>Message</label><textarea id="sns-msg">Hello from the LocalEmu dashboard.</textarea>' +
      '<label>MessageGroupId (FIFO only)</label><input id="sns-group" type="text" placeholder="(optional)">' +
      '<div class="action-modal-error" id="sns-err"></div>' +
      '<div id="sns-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="sns-close">Close</button>' +
        '<button type="button" class="primary" id="sns-publish">Publish</button>' +
      '</div>'
    );
    document.getElementById("sns-close").addEventListener("click", M.close);
    document.getElementById("sns-publish").addEventListener("click", function (e) {
      var body = { message: document.getElementById("sns-msg").value };
      var arnVal = (document.getElementById("sns-arn").value || "").trim();
      if (arnVal) body.topic_arn = arnVal;
      else body.topic_name = name;
      var subj = (document.getElementById("sns-subject").value || "").trim(); if (subj) body.subject = subj;
      var g = (document.getElementById("sns-group").value || "").trim(); if (g) body.message_group_id = g;
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/sns/publish", body, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("sns-result").innerHTML = M.renderResult(r);
        M.invalidate(["resources:sns", "sns:" + name]);
        M.showToast("Message published", "ok");
      }).catch(function (ex) {
        document.getElementById("sns-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }
  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.snsPublish = { open: open };
})();
