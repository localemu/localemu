// Secrets Manager rotate-now modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    var name = row.name || "";
    M.open(
      '<h2>Rotate secret: ' + u.esc(name) + '</h2>' +
      '<div class="subtitle"><code>RotateSecret</code> with <code>RotateImmediately=true</code>. Requires a rotation Lambda either already configured on the secret or supplied below.</div>' +
      '<label>Rotation Lambda ARN (optional)</label>' +
      '<input id="sec-lambda" type="text" placeholder="arn:aws:lambda:us-east-1:000000000000:function:rotator">' +
      '<div class="action-modal-error" id="sec-err"></div>' +
      '<div id="sec-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="sec-close">Close</button>' +
        '<button type="button" class="primary" id="sec-rotate">Rotate now</button>' +
      '</div>'
    );
    document.getElementById("sec-close").addEventListener("click", M.close);
    document.getElementById("sec-rotate").addEventListener("click", function (e) {
      var body = { secret_id: name, rotate_immediately: true };
      var arn = (document.getElementById("sec-lambda").value || "").trim(); if (arn) body.rotation_lambda_arn = arn;
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/secretsmanager/rotate-secret", body, { timeoutMs: 30000 }).then(function (r) {
        document.getElementById("sec-result").innerHTML = M.renderResult(r);
        M.invalidate(["resources:secretsmanager"]);
        M.showToast("Secret rotated", "ok");
      }).catch(function (ex) {
        document.getElementById("sec-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }
  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.secretRotate = { open: open };
})();
