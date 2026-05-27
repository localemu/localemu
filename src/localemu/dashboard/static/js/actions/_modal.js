// Shared action-modal helpers.
//
// Six action panels (lambda, sqs, sns, events, secretsmanager, dynamodb)
// share one #action-modal element. This module owns lifecycle (open /
// close), keyboard handling (ESC closes), backdrop click-to-close, the
// result + error renderers, and the post-action cache invalidation
// pattern. Action panels only declare their form HTML and submit body.
//
// One ESC + backdrop listener is registered ONCE at init(); subsequent
// re-opens reuse it.
(function () {
  "use strict";

  var bd = null;
  var modal = null;
  var inited = false;

  function ensureRefs() {
    if (!bd) bd = document.getElementById("action-modal-backdrop");
    if (!modal) modal = document.getElementById("action-modal");
  }

  function open(html) {
    ensureRefs();
    if (!bd || !modal) return;
    modal.innerHTML = html;
    bd.classList.add("open");
    bd.setAttribute("aria-hidden", "false");
  }

  function close() {
    ensureRefs();
    if (!bd || !modal) return;
    bd.classList.remove("open");
    bd.setAttribute("aria-hidden", "true");
    modal.innerHTML = "";
  }

  function isOpen() {
    ensureRefs();
    return !!(bd && bd.classList.contains("open"));
  }

  // Disable the button that received the click WITHOUT relying on
  // e.target -- when the user clicks an inner span/icon, e.target is
  // the span and disabling it is silently a no-op (so double-submit
  // sneaks through). e.currentTarget is always the button the listener
  // is bound to.
  function busy(e) {
    var btn = e && e.currentTarget;
    if (btn && "disabled" in btn) btn.disabled = true;
    return function release() {
      if (btn && "disabled" in btn) btn.disabled = false;
    };
  }

  function renderResult(r) {
    var u = DASH.utils;
    var result = (r && r.data && r.data.result) || (r && r.data) || r;
    return '<div class="action-modal-result"><div class="ok-line">OK</div><pre>'
         + u.esc(JSON.stringify(result, null, 2))
         + '</pre></div>';
  }

  function renderError(ex) {
    var u = DASH.utils;
    var msg = (ex && ex.data && ex.data.error) || (ex && ex.message) || String(ex);
    var code = (ex && ex.data && ex.data.error_code) ? " (" + ex.data.error_code + ")" : "";
    return '<div class="action-modal-result"><div class="fail-line">FAILED' + code + '</div><pre>'
         + u.esc(msg) + '</pre></div>';
  }

  // Post-action cache invalidation. Each action panel calls this after
  // a successful mutation so the resource list, drill-downs, CloudTrail
  // and the activity feed see fresh data without the user manually
  // refreshing.
  function invalidate(serviceTags) {
    if (!serviceTags) return;
    if (!Array.isArray(serviceTags)) serviceTags = [serviceTags];
    serviceTags.forEach(function (tag) {
      try { DASH.cache.invalidateKey(tag); } catch (_) {}
    });
    // CloudTrail always learns about the new event.
    try { DASH.cache.invalidateKey("cloudtrail:200"); } catch (_) {}
    // If the user is currently on the affected service's list page,
    // re-fetch immediately so they see the new state in-place.
    var current = (DASH.app && DASH.app.state && DASH.app.state.route.service) || "";
    if (current && DASH.resources && DASH.resources.refresh) {
      var matches = serviceTags.some(function (t) { return t === "resources:" + current; });
      if (matches) {
        try { DASH.resources.refresh(true); } catch (_) {}
      }
    }
  }

  function showToast(msg, kind) {
    try { DASH.utils.showToast(msg, kind || "ok"); } catch (_) {}
  }

  function init() {
    if (inited) return;
    inited = true;
    ensureRefs();
    if (!bd) return;
    // ESC closes.
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && isOpen()) close();
    });
    // Click on the backdrop (NOT on the modal body) closes.
    bd.addEventListener("click", function (e) {
      if (e.target === bd) close();
    });
  }

  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions._modal = {
    open: open, close: close, isOpen: isOpen,
    busy: busy,
    renderResult: renderResult,
    renderError: renderError,
    invalidate: invalidate,
    showToast: showToast,
    init: init
  };
})();
