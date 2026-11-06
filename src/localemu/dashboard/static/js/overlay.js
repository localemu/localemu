// Overlay layer for the console: scrim, popover menu, form modals.
// One overlay at a time lives in #overlay; Escape or a scrim click closes
// it. (Drill action panels keep using #action-modal via actions/_modal.js.)
(function () {
  "use strict";

  var onClose = null;

  function el() { return document.getElementById("overlay"); }

  function open(html, opts) {
    close();
    el().innerHTML = html;
    onClose = (opts && opts.onClose) || null;
  }

  function close() {
    var o = el();
    if (o && o.innerHTML) {
      o.innerHTML = "";
      var cb = onClose;
      onClose = null;
      if (cb) { try { cb(); } catch (_) {} }
    }
    var nav = document.getElementById("nav");
    if (nav) nav.classList.remove("open");
  }

  function isOpen() { var o = el(); return !!(o && o.innerHTML); }

  function field(label, inputHtml, help) {
    return '<div class="field"><label>' + DASH.utils.esc(label) + "</label>" + inputHtml +
      (help ? '<div class="help">' + help + "</div>" : "") + "</div>";
  }

  // Generic form modal. spec: {title, sub, svc, body (html), goLabel,
  // onGo(modalEl) -> Promise<{ok, status?, label?, data}> }
  function modal(spec) {
    var u = DASH.utils;
    open('<div class="scrim" data-close="1"></div>' +
      '<div class="modal" role="dialog" aria-modal="true" aria-labelledby="mTitle">' +
        '<div class="modal-head">' + (spec.svc ? u.tile(spec.svc, "md", true) : "") +
          '<div style="flex:1;min-width:0"><h3 id="mTitle">' + u.esc(spec.title) + "</h3>" +
          (spec.sub ? '<div class="sub">' + u.esc(spec.sub) + "</div>" : "") + "</div>" +
          '<button class="icon-btn" type="button" data-close="1" aria-label="Close">&#10005;</button></div>' +
        '<div class="modal-body">' + (spec.body || "") + '<div id="mResult"></div></div>' +
        '<div class="modal-foot"><button class="btn ghost" type="button" data-close="1">' +
          (spec.onGo ? "Cancel" : "Close") + "</button>" +
          (spec.onGo ? '<button class="btn primary" type="button" id="mGo">' + u.esc(spec.goLabel || "Run") + "</button>" : "") +
        "</div></div>");
    var first = document.querySelector("#overlay .modal textarea, #overlay .modal input, #overlay .modal select");
    if (first) first.focus();
    var go = document.getElementById("mGo");
    if (!go) return;
    go.addEventListener("click", function () {
      var out = document.getElementById("mResult");
      go.disabled = true;
      var started = performance.now();
      Promise.resolve().then(function () { return spec.onGo(document.querySelector("#overlay .modal")); })
        .then(function (r) {
          go.disabled = false;
          if (!out) return;
          var ms = Math.round(performance.now() - started);
          out.innerHTML = '<div class="result"><div class="result-head"><span class="chip ok">OK</span>' +
            u.esc(r && r.label ? r.label : "") + " &middot; " + ms + ' ms round trip</div><pre>' +
            u.esc(JSON.stringify(r && r.data !== undefined ? r.data : r, null, 2)) + "</pre></div>";
          go.textContent = "Run again";
        })
        .catch(function (err) {
          go.disabled = false;
          if (!out) return;
          var msg = (err && err.data && (err.data.error || err.data.message)) || (err && err.message) || String(err);
          var code = err && err.data && err.data.error_code ? " " + err.data.error_code : "";
          out.innerHTML = '<div class="result"><div class="result-head"><span class="chip err">' +
            u.esc((err && err.status ? err.status : "failed") + code) + "</span></div><pre>" + u.esc(msg) + "</pre></div>";
        });
    });
  }

  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("[data-close]")) close();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && isOpen()) close();
  });

  window.DASH.overlay = { open: open, close: close, isOpen: isOpen, modal: modal, field: field };
})();
