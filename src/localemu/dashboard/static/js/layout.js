// Manual collapse for the left service nav and right live-calls panel.
// Loaded synchronously in <head>, like theme.js, so a saved collapsed
// state applies before first paint (no flash of a panel that then
// disappears). Persisted in localStorage; if storage is unavailable
// (private window, blocked site data) the toggles still work for the
// session. Below 781px wide the nav is a separate off-canvas overlay
// (toggled by #menuBtn) and this module leaves it alone (see console.css).
(function () {
  "use strict";
  var NAV_KEY = "localemu-console-nav-collapsed";
  var WIRE_KEY = "localemu-console-wire-collapsed";
  var root = document.documentElement;

  function read(key) {
    try { return localStorage.getItem(key) === "1"; } catch (_) { return false; }
  }
  function write(key, v) {
    try { localStorage.setItem(key, v ? "1" : "0"); } catch (_) { /* session only */ }
  }
  function apply(attr, on) {
    if (on) root.setAttribute(attr, "1"); else root.removeAttribute(attr);
  }

  var navCollapsed = read(NAV_KEY);
  var wireCollapsed = read(WIRE_KEY);
  apply("data-nav-collapsed", navCollapsed);
  apply("data-wire-collapsed", wireCollapsed);

  function syncButtons() {
    var navBtn = document.getElementById("menuBtn");
    if (navBtn) navBtn.setAttribute("aria-label", navCollapsed ? "Show service menu" : "Hide service menu");
    var wireShow = document.getElementById("wireShowBtn");
    if (wireShow) wireShow.setAttribute("aria-label", "Show live API calls panel");
  }

  function setNavCollapsed(v) {
    navCollapsed = !!v;
    apply("data-nav-collapsed", navCollapsed);
    write(NAV_KEY, navCollapsed);
    syncButtons();
  }
  function setWireCollapsed(v) {
    wireCollapsed = !!v;
    apply("data-wire-collapsed", wireCollapsed);
    write(WIRE_KEY, wireCollapsed);
    syncButtons();
  }

  window.DASH = window.DASH || {};
  window.DASH.layout = {
    navCollapsed: function () { return navCollapsed; },
    wireCollapsed: function () { return wireCollapsed; },
    setNavCollapsed: setNavCollapsed,
    setWireCollapsed: setWireCollapsed,
    toggleNav: function () { setNavCollapsed(!navCollapsed); },
    toggleWire: function () { setWireCollapsed(!wireCollapsed); },
    syncButtons: syncButtons
  };
})();
