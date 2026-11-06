// Light / dark theme. Loaded synchronously in <head> so the saved theme
// applies before first paint (no flash). Without a saved choice the page
// follows the OS preference (prefers-color-scheme in console.css). The
// choice is kept in localStorage; if storage is unavailable (private
// window, blocked site data) the toggle still works for the session.
(function () {
  "use strict";
  var KEY = "localemu-console-theme";
  var root = document.documentElement;

  function read() {
    try { return localStorage.getItem(KEY); } catch (_) { return null; }
  }
  function write(v) {
    try { localStorage.setItem(KEY, v); } catch (_) { /* session only */ }
  }
  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
  }
  function set(t) {
    root.setAttribute("data-theme", t);
    write(t);
    var btn = document.getElementById("themeBtn");
    if (btn) btn.setAttribute("aria-label", "Switch to " + (t === "dark" ? "light" : "dark") + " theme");
  }

  var saved = read();
  if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);

  window.DASH = window.DASH || {};
  window.DASH.theme = {
    current: current,
    set: set,
    toggle: function () { set(current() === "dark" ? "light" : "dark"); }
  };
})();
