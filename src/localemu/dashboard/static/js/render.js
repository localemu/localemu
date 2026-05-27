// Minimal diff-based renderer. Each "view" is a function that takes
// state and returns an HTML string; we render into a stable container
// and cache the render key so a no-op render does NOT blow away the
// DOM (preserving focus, scroll position, in-flight event listeners).
(function () {
  "use strict";

  function renderInto(container, key, html) {
    if (!container) return;
    if (container.dataset.lastKey === key) return;
    container.dataset.lastKey = key;
    container.innerHTML = html;
  }

  // For lists where we already have a stable parent and just want to
  // append. Used by the activity feed.
  function prependRow(container, key, rowHtml, maxRows) {
    if (!container) return;
    if (container.querySelector("[data-row-key=\"" + cssEscape(key) + "\"]")) return;
    var holder = document.createElement("div");
    holder.innerHTML = rowHtml;
    var node = holder.firstChild;
    if (!node) return;
    if (node.setAttribute) node.setAttribute("data-row-key", key);
    container.insertBefore(node, container.firstChild);
    if (maxRows && container.children.length > maxRows) {
      while (container.children.length > maxRows) {
        container.removeChild(container.lastChild);
      }
    }
  }

  function clear(container) {
    if (!container) return;
    container.innerHTML = "";
    delete container.dataset.lastKey;
  }

  function cssEscape(s) {
    if (window.CSS && typeof CSS.escape === "function") return CSS.escape(String(s));
    return String(s).replace(/[^a-zA-Z0-9_-]/g, function (c) {
      return "\\" + c.charCodeAt(0).toString(16) + " ";
    });
  }

  window.DASH.render = {
    renderInto: renderInto,
    prependRow: prependRow,
    clear: clear,
    cssEscape: cssEscape
  };
})();
