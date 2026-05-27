// Tiny utilities shared by every other module. Loaded first.
//
// We do NOT use a module bundler. Every script exposes its public
// surface via `window.DASH.<module> = {...}` and modules are loaded
// in dependency order from index.html.
(function () {
  "use strict";

  window.DASH = window.DASH || {};

  function esc(str) {
    if (str == null) return "";
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  }

  function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes)) return "-";
    var b = Number(bytes);
    if (b === 0) return "0 B";
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    if (b < 1024 * 1024 * 1024) return (b / 1024 / 1024).toFixed(1) + " MB";
    return (b / 1024 / 1024 / 1024).toFixed(1) + " GB";
  }

  function formatUptime(seconds) {
    if (seconds == null || isNaN(seconds)) return "...";
    var s = Math.floor(seconds);
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    var sec = s % 60;
    if (h > 0) return h + "h " + m + "m " + sec + "s";
    if (m > 0) return m + "m " + sec + "s";
    return sec + "s";
  }

  function formatTimestamp(ts) {
    if (!ts) return "--:--:--";
    var d;
    if (typeof ts === "number") {
      d = new Date(ts < 1e12 ? ts * 1000 : ts);
    } else {
      d = new Date(ts);
    }
    if (isNaN(d.getTime())) return String(ts);
    var hh = String(d.getHours()).padStart(2, "0");
    var mm = String(d.getMinutes()).padStart(2, "0");
    var ss = String(d.getSeconds()).padStart(2, "0");
    return hh + ":" + mm + ":" + ss;
  }

  function statusClass(code) {
    var c = Number(code);
    if (c >= 200 && c < 300) return "ok";
    if (c >= 400 && c < 500) return "warn";
    if (c >= 500) return "error";
    return "";
  }

  function highlight(str, query) {
    if (!query || str == null) return esc(str != null ? str : "-");
    var s = String(str);
    var qLower = query.toLowerCase();
    var idx = s.toLowerCase().indexOf(qLower);
    if (idx === -1) return esc(s);
    return esc(s.substring(0, idx)) +
      '<span class="match-hi">' + esc(s.substring(idx, idx + qLower.length)) + "</span>" +
      esc(s.substring(idx + qLower.length));
  }

  // Toast: brief banner in the bottom-right corner.
  var toastTimer = null;
  function showToast(msg, kind) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.className = "visible" + (kind === "error" ? " error" : "");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.className = ""; }, 2200);
  }

  // Surface a fetch/api failure to the user. Use from every silent
  // .catch() to convert a swallowed promise rejection into a visible
  // toast. The label argument identifies the source ("overview",
  // "activity", "lambda invocations", ...).
  function showApiError(err, label) {
    var msg = (err && err.data && err.data.error)
           || (err && err.message)
           || String(err || "unknown error");
    showToast((label ? (label + ": ") : "") + msg, "error");
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { showToast("Copied to clipboard"); },
        function () { showToast("Copy failed", "error"); }
      );
      return;
    }
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      showToast("Copied to clipboard");
    } catch (e) {
      showToast("Copy failed", "error");
    }
  }

  function debounce(fn, ms) {
    var t = null;
    return function () {
      var ctx = this, args = arguments;
      if (t) clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }

  function iconUrl(service) {
    return "/_localemu/dashboard/static/icons/" + encodeURIComponent(service) + ".svg";
  }

  // Services that ship an SVG icon under static/icons/. Anything else
  // falls back to a styled letter badge so the UI never shows a broken
  // image. Keep this list in sync with ``ls dashboard/static/icons``.
  var SVG_ICONS = new Set([
    "apigateway", "apigatewayv2", "cloudformation", "cloudtrail",
    "cloudwatch", "dynamodb", "ec2", "ecs", "eks", "elbv2", "events",
    "iam", "kinesis", "kms", "lambda", "logs", "opensearch", "rds",
    "route53", "s3", "secretsmanager", "sns", "sqs", "ssm",
    "stepfunctions", "sts", "vpc"
  ]);

  // Stable colour per first letter so two services starting with the
  // same letter always share the same badge colour. Picked from the
  // solarized accent ramp so they sit consistently with the rest of
  // the dark theme.
  var LETTER_COLORS = [
    "#268bd2", "#2aa198", "#859900", "#b58900", "#cb4b16",
    "#dc322f", "#d33682", "#6c71c4", "#dca7e6", "#b294ff"
  ];

  function letterColor(svc) {
    var s = (svc || "").toLowerCase();
    var code = s.length ? s.charCodeAt(0) : 0;
    return LETTER_COLORS[code % LETTER_COLORS.length];
  }

  function iconHtml(service, size) {
    size = size || 22;
    if (SVG_ICONS.has(service)) {
      return '<img src="' + esc(iconUrl(service)) + '" alt="" width="' + size + '" height="' + size + '" loading="lazy">';
    }
    // Letter-badge fallback. Use the first 1-2 alphanumeric characters,
    // skip dashes/underscores so e.g. "vpc-peering" -> "VP" not "V-".
    var clean = String(service || "?").replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
    var letters = clean.substring(0, clean.length === 1 ? 1 : 2) || "?";
    var fs = Math.max(9, Math.round(size * 0.42));
    return (
      '<span class="letter-icon" style="' +
        'display:inline-flex;align-items:center;justify-content:center;' +
        'width:' + size + 'px;height:' + size + 'px;' +
        'background:' + letterColor(service) + ';color:#fff;' +
        'border-radius:3px;font-weight:700;font-size:' + fs + 'px;' +
        'font-family:Menlo,Monaco,Consolas,monospace;letter-spacing:0;' +
        'flex-shrink:0;">' + esc(letters) + '</span>'
    );
  }

  window.DASH.utils = {
    esc: esc,
    formatBytes: formatBytes,
    formatUptime: formatUptime,
    formatTimestamp: formatTimestamp,
    statusClass: statusClass,
    highlight: highlight,
    showToast: showToast,
    showApiError: showApiError,
    copyToClipboard: copyToClipboard,
    debounce: debounce,
    iconHtml: iconHtml
  };
})();
