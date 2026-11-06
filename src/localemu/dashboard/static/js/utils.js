// Tiny utilities shared by every other module. Loaded first.
//
// We do NOT use a module bundler. Every script exposes its public
// surface via `window.DASH.<module> = {...}` and modules are loaded
// in dependency order from index.html.
(function () {
  "use strict";

  window.DASH = window.DASH || {};

  // "awsemu" is this install's shell alias for `aws --endpoint-url=<endpoint>`
  // (see GETTING_STARTED.md). Every copyable snippet is authored once as
  // "awsemu ...", and this turns it into the plain AWS CLI form on the fly
  // for anyone who hasn't set up the alias -- `awsemu` only ever appears as
  // the command itself, never inside a flag value, so a whole-word swap is
  // exact for every snippet in services.js.
  function toAwsCli(cmd, endpoint) {
    if (!cmd) return cmd;
    var ep = endpoint || (window.DASH && window.DASH.app && window.DASH.app.state &&
      window.DASH.app.state.system && window.DASH.app.state.system.endpoint) || window.location.origin;
    return cmd.replace(/\bawsemu\b/g, "aws --endpoint-url=" + ep);
  }

  // Renders one or more labelled, individually-copyable command lines.
  // variants: [{ label, cmd }, ...]
  function cmdBlock(variants) {
    return '<div class="cmdline-group">' + variants.filter(function (v) { return v && v.cmd; }).map(function (v) {
      return '<div class="cmdline"><span class="cmd-tag">' + esc(v.label) + '</span><span class="pr">$</span><code>' + esc(v.cmd) +
        '</code><button type="button" data-copy="' + esc(v.cmd) + '">Copy</button></div>';
    }).join("") + "</div>";
  }

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


  // ── Service glyphs: monogram tiles ──
  // One glyph system for all 132 services (no per-service artwork to
  // license or keep in sync). Hand-picked monograms for the common
  // services, a derived one for the rest.
  var MONOGRAMS = {
    ec2: "EC2", lambda: "λ", ecs: "ECS", eks: "EKS", batch: "BAT", apprunner: "AR",
    s3: "S3", dynamodb: "DDB", rds: "RDS", efs: "EFS", ecr: "ECR", elasticache: "EC",
    opensearch: "OS", redshift: "RS", sqs: "SQS", sns: "SNS", events: "EB",
    stepfunctions: "SFN", kinesis: "KIN", firehose: "FH", kafka: "MSK", mq: "MQ",
    pipes: "PIP", scheduler: "SCH", vpc: "VPC", apigateway: "API", apigatewayv2: "AP2",
    route53: "R53", elbv2: "ELB", cloudfront: "CF", iam: "IAM", kms: "KMS",
    secretsmanager: "SM", "cognito-idp": "CUP", "cognito-identity": "CIP", acm: "ACM",
    wafv2: "WAF", guardduty: "GD", ssm: "SSM", cloudformation: "CFN", appconfig: "APC",
    athena: "ATH", glue: "GLU", emr: "EMR", bedrock: "BR", sagemaker: "SGM",
    comprehend: "CMP", codecommit: "CC", codebuild: "CB", mediaconvert: "MC", iot: "IoT",
    dms: "DMS", logs: "CWL", cloudwatch: "CW", cloudtrail: "CT", xray: "XR", ce: "CE",
    budgets: "BUD", ses: "SES", sts: "STS", accounts: "ACC"
  };
  function monogram(service) {
    var s = String(service || "?");
    if (MONOGRAMS[s]) return MONOGRAMS[s];
    var parts = s.split(/[^a-zA-Z0-9]+/).filter(Boolean);
    if (parts.length > 1) return parts.map(function (p) { return p[0]; }).join("").slice(0, 3).toUpperCase();
    return s.replace(/[^a-zA-Z0-9]/g, "").slice(0, 3).toUpperCase() || "?";
  }
  // Services with a real SVG icon under dashboard/static/icons/ - everything
  // else falls back to the text monogram tile below.
  var ICON_SERVICES = {
    apigateway: 1, apigatewayv2: 1, cloudformation: 1, cloudtrail: 1, cloudwatch: 1,
    dynamodb: 1, ec2: 1, ecs: 1, eks: 1, elbv2: 1, events: 1, iam: 1, kinesis: 1,
    kms: 1, lambda: 1, logs: 1, opensearch: 1, rds: 1, route53: 1, s3: 1,
    secretsmanager: 1, sns: 1, sqs: 1, ssm: 1, stepfunctions: 1, sts: 1, vpc: 1
  };
  function tile(service, size, hot) {
    var s = String(service || "");
    if (ICON_SERVICES[s]) {
      return '<img class="mono-tile ' + (size || "sm") + (hot ? " hot" : "") +
        '" src="/_localemu/dashboard/static/icons/' + s + '.svg" alt="" aria-hidden="true">';
    }
    return '<span class="mono-tile ' + (size || "sm") + (hot ? " hot" : "") + '" aria-hidden="true">' +
      esc(monogram(service)) + "</span>";
  }
  // Back-compat for drills that call iconHtml(service, px).
  function iconHtml(service, size) {
    size = size || 22;
    return tile(service, size >= 40 ? "lg" : size >= 26 ? "md" : "sm");
  }

  function toMillis(ts) {
    if (ts == null || ts === "") return NaN;
    if (typeof ts === "number") return ts < 1e12 ? ts * 1000 : ts;
    var n = Date.parse(ts);
    return n;
  }
  function relTime(ts) {
    var t = toMillis(ts);
    if (isNaN(t)) return "-";
    var d = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (d < 5) return "just now";
    if (d < 60) return d + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }
  function fmtLatency(ms) {
    if (ms == null || isNaN(ms)) return "-";
    if (ms >= 1000) return (ms / 1000).toFixed(2) + " s";
    if (ms >= 100) return Math.round(ms) + " ms";
    return (Math.round(ms * 10) / 10) + " ms";
  }
  function shortAcct(a) {
    a = String(a || "");
    return a.length === 12 ? a.slice(0, 4) + "…" + a.slice(-4) : a;
  }
  // "arn:aws:iam::000000000000:user/ci" -> "user/ci"; root -> "root".
  function shortPrincipal(p) {
    if (!p) return "anonymous";
    if (p.arn) {
      var m = /^arn:[^:]+:(?:iam|sts)::\d{12}:(.+)$/.exec(p.arn);
      return m ? m[1] : p.arn;
    }
    if (p.type === "anonymous") return "anonymous";
    return "key " + (p.access_key || "?");
  }
  function fmtInt(n) {
    n = Number(n || 0);
    return n.toLocaleString("en-US");
  }

  // Inline SVG icons (stroke = currentColor).
  var ICON = {
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>',
    plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
    doc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
    bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg>',
    chev: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="m6 9 6 6 6-6"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/></svg>',
    filter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M7 12h10M10 18h4"/></svg>',
    acct: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18"/></svg>'
  };

  window.DASH.utils = {
    esc: esc,
    toAwsCli: toAwsCli,
    cmdBlock: cmdBlock,
    formatBytes: formatBytes,
    formatUptime: formatUptime,
    formatTimestamp: formatTimestamp,
    statusClass: statusClass,
    highlight: highlight,
    showToast: showToast,
    showApiError: showApiError,
    copyToClipboard: copyToClipboard,
    debounce: debounce,
    iconHtml: iconHtml,
    tile: tile,
    monogram: monogram,
    relTime: relTime,
    toMillis: toMillis,
    fmtLatency: fmtLatency,
    fmtInt: fmtInt,
    shortAcct: shortAcct,
    shortPrincipal: shortPrincipal,
    ICON: ICON
  };
})();
