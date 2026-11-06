// Live API calls panel ("the wire").
//
// Source: ``call`` events on the SSE stream (one per AWS API call the
// gateway handled, recorded by dashboard/telemetry.py), hydrated on load
// from /_localemu/api/calls. Each row shows operation, service, HTTP
// status / error code, the resource it touched, the calling principal,
// the account and the server-side handling time. IAM denials (enforced
// 403s and IAM_ENFORCEMENT=soft audit denials) are marked. Clicking a row
// loads the stored CloudTrail record for that request id.
(function () {
  "use strict";

  var MAX = 500, MAX_DOM = 150;
  var events = [];          // newest first
  var paused = false;
  var queuedWhilePaused = [];
  var filter = "all";
  var openSeq = null;
  var details = {};         // request_id -> CloudTrail detail | {missing: true}

  function u() { return DASH.utils; }

  function passes(e) {
    if (filter === "errors") return e.status >= 400 || !!e.denied;
    if (filter === "writes") return !!e.mutating;
    if (filter === "acct") return e.account_id === DASH.app.state.account;
    if (filter === "external") return !e.internal || e.via === "console";
    return true;
  }

  function statusChip(e) {
    if (e.denied === "enforced") return '<span class="chip err" title="' + u().esc(e.denial_reason || "") + '">' + e.status + " denied</span>";
    if (e.denied === "audit") return '<span class="chip warn" title="' + u().esc(e.denial_reason || "") + '">audit deny</span>';
    if (e.status >= 500) return '<span class="chip err">' + e.status + (e.error_code ? " " + u().esc(shortCode(e.error_code)) : "") + "</span>";
    if (e.status >= 400) return '<span class="chip warn">' + e.status + (e.error_code ? " " + u().esc(shortCode(e.error_code)) : "") + "</span>";
    return '<span class="chip ok">' + e.status + "</span>";
  }
  function shortCode(c) { return String(c).replace(/Exception$/, ""); }

  function jsonHtml(obj) {
    var text = JSON.stringify(obj, null, 2);
    return u().esc(text).replace(/^(\s*)(&quot;[^&]*?&quot;)(:)/gm, '$1<span class="k">$2</span>$3');
  }

  function detailHtml(e) {
    var d = details[e.request_id];
    var why = e.denial_reason ? '<div class="why">' + u().esc(e.denied === "audit" ? "Would be denied (audit mode): " : "Denied: ") + u().esc(e.denial_reason) + "</div>" : "";
    if (!d) return '<div class="ev-detail">' + why + '<div class="note">Loading CloudTrail record...</div></div>';
    if (d.missing) {
      return '<div class="ev-detail">' + why + '<div class="note" style="margin-bottom:6px">No CloudTrail record for request ' + u().esc(e.request_id) +
        " (a trail event selector may exclude it). Console record:</div><pre class=\"json\">" + jsonHtml(e) + "</pre></div>";
    }
    var inner = d.CloudTrailEvent ? (function () { try { return JSON.parse(d.CloudTrailEvent); } catch (_) { return d; } })() : d;
    return '<div class="ev-detail">' + why + '<pre class="json">' + jsonHtml(inner) + "</pre>" +
      '<div style="margin-top:6px"><button class="btn sm ghost" type="button" data-ct-open="' + u().esc(e.request_id) + '">Open in CloudTrail view</button></div></div>';
  }

  function evHtml(e, fresh) {
    var cls = "ev" + (e.denied === "enforced" ? " denied" : e.denied === "audit" ? " audit" : e.status >= 500 ? " e5" : e.status >= 400 ? " e4" : "") + (fresh ? " fresh" : "");
    var open = openSeq === e.seq;
    var res = e.resource ? (e.resource.name || e.resource.arn) : (e.error_message || "");
    var lat = e.latency_ms;
    return '<li class="' + cls + '" data-seq="' + e.seq + '" tabindex="0" aria-expanded="' + open + '">' +
      '<span class="tm">' + u().formatTimestamp(e.ts) + "</span>" +
      '<span class="op">' + u().esc(e.operation) + ' <span class="svc">' + u().esc(DASH.catalog.label(e.service)) + "</span></span>" +
      '<span class="st">' + statusChip(e) + "</span>" +
      '<span class="rs" title="' + u().esc(e.resource ? e.resource.arn || e.resource.name : res) + '">' + u().esc(res || "–") + "</span>" +
      '<span class="who">' +
      (e.via ? '<span class="chip ' + (e.via === "console" ? "accent" : "neutral") + '" title="' +
        u().esc(e.via === "console" ? "Made by this console (dashboard action)" : "LocalEmu-internal call made on behalf of " + e.via) + '">' +
        (e.via === "console" ? "console" : "internal") + "</span>" : "") +
      '<span title="' + u().esc((e.principal && (e.principal.arn || e.principal.access_key)) || "") + (e.via && e.via !== "console" ? " via " + u().esc(e.via) : "") + '">' + u().esc(u().shortPrincipal(e.principal)) + "</span>" +
      '<span title="' + u().esc(e.account_id) + '">' + u().esc(u().shortAcct(e.account_id)) + "</span>" +
      '<span class="lat' + (lat > 1000 ? " slow" : "") + '" title="server-side handling time">' + u().fmtLatency(lat) + "</span></span>" +
      (open ? detailHtml(e) : "") + "</li>";
  }

  function renderList() {
    var list = document.getElementById("wireList");
    if (!list) return;
    var shown = events.filter(passes).slice(0, MAX_DOM);
    list.innerHTML = shown.length ? shown.map(function (e) { return evHtml(e); }).join("")
      : '<li class="wire-empty">No calls match this filter yet. They appear here as soon as LocalEmu handles one.</li>';
    foot();
  }
  function foot() {
    var b = document.getElementById("bufN");
    if (b) b.textContent = events.length;
    var q = document.getElementById("wireQueued");
    if (q) q.textContent = paused && queuedWhilePaused.length ? queuedWhilePaused.length + " new while paused" : "";
  }

  function add(e, fresh) {
    if (!e || typeof e.seq !== "number") return;
    if (events.length && events[0].seq >= e.seq && events.some(function (x) { return x.seq === e.seq; })) return;
    events.unshift(e);
    if (events.length > MAX) events.pop();
    if (!passes(e)) { foot(); return; }
    var list = document.getElementById("wireList");
    if (!list) return;
    var empty = list.querySelector(".wire-empty");
    if (empty) empty.remove();
    list.insertAdjacentHTML("afterbegin", evHtml(e, fresh));
    while (list.children.length > MAX_DOM) list.removeChild(list.lastChild);
    foot();
  }

  function onCall(e) {
    if (paused) { queuedWhilePaused.push(e); if (queuedWhilePaused.length > MAX) queuedWhilePaused.shift(); foot(); return; }
    add(e, true);
  }

  function setPaused(p) {
    paused = p;
    var btn = document.getElementById("pauseBtn");
    if (btn) btn.textContent = p ? "Resume" : "Pause";
    if (!p && queuedWhilePaused.length) {
      queuedWhilePaused.forEach(function (e) { add(e, false); });
      queuedWhilePaused = [];
    }
    DASH.app.state.sse && onStatus(DASH.app.state.sse.status);
    var live = document.getElementById("liveBtn");
    var txt = document.getElementById("liveText");
    if (live) {
      live.classList.toggle("paused", p);
      if (!p) { live.classList.remove("paused"); live.classList.add(DASH.app.state.sse.status || "offline"); }
    }
    if (txt) txt.textContent = p ? "Paused" : ({ connected: "Live", polling: "Polling" }[DASH.app.state.sse.status] || "Offline");
    foot();
  }

  function onStatus(status) {
    var chip = document.getElementById("wireState");
    if (!chip) return;
    if (paused) { chip.className = "chip warn"; chip.textContent = "panel paused"; return; }
    if (status === "connected") { chip.className = "chip ok"; chip.textContent = "SSE connected"; }
    else if (status === "polling") { chip.className = "chip warn"; chip.textContent = "polling (no SSE)"; }
    else { chip.className = "chip err"; chip.textContent = "disconnected"; }
  }

  function toggleRow(seq) {
    openSeq = openSeq === seq ? null : seq;
    var e = events.filter(function (x) { return x.seq === seq; })[0];
    var li = document.querySelector('#wireList [data-seq="' + seq + '"]');
    if (!e || !li) return;
    li.outerHTML = evHtml(e);
    if (openSeq === seq && !details[e.request_id] && e.request_id) {
      DASH.api.fetchJSON("/_localemu/api/cloudtrail/" + encodeURIComponent(e.request_id), { etag: false, timeoutMs: 6000 })
        .then(function (r) { details[e.request_id] = r.data || { missing: true }; })
        .catch(function () { details[e.request_id] = { missing: true }; })
        .then(function () {
          var cur = document.querySelector('#wireList [data-seq="' + seq + '"]');
          if (cur && openSeq === seq) cur.outerHTML = evHtml(e);
        });
    }
  }

  function hydrate() {
    return DASH.api.fetchJSON("/_localemu/api/calls?limit=200", { etag: false, timeoutMs: 8000 }).then(function (r) {
      var calls = (r.data && r.data.calls) || [];
      var known = {};
      events.forEach(function (e) { known[e.seq] = true; });
      calls.forEach(function (c) { if (!known[c.seq]) events.push(c); });
      events.sort(function (a, b) { return b.seq - a.seq; });
      if (events.length > MAX) events.length = MAX;
      renderList();
    }).catch(function (err) { DASH.utils.showApiError(err, "live calls"); });
  }

  function init() {
    DASH.bus.subscribe("call", onCall);
    DASH.bus.subscribe("dropped", function () { hydrate(); });
    var sel = document.getElementById("wireFilter");
    sel.addEventListener("change", function () { filter = sel.value; renderList(); });
    document.getElementById("pauseBtn").addEventListener("click", function () { setPaused(!paused); });
    document.getElementById("clearBtn").addEventListener("click", function () {
      events = []; queuedWhilePaused = []; openSeq = null; renderList();
      DASH.utils.showToast("Local buffer cleared. CloudTrail keeps the history.");
    });
    var list = document.getElementById("wireList");
    list.addEventListener("click", function (e) {
      var ct = e.target.closest("[data-ct-open]");
      if (ct) { DASH.cloudtrail.openDetail(ct.getAttribute("data-ct-open")); return; }
      if (e.target.closest(".ev-detail")) return;
      var li = e.target.closest("[data-seq]");
      if (li) toggleRow(Number(li.getAttribute("data-seq")));
    });
    list.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      var li = e.target.closest && e.target.closest("[data-seq]");
      if (li && e.target === li) { e.preventDefault(); toggleRow(Number(li.getAttribute("data-seq"))); }
    });
    renderList();
    hydrate();
  }

  window.DASH.wire = {
    init: init,
    togglePause: function () { setPaused(!paused); },
    setPaused: setPaused,
    isPaused: function () { return paused; },
    onStatus: onStatus,
    onAccountChange: function () { if (filter === "acct") renderList(); }
  };
})();
