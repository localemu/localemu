// Accounts: top-bar switcher + #/accounts page.
//
// Backed by the account registry (/_localemu/api/accounts): every account
// this instance has seen (access keys auto-register on first use),
// created through Organizations, or added here. Per-account resource
// totals come from /_localemu/api/accounts/<id>/summary, which runs the
// same counters as the overview restricted to that account.
//
// Switching account scopes the overview counts, the service pages, the
// recently-changed table, the CloudTrail view's account filter, the
// "This account only" live filter and the write actions.
(function () {
  "use strict";

  var SWATCHES = ["var(--accent)", "var(--box)", "var(--warn)", "var(--ok)", "var(--err)", "var(--fg-2)"];
  var summaries = {};   // account id -> summary payload

  function u() { return DASH.utils; }
  function list() { return DASH.app.state.accounts || []; }
  function find(id) { return list().filter(function (a) { return a.Id === id; })[0] || null; }
  function swatch(id) {
    var ids = list().map(function (a) { return a.Id; }).sort();
    var i = ids.indexOf(id);
    if (i < 0) i = 0;
    return SWATCHES[i % SWATCHES.length];
  }

  function refresh() {
    DASH.cache.invalidateKey("accounts:list");
    return DASH.api.get("/_localemu/api/accounts", { cacheKey: "accounts:list", ttlMs: 5000, tags: ["accounts"] }).then(function (r) {
      var accts = ((r.value && r.value.Accounts) || []).slice().sort(function (a, b) { return a.Id.localeCompare(b.Id); });
      DASH.app.state.accounts = accts;
      DASH.app.renderTopbar();
      if (DASH.app.state.route.service === "accounts") render();
      return accts;
    }).catch(function (err) { DASH.utils.showApiError(err, "accounts"); return []; });
  }

  function fetchSummary(id) {
    return DASH.api.fetchJSON("/_localemu/api/accounts/" + encodeURIComponent(id) + "/summary", { etag: false, timeoutMs: 10000 })
      .then(function (r) { summaries[id] = r.data; return r.data; })
      .catch(function () { return null; });
  }

  function renderButton() {
    var id = DASH.app.state.account;
    var rec = find(id);
    var e;
    if ((e = document.getElementById("acctId"))) e.textContent = id;
    if ((e = document.getElementById("acctAlias"))) e.textContent = rec ? (rec.Name || "") : "not registered";
    if ((e = document.getElementById("acctSwatch"))) e.style.background = swatch(id);
  }

  function menuHtml() {
    var cur = DASH.app.state.account;
    var rows = list().map(function (a) {
      var s = summaries[a.Id];
      return '<button class="menu-item' + (a.Id === cur ? " on" : "") + '" role="menuitem" type="button" data-switch="' + u().esc(a.Id) + '">' +
        '<span class="acct-swatch" style="background:' + swatch(a.Id) + '"></span><span class="id">' + u().esc(a.Id) + "</span>" +
        '<span class="al">' + u().esc(a.Name || "") + (a.Status && a.Status !== "ACTIVE" ? " &middot; " + u().esc(a.Status) : "") + "</span>" +
        '<span class="c" data-sum="' + u().esc(a.Id) + '">' + (s ? s.total + " res" : "&hellip;") + "</span></button>";
    }).join("");
    if (!rows) rows = '<div class="nav-hint" style="padding:8px">No accounts registered yet.</div>';
    return rows + '<div class="menu-sep"></div><button class="menu-item" type="button" data-route="accounts"><span></span>' +
      '<span class="id" style="font-family:var(--font-body)">Manage accounts</span></button>';
  }

  function openMenu() {
    var btn = document.getElementById("acctBtn");
    var r = btn.getBoundingClientRect();
    var left = Math.max(16, Math.min(r.right - 340, window.innerWidth - 356));
    DASH.overlay.open('<div class="scrim" data-close="1" style="background:transparent"></div>' +
      '<div class="menu" role="menu" id="acctMenu" style="top:' + (r.bottom + 6) + "px;left:" + left + 'px">' + menuHtml() + "</div>");
    refresh().then(function () {
      var m = document.getElementById("acctMenu");
      if (m) m.innerHTML = menuHtml();
      list().forEach(function (a) {
        fetchSummary(a.Id).then(function (s) {
          var cell = document.querySelector('#acctMenu [data-sum="' + a.Id + '"]');
          if (cell && s) cell.textContent = s.total + " res";
        });
      });
    });
  }

  function render() {
    var el = document.getElementById("main-content");
    if (!el || DASH.app.state.route.service !== "accounts") return;
    var cur = DASH.app.state.account;
    var head = '<div><div class="crumbs"><button type="button" data-route="overview">Overview</button><span>/</span><span>Accounts</span></div>' +
      '<div class="page-head"><div><h1>Accounts</h1><p>Every AWS account this instance has seen. Requests are scoped by the access key ' +
      '(a 12-digit key selects that account), so each account keeps its own resources.</p></div>' +
      '<div class="head-actions"><button class="btn primary" type="button" id="acctCreate">' + u().ICON.plus + "Create account</button></div></div></div>";
    var rows = list();
    var body;
    if (!rows.length) {
      body = '<section class="panel"><div class="panel-empty"><h3>No accounts registered yet</h3><p>Make any AWS call against LocalEmu; its access key is registered automatically.</p></div></section>';
    } else {
      body = '<section class="panel"><div class="tbl-wrap"><table class="tbl compact"><thead><tr><th>Account ID</th><th>Name</th><th>Status</th><th>Joined</th>' +
        '<th class="r">Resources</th><th class="r">Services in use</th><th class="r"></th></tr></thead><tbody>' +
        rows.map(function (a) {
          var s = summaries[a.Id];
          var joined = a.JoinedTimestamp ? new Date(a.JoinedTimestamp * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
          return '<tr><td class="res"><span class="svc-cell"><span class="acct-swatch" style="background:' + swatch(a.Id) + '"></span>' + u().esc(a.Id) + "</span></td>" +
            "<td>" + u().esc(a.Name || "") + (a.Id === cur ? ' <span class="chip accent">current</span>' : "") + "</td>" +
            '<td><span class="chip ' + (a.Status === "ACTIVE" ? "ok" : "warn") + '">' + u().esc(a.Status || "") + "</span></td>" +
            '<td class="dim">' + u().esc((a.JoinedMethod || "").toLowerCase()) + (joined ? " &middot; " + u().esc(joined) : "") + "</td>" +
            '<td class="r num" data-tot="' + u().esc(a.Id) + '">' + (s ? s.total : "&hellip;") + "</td>" +
            '<td class="r num" data-use="' + u().esc(a.Id) + '">' + (s ? s.services_in_use : "&hellip;") + "</td>" +
            '<td class="r"><span class="row-actions">' +
              (a.Id === cur ? "" : '<button class="btn sm" type="button" data-switch="' + u().esc(a.Id) + '">Switch</button>') +
              (a.Id === "000000000000" ? "" : '<button class="btn sm ghost danger" type="button" data-acct-del="' + u().esc(a.Id) + '">Delete</button>') +
            "</span></td></tr>";
        }).join("") + "</tbody></table></div></section>" +
        '<p class="note">Resource totals use the same counters as the overview (' +
        ((DASH.app.state.overview && DASH.app.state.overview.totals && DASH.app.state.overview.totals.services_counted) || "the counted") +
        " services that have one).</p>";
    }
    el.innerHTML = head + body;
    document.getElementById("acctCreate").addEventListener("click", openCreate);
    rows.forEach(function (a) {
      fetchSummary(a.Id).then(function (s) {
        if (!s) return;
        var t = document.querySelector('[data-tot="' + a.Id + '"]');
        var us = document.querySelector('[data-use="' + a.Id + '"]');
        if (t) t.textContent = s.total;
        if (us) us.textContent = s.services_in_use;
      });
    });
  }

  function openCreate() {
    var f = DASH.overlay.field;
    DASH.overlay.modal({
      title: "Create account",
      body: f("Account ID", '<input id="mAcct" type="text" inputmode="numeric" maxlength="12" placeholder="111111111111" class="mono">', "12 digits. Use it as AWS_ACCESS_KEY_ID to act in this account.") +
        f("Name (optional)", '<input id="mName" type="text" placeholder="staging">') +
        f("Email (optional)", '<input id="mEmail" type="text" placeholder="team@example.com">'),
      goLabel: "Create account",
      onGo: function () {
        var id = document.getElementById("mAcct").value.trim();
        if (!/^\d{12}$/.test(id)) return Promise.reject(new Error("Account ID must be exactly 12 digits."));
        var body = { account_id: id };
        var n = document.getElementById("mName").value.trim();
        var em = document.getElementById("mEmail").value.trim();
        if (n) body.name = n;
        if (em) body.email = em;
        return DASH.api.fetchJSON("/_localemu/api/accounts", { method: "POST", body: body, etag: false }).then(function (r) {
          refresh();
          return { label: "account " + id + " registered", data: r.data };
        });
      }
    });
  }

  function del(id) {
    if (!window.confirm("Remove account " + id + " from the registry?\n\nResources it owns in other services are kept.")) return;
    DASH.api.fetchJSON("/_localemu/api/accounts/" + encodeURIComponent(id), { method: "DELETE", etag: false }).then(function () {
      if (DASH.app.state.account === id) DASH.app.setAccount("000000000000");
      refresh();
      DASH.utils.showToast("Account " + id + " removed from the registry");
    }).catch(function (err) { DASH.utils.showApiError(err, "delete account"); });
  }

  function init() {
    document.getElementById("acctBtn").addEventListener("click", openMenu);
    document.addEventListener("click", function (e) {
      if (!e.target.closest) return;
      var sw = e.target.closest("[data-switch]");
      if (sw) { DASH.overlay.close(); DASH.app.setAccount(sw.getAttribute("data-switch")); return; }
      var d = e.target.closest("[data-acct-del]");
      if (d) del(d.getAttribute("data-acct-del"));
    });
    // New access keys register accounts implicitly; pick them up.
    var seen = {};
    DASH.bus.subscribe("call", function (c) {
      if (c && c.account_id && !seen[c.account_id] && !find(c.account_id)) {
        seen[c.account_id] = true;
        refresh();
      }
    });
    renderButton();
  }

  window.DASH.accounts = {
    init: init, render: render, refresh: refresh, renderButton: renderButton, find: find,
    open: function () { DASH.app.navigate({ service: "accounts", resource: null }); },
    list: list, swatch: swatch, openCreate: openCreate
  };
})();
