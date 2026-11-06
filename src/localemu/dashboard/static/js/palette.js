// Command palette (Cmd/Ctrl+K or "/").
//
// Searches three real sources:
//   Services   every registered service (registry, 132), ranked by count
//   Resources  the resource lists (/_localemu/api/resources/<svc>) of the
//              services that have resources in the current account,
//              fetched when the palette opens
//   Actions    console actions that do something real: create resources
//              through /_localemu/api/actions, switch account, open pages,
//              pause the live panel, toggle theme, copy endpoint exports
(function () {
  "use strict";

  var items = [], sel = 0;
  var resIndex = [];        // [{svc, name, key, detail}]
  var resLoading = false;

  function u() { return DASH.utils; }

  // Create forms: service -> {action, title, fields, body(form) -> json}
  var CREATE = {
    s3: { action: "create-bucket", title: "Create S3 bucket", ph: "my-bucket", help: "Lowercase letters, digits, dots and hyphens." },
    sqs: { action: "create-queue", title: "Create SQS queue", ph: "my-queue", help: "End the name with .fifo for a FIFO queue." },
    sns: { action: "create-topic", title: "Create SNS topic", ph: "my-topic" },
    dynamodb: { action: "create-table", title: "Create DynamoDB table", ph: "my-table", pk: true }
  };

  function openCreate(svc) {
    var spec = CREATE[svc];
    if (!spec) return openCliCreate(svc);
    var f = DASH.overlay.field;
    var region = (DASH.app.state.system && DASH.app.state.system.default_region) || "us-east-1";
    DASH.overlay.modal({
      title: spec.title, sub: "account " + DASH.app.state.account, svc: svc,
      body: f("Name", '<input id="mName" type="text" placeholder="' + spec.ph + '">', spec.help) +
        (spec.pk ? f("Partition key (string)", '<input id="mPk" type="text" value="id">', "On-demand billing. Add sort keys and indexes with the CLI.") : "") +
        f("Region", '<input id="mRegion" type="text" value="' + u().esc(region) + '">'),
      goLabel: "Create",
      onGo: function () {
        var body = { name: document.getElementById("mName").value.trim(), region: document.getElementById("mRegion").value.trim() || region };
        if (spec.pk) body.partition_key = document.getElementById("mPk").value.trim() || "id";
        return DASH.api.post("/_localemu/api/actions/" + svc + "/" + spec.action, body, { timeoutMs: 20000 }).then(function (r) {
          DASH.cache.invalidateKey("resources:" + svc);
          if (DASH.app.state.route.service === svc && DASH.resources.refresh) DASH.resources.refresh(true);
          return { label: svc + " " + spec.action, data: r.data && r.data.result };
        });
      }
    });
  }

  // Services without a console create form: show the real CLI command.
  function openCliCreate(svc) {
    var cmd = DASH.registry.emptyStateText(svc);
    var ep = (DASH.app.state.system && DASH.app.state.system.endpoint) || window.location.origin;
    DASH.overlay.modal({
      title: "Create " + DASH.catalog.label(svc), svc: svc,
      body: cmd
        ? '<p class="note">The console creates S3 buckets, SQS queues, SNS topics and DynamoDB tables directly. For ' + u().esc(DASH.catalog.label(svc)) +
          ", run one of these against LocalEmu (awsemu is a shell alias for the AWS CLI with " + u().esc(ep) + " as its endpoint; the aws cli line works with no alias set up):</p>" +
          u().cmdBlock([{ label: "awsemu", cmd: cmd }, { label: "aws cli", cmd: u().toAwsCli(cmd, ep) }])
        : '<p class="note">No create form or sample command is available for ' + u().esc(DASH.catalog.label(svc)) + ". Use the AWS CLI or SDK against " +
          u().esc(ep) + ".</p>"
    });
  }

  function actions() {
    var a = [];
    Object.keys(CREATE).forEach(function (svc) {
      a.push({ label: CREATE[svc].title, hint: "create " + svc, icon: svc, run: function () { openCreate(svc); } });
    });
    a.push({ label: "Open CloudTrail events", hint: "cloudtrail", run: function () { DASH.app.navigate({ service: "cloudtrail" }); } });
    a.push({ label: "Manage accounts", hint: "accounts", run: function () { DASH.app.navigate({ service: "accounts" }); } });
    a.push({ label: "Create account", hint: "accounts create", run: function () { DASH.accounts.openCreate(); } });
    DASH.accounts.list().forEach(function (acc) {
      if (acc.Id === DASH.app.state.account) return;
      a.push({ label: "Switch to account " + acc.Id + (acc.Name ? " (" + acc.Name + ")" : ""), hint: "switch account", run: function () { DASH.app.setAccount(acc.Id); } });
    });
    a.push({ label: DASH.wire.isPaused() ? "Resume live calls" : "Pause live calls", hint: "live stream", run: function () { DASH.wire.togglePause(); } });
    a.push({ label: "Toggle theme", hint: "light / dark", run: function () { DASH.theme.toggle(); } });
    a.push({ label: "Copy endpoint exports", hint: "shell", run: function () {
      var sys = DASH.app.state.system || {};
      var key = DASH.app.state.account === "000000000000" ? "test" : DASH.app.state.account;
      u().copyToClipboard("export AWS_ENDPOINT_URL=" + (sys.endpoint || window.location.origin) + " AWS_ACCESS_KEY_ID=" + key +
        " AWS_SECRET_ACCESS_KEY=test AWS_REGION=" + (sys.default_region || "us-east-1"));
    } });
    return a;
  }

  function loadResources() {
    if (resLoading) return;
    resLoading = true;
    var c = DASH.catalog;
    var svcs = c.services().filter(function (s) { return c.counted(s) && c.count(s) > 0 && s !== "cloudtrail"; });
    var acct = DASH.app.state.account;
    var next = [];
    Promise.all(svcs.map(function (svc) {
      var url = "/_localemu/api/resources/" + encodeURIComponent(svc) + "?account=" + encodeURIComponent(acct);
      return DASH.api.get(url, { cacheKey: "palette:" + acct + ":" + svc, ttlMs: 15000 }).then(function (r) {
        ((r.value && r.value.resources) || []).forEach(function (row) {
          var key = row.name || row.instance_id || row.id || row.key_id || row.arn || "";
          if (!key) return;
          next.push({ svc: svc, name: String(row.name || key), key: String(key), row: row });
        });
      }).catch(function () {});
    })).then(function () {
      resIndex = next;
      resLoading = false;
      var inp = document.getElementById("palIn");
      if (inp) renderList(inp.value);
    });
  }

  function open(prefill) {
    sel = 0;
    DASH.overlay.open('<div class="scrim" data-close="1"></div><div class="palette" role="dialog" aria-label="Search">' +
      '<div class="palette-in">' + u().ICON.search +
      '<input id="palIn" type="text" placeholder="Jump to a service, resource or action" autocomplete="off" aria-label="Search"><kbd>esc</kbd></div>' +
      '<div class="palette-list" id="palList"></div><div class="palette-foot"><span><kbd>&uarr;</kbd> <kbd>&darr;</kbd> move</span>' +
      '<span><kbd>&crarr;</kbd> open</span><span id="palCount"></span></div></div>');
    var inp = document.getElementById("palIn");
    if (prefill) inp.value = prefill;
    inp.focus();
    inp.addEventListener("input", function () { sel = 0; renderList(inp.value); });
    inp.addEventListener("keydown", keys);
    renderList(inp.value);
    loadResources();
  }

  function matches(text, q) { return String(text).toLowerCase().indexOf(q) !== -1; }

  function renderList(q) {
    var box = document.getElementById("palList");
    if (!box) return;
    q = (q || "").trim().toLowerCase();
    var c = DASH.catalog;
    var all = c.services();
    var svcs = all.filter(function (s) { return !q || matches(c.label(s), q) || matches(s, q); })
      .sort(function (a, b) { return (c.count(b) + c.recentCalls(b)) - (c.count(a) + c.recentCalls(a)) || c.label(a).localeCompare(c.label(b)); })
      .slice(0, q ? 8 : 6);
    var res = q.length > 1 ? resIndex.filter(function (r) { return matches(r.name, q) || matches(r.key, q); }).slice(0, 8) : [];
    var acts = actions().filter(function (a) { return !q || matches(a.label, q) || matches(a.hint, q); });
    items = [];
    var html = "";
    function item(ic, lbl, hint) {
      var i = items.length - 1;
      return '<div class="pl-item' + (i === sel ? " sel" : "") + '" data-pi="' + i + '">' + ic + '<span class="lbl">' + lbl + '</span><span class="hint">' + u().esc(hint) + "</span></div>";
    }
    if (svcs.length) {
      html += '<div class="pl-group">Services</div>';
      svcs.forEach(function (s) {
        items.push(function () { DASH.app.navigate({ service: s }); });
        html += item(u().tile(s, "sm"), u().esc(c.label(s)), c.counted(s) ? c.count(s) + " res" : s);
      });
    }
    if (res.length) {
      html += '<div class="pl-group">Resources in ' + u().esc(DASH.app.state.account) + "</div>";
      res.forEach(function (r) {
        items.push(function () { DASH.resources.openRow(r.svc, r.row); });
        html += item(u().tile(r.svc, "sm"), '<span class="mono">' + u().esc(r.name) + "</span>", c.label(r.svc));
      });
    } else if (q.length > 1 && resLoading) {
      html += '<div class="pl-group">Resources</div><div class="pl-item" style="cursor:default"><span class="lbl note">Searching resource lists...</span></div>';
    }
    if (acts.length) {
      html += '<div class="pl-group">Actions</div>';
      acts.forEach(function (a) {
        items.push(a.run);
        html += item(a.icon ? u().tile(a.icon, "sm") : '<span class="pl-ico">' + u().ICON.bolt + "</span>", u().esc(a.label), a.hint);
      });
    }
    if (!items.length) html = '<div class="pl-group">No match for "' + u().esc(q) + '"</div>';
    box.innerHTML = html;
    var cnt = document.getElementById("palCount");
    if (cnt) cnt.textContent = "Matches all " + DASH.registry.aws().length + " services" + (resIndex.length ? " and " + resIndex.length + " resources" : "");
  }

  function keys(e) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!items.length) return;
      sel = (sel + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
      document.querySelectorAll(".pl-item[data-pi]").forEach(function (el) { el.classList.toggle("sel", +el.getAttribute("data-pi") === sel); });
      var s = document.querySelector(".pl-item.sel");
      if (s && s.scrollIntoView) s.scrollIntoView({ block: "nearest" });
    } else if (e.key === "Enter" && items[sel]) {
      e.preventDefault();
      var f = items[sel];
      DASH.overlay.close();
      f();
    }
  }

  function init() {
    document.getElementById("searchBtn").addEventListener("click", function () { open(); });
    document.addEventListener("click", function (e) {
      var el = e.target.closest && e.target.closest("#palList [data-pi]");
      if (!el) return;
      var f = items[+el.getAttribute("data-pi")];
      DASH.overlay.close();
      if (f) f();
    });
    document.addEventListener("keydown", function (e) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); open(); return; }
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(tag) && !DASH.overlay.isOpen() &&
          !(document.getElementById("action-modal-backdrop") || {}).classList.contains("open")) {
        e.preventDefault();
        open();
      }
    });
  }

  window.DASH.palette = { init: init, open: open, openCreate: openCreate, canCreate: function (svc) { return !!CREATE[svc]; } };
})();
