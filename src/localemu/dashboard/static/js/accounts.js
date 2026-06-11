// Accounts panel: list every AWS account the LocalEmu instance has seen,
// with per-account resource counts and a button to mint a new account
// out of band. Backed by ``/_localemu/api/accounts`` (the admin API the
// account registry exposes). Routes on ``#/accounts``.
(function () {
  "use strict";

  var lastFetch = 0;
  var FETCH_MIN_MS = 5000;

  // Resource services we sum to derive the "Resources" badge per row.
  // Stays in line with the admin API's summary route, which already
  // reports counts for these.
  var COUNTED_SERVICES = [
    "s3", "sqs", "sns", "lambda", "dynamodb", "ec2", "kms", "iam",
    "events", "logs", "stepfunctions", "secretsmanager",
    "cloudwatch", "kinesis", "firehose"
  ];

  function fetchAccounts() {
    return DASH.api.get("/_localemu/api/accounts", {
      cacheKey: "accounts:list", ttlMs: 5000, tags: ["accounts"],
    });
  }

  function fetchSummary(id) {
    return DASH.api.get(
      "/_localemu/api/accounts/" + encodeURIComponent(id) + "/summary",
      { cacheKey: "accounts:summary:" + id, ttlMs: 10000, tags: ["accounts"] },
    );
  }

  function open() {
    if (DASH.app.state.route.service !== "accounts") {
      DASH.app.navigate({ service: "accounts", resource: null });
    }
  }

  function render() {
    var state = DASH.app.state;
    if (state.route.service !== "accounts") return;
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    if (!elMain) return;

    // First render: paint a skeleton so the user sees something
    // immediately; the fetch resolves in-line.
    if (elMain.dataset.lastKey !== "accounts:loading"
        && elMain.dataset.lastKey !== "accounts:loaded") {
      elMain.innerHTML = headerHtml() + '<div class="accounts-empty">Loading accounts...</div>';
      elMain.dataset.lastKey = "accounts:loading";
    }

    fetchAccounts().then(function (resp) {
      var accounts = (resp && resp.Accounts) || [];
      var rows = accounts.slice().sort(function (a, b) {
        return (a.Id || "").localeCompare(b.Id || "");
      });

      // Fan out summary fetches so the resource column populates without
      // blocking the initial render of the rows themselves.
      rows.forEach(function (rec) {
        fetchSummary(rec.Id).then(function (sum) {
          var cell = document.querySelector(
            '.accounts-resource-count[data-acct="' + cssEsc(rec.Id) + '"]',
          );
          if (!cell) return;
          var total = 0;
          var perService = (sum && sum.resources) || {};
          COUNTED_SERVICES.forEach(function (s) {
            total += (perService[s] | 0);
          });
          // Show the total and a quick breakdown of the top 3 services on hover.
          var breakdown = Object.keys(perService)
            .filter(function (s) { return perService[s] > 0; })
            .sort(function (a, b) { return perService[b] - perService[a]; })
            .slice(0, 5)
            .map(function (s) { return s + ":" + perService[s]; })
            .join(", ");
          cell.textContent = String(total);
          if (breakdown) cell.title = breakdown;
        }).catch(function () { /* silent */ });
      });

      var key = "accounts:" + rows.map(function (r) {
        return r.Id + ":" + r.Status + ":" + r.JoinedMethod;
      }).join(",");
      if (elMain.dataset.lastKey === key) return;
      elMain.dataset.lastKey = key;

      var body = "";
      if (!rows.length) {
        body = '<div class="accounts-empty">No accounts registered yet. '
             + 'Hit any AWS endpoint and the access key will be auto-registered.</div>';
      } else {
        body = '<table class="accounts-table">'
             + '<thead><tr>'
             + '<th>Account ID</th>'
             + '<th>Name</th>'
             + '<th>Email</th>'
             + '<th>Status</th>'
             + '<th>Joined</th>'
             + '<th class="num">Resources</th>'
             + '<th></th>'
             + '</tr></thead><tbody>';
        rows.forEach(function (rec) {
          var statusCls = (rec.Status === "ACTIVE") ? "active" : "suspended";
          body += '<tr data-acct="' + u.esc(rec.Id) + '">'
               + '<td class="acct-id">' + u.esc(rec.Id) + '</td>'
               + '<td>' + u.esc(rec.Name || "") + '</td>'
               + '<td class="acct-email">' + u.esc(rec.Email || "") + '</td>'
               + '<td><span class="acct-status ' + statusCls + '">' + u.esc(rec.Status || "") + '</span></td>'
               + '<td>' + u.esc(rec.JoinedMethod || "") + '</td>'
               + '<td class="num accounts-resource-count" data-acct="' + u.esc(rec.Id) + '">...</td>'
               + '<td class="acct-actions">';
          if (rec.Id !== "000000000000") {
            body += '<button class="acct-delete-btn" data-acct="' + u.esc(rec.Id) + '" type="button">Delete</button>';
          }
          body += '</td>'
               + '</tr>';
        });
        body += '</tbody></table>';
      }

      elMain.innerHTML = headerHtml() + body;
    }).catch(function (err) {
      elMain.innerHTML = headerHtml()
        + '<div class="accounts-empty">Failed to load accounts: '
        + u.esc(err && err.message ? err.message : String(err)) + '</div>';
      elMain.dataset.lastKey = "accounts:error";
    });
  }

  function headerHtml() {
    return '<div class="accounts-header">'
         + '<div class="accounts-header-left">'
         + DASH.utils.iconHtml("iam", 28)
         + '<div>'
         + '<h1 class="accounts-title">Accounts</h1>'
         + '<p class="accounts-subtitle">Every AWS account this LocalEmu instance has seen. Access keys are auto-registered on first use.</p>'
         + '</div>'
         + '</div>'
         + '<div class="accounts-header-right">'
         + '<button id="accounts-create-btn" type="button" class="accounts-create-btn">+ Create account</button>'
         + '</div>'
         + '</div>';
  }

  function cssEsc(s) {
    return String(s || "").replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function init() {
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    elMain.addEventListener("click", function (e) {
      if (e.target.id === "accounts-create-btn") {
        return promptCreate();
      }
      var del = e.target.closest(".acct-delete-btn");
      if (del) {
        return promptDelete(del.dataset.acct);
      }
    });
  }

  function promptCreate() {
    var id = window.prompt("12-digit account ID:");
    if (!id) return;
    if (!/^\d{12}$/.test(id)) {
      window.alert("Account ID must be exactly 12 digits.");
      return;
    }
    var name = window.prompt("Display name (optional):", "");
    var body = { account_id: id };
    if (name) body.name = name;
    fetch("/_localemu/api/accounts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) {
      return r.json().then(function (data) {
        if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
        return data;
      });
    }).then(function () {
      DASH.api.invalidate(["accounts"]);
      // Force re-render
      var elMain = document.getElementById("main-content");
      if (elMain) elMain.dataset.lastKey = "";
      render();
    }).catch(function (e) {
      window.alert("Create failed: " + e.message);
    });
  }

  function promptDelete(id) {
    if (!window.confirm("Delete account " + id + " from the registry?\n\n"
        + "Resources owned by this account in other services are kept.")) {
      return;
    }
    fetch("/_localemu/api/accounts/" + encodeURIComponent(id), {
      method: "DELETE",
    }).then(function (r) {
      return r.json().then(function (data) {
        if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
        return data;
      });
    }).then(function () {
      DASH.api.invalidate(["accounts"]);
      var elMain = document.getElementById("main-content");
      if (elMain) elMain.dataset.lastKey = "";
      render();
    }).catch(function (e) {
      window.alert("Delete failed: " + e.message);
    });
  }

  DASH.accounts = { open: open, render: render, init: init };
})();
