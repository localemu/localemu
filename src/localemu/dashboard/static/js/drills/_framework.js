// Shared tabbed drill framework.
//
// Every per-service drill declares one DrillSpec and the framework
// renders the AWS-Console-style page:
//
//   [icon] [Title]  [Tier badge]  [actions]   [Back to <service>]
//   [tabs: Overview | Permissions | ... | Recent activity]
//   [active-tab body]
//
// DrillSpec shape:
//   {
//     service: "iam",         // registry service name (for tier badge)
//     kind: "roles",          // optional sub-kind (for sub-routes)
//     title: function(row),
//     subtitle: function(row),
//     fetch: function(key, ctx) -> Promise<row>,
//     tabs: [
//       { id, label, render(row, ctx) -> HTMLString | Element,
//         availableWhen(row) -> bool (optional) },
//       ...
//     ],
//     actions: [
//       { id, label, primary?, destructive?, run(row, ctx) },
//       ...
//     ],
//     backTo: function(row),    // navigate target (default: service overview)
//     defaultTab: "overview",
//   }
//
// The framework owns:
//   - lazy fetch of the row (drill.fetch)
//   - tab strip with active state
//   - URL fragment for active tab (#/svc/key/tabId)
//   - lazy render per-tab (tab.render only fires on activate)
//   - "Recent activity" tab inserted automatically when not declared
//   - tier banner (Live / Metadata only / Not emulated) from registry
//   - destructive-action confirm
//
// Usage:
//   DASH.drills.framework.open(drillSpec, key, meta);
(function () {
  "use strict";

  // Common identifier fields across AWS resource shapes. The drill
  // framework uses keyOf(row) to find the right identifier for tab
  // navigation (so the URL stays on the drill page instead of
  // bouncing back to the service list) AND for destructive-confirm
  // (so the user has a real string to type). Per-service drills can
  // override by setting ``spec.keyOf(row) -> string``.
  var KEY_FIELDS = [
    "name", "key", "id", "arn",
    "instance_id", "function_name", "key_id",
    "db_instance_identifier", "db_cluster_identifier",
    "cluster_name", "table_name", "queue_name", "bucket_name",
    "topic_name", "role_name", "user_name", "group_name",
    "stack_name", "stream_name", "broker_name", "domain_name",
    "alias", "state_machine_arn", "execution_arn",
  ];
  function keyOf(row, spec) {
    if (!row) return "";
    if (spec && typeof spec.keyOf === "function") {
      try {
        var v = spec.keyOf(row);
        if (v != null && v !== "") return String(v);
      } catch (_) { /* fall through to default chain */ }
    }
    for (var i = 0; i < KEY_FIELDS.length; i++) {
      var f = KEY_FIELDS[i];
      if (row[f] != null && row[f] !== "") return String(row[f]);
    }
    return "";
  }

  function open(spec, key, meta) {
    if (!spec) {
      renderNotFound(key);
      return;
    }
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    elMain.innerHTML = '<div class="loading-state">Loading...</div>';

    var fetch = spec.fetch || function (k, ctx) {
      return Promise.resolve({ name: k, key: k });
    };
    Promise.resolve(fetch(key, makeCtx(spec))).then(function (row) {
      if (!row) row = { name: key, key: key };
      render(spec, row, meta || {});
    }).catch(function (err) {
      renderError(spec, key, err);
    });
  }

  function makeCtx(spec) {
    return {
      service: spec.service,
      kind: spec.kind,
      fetchJson: function (path, opts) {
        return DASH.api.fetchJSON(path, opts || { etag: false, timeoutMs: 8000 });
      },
      iconHtml: function (name, size) { return DASH.utils.iconHtml(name, size || 24); },
      esc: function (s) { return DASH.utils.esc(s); },
      relativeTime: function (ts) {
        if (!ts) return "-";
        try {
          var t = (typeof ts === "string") ? Date.parse(ts) : Number(ts);
          if (isNaN(t)) return String(ts);
          var d = Math.round((Date.now() - t) / 1000);
          if (d < 60) return d + "s ago";
          if (d < 3600) return Math.round(d / 60) + "m ago";
          if (d < 86400) return Math.round(d / 3600) + "h ago";
          return Math.round(d / 86400) + "d ago";
        } catch (e) { return String(ts); }
      },
      copyToClipboard: function (text) { DASH.utils.copyToClipboard(text); },
      // Render a Recent-activity tab body driven by CloudTrail
      // filtered by the spec. Returns an HTML string.
      activity: renderActivityTab,
    };
  }

  function render(spec, row, meta) {
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    var u = DASH.utils;
    var ctx = makeCtx(spec);

    // Compose tabs; auto-append Recent activity if not present.
    var tabs = (spec.tabs || []).slice();
    var hasActivity = tabs.some(function (t) { return t.id === "activity"; });
    if (!hasActivity && spec.service) {
      tabs.push({
        id: "activity",
        label: "Recent activity",
        render: function (r, c) {
          return c.activity({
            filters: defaultActivityFilters(spec, r),
            limit: 50,
          });
        }
      });
    }

    var defaultTab = (meta && meta.tab) || spec.defaultTab || (tabs[0] && tabs[0].id);
    var activeTabId = defaultTab;

    var titleHtml = (typeof spec.title === "function") ? spec.title(row) : (row.name || "");
    var subtitleHtml = (typeof spec.subtitle === "function") ? spec.subtitle(row) : "";
    var badge = DASH.registry.tierBadge(spec.service || "");

    var html = '<div class="detail-header drill-header">';
    if (spec.service) html += u.iconHtml(spec.service, 28);
    html += '<h2>' + u.esc(titleHtml) + '</h2>';
    html += '<span class="tier-badge ' + badge.cls + '">' + u.esc(badge.label) + '</span>';
    if (subtitleHtml) html += '<span class="drill-subtitle">' + u.esc(subtitleHtml) + '</span>';
    (spec.actions || []).forEach(function (a) {
      var cls = "row-action" + (a.primary ? " primary" : "") + (a.destructive ? " destructive" : "");
      html += '<button class="' + cls + '" data-drill-action="' + u.esc(a.id) + '">' + u.esc(a.label) + '</button>';
    });
    var backLabel = "&larr; Back";
    if (spec.service) backLabel = "&larr; Back to " + u.esc(DASH.registry.label(spec.service));
    html += '<button class="back-link" id="drill-back-btn">' + backLabel + '</button>';
    html += '</div>';

    // Optional service-level honesty banner
    var bnr = spec.service ? DASH.registry.banner(spec.service) : "";
    if (bnr) {
      html += '<div class="tier-banner tier-banner-' + (DASH.registry.tier(spec.service) || "metadata") + '">';
      html += u.esc(bnr);
      html += '</div>';
    }

    // Tab strip
    html += '<div class="drill-tabs">';
    tabs.forEach(function (t) {
      var disabled = (typeof t.availableWhen === "function") && !t.availableWhen(row);
      var cls = "drill-tab" + (t.id === activeTabId ? " active" : "") + (disabled ? " disabled" : "");
      html += '<button class="' + cls + '" data-drill-tab="' + u.esc(t.id) + '"' + (disabled ? " disabled" : "") + '>' + u.esc(t.label) + '</button>';
    });
    html += '</div>';

    html += '<div class="drill-body" id="drill-body"></div>';

    elMain.innerHTML = html;

    // Wire back + actions + tabs
    var back = document.getElementById("drill-back-btn");
    if (back) back.addEventListener("click", function () {
      if (typeof spec.backTo === "function") {
        spec.backTo(row);
      } else if (spec.service) {
        DASH.app.navigate({ service: spec.service, resource: null });
      } else {
        DASH.app.navigate({ service: null, resource: null });
      }
    });

    elMain.querySelectorAll("[data-drill-action]").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        var aid = btn.getAttribute("data-drill-action");
        var act = (spec.actions || []).find(function (a) { return a.id === aid; });
        if (!act) return;
        if (act.destructive) {
          // Show the user the actual identifier they need to type. Prefer
          // the drill's title (already in the heading), fall back to
          // keyOf(row) so the prompt is never asking against an empty
          // string (the bug that made destructive buttons look dead).
          var titleStr = (typeof spec.title === "function")
            ? String(spec.title(row) || "")
            : "";
          var expected = String(keyOf(row, spec) || titleStr || "").trim();
          var typed = window.prompt(
            'Type "' + (expected || act.label) + '" to confirm '
              + act.label + ":",
            ""
          );
          if (typed === null) return;
          if (!expected) {
            DASH.utils.showToast(
              "Cancelled: no identifier to confirm against", "error",
            );
            return;
          }
          if (typed.trim() !== expected) {
            DASH.utils.showToast("Cancelled: name did not match", "error");
            return;
          }
        }
        try { act.run(row, ctx); } catch (err) { DASH.utils.showApiError(err, "action"); }
      });
    });

    elMain.querySelectorAll("[data-drill-tab]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        if (btn.disabled) return;
        activeTabId = btn.getAttribute("data-drill-tab");
        elMain.querySelectorAll("[data-drill-tab]").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
        renderActiveTab(tabs, activeTabId, row, ctx);
        // Persist tab in the URL hash so back/forward + bookmarks
        // restore it. navigate() short-circuits the drill re-render
        // when only the tab changed, so this is cheap. We must pass
        // the actual resource identifier (instance_id for EC2,
        // function_name for Lambda, ...) so the short-circuit check
        // matches; otherwise navigate() treats the call as "drop to
        // service list" and bounces the user back.
        if (spec.service) {
          var navKey = keyOf(row, spec);
          var sub = (meta && meta.highlight) || null;
          if (navKey) {
            DASH.app.navigate({
              service: spec.service, resource: navKey,
              tab: activeTabId, sub: sub,
            });
          }
        }
      });
    });

    renderActiveTab(tabs, activeTabId, row, ctx);
  }

  function renderActiveTab(tabs, id, row, ctx) {
    var tab = tabs.find(function (t) { return t.id === id; });
    var body = document.getElementById("drill-body");
    if (!body) return;
    if (!tab) { body.innerHTML = ""; return; }
    body.innerHTML = '<div class="loading-state">Loading...</div>';
    try {
      var out = tab.render(row, ctx);
      if (typeof out === "string") {
        body.innerHTML = out;
      } else if (out && out.then) {
        out.then(function (h) {
          body.innerHTML = (typeof h === "string") ? h : "";
        }).catch(function (err) {
          body.innerHTML = '<div class="empty-state">' + DASH.utils.esc("Error: " + (err && err.message || err)) + '</div>';
        });
      } else if (out instanceof Element) {
        body.innerHTML = "";
        body.appendChild(out);
      } else {
        body.innerHTML = "";
      }
    } catch (err) {
      body.innerHTML = '<div class="empty-state">' + DASH.utils.esc("Render error: " + (err && err.message || err)) + '</div>';
    }
  }

  // A5: Recent activity tab helper. ``spec`` is
  //   { filters: { eventSource, eventName?, resourceName?, principal? },
  //     limit, columns? }
  function renderActivityTab(spec) {
    var qs = "limit=" + (spec.limit || 50);
    var f = spec.filters || {};
    if (f.eventSource) qs += "&service=" + encodeURIComponent(stripServiceSuffix(f.eventSource));
    return DASH.api.fetchJSON("/_localemu/api/cloudtrail?" + qs, { etag: false, timeoutMs: 6000 })
      .then(function (resp) {
        var events = (resp && resp.data && resp.data.events) || [];
        // Client-side narrowing for extra filters (resourceName, eventName).
        if (f.eventName) {
          events = events.filter(function (e) { return e.eventName === f.eventName; });
        }
        if (f.resourceName) {
          events = events.filter(function (e) {
            var blob = JSON.stringify(e.requestParameters || {});
            return blob.indexOf(f.resourceName) !== -1
              || (e.resources || []).some(function (r) {
                return (r && (r.ARN || r.arn || "")).indexOf(f.resourceName) !== -1;
              });
          });
        }
        if (f.principal) {
          events = events.filter(function (e) {
            var u = (e.userIdentity && (e.userIdentity.userName || e.userIdentity.arn)) || "";
            return u && u.indexOf(f.principal) !== -1;
          });
        }
        return renderActivityRows(events, spec.columns);
      })
      .catch(function () {
        return '<div class="empty-state">Failed to load activity.</div>';
      });
  }

  function stripServiceSuffix(es) {
    return String(es || "").replace(/\.amazonaws\.com$/, "");
  }

  function renderActivityRows(events, columns) {
    var u = DASH.utils;
    if (!events.length) {
      return '<div class="empty-state">No recent activity recorded for this resource.</div>';
    }
    var cols = columns || ["Time", "Operation", "User", "Status", "Request ID"];
    var html = '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
    cols.forEach(function (c) { html += '<th>' + u.esc(c) + '</th>'; });
    html += '</tr></thead><tbody>';
    events.forEach(function (e) {
      var rid = e.requestId || e.requestID || "";
      var code = e.responseCode || 0;
      var cls = u.statusClass(code);
      var when = u.formatTimestamp(e.eventTime);
      var who = (e.userIdentity && (e.userIdentity.userName || e.userIdentity.arn)) || e.user || "-";
      html += '<tr>';
      cols.forEach(function (c) {
        var val = "";
        switch (c) {
          case "Time":       val = when; break;
          case "Operation":  val = e.eventName || ""; break;
          case "User":       val = who; break;
          case "Status":     val = '<span class="activity-status ' + cls + '">' + u.esc(code) + '</span>'; break;
          case "Request ID": val = rid; break;
          case "Source":     val = stripServiceSuffix(e.eventSource); break;
          case "Region":     val = e.awsRegion || "-"; break;
          default:           val = String(e[c.toLowerCase()] || "");
        }
        if (c === "Status") html += '<td>' + val + '</td>';
        else html += '<td>' + u.esc(val) + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
  }

  function defaultActivityFilters(spec, row) {
    var source = spec.service ? (spec.service + ".amazonaws.com") : "";
    // Strip our extra-hop service-id suffixes like "events.amazonaws.com"
    // that CloudTrail does not natively produce.
    var f = { eventSource: source };
    var rn = row.name || row.key || row.arn || row.key_id || row.id;
    if (rn) f.resourceName = String(rn);
    return f;
  }

  function renderNotFound(key) {
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    elMain.innerHTML = '<div class="empty-state">No drill registered for resource ' + DASH.utils.esc(key || "") + '</div>';
  }

  function renderError(spec, key, err) {
    var elMain = document.getElementById("main-content");
    if (!elMain) return;
    elMain.innerHTML = '<div class="empty-state">Failed to load '
      + DASH.utils.esc(key || "")
      + ': ' + DASH.utils.esc((err && err.message) || String(err))
      + '</div>';
  }

  // -------------------------------------------------------------------
  // Reusable cell helpers exposed to drill render functions.
  // -------------------------------------------------------------------
  function jsonBlock(obj, opts) {
    opts = opts || {};
    var u = DASH.utils;
    var text;
    try {
      text = (obj === null || obj === undefined) ? "" : JSON.stringify(obj, null, 2);
    } catch (e) { text = String(obj); }
    var max = opts.maxHeight || 360;
    return '<pre class="drill-json" style="max-height:' + max + 'px;overflow:auto">'
      + u.esc(text) + '</pre>';
  }

  function kvTable(rows) {
    var u = DASH.utils;
    var html = '<table class="drill-kv"><tbody>';
    rows.forEach(function (r) {
      var k = r[0]; var v = r[1];
      var rendered;
      if (v && typeof v === "object") rendered = jsonBlock(v, { maxHeight: 200 });
      else rendered = u.esc(v == null ? "-" : String(v));
      html += '<tr><th>' + u.esc(k) + '</th><td>' + rendered + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
  }

  function table(rows, columns) {
    var u = DASH.utils;
    if (!rows || rows.length === 0) {
      return '<div class="empty-state">No items.</div>';
    }
    var html = '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
    columns.forEach(function (c) { html += '<th>' + u.esc(c.label || c.key) + '</th>'; });
    html += '</tr></thead><tbody>';
    rows.forEach(function (row) {
      html += '<tr>';
      columns.forEach(function (c) {
        var v = (typeof c.render === "function") ? c.render(row) : (row[c.key] == null ? "-" : row[c.key]);
        if (c.html) html += '<td>' + v + '</td>';
        else html += '<td>' + u.esc(String(v)) + '</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
  }

  // Generic drill spec used when a service has no custom drill.
  // Pulls the row from the list payload (already in state.resources)
  // and renders a 3-tab page: Overview (kv table), JSON (raw row),
  // Recent activity (CloudTrail filtered to the service).
  function genericSpec(service) {
    return {
      service: service,
      title: function (row) { return row.name || row.key || row.arn || ""; },
      subtitle: function (row) { return row.region || ""; },
      fetch: function (key) {
        // First check state.resources -- the user clicked from a list
        // that the resources panel just loaded. Walk fields for a key
        // match. If not found, return a minimal stub.
        try {
          var rows = (DASH.app.state.resources || []);
          var hit = rows.find(function (r) {
            return r.name === key || r.id === key || r.arn === key || r.key_id === key;
          });
          if (hit) return Promise.resolve(hit);
        } catch (e) { /* fall through */ }
        return Promise.resolve({ name: key, key: key });
      },
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            var rows = Object.keys(row).map(function (k) {
              var v = row[k];
              return [k, v];
            });
            return kvTable(rows);
          }
        },
        {
          id: "json", label: "JSON",
          render: function (row) {
            return '<p class="hint">Full resource record as the dashboard sees it.</p>' + jsonBlock(row);
          }
        },
      ],
    };
  }

  function openGeneric(service, key, meta) {
    open(genericSpec(service), key, meta);
  }

  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.framework = {
    open: open,
    openGeneric: openGeneric,
    genericSpec: genericSpec,
    keyOf: keyOf,
    helpers: { jsonBlock: jsonBlock, kvTable: kvTable, table: table },
  };
})();
