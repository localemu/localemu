// EventBridge PutEvents modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    // Resolve the bus name. Prefer in priority order:
    //   1. row.bus  (set when called from a rule row in the events list)
    //   2. state.route.resource  (set when called from inside a bus drill-down)
    //   3. "default"  (the always-present AWS account-default bus)
    //
    // Do NOT fall back to row.name -- if the row is a rule, row.name is
    // the rule and the fallback would PutEvents on a bus that doesn't
    // exist (silent misroute).
    var routeRes = (DASH.app && DASH.app.state && DASH.app.state.route.resource) || "";
    var bus = row.bus || routeRes || "default";
    M.open(
      '<h2>EventBridge: ' + u.esc(bus) + '</h2>' +
      '<div class="subtitle">Calls <code>PutEvents</code> on the bus.</div>' +
      '<label>Event bus name</label><input id="ev-bus" type="text" value="' + u.esc(bus) + '">' +
      '<div class="row">' +
        '<div><label>Source</label><input id="ev-source" type="text" value="localemu.dashboard"></div>' +
        '<div><label>Detail type</label><input id="ev-type" type="text" value="Dashboard Test"></div>' +
      '</div>' +
      '<label>Detail (JSON)</label><textarea id="ev-detail">{"hello":"world"}</textarea>' +
      '<div class="action-modal-error" id="ev-err"></div>' +
      '<div id="ev-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="ev-close">Close</button>' +
        '<button type="button" class="primary" id="ev-send">Send event</button>' +
      '</div>'
    );
    document.getElementById("ev-close").addEventListener("click", M.close);
    document.getElementById("ev-send").addEventListener("click", function (e) {
      var err = document.getElementById("ev-err"); err.textContent = "";
      var raw = (document.getElementById("ev-detail").value || "{}").trim();
      var detail; try { detail = JSON.parse(raw); }
      catch (ex) { err.textContent = "Detail is not valid JSON: " + ex.message; return; }
      var actualBus = (document.getElementById("ev-bus").value || "").trim() || "default";
      var body = { entries: [{
        source: document.getElementById("ev-source").value || "localemu.dashboard",
        detail_type: document.getElementById("ev-type").value || "Dashboard Test",
        detail: detail,
        event_bus_name: actualBus
      }] };
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/events/put-events", body, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("ev-result").innerHTML = M.renderResult(r);
        M.invalidate(["resources:events", "events:" + actualBus]);
        M.showToast("Event published", "ok");
      }).catch(function (ex) {
        document.getElementById("ev-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }
  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.eventsPut = { open: open };
})();
