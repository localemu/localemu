// DynamoDB PutItem + GetItem + Query + Scan modal.
(function () {
  "use strict";
  function open(row) {
    var u = DASH.utils, M = DASH.actions._modal;
    var table = row.name || "";
    M.open(
      '<h2>DynamoDB: ' + u.esc(table) + '</h2>' +
      '<div class="subtitle">All operations use AttributeValue form (<code>{"id":{"S":"x"}}</code>). Limit applies to Scan and Query.</div>' +
      '<label>Item / Key (PutItem uses Item; GetItem uses Key)</label>' +
      '<textarea id="ddb-item">{"id":{"S":"demo"},"value":{"N":"1"}}</textarea>' +
      '<label>KeyConditionExpression (Query)</label>' +
      '<input id="ddb-kce" type="text" placeholder="e.g. id = :id">' +
      '<label>ExpressionAttributeValues (Query, JSON)</label>' +
      '<textarea id="ddb-eav">{":id":{"S":"demo"}}</textarea>' +
      '<div class="row">' +
        '<div><label>Limit (Scan / Query)</label><input id="ddb-limit" type="number" min="1" max="1000" value="10"></div>' +
      '</div>' +
      '<div class="action-modal-error" id="ddb-err"></div>' +
      '<div id="ddb-result"></div>' +
      '<div class="action-modal-actions">' +
        '<button type="button" id="ddb-close">Close</button>' +
        '<button type="button" id="ddb-scan">Scan</button>' +
        '<button type="button" id="ddb-query">Query</button>' +
        '<button type="button" id="ddb-get">Get item</button>' +
        '<button type="button" class="primary" id="ddb-put">Put item</button>' +
      '</div>'
    );
    document.getElementById("ddb-close").addEventListener("click", M.close);

    function parseItemField() {
      var raw = (document.getElementById("ddb-item").value || "{}").trim();
      try { return [JSON.parse(raw), null]; }
      catch (ex) { return [null, "Item is not valid JSON: " + ex.message]; }
    }
    function clearErr() { document.getElementById("ddb-err").textContent = ""; }
    function setErr(msg) { document.getElementById("ddb-err").textContent = msg; }

    document.getElementById("ddb-put").addEventListener("click", function (e) {
      clearErr();
      var parts = parseItemField(); if (parts[1]) { setErr(parts[1]); return; }
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/dynamodb/put-item", { table_name: table, item: parts[0] }, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("ddb-result").innerHTML = M.renderResult(r);
        M.invalidate(["resources:dynamodb", "ddb:" + table]);
        M.showToast("Item written", "ok");
      }).catch(function (ex) {
        document.getElementById("ddb-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
    document.getElementById("ddb-get").addEventListener("click", function (e) {
      clearErr();
      var parts = parseItemField(); if (parts[1]) { setErr(parts[1]); return; }
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/dynamodb/get-item", { table_name: table, key: parts[0] }, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("ddb-result").innerHTML = M.renderResult(r);
      }).catch(function (ex) {
        document.getElementById("ddb-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
    document.getElementById("ddb-query").addEventListener("click", function (e) {
      clearErr();
      var kce = (document.getElementById("ddb-kce").value || "").trim();
      if (!kce) { setErr("KeyConditionExpression is required for Query."); return; }
      var rawEav = (document.getElementById("ddb-eav").value || "{}").trim();
      var eav; try { eav = JSON.parse(rawEav); }
      catch (ex) { setErr("ExpressionAttributeValues is not valid JSON: " + ex.message); return; }
      var limit = Number(document.getElementById("ddb-limit").value || 10);
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/dynamodb/query", {
        table_name: table, key_condition_expression: kce, expression_attribute_values: eav, limit: limit
      }, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("ddb-result").innerHTML = M.renderResult(r);
      }).catch(function (ex) {
        document.getElementById("ddb-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
    document.getElementById("ddb-scan").addEventListener("click", function (e) {
      clearErr();
      var limit = Number(document.getElementById("ddb-limit").value || 10);
      var release = M.busy(e);
      DASH.api.post("/_localemu/api/actions/dynamodb/scan", { table_name: table, limit: limit }, { timeoutMs: 15000 }).then(function (r) {
        document.getElementById("ddb-result").innerHTML = M.renderResult(r);
      }).catch(function (ex) {
        document.getElementById("ddb-result").innerHTML = M.renderError(ex);
      }).finally(release);
    });
  }
  window.DASH.actions = window.DASH.actions || {};
  window.DASH.actions.dynamoDb = { open: open };
})();
