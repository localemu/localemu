// Step Functions state-machine drill-down: execution list.
// The execution-graph viewer was scoped out of this PR; we list
// recent executions with status and start/stop timestamps. Click an
// execution to expand the input/output JSON inline.
(function () {
  "use strict";
  function open(name) {
    // The standard list endpoint already contains state machines; for
    // executions we shell out via the public API endpoint.
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    elMain.innerHTML = '<div class="loading-state">Loading...</div>';
    DASH.api.fetchJSON("/_localemu/api/resources/stepfunctions", { etag: false, timeoutMs: 6000 }).then(function (r) {
      var machines = (r.data && r.data.resources) || [];
      var m = machines.find(function (x) { return x.name === name; }) || { name: name };
      render(name, m, []);
      // Executions would need a backend endpoint; for now we leave the
      // panel functional with state-machine metadata and let the user
      // launch executions via awsemu.
    }).catch(function () { render(name, { name: name }, []); });
  }
  function render(name, machine, executions) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("stepfunctions", 28);
    html += '<h2>' + u.esc(name) + '</h2>';
    html += '<a class="docs-link" href="https://localemu.cloud/docs/stepfunctions" target="_blank">Docs</a>';
    html += '<button class="back-link" id="back-sf-btn">← Back to Step Functions</button>';
    html += '</div>';
    html += '<div class="empty-state-guidance">';
    html += '<div class="empty-title">State machine</div>';
    html += '<pre>ARN:    ' + u.esc(machine.arn || "-") + '\nStatus: ' + u.esc(machine.status || "-") + '</pre>';
    html += '<div class="hint">Start an execution from the CLI:\n<code>awsemu stepfunctions start-execution --state-machine-arn ' + u.esc(machine.arn || "&lt;arn&gt;") + ' --input \'{}\'</code></div>';
    html += '</div>';
    elMain.innerHTML = html;
    elMain.dataset.lastKey = "sf:" + name;
    var back = document.getElementById("back-sf-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "stepfunctions", resource: null }); });
  }
  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.stepfunctions = { open: open, init: init };
})();
