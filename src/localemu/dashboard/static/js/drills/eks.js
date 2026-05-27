// EKS cluster drill. Surfaces the moto cluster metadata + the k3d
// cluster info (k3d_name, api_port, kubeconfig) so the user can
// copy the kubeconfig and talk to a real running cluster.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "eks",
      title: function (row) { return row.name; },
      subtitle: function (row) {
        return [row.version, row.status, row.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/eks/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 8000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (row) {
            return H.kvTable([
              ["Cluster name", row.name],
              ["ARN", row.arn || "-"],
              ["Status", row.status],
              ["Kubernetes version", row.version || "-"],
              ["Endpoint", row.endpoint || "-"],
              ["Role ARN", row.role_arn || "-"],
              ["Platform version", row.platform_version || "-"],
              ["Region", row.region],
            ]);
          }
        },
        {
          id: "k3d", label: "k3d cluster",
          availableWhen: function (row) { return !!row.k3d; },
          render: function (row) {
            var u = DASH.utils;
            var k = row.k3d || {};
            var kubeconfigPath = "~/.kube/le-" + row.name + ".yaml";
            var saveCmd = "awsemu eks update-kubeconfig --name " + row.name + " --kubeconfig " + kubeconfigPath;
            var html = H.kvTable([
              ["k3d cluster name", k.k3d_name],
              ["Kubernetes API port", k.api_port],
              ["Kubectl context", "Copy kubeconfig below, save to " + kubeconfigPath + ", then KUBECONFIG=" + kubeconfigPath + " kubectl get pods -A"],
            ]);
            html += '<h3 style="margin-top:18px">Copy kubeconfig</h3>';
            html += '<pre class="drill-json" style="max-height:300px">' + u.esc(k.kubeconfig || "(kubeconfig not yet retrieved)") + '</pre>';
            html += '<p><button class="row-action primary" data-copy="' + u.esc(k.kubeconfig || "") + '">Copy kubeconfig</button>';
            html += ' <button class="row-action" data-copy="' + u.esc(saveCmd) + '">Copy update-kubeconfig command</button></p>';
            html += '<script>(function(){var bs=document.querySelectorAll("[data-copy]");bs.forEach(function(b){b.addEventListener("click",function(){DASH.utils.copyToClipboard(b.getAttribute("data-copy"));DASH.utils.showToast("Copied","ok");});});})();</script>';
            return html;
          }
        },
        {
          id: "networking", label: "Networking",
          render: function (row) {
            var v = row.resources_vpc_config || {};
            return H.kvTable([
              ["VPC", v.vpcId || v.VpcId || "-"],
              ["Subnets", (v.subnetIds || v.SubnetIds || []).join(", ") || "-"],
              ["Security groups", (v.securityGroupIds || v.SecurityGroupIds || []).join(", ") || "-"],
              ["Endpoint public access", v.endpointPublicAccess === false ? "No" : "Yes"],
              ["Endpoint private access", v.endpointPrivateAccess ? "Yes" : "No"],
              ["Public access CIDRs", (v.publicAccessCidrs || []).join(", ") || "-"],
            ]);
          }
        },
        {
          id: "logging", label: "Logging",
          render: function (row) {
            return H.jsonBlock(row.logging || {});
          }
        },
        {
          id: "auth", label: "Authentication",
          render: function (row) {
            return H.jsonBlock(row.identity || {});
          }
        },
        {
          id: "tags", label: "Tags",
          render: function (row) {
            var tags = row.tags || {};
            var keys = Object.keys(tags);
            if (!keys.length) return '<div class="empty-state">No tags.</div>';
            return H.table(keys.map(function (k) { return { key: k, value: tags[k] }; }),
              [{ key: "key", label: "Key" }, { key: "value", label: "Value" }]);
          }
        },
      ],
      actions: [
        { id: "copy-name", label: "Copy cluster name",
          run: function (row) {
            DASH.utils.copyToClipboard(row.name || "");
            DASH.utils.showToast("Name copied", "ok");
          } },
        { id: "delete", label: "Delete", destructive: true,
          run: function (row) {
            DASH.utils.copyToClipboard("awsemu eks delete-cluster --name " + row.name);
            DASH.utils.showToast("Copied delete-cluster", "ok");
          } },
      ],
    };
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("eks", spec());
  }
})();
