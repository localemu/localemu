// ECR drill: repository metadata + images + lifecycle policy.
// Tabs: Overview, Images, Policy, Lifecycle.
(function () {
  "use strict";

  function spec() {
    var H = DASH.drills.framework.helpers;
    var u = DASH.utils;
    return {
      service: "ecr",
      title: function (r) { return r.name || "(repository)"; },
      subtitle: function (r) {
        return [r.uri, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (key) {
        return DASH.api.fetchJSON(
          "/_localemu/api/resources/ecr/" + encodeURIComponent(key),
          { etag: false, timeoutMs: 6000 }
        ).then(function (r) { return (r && r.data) || { name: key, error: "not found" }; });
      },
      defaultTab: "overview",
      tabs: [
        {
          id: "overview", label: "Overview",
          render: function (r) {
            var enc = r.encryption_configuration || {};
            var scan = r.image_scanning_configuration || {};
            return H.kvTable([
              ["Name", r.name],
              ["Repository URI", r.uri],
              ["ARN", r.arn],
              ["Registry ID", r.registry_id],
              ["Tag mutability", r.image_tag_mutability],
              ["Scan on push", scan.scanOnPush ? "yes" : "no"],
              ["Encryption type", enc.encryptionType || "AES256"],
              ["KMS key", enc.kmsKey || "-"],
              ["Created", r.created_at],
              ["Region", r.region],
            ]);
          }
        },
        {
          id: "images", label: "Images",
          render: function (r) {
            var rows = r.images || [];
            if (!rows.length) {
              return '<div class="empty-state">No images pushed to this repository yet.<br>'
                + '<span class="hint">Push with: <code>docker tag my-app ' + u.esc(r.uri || '&lt;uri&gt;')
                + ':v1 &amp;&amp; docker push ' + u.esc(r.uri || '&lt;uri&gt;') + ':v1</code></span></div>';
            }
            return H.table(rows, [
              { key: "digest", label: "Digest",
                render: function (i) {
                  var d = i.digest || "";
                  return d.length > 24 ? d.slice(0, 24) + "..." : d;
                } },
              { key: "tags", label: "Tags",
                render: function (i) { return (i.tags || []).join(", ") || "(untagged)"; } },
              { key: "manifest_media_type", label: "Manifest media type" },
              { key: "pushed_at", label: "Pushed",
                render: function (i) {
                  if (!i.pushed_at) return "-";
                  try { return new Date(i.pushed_at * 1000).toISOString(); }
                  catch (e) { return String(i.pushed_at); }
                } },
            ]);
          }
        },
        {
          id: "policy", label: "Repository policy",
          render: function (r) {
            if (!r.policy) return '<div class="empty-state">No repository policy attached.</div>';
            return '<p class="hint">Resource-based policy on this repository.</p>'
              + H.helpers ? H.helpers.jsonBlock(safeJson(r.policy))
                          : '<pre>' + u.esc(r.policy) + '</pre>';
          }
        },
        {
          id: "lifecycle", label: "Lifecycle policy",
          render: function (r) {
            if (!r.lifecycle_policy) return '<div class="empty-state">No lifecycle policy attached.</div>';
            return '<p class="hint">Image-expiration rules evaluated by ECR.</p>'
              + '<pre>' + u.esc(safeStringify(r.lifecycle_policy)) + '</pre>';
          }
        },
      ],
      actions: [
        {
          id: "copy-uri", label: "Copy repository URI",
          run: function (row) {
            DASH.utils.copyToClipboard(row.uri || "");
            DASH.utils.showToast("Repository URI copied", "ok");
          }
        },
      ],
    };
  }

  function safeJson(s) {
    try { return JSON.parse(s); } catch (e) { return s; }
  }
  function safeStringify(v) {
    if (typeof v === "string") {
      try { return JSON.stringify(JSON.parse(v), null, 2); } catch (e) { return v; }
    }
    try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); }
  }

  if (window.DASH && window.DASH.registry && window.DASH.registry.registerDrill) {
    window.DASH.registry.registerDrill("ecr", spec());
  }
})();
