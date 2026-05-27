// S3 bucket drill-down: object list + upload + per-row download/preview.
//
// All bucket I/O goes through the LocalEmu gateway on the same origin
// (``/<bucket>/<key>``) rather than a new dashboard backend. The dashboard
// is served from the gateway port (4566) so same-origin fetch is enough,
// and the S3 service already handles the right content-types and ranges.
(function () {
  "use strict";

  var PREVIEW_BYTES_LIMIT = 256 * 1024; // 256 KiB cap for inline preview

  // Called by app.openDrill after navigate() has already set state.route
  // and written the URL hash. Just renders.
  function open(bucket) {
    refresh(bucket);
  }

  function refresh(bucket) {
    var url = "/_localemu/api/resources/s3/" + encodeURIComponent(bucket);
    DASH.cache.invalidateKey("s3:" + bucket);
    DASH.api.get(url, { cacheKey: "s3:" + bucket, ttlMs: 15000 }).then(function (r) {
      render(bucket, (r.value && r.value.objects) || []);
    }).catch(function (err) {
      DASH.utils.showApiError(err, "s3 objects");
      render(bucket, []);
    });
  }

  function render(bucket, objects) {
    var u = DASH.utils;
    var elMain = document.getElementById("main-content");
    var html = '<div class="detail-header">';
    html += u.iconHtml("s3", 28);
    html += '<h2>' + u.esc(bucket) + '</h2>';
    html += '<button class="row-action primary" id="s3-upload-btn">Upload</button>';
    html += '<input type="file" id="s3-upload-input" multiple style="display:none">';
    html += '<button class="back-link" id="back-s3-btn">← Back to S3 buckets</button>';
    html += '</div>';

    if (!objects || objects.length === 0) {
      html += '<div class="empty-state">No objects in this bucket. Click <strong>Upload</strong> above to add one.</div>';
    } else {
      html += '<div class="resource-table-wrap"><table class="resource-table"><thead><tr>';
      html += '<th>Key</th><th>Size</th><th>Last Modified</th><th>Actions</th>';
      html += '</tr></thead><tbody>';
      objects.forEach(function (o) {
        var key = o.key || o.Key || "";
        html += '<tr>';
        html += '<td>' + u.esc(key) + '</td>';
        html += '<td>' + u.esc(u.formatBytes(o.size != null ? o.size : o.Size)) + '</td>';
        html += '<td>' + u.esc(o.last_modified || o.LastModified || "-") + '</td>';
        html += '<td>';
        html += '<button class="row-action s3-preview-btn" data-key="' + u.esc(key) + '">Preview</button> ';
        html += '<button class="row-action s3-download-btn" data-key="' + u.esc(key) + '">Download</button>';
        html += '</td>';
        html += '</tr>';
        html += '<tr class="s3-preview-row" id="s3-preview-' + idSafe(key) + '" style="display:none">';
        html += '<td colspan="4"><pre class="s3-preview-pane"></pre></td>';
        html += '</tr>';
      });
      html += '</tbody></table></div>';
    }

    elMain.innerHTML = html;
    elMain.dataset.lastKey = "s3:" + bucket + ":" + (objects ? objects.length : 0);

    var back = document.getElementById("back-s3-btn");
    if (back) back.addEventListener("click", function () { DASH.app.navigate({ service: "s3", resource: null }); });

    var uploadBtn = document.getElementById("s3-upload-btn");
    var fileInput = document.getElementById("s3-upload-input");
    if (uploadBtn && fileInput) {
      uploadBtn.addEventListener("click", function () { fileInput.click(); });
      fileInput.addEventListener("change", function () {
        var files = Array.from(fileInput.files || []);
        if (files.length === 0) return;
        Promise.all(files.map(function (f) { return uploadOne(bucket, f); }))
          .then(function () { refresh(bucket); })
          .catch(function (err) {
            alert("Upload failed: " + (err && err.message ? err.message : err));
          });
      });
    }

    elMain.querySelectorAll(".s3-download-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        downloadObject(bucket, btn.dataset.key);
      });
    });
    elMain.querySelectorAll(".s3-preview-btn").forEach(function (btn) {
      btn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        previewObject(bucket, btn.dataset.key);
      });
    });
  }

  function objectUrl(bucket, key) {
    // Path-style addressing: ``/<bucket>/<key>``. ``key`` may contain
    // slashes, so encode each segment individually rather than the whole
    // string (preserves S3 prefix semantics on the wire).
    var encoded = String(key)
      .split("/")
      .map(function (p) { return encodeURIComponent(p); })
      .join("/");
    return "/" + encodeURIComponent(bucket) + "/" + encoded;
  }

  function uploadOne(bucket, file) {
    return file.arrayBuffer().then(function (buf) {
      return fetch(objectUrl(bucket, file.name), {
        method: "PUT",
        body: buf,
        headers: { "content-type": file.type || "application/octet-stream" }
      }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
      });
    });
  }

  function downloadObject(bucket, key) {
    // Trigger a browser download via an <a download>. We can't set the
    // ``Content-Disposition: attachment`` header from JS, but the
    // ``download`` attribute on a same-origin link does the same thing.
    var a = document.createElement("a");
    a.href = objectUrl(bucket, key);
    a.download = key.split("/").pop() || key;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  function previewObject(bucket, key) {
    var row = document.getElementById("s3-preview-" + idSafe(key));
    if (!row) return;
    if (row.style.display === "table-row") {
      row.style.display = "none";
      return;
    }
    var pane = row.querySelector(".s3-preview-pane");
    pane.textContent = "loading...";
    row.style.display = "table-row";

    fetch(objectUrl(bucket, key), {
      method: "GET",
      headers: { Range: "bytes=0-" + (PREVIEW_BYTES_LIMIT - 1) }
    }).then(function (r) {
      if (!r.ok && r.status !== 206 && r.status !== 200) {
        throw new Error("HTTP " + r.status);
      }
      var ct = (r.headers.get("content-type") || "").toLowerCase();
      if (isTextLike(ct, key)) return r.text().then(function (t) { return [ct, t, false]; });
      // Binary: render a hint instead of garbled bytes.
      return r.blob().then(function (b) {
        return [ct, "[binary " + DASH.utils.formatBytes(b.size) + ", content-type=" + (ct || "?") + "]\nClick Download for the full file.", true];
      });
    }).then(function (parts) {
      var ct = parts[0], text = parts[1], binary = parts[2];
      if (!binary && /json/i.test(ct)) {
        try { text = JSON.stringify(JSON.parse(text), null, 2); } catch (e) { /* leave raw */ }
      }
      pane.textContent = text;
    }).catch(function (err) {
      pane.textContent = "Preview failed: " + (err && err.message ? err.message : err);
    });
  }

  function isTextLike(contentType, key) {
    if (!contentType) return /\.(txt|json|csv|tsv|md|log|html?|xml|yaml|yml|js|css|sh|py)$/i.test(key);
    return /^text\//.test(contentType)
      || /(json|xml|yaml|javascript|csv|x-sh|x-python)/i.test(contentType);
  }

  function idSafe(s) {
    return encodeURIComponent(s).replace(/%/g, "_");
  }

  function init() {}
  window.DASH.drills = window.DASH.drills || {};
  window.DASH.drills.s3 = { open: open, init: init };
})();
