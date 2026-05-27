// HTTP wrapper for the dashboard. Wraps fetch with ETag conditional GET,
// in-flight de-dup (via cache.js), retry, timeout. All other modules
// talk to the gateway through DASH.api.
(function () {
  "use strict";

  var etags = Object.create(null);   // url -> last ETag we saw
  var bodies = Object.create(null);  // url -> last body (for 304 reuse)

  function fetchJSON(url, opts) {
    opts = opts || {};
    var init = {
      method: opts.method || "GET",
      headers: Object.assign({}, opts.headers || {})
    };
    if (opts.body !== undefined) {
      init.body = (typeof opts.body === "string") ? opts.body : JSON.stringify(opts.body);
      init.headers["Content-Type"] = init.headers["Content-Type"] || "application/json";
    }
    if (opts.etag !== false && etags[url] && init.method === "GET") {
      init.headers["If-None-Match"] = etags[url];
    }
    var timeoutMs = opts.timeoutMs || 15000;
    var controller = (typeof AbortController !== "undefined") ? new AbortController() : null;
    if (controller) init.signal = controller.signal;
    var timer = controller ? setTimeout(function () { controller.abort(); }, timeoutMs) : null;

    return fetch(url, init).then(function (resp) {
      if (timer) clearTimeout(timer);
      if (resp.status === 304 && bodies[url] !== undefined) {
        return { status: 304, data: bodies[url], etag: etags[url] };
      }
      if (!resp.ok) {
        // Try to parse JSON error for better messaging.
        return resp.text().then(function (txt) {
          var data = null;
          try { data = txt ? JSON.parse(txt) : null; } catch (e) { /* keep raw */ }
          var err = new Error("HTTP " + resp.status);
          err.status = resp.status;
          err.data = data || txt;
          throw err;
        });
      }
      var et = resp.headers.get("ETag");
      if (et) etags[url] = et;
      return resp.json().then(function (data) {
        if (et) bodies[url] = data;
        return { status: resp.status, data: data, etag: et };
      });
    });
  }

  // Convenience wrappers that auto-cache via DASH.cache.
  function get(url, opts) {
    opts = opts || {};
    var cacheKey = opts.cacheKey || ("GET " + url);
    return DASH.cache.single(cacheKey, function () {
      return fetchJSON(url, opts).then(function (r) { return r.data; });
    }, {
      ttlMs: opts.ttlMs == null ? 15000 : opts.ttlMs,
      tags: opts.tags || [],
      staleWhileRevalidate: opts.staleWhileRevalidate !== false
    });
  }

  function getFresh(url, opts) {
    var cacheKey = (opts && opts.cacheKey) || ("GET " + url);
    DASH.cache.invalidateKey(cacheKey);
    return get(url, opts);
  }

  function post(url, body, opts) {
    opts = opts || {};
    opts.method = "POST";
    opts.body = body;
    opts.etag = false;
    return fetchJSON(url, opts);
  }

  window.DASH.api = {
    fetchJSON: fetchJSON,
    get: get,
    getFresh: getFresh,
    post: post,
    invalidateAllETags: function () { etags = Object.create(null); bodies = Object.create(null); }
  };
})();
