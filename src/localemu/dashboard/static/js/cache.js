// TTL cache with tag-based invalidation, in-flight de-dup, and
// stale-while-revalidate semantics. Used by api.js for snapshot
// endpoints. Tag invalidation hooks into bus.js so SSE events can
// expire cached entries instantly.
(function () {
  "use strict";

  var entries = Object.create(null);    // key -> {value, expires, tags}
  var inflight = Object.create(null);   // key -> Promise

  function set(key, value, ttlMs, tags) {
    entries[key] = {
      value: value,
      expires: Date.now() + (ttlMs || 0),
      tags: tags || []
    };
  }

  function get(key) {
    var e = entries[key];
    if (!e) return null;
    return { value: e.value, fresh: Date.now() < e.expires };
  }

  function invalidateTag(tag) {
    for (var k in entries) {
      if (entries[k].tags.indexOf(tag) !== -1) delete entries[k];
    }
  }

  function invalidateKey(key) { delete entries[key]; }

  function clearAll() {
    for (var k in entries) delete entries[k];
    for (var p in inflight) delete inflight[p];
  }

  // Wrap a fetcher in single-flight + cache semantics.
  // fetcher() must return a Promise resolving to the value to cache.
  //
  // Returns { value, fresh, fromCache } where:
  //   value     = the resolved data
  //   fresh     = true if served from a non-expired cache entry
  //   fromCache = true if the request hit a cache (fresh or stale)
  function single(key, fetcher, opts) {
    opts = opts || {};
    var ttlMs = opts.ttlMs || 15000;
    var tags = opts.tags || [];
    var staleWhileRevalidate = opts.staleWhileRevalidate !== false;

    var cached = get(key);
    if (cached && cached.fresh) {
      return Promise.resolve({ value: cached.value, fresh: true, fromCache: true });
    }
    if (inflight[key]) {
      // De-dup concurrent callers.
      return inflight[key];
    }
    var promise = fetcher().then(function (value) {
      set(key, value, ttlMs, tags);
      delete inflight[key];
      return { value: value, fresh: true, fromCache: false };
    }).catch(function (err) {
      delete inflight[key];
      // On error: if we have a stale entry, serve it. Otherwise rethrow.
      if (cached && staleWhileRevalidate) {
        return { value: cached.value, fresh: false, fromCache: true, error: err };
      }
      throw err;
    });
    inflight[key] = promise;
    if (cached && staleWhileRevalidate) {
      // Return stale immediately; the in-flight Promise refreshes it.
      return Promise.resolve({ value: cached.value, fresh: false, fromCache: true });
    }
    return promise;
  }

  window.DASH.cache = {
    set: set,
    get: get,
    invalidateTag: invalidateTag,
    invalidateKey: invalidateKey,
    clearAll: clearAll,
    single: single
  };
})();
