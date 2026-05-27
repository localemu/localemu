// ACM certificate drill.
(function () {
  "use strict";
  function spec() {
    var H = DASH.drills.framework.helpers;
    return {
      service: "acm",
      title: function (r) {
        var d = r.detail || r;
        return d.domain_name || d.DomainName || "(certificate)";
      },
      subtitle: function (r) {
        var d = r.detail || r;
        return [d.status || d.Status, d.type || d.Type, r.region].filter(Boolean).join(" \u00b7 ");
      },
      fetch: function (k) {
        return DASH.api.fetchJSON("/_localemu/api/resources/acm/" + encodeURIComponent(k),
          { etag: false, timeoutMs: 6000 }).then(function (r) { return (r && r.data) || { arn: k }; });
      },
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", render: function (r) {
          var d = r.detail || r;
          return H.kvTable([
            ["Domain", d.domain_name || d.DomainName],
            ["ARN", d.arn || d.CertificateArn || r.arn],
            ["Subject alternative names", (d.subject_alternative_names || d.SubjectAlternativeNames || []).join(", ") || "-"],
            ["Status", d.status || d.Status],
            ["Type", d.type || d.Type],
            ["Key algorithm", d.key_algorithm || d.KeyAlgorithm],
            ["Signature algorithm", d.signature_algorithm || d.SignatureAlgorithm],
            ["Not before", d.not_before || d.NotBefore],
            ["Not after", d.not_after || d.NotAfter],
            ["In use by", (d.in_use_by || d.InUseBy || []).join(", ") || "(unused)"],
            ["Region", r.region],
          ]);
        }},
        { id: "json", label: "Full JSON", render: function (r) { return H.jsonBlock(r.detail || r); }},
      ],
    };
  }
  DASH.registry && DASH.registry.registerDrill && DASH.registry.registerDrill("acm", spec());
})();
