/* ═══════════════════════════════════════════════════════════════
   AzIP-Ranger · version.js — SINGLE SOURCE OF TRUTH for versions.

   Bump the numbers HERE and they propagate everywhere: the header
   badge, generated Markdown/CSV/JSON exports, in-app labels and
   engine warnings, plus the repo / site links. Keep these in sync
   with the docs:
     ipPlan      → docs/azure-landing-zone-ip-plan.md
     designGuide → docs/azure-landing-zone-network-design-guide.md

   When you bump `app`, also bump the ?v= cache-busting query
   strings on the <script>/<link> tags in index.html so browsers
   fetch the new build instead of a stale cache.
   ═══════════════════════════════════════════════════════════════ */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.LZ_VERSION = factory();
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var V = {
    app:         "2.7.4",  // AzIP-Ranger tool / engine release (matches ?v= in index.html)
    ipPlan:      "5.2",    // docs/azure-landing-zone-ip-plan.md
    designGuide: "1.1",    // docs/azure-landing-zone-network-design-guide.md
    repoUrl:     "https://github.com/sarmadjari/AzIP-Ranger",
    siteUrl:     "https://sarmadjari.github.io/AzIP-Ranger/",
  };

  /* derived, read-only convenience strings */
  V.badge    = "v" + V.app + " · plan v" + V.ipPlan;
  V.docBasis = "based on IP Plan v" + V.ipPlan +
               " + Network Design Guide v" + V.designGuide;

  return V;
}));
