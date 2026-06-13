/* ═══════════════════════════════════════════════════════════════
   AzIP-Ranger · app.js, UI state, rendering, SVG topology,
   exports, theming. Pure client-side.
   ═══════════════════════════════════════════════════════════════ */
(function () {
  "use strict";
  const C = window.LZ_CIDR, E = window.LZ_ENGINE, X = window.LZ_EXPORT;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const LS_STATE = "alz-designer-state-v1";
  const LS_THEME = "alz-designer-theme";

  let state = E.defaultState();
  let plan = null;
  let seq = 100;
  let diagramExpanded = false;

  /* dropdown/value lists live in config.js, safe fallbacks here */
  const CFG = window.AZIP_CONFIG || {
    defaults: { region: "westeurope", environment: "prod" },
    regions: [], environments: [],
    spokeSizes: [{ name: "S /24", value: "S", prefix: 24 }, { name: "M /22", value: "M", prefix: 22 }, { name: "L /20", value: "L", prefix: 20 }],
    nvaVmCounts: [1, 2, 3],
  };
  const VM_MAX = Math.max(...(CFG.nvaVmCounts && CFG.nvaVmCounts.length ? CFG.nvaVmCounts : [3]));

  /* version + links — single source of truth is js/version.js */
  const V = window.LZ_VERSION || {
    app: "", ipPlan: "", designGuide: "", badge: "",
    repoUrl: "https://github.com/sarmadjari/AzIP-Ranger",
    siteUrl: "https://sarmadjari.github.io/AzIP-Ranger/",
  };
  function applyVersion() {
    const badge = document.querySelector("#ver-badge");
    if (badge) {
      badge.textContent = V.badge;
      badge.title = `Engine v${V.app} · IP Plan v${V.ipPlan} · Network Design Guide v${V.designGuide}. ` +
        `If this badge looks stale, your browser is serving a cached build — hard-refresh (Ctrl/Cmd+Shift+R).`;
    }
    document.querySelectorAll("[data-repo-link]").forEach(a => a.setAttribute("href", V.repoUrl));
  }

  /* ───────────────────────── helpers ────────────────────────── */
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = C.fmt;
  /** truncate to a pixel budget (approx char width per font) */
  const fitPx = (s, px, charW) => {
    s = String(s ?? "");
    const max = Math.max(3, Math.floor(px / charW));
    return s.length > max ? s.slice(0, max - 1) + "…" : s;
  };

  /* Section references become linked tooltips into Microsoft Learn.
     Applied AFTER esc() on engine-generated notes/hints.            */
  const MS = "https://learn.microsoft.com/";
  const REFS = {
    "1":   ["Azure Landing Zone design principles", MS + "azure/cloud-adoption-framework/ready/landing-zone/design-principles"],
    "2":   ["CAF: plan for IP addressing", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing"],
    "3":   ["CAF: traditional hub-and-spoke topology", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology"],
    "3.2": ["Azure DNS Private Resolver, requirements & constraints", MS + "azure/dns/dns-private-resolver-overview"],
    "4":   ["CAF: plan for IP addressing, spoke sizing", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing"],
    "4.3": ["VNet peering, gateway transit & forwarded traffic", MS + "azure/virtual-network/virtual-network-peering-overview"],
    "5":   ["HA NVAs behind Standard Load Balancer", MS + "azure/architecture/networking/guide/network-virtual-appliance-high-availability"],
    "6":   ["HA NVAs, symmetry, Floating IP, SNAT", MS + "azure/architecture/networking/guide/network-virtual-appliance-high-availability"],
    "6.5": ["Azure Firewall SNAT private IP ranges", MS + "azure/firewall/snat-private-range"],
    "7":   ["User-defined routes overview", MS + "azure/virtual-network/virtual-networks-udr-overview"],
    "8":   ["VPN Gateway settings, BGP & route propagation", MS + "azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings"],
    "9":   ["Network security groups overview", MS + "azure/virtual-network/network-security-groups-overview"],
    "9.1": ["Azure Bastion, required NSG rules", MS + "azure/bastion/bastion-nsg"],
    "9.6": ["AD DS firewall port requirements", MS + "troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts"],
    "10":  ["Application security groups", MS + "azure/virtual-network/application-security-groups"],
    "11":  ["Private endpoints overview", MS + "azure/private-link/private-endpoint-overview"],
    "11.5":["Private endpoint DNS integration", MS + "azure/private-link/private-endpoint-dns"],
    "12":  ["Virtual network service limits & hardening", MS + "azure/azure-resource-manager/management/azure-subscription-service-limits"],
    "12.6":["Default outbound access retirement", MS + "azure/virtual-network/ip-services/default-outbound-access"],
    "15":  ["Azure networking limits", MS + "azure/azure-resource-manager/management/azure-subscription-service-limits"],
    "16":  ["CAF: plan for IP addressing", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing"],
    "17":  ["ALZ implementation guidance", MS + "azure/cloud-adoption-framework/ready/landing-zone/"],
    "20":  ["Azure route selection (LPM) & UDR rules", MS + "azure/virtual-network/virtual-networks-udr-overview#how-azure-selects-routes-for-traffic-routing"],
    "20.3":["HA NVA patterns / Gateway Load Balancer", MS + "azure/architecture/networking/guide/network-virtual-appliance-high-availability"],
    "21":  ["Azure Firewall SNAT private ranges", MS + "azure/firewall/snat-private-range"],
    "23":  ["CAF resource abbreviations", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations"],
    "24":  ["CAF traditional networking topology", MS + "azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology"],
    "25":  ["Azure subscription & service limits", MS + "azure/azure-resource-manager/management/azure-subscription-service-limits"],
  };
  function refFor(num) {
    let k = num;
    while (k) {
      if (REFS[k]) return REFS[k];
      const i = k.lastIndexOf(".");
      k = i > 0 ? k.slice(0, i) : "";
    }
    return null;
  }
  /** turn "Section x.y" / "Sections x-y" tokens into a linked ⓘ tooltip (visible text kept) */
  function refLinks(escaped) {
    return String(escaped).replace(/\bSections?\s+(\d[\d.]*)(?:\s*-\s*\d[\d.]*)?/g, (m, num) => {
      const r = refFor(num.replace(/\.$/, ""));
      if (!r) return m;
      return `${m} <a class="ref" href="${r[1]}" target="_blank" rel="noopener noreferrer" title="${esc(r[0])} (Microsoft Learn)">ⓘ</a>`;
    });
  }
  const noteHtml = (s) => refLinks(esc(s));

  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toast._h);
    toast._h = setTimeout(() => t.classList.remove("show"), 2400);
  }

  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime || "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 200);
  }

  /* ───────────────────────── theme ──────────────────────────── */
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === "dark" ? "#0a0a0a" : "#fafafa";
    try { localStorage.setItem(LS_THEME, theme); } catch (e) { /* private mode */ }
  }
  function initTheme() {
    let t = null;
    try { t = localStorage.getItem(LS_THEME); } catch (e) {}
    if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    applyTheme(t);
  }
  $("#btn-theme").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });

  /* ───────────────────── state ⇄ DOM (config) ───────────────── */
  function readStaticInputs() {
    state.azure.cidr = $("#az-cidr").value;
    state.azure.region = $("#az-region").value;
    state.azure.mode = ($('input[name="az-mode"]:checked') || {}).value || "reference";
    state.azure.reserveRegion2 = $("#az-region2").checked;
    state.azure.headroom = $("#az-headroom").checked;
    // hybrid gateways only make sense with at least one on-prem network
    const hasOnprem = (state.onprem || []).some(o => (o.cidr || "").trim());
    state.connectivity.expressRoute = hasOnprem && $("#conn-er").checked;
    state.connectivity.vpn = hasOnprem && $("#conn-vpn").checked;
    state.connectivity.routeServer = $("#conn-rs").checked;
    state.security.arch = ($('input[name="sec-arch"]:checked') || {}).value || "dual";
    // tiers are state-driven (group rows mutate state directly), just guarantee shape
    ["ns", "ew"].forEach(k => {
      const t = state.security[k];
      if (!t || !Array.isArray(t.groups) || !t.groups.length) {
        state.security[k] = { groups: [{ kind: "vm", count: 2, min: 2, max: 4, name: "", names: [] }] };
      }
    });
    state.security.azfwAdd = $("#azfw-add").checked;
    state.security.azfwTier = ($('input[name="azfw-tier"]:checked') || {}).value || "ns";
    state.security.azfwPos = clampInt($("#azfw-pos").value, 1, 999, state.security.azfwPos || 1);
    state.security.azfwReserve = $("#sec-azfw-reserve").checked;
    state.security.azfwMgmt = $("#azfw-mgmt").checked;
    state.services.bastion = $("#svc-bastion").checked;
    state.services.dns = $("#svc-dns").checked;
    state.services.dc = $("#svc-dc").checked;
    state.services.mon = $("#svc-mon").checked;
    state.services.kv = $("#svc-kv").checked;
    state.services.jump = $("#svc-jump").checked;
    state.services.pe = $("#svc-pe").checked;
    state.services.mgmt = $("#svc-mgmt").checked;
    state.services.ddos = $("#svc-ddos").checked;
  }
  function clampInt(v, min, max, dflt) {
    const n = parseInt(v, 10);
    if (isNaN(n)) return dflt;
    return Math.min(max, Math.max(min, n));
  }

  /* migrate older saved designs (count-based spokes, nsMode tiers) */
  function normalizeLegacy(st) {
    const s = st.security || (st.security = {});
    const mkGroup = (cfg) => {
      const o = Object.assign({ kind: "vm", count: 2, min: 2, max: 4, name: "", names: [] }, cfg || {});
      o.kind = o.kind === "vmss" ? "vmss" : "vm";
      o.count = clampInt(o.count, 1, VM_MAX, 2);
      o.min = clampInt(o.min, 1, 50, 2);
      o.max = Math.max(o.min, clampInt(o.max, 1, 50, 4));
      o.name = typeof o.name === "string" ? o.name : "";
      o.names = Array.isArray(o.names) ? o.names : [];
      o.standalone = !!o.standalone;
      return o;
    };
    const mk = (cfg, legacyCount, legacyMode) => {
      if (cfg && Array.isArray(cfg.groups) && cfg.groups.length) return { groups: cfg.groups.slice(0, 160).map(mkGroup) };
      if (cfg) return { groups: [mkGroup(cfg)] };
      const g = mkGroup({});
      if (legacyMode === "single") g.count = 1;
      else if (legacyCount != null) g.count = clampInt(legacyCount, 1, VM_MAX, 2);
      return { groups: [g] };
    };
    s.ns = mk(s.ns, s.nsCount, s.nsMode);
    s.ew = mk(s.ew, s.ewCount, s.ewMode);
    delete s.nsMode; delete s.ewMode; delete s.nsCount; delete s.ewCount;
    if (!["ns", "ew"].includes(s.azfwTier)) s.azfwTier = "ns";
    s.azfwAdd = !!s.azfwAdd;
    s.azfwPos = clampInt(s.azfwPos, 1, 999, 1);
    // legacy "mixed" (NVA one tier + AzFW the other) → nearest current shape:
    // dual-tier NVA with the firewall chained into the tier AzFW used to own
    if (s.arch === "mixed") {
      s.arch = "dual";
      s.azfwAdd = true;
      s.azfwTier = s.mixedNvaRole === "ns" ? "ew" : "ns";
    }
    delete s.mixedNvaRole;
    if (!["dual", "single", "azfw", "none"].includes(s.arch)) s.arch = "dual";
    if (!st.azure.region) st.azure.region = "westeurope";
    if (!Array.isArray(st.spokes)) {
      const o = st.spokes || {};
      const arr = [];
      for (let i = 0; i < (o.prodM | 0); i++) arr.push({ id: ++seq, name: `app${i + 1}`, env: "prod", size: "M" });
      for (let i = 0; i < (o.prodL | 0); i++) arr.push({ id: ++seq, name: `big${i + 1}`, env: "prod", size: "L" });
      for (let i = 0; i < (o.dev | 0); i++) arr.push({ id: ++seq, name: `app${i + 1}`, env: "dev", size: "S" });
      for (let i = 0; i < (o.test | 0); i++) arr.push({ id: ++seq, name: `app${i + 1}`, env: "test", size: "S" });
      st.spokes = arr;
    }
    return st;
  }

  function writeInputs() {
    $("#az-cidr").value = state.azure.cidr;
    $("#az-region").value = state.azure.region || "westeurope";
    $$('input[name="az-mode"]').forEach(r => r.checked = r.value === state.azure.mode);
    $("#az-region2").checked = state.azure.reserveRegion2;
    $("#az-headroom").checked = state.azure.headroom;
    $("#conn-er").checked = state.connectivity.expressRoute;
    $("#conn-vpn").checked = state.connectivity.vpn;
    $("#conn-rs").checked = state.connectivity.routeServer;
    $$('input[name="sec-arch"]').forEach(r => r.checked = r.value === state.security.arch);
    renderTierGroups("ns");
    renderTierGroups("ew");
    $("#azfw-add").checked = !!state.security.azfwAdd;
    $$('input[name="azfw-tier"]').forEach(r => r.checked = r.value === (state.security.azfwTier || "ns"));
    $("#sec-azfw-reserve").checked = state.security.azfwReserve;
    $("#azfw-mgmt").checked = state.security.azfwMgmt;
    $("#svc-bastion").checked = state.services.bastion;
    $("#svc-dns").checked = state.services.dns;
    $("#svc-dc").checked = state.services.dc;
    $("#svc-mon").checked = state.services.mon;
    $("#svc-kv").checked = state.services.kv;
    $("#svc-jump").checked = state.services.jump;
    $("#svc-pe").checked = state.services.pe;
    $("#svc-mgmt").checked = state.services.mgmt;
    $("#svc-ddos").checked = state.services.ddos;
    renderOnpremRows();
    renderSpokeRows();
  }

  /* ── on-prem dynamic rows ── */
  function renderOnpremRows() {
    const wrap = $("#onprem-list");
    wrap.innerHTML = "";
    state.onprem.forEach((o) => {
      const row = document.createElement("div");
      row.className = "onprem-row";
      row.innerHTML =
        `<input type="text" autocomplete="off" spellcheck="false" placeholder="Site name…" aria-label="On-prem site name" value="${esc(o.name)}" data-f="name">` +
        `<input type="text" class="mono" autocomplete="off" spellcheck="false" placeholder="192.168.0.0/16…" aria-label="On-prem CIDR" value="${esc(o.cidr)}" data-f="cidr">` +
        `<button class="btn danger-ghost" type="button" aria-label="Remove ${esc(o.name || "site")}" title="Remove">` +
        `<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M3 4h10M6.5 4V2.5h3V4M5 4l.6 9.5A1 1 0 0 0 6.6 14.5h2.8a1 1 0 0 0 1-.95L11 4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg></button>`;
      row.querySelectorAll("input").forEach(inp => {
        inp.addEventListener("input", () => { o[inp.dataset.f] = inp.value; recompute(); });
      });
      row.querySelector("button").addEventListener("click", () => {
        state.onprem = state.onprem.filter(x => x !== o);
        renderOnpremRows(); recompute();
      });
      wrap.appendChild(row);
    });
    $("#onprem-empty").hidden = state.onprem.length > 0;
  }
  $("#btn-add-onprem").addEventListener("click", () => {
    state.onprem.push({ id: ++seq, name: "", cidr: "" });
    renderOnpremRows();
    const inputs = $("#onprem-list").querySelectorAll(".onprem-row:last-child input");
    if (inputs[0]) inputs[0].focus();
    recompute();
  });

  /* ── spoke dynamic rows (name · env · size) ── */
  function renderSpokeRows() {
    const wrap = $("#spoke-list");
    wrap.innerHTML = "";
    (state.spokes || []).forEach((s) => {
      const row = document.createElement("div");
      row.className = "spoke-row";
      row.innerHTML =
        `<input type="text" autocomplete="off" spellcheck="false" placeholder="workload name…" aria-label="Spoke name" value="${esc(s.name)}" data-f="name">` +
        `<input type="text" autocomplete="off" spellcheck="false" placeholder="env…" aria-label="Environment" list="env-list" value="${esc(s.env)}" data-f="env">` +
        `<select aria-label="Spoke size" data-f="size">` +
          (CFG.spokeSizes || []).map(z => `<option value="${esc(z.value)}"${s.size === z.value ? " selected" : ""}>${esc(z.name)}</option>`).join("") +
        `</select>` +
        `<button class="btn danger-ghost" type="button" aria-label="Remove spoke ${esc(s.name || "")}" title="Remove">` +
        `<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M3 4h10M6.5 4V2.5h3V4M5 4l.6 9.5A1 1 0 0 0 6.6 14.5h2.8a1 1 0 0 0 1-.95L11 4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg></button>`;
      row.querySelectorAll("input").forEach(inp => {
        inp.addEventListener("input", () => { s[inp.dataset.f] = inp.value; recompute(); });
      });
      row.querySelector("select").addEventListener("change", (e) => { s.size = e.target.value; recompute(); });
      row.querySelector("button").addEventListener("click", () => {
        state.spokes = state.spokes.filter(x => x !== s);
        renderSpokeRows(); recompute();
      });
      wrap.appendChild(row);
    });
    $("#spoke-empty").hidden = (state.spokes || []).length > 0;
  }
  $("#btn-add-spoke").addEventListener("click", () => {
    state.spokes.push({ id: ++seq, name: "", env: (CFG.defaults && CFG.defaults.environment) || "prod", size: (CFG.spokeSizes && CFG.spokeSizes[1] && CFG.spokeSizes[1].value) || "M" });
    renderSpokeRows();
    const inputs = $("#spoke-list").querySelectorAll(".spoke-row:last-child input");
    if (inputs[0]) inputs[0].focus();
    recompute();
  });

  /* ── ordered NVA group rows per tier (chained by sort order) ── */
  function renderTierGroups(k) {
    const wrap = $(`#${k}-groups`);
    if (!wrap) return;
    const tier = state.security[k];
    if (!tier || !Array.isArray(tier.groups)) return;
    wrap.innerHTML = "";
    const entryIdx = tier.groups.findIndex(g => !g.standalone);
    tier.groups.forEach((g, gi) => {
      const row = document.createElement("div");
      row.className = "group-row";
      const kindName = `${k}-g${gi}-kind`;
      const gslug = (g.name || (gi === 0 ? k : k + (gi + 1))).toLowerCase().replace(/[^a-z0-9]+/g, "") || k;
      const pillTxt = g.standalone ? "solo" : gi === entryIdx ? "entry" : "#" + (gi + 1);
      const pillCls = g.standalone ? "info" : gi === entryIdx ? "ok" : "neutral";
      const pillTip = g.standalone ? "Standalone, reached directly (e.g., explicit proxy), not in the chain (VIP .10" + gi + ")"
        : gi === entryIdx ? "Entry point, route tables send traffic here (VIP .10" + gi + ")"
        : "Chain hop (VIP .10" + gi + ")";
      row.innerHTML =
        `<div class="tier-head">
           <span class="pill ${pillCls}" title="${pillTip}">${pillTxt}</span>
           <input type="text" class="g-name" autocomplete="off" spellcheck="false" placeholder="group name… e.g. fortigate" aria-label="NVA group ${gi + 1} name" value="${esc(g.name || "")}">
           <div class="seg compact" role="radiogroup" aria-label="Group ${gi + 1} deployment model">
             <label class="seg-opt"><input type="radio" name="${kindName}" value="vm"${g.kind !== "vmss" ? " checked" : ""}><span>VMs</span></label>
             <label class="seg-opt"><input type="radio" name="${kindName}" value="vmss"${g.kind === "vmss" ? " checked" : ""}><span>VMSS</span></label>
           </div>
           <button class="btn icon-btn g-up" type="button" aria-label="Move group ${gi + 1} up"${gi === 0 ? " disabled" : ""}>↑</button>
           <button class="btn icon-btn g-down" type="button" aria-label="Move group ${gi + 1} down"${gi === tier.groups.length - 1 ? " disabled" : ""}>↓</button>
           <button class="btn danger-ghost g-del" type="button" aria-label="Remove group ${gi + 1}"${tier.groups.length === 1 ? " disabled" : ""}>✕</button>
         </div>
         <div class="tier-head">
           <label class="check g-sa" title="Standalone groups sit outside the chain, no UDR points at them; clients reach them directly (explicit proxy pattern)."><input type="checkbox" class="g-alone"${g.standalone ? " checked" : ""}><span>standalone <small>(e.g., explicit proxy, not chained)</small></span></label>
         </div>
         <div class="tier-controls">` +
        (g.kind === "vmss"
          ? `<label class="count-field"><span>Min</span><input type="number" class="g-min" min="1" max="50" step="1" value="${g.min}" inputmode="numeric"></label>
             <label class="count-field"><span>Max</span><input type="number" class="g-max" min="1" max="50" step="1" value="${g.max}" inputmode="numeric"></label>
             <span class="hint" style="align-self:center">vmss-${esc(gslug)}</span>`
          : `<label class="count-field"><span>NVAs</span><select class="g-count">${(CFG.nvaVmCounts && CFG.nvaVmCounts.length ? CFG.nvaVmCounts : [1, 2, 3]).map(n => `<option value="${n}"${g.count === n ? " selected" : ""}>${n}</option>`).join("")}</select></label>
             <div class="nva-names g-names">` +
              Array.from({ length: g.count }, (_, i) =>
                `<input type="text" autocomplete="off" spellcheck="false" placeholder="nva-${esc(gslug)}-0${i + 1}…" aria-label="Group ${gi + 1} NVA ${i + 1} name" value="${esc((g.names && g.names[i]) || "")}" data-i="${i}">`).join("") +
             `</div>`) +
        `</div>`;
      row.querySelector(".g-name").addEventListener("input", (e) => { g.name = e.target.value; recompute(); });
      row.querySelector(".g-alone").addEventListener("change", (e) => { g.standalone = e.target.checked; renderTierGroups(k); recompute(); });
      row.querySelectorAll(`input[name="${kindName}"]`).forEach(r =>
        r.addEventListener("change", () => { g.kind = r.value; renderTierGroups(k); recompute(); }));
      const sel = row.querySelector(".g-count");
      if (sel) sel.addEventListener("change", () => { g.count = clampInt(sel.value, 1, VM_MAX, 2); renderTierGroups(k); recompute(); });
      row.querySelectorAll(".g-names input").forEach(inp =>
        inp.addEventListener("input", () => { g.names = g.names || []; g.names[+inp.dataset.i] = inp.value; recompute(); }));
      const mn = row.querySelector(".g-min"), mx = row.querySelector(".g-max");
      if (mn) mn.addEventListener("input", () => { g.min = clampInt(mn.value, 1, 50, 2); recompute(); });
      if (mx) mx.addEventListener("input", () => { g.max = clampInt(mx.value, 1, 50, 4); recompute(); });
      row.querySelector(".g-up").addEventListener("click", () => { const a = tier.groups; [a[gi - 1], a[gi]] = [a[gi], a[gi - 1]]; renderTierGroups(k); recompute(); });
      row.querySelector(".g-down").addEventListener("click", () => { const a = tier.groups; [a[gi + 1], a[gi]] = [a[gi], a[gi + 1]]; renderTierGroups(k); recompute(); });
      row.querySelector(".g-del").addEventListener("click", () => { tier.groups.splice(gi, 1); renderTierGroups(k); recompute(); });
      wrap.appendChild(row);
    });
  }

  /* ── conditional visibility in config ── */
  function syncConfigVisibility() {
    const arch = state.security.arch;
    // hybrid connectivity is only meaningful with an on-prem network
    const hasOnprem = (state.onprem || []).some(o => (o.cidr || "").trim());
    $("#card-conn").classList.toggle("dimmed", !hasOnprem);
    $("#conn-er").disabled = !hasOnprem;
    $("#conn-vpn").disabled = !hasOnprem;
    $("#conn-gate-hint").hidden = hasOnprem;
    // group rows are rebuilt only when the group count changes (keeps typing focus)
    ["ns", "ew"].forEach(k => {
      const t = state.security[k];
      if (t && Array.isArray(t.groups) && $(`#${k}-groups`) && $(`#${k}-groups`).childElementCount !== t.groups.length) renderTierGroups(k);
    });
    $("#nva-config").hidden = !(arch === "dual" || arch === "single");
    $("#tier-ns").hidden = !(arch === "dual" || arch === "single");
    $("#tier-ew").hidden = arch !== "dual";
    $("#tier-ns-label").textContent = arch === "single" ? "NVA tier" : "North-South tier";
    $("#tier-ew-label").textContent = "East-West tier";
    ["ns", "ew"].forEach(k => {
      const t = state.security[k];
      const el = $(`#${k}-badge`);
      if (!el || !t || !Array.isArray(t.groups) || !t.groups.length) return;
      if (t.groups.length > 1) { el.textContent = `${t.groups.length} groups · chained`; el.className = "pill info"; }
      else {
        const g = t.groups[0];
        if (g.kind === "vmss") { el.textContent = `VMSS ${g.min}–${g.max} · VIP .100`; el.className = "pill info"; }
        else if (g.count >= 2) { el.textContent = "HA (ILB) · VIP .100"; el.className = "pill ok"; }
        else { el.textContent = "Single, SPOF"; el.className = "pill warn"; }
      }
    });
    // supernet hint
    const p = C.parseCidr(state.azure.cidr);
    const hint = $("#az-cidr-hint");
    const input = $("#az-cidr");
    if (p.ok) {
      input.classList.remove("invalid");
      const rfc = C.isRfc1918(p.base, p.prefix);
      hint.className = "hint";
      hint.innerHTML = `<b>${fmt(p.size)}</b> addresses · ${rfc ? "RFC 1918 ✓" : "⚠ not RFC 1918"}${p.exact ? "" : ` · normalized to <code>${p.normalized}</code>`}`;
    } else {
      input.classList.add("invalid");
      hint.className = "hint err";
      hint.textContent = p.error;
    }
    $("#region2-cidr").textContent = plan && plan.region2 ? plan.region2.cidr : "-";
    $("#row-headroom").style.display = state.azure.mode === "auto" ? "" : "none";
    // chained Azure Firewall (dual: pick the tier · single: no tier choice)
    const chained = (arch === "dual" || arch === "single") && state.security.azfwAdd;
    $("#azfw-add-block").hidden = !(arch === "dual" || arch === "single");
    $("#azfw-add-arch").textContent = arch === "single" ? "single" : "dual";
    $("#azfw-tier-row").hidden = !(chained && arch === "dual");
    $("#azfw-chain-hint").hidden = !chained;
    $("#azfw-chain-badge").textContent = chained && plan && plan.azfw ? `AzFW ${plan.azfw.ip}` : "-";
    // firewall position within the chosen tier's chain
    $("#azfw-pos-row").hidden = !chained;
    if (chained) {
      const tierKey = arch === "single" ? "ns" : (state.security.azfwTier === "ew" ? "ew" : "ns");
      const gs = ((state.security[tierKey] && state.security[tierKey].groups) || []).filter(g => !g.standalone);
      const cur = clampInt(state.security.azfwPos, 1, gs.length + 1, 1);
      state.security.azfwPos = cur;
      const nameOf = (g, i) => (g && g.name && g.name.trim()) || `group ${i + 1}`;
      $("#azfw-pos").innerHTML = Array.from({ length: gs.length + 1 }, (_, i) => {
        const pp = i + 1;
        const lbl = pp === 1 ? `1, entry (before ${nameOf(gs[0], 0)})`
          : pp === gs.length + 1 ? `${pp}, last (after ${nameOf(gs[gs.length - 1], gs.length - 1)}, egress side)`
          : `${pp}, after ${nameOf(gs[pp - 2], pp - 2)}`;
        return `<option value="${pp}"${pp === cur ? " selected" : ""}>${esc(lbl)}</option>`;
      }).join("");
    }
    $("#azfw-config").hidden = !(arch === "azfw" || chained);
    $("#row-azfw-reserve").hidden = !((arch === "dual" || arch === "single") && !state.security.azfwAdd);
  }

  /* ── pool meters in config ── */
  function renderPoolMeters() {
    const wrap = $("#pool-meters");
    const pools = (plan && plan.pools || []).filter(p => p.allocs.length);
    if (!pools.length) { wrap.innerHTML = ""; return; }
    wrap.innerHTML = pools.map(p => {
      const pct = Math.min(100, Math.round(p.used / p.size * 100));
      const over = p.used > p.size;
      const cls = over ? "err" : pct > 80 ? "warn" : "";
      return `<div class="meter"><div class="meter-top"><span>${esc(p.name)} · <code>${p.cidr}</code></span><b>${over ? "OVER" : pct + "%"}</b></div>
        <div class="meter-bar"><div class="meter-fill ${cls}" style="width:${Math.min(100, pct)}%"></div></div></div>`;
    }).join("");
  }

  /* ═══════════════════ RESULT RENDERING ═══════════════════════ */

  const ICONS = {
    err: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 4.8v3.8M8 11.2v.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    warn: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M8 2.2 14.5 13.5H1.5L8 2.2Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.8v.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    info: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 7.4v3.8M8 4.7v.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  };

  function renderWarnings() {
    const order = { err: 0, warn: 1, info: 2 };
    const msgs = [...plan.msgs].sort((a, b) => order[a.level] - order[b.level]);
    $("#warnings").innerHTML = msgs.map(m =>
      `<div class="alert ${m.level}">${ICONS[m.level]}<div class="alert-body"><b>${esc(m.title)}.</b> ${noteHtml(m.text)}</div></div>`
    ).join("");
  }

  function statCard(label, value, sub, accent) {
    return `<div class="stat${accent ? " accent" : ""}"><div class="stat-label">${esc(label)}</div><div class="stat-value">${value}</div>${sub ? `<div class="stat-sub">${sub}</div>` : ""}</div>`;
  }

  function renderSummary() {
    const s = plan.summary;
    const hops = [];
    if (plan.nsHop) hops.push(`Internet egress → <code>${plan.nsHop.ip}</code>`);
    if (plan.ewHop && (!plan.nsHop || plan.ewHop.ip !== plan.nsHop.ip)) hops.push(`East-West → <code>${plan.ewHop.ip}</code>`);
    $("#summary-cards").innerHTML =
      statCard("Architecture", `<small>${esc(s.arch)}</small>`, hops.join(" · ") || "system routing only") +
      statCard("Hybrid", `<small>${esc(s.hybrid)}</small>`, `${s.onpremCount} on-prem prefix${s.onpremCount === 1 ? "" : "es"}`) +
      statCard("Hub VNet", plan.hub.prefixes.length ? `${fmt(plan.hub.declared)}<small> addrs</small>` : "-",
        `<code>${esc(plan.hub.name)}</code>` + (plan.hub.prefixes.length > 1 ? ` · 3 × /19` : "")) +
      statCard("Spokes", String(s.totalSpokes), `region <code>${esc(s.region)}</code> · ${esc(s.mode === "reference" ? `v${V.ipPlan} layout` : "auto right-sized")}`, true);
  }

  function tbl(headers, rowsHtml) {
    return `<div class="tbl-wrap"><table><thead><tr>${headers.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
  }
  const pill = (txt, cls) => `<span class="pill ${cls}">${txt}</span>`;

  function renderCapacity() {
    const g = plan.capacity.guardrails;
    $("#capacity").innerHTML = tbl(["Guardrail", "Value", "Status", "Note"],
      g.map(r => `<tr><td>${esc(r.name)}</td><td class="mono">${esc(r.value)}</td><td>${pill(r.status.toUpperCase(), r.status)}</td><td class="muted">${noteHtml(r.note)}</td></tr>`).join(""));
  }

  function renderMaster() {
    $("#master-plan").innerHTML = tbl(["Block", "CIDR", "Addresses", "Notes"],
      plan.masterRows.map(r =>
        `<tr class="${r.kind === "reserved" || r.kind === "free" ? "row-reserved" : ""}"><td>${r.name}</td><td class="mono">${esc(r.cidr)}</td><td class="mono">${fmt(r.addresses)}</td><td class="muted">${noteHtml(r.note)}</td></tr>`
      ).join(""));
  }

  function renderHub() {
    const h = plan.hub;
    if (!h.subnets.length) {
      $("#hub-plan").innerHTML = `<p class="hint">No hub components selected.</p>`;
      return;
    }
    let html = `<p class="hint"><code>${esc(h.name)}</code> · <code>addressSpace.addressPrefixes</code> = ${h.prefixes.map(p => `<code>${p}</code>`).join(" + ")}, ${fmt(h.declared)} addresses declared, ${fmt(h.subnetted)} subnetted${plan.mode === "reference" ? " (remaining plan space stays unassigned per CAF, never declare an idle /16)" : ""}.</p>`;

    const sections = plan.mode === "reference"
      ? [["conn", "Connectivity"], ["shared", "Shared Services"], ["mgmt", "Management"]]
      : [[null, null]];
    let rows = "";
    sections.forEach(([key, label], i) => {
      const subs = h.subnets.filter(s => !key || s.section === key);
      if (!subs.length) return;
      if (key) rows += `<tr class="row-section"><td colspan="6">${label}, <span class="mono">${esc(h.sections[i] ? h.sections[i].cidr : "")}</span></td></tr>`;
      rows += subs.map(s =>
        `<tr class="${s.reserved ? "row-reserved" : ""}"><td>${esc(s.name)}${s.delegation ? ` <span class="muted">⌁ ${esc(s.delegation)}</span>` : ""}</td><td class="mono">${s.cidr}</td><td class="mono">${s.reserved ? "-" : fmt(s.usable)}</td><td>${esc(s.purpose)}</td><td class="mono">${esc(s.rt)}</td><td class="mono">${esc(s.nsg)}</td></tr>`
      ).join("");
    });
    html += tbl(["Subnet", "CIDR", "Usable", "Purpose", "Route Table", "NSG"], rows);

    if (plan.ilbs.length) {
      html += `<h3 style="margin-top:14px">Internal Load Balancer VIPs</h3>`;
      html += tbl(["ILB", "VIP", "Subnet", "Backend Pool", "Purpose"],
        plan.ilbs.map(l => `<tr><td>${esc(l.name)}</td><td class="mono">${l.vip}</td><td>${esc(l.subnet)}</td><td>${esc(l.pool)}</td><td class="muted">${esc(l.purpose)}</td></tr>`).join(""));
      html += `<p class="hint" style="margin-top:6px">Standard SKU with <b>HA Ports</b> + Floating IP; configure each VIP as a loopback on every NVA. <a class="ref" href="${MS}azure/architecture/networking/guide/network-virtual-appliance-high-availability" target="_blank" rel="noopener noreferrer" title="HA NVAs behind Standard Load Balancer, Microsoft Learn">ⓘ</a> 5-tuple session persistence for stateful inspection.</p>`;
    }

    if (plan.nva && plan.nva.tiers.length) {
      html += `<h3 style="margin-top:14px">NVA Inventory</h3>`;
      let rows2 = "";
      plan.nva.tiers.forEach(t => {
        t.groups.forEach((g, gi) => {
          const pos = t.groups.length > 1 ? (gi === 0 ? "chain entry · " : `chain hop ${gi + 1} · `) : "";
          const head = g.vmss
            ? `VMSS Flex · autoscale ${g.scale.min}–${g.scale.max} behind ${esc(g.ilbName)} (VIP ${g.hop.ip})`
            : `${g.count}× ${g.ha ? `active-active behind ${esc(g.ilbName)} (VIP ${g.hop.ip})` : "single instance · next hop = NIC IP"}`;
          rows2 += `<tr class="row-section"><td colspan="5">${esc(g.display)}, ${esc(t.label)} tier · ${pos}${head}</td></tr>`;
          if (g.vmss) {
            rows2 += `<tr><td class="mono">${esc(g.vmssName)}</td><td class="mono">dynamic <span class="muted">${g.extSubnet || t.extSubnet}</span></td><td class="mono">dynamic <span class="muted">${g.intSubnet || t.intSubnet}</span></td><td class="mono">dynamic</td><td class="mono">${g.hop.ip} <span class="muted">via VMSS profile</span></td></tr>`;
          } else {
            rows2 += g.instances.map(x =>
              `<tr><td class="mono">${esc(x.name)}</td><td class="mono">${x.ext} <span class="muted">${g.extSubnet || t.extSubnet}</span></td><td class="mono">${x.int} <span class="muted">${g.intSubnet || t.intSubnet}</span></td><td class="mono">${x.mgmt || "-"}</td><td class="mono">${x.loopbacks.join(", ") || "-"}</td></tr>`).join("");
          }
        });
      });
      html += tbl(["NVA", "External NIC", "Internal NIC", "Mgmt NIC", "Loopback VIP (Section 6.4)"], rows2);
      html += `<p class="hint" style="margin-top:6px">VM tiers get static NIC IPs from the first usable host (.4, .5, .6…). VMSS tiers receive dynamic NICs from the same subnets, the ILB VIP is the only stable address, so routing never changes on scale events.</p>`;
    }
    $("#hub-plan").innerHTML = html;
  }

  function renderSpokes() {
    const wrap = $("#spoke-plan");
    const allAllocs = plan.pools.flatMap(p => p.allocs.map(a => ({ ...a, pool: p.name })));
    if (!allAllocs.length) { wrap.innerHTML = `<p class="hint">No spokes yet, add workloads in the Spoke VNets card.</p>`; return; }
    let html = "";

    plan.pools.filter(p => p.allocs.length).forEach(p => {
      const pct = Math.min(100, Math.round(p.used / p.size * 100));
      html += `<div class="meter" style="margin-bottom:10px"><div class="meter-top"><span><b>${esc(p.name)}</b> pool · <code>${p.cidr}</code> · ${p.allocs.length} spoke${p.allocs.length === 1 ? "" : "s"}</span><b>${pct}% used</b></div><div class="meter-bar"><div class="meter-fill ${pct > 80 ? "warn" : ""}" style="width:${pct}%"></div></div></div>`;
    });

    const MAXROWS = 300;
    html += tbl(["VNet (CAF name)", "Workload", "Env", "Size", "CIDR", "Route table"],
      allAllocs.slice(0, MAXROWS).map(a =>
        `<tr><td class="mono">${esc(a.name)}</td><td>${esc(a.label)}</td><td>${esc(a.env)}</td><td>${esc(a.size)}</td><td class="mono">${a.cidr}</td><td class="mono">${esc(a.rtName)}</td></tr>`).join(""));
    if (allAllocs.length > MAXROWS) html += `<p class="hint">…and ${fmt(allAllocs.length - MAXROWS)} more, the CSV / Markdown exports contain the full list.</p>`;

    // template breakdowns, worked example per template kind with real CAF names
    const kinds = [["std22", "Medium /22 spoke template"], ["std24", "Small /24 spoke template"], ["large20", "Large /20 spoke"]];
    kinds.forEach(([k, label]) => {
      const sample = allAllocs.find(a => a.template === k);
      if (!sample) return;
      const t = plan.templates[k];
      html += `<details class="block" style="margin-top:10px"><summary><svg class="chev" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>${esc(label)}<span class="sum-sub">example: ${esc(sample.name)} = ${sample.cidr}</span></summary><div class="block-body">` +
        tbl(["Subnet", "CIDR", "Usable", "Purpose", "NSG"],
          t.map(s => {
            const snet = s.reserved || s.tier.startsWith("(") ? s.tier : `snet-${s.tier}-${sample.nameBase}`;
            const nsg = s.reserved || s.tier.startsWith("(") ? "-" : `nsg-${s.tier}-${sample.nameBase}`;
            return `<tr class="${s.reserved ? "row-reserved" : ""}"><td class="mono">${esc(snet)}</td><td class="mono">${C.cidr(sample.base + s.off, s.prefix)}</td><td class="mono">${s.reserved || s.prefix === 20 ? "-" : fmt(C.usable(s.prefix))}</td><td>${esc(s.purpose)}</td><td class="mono">${esc(nsg)}</td></tr>`;
          }).join("")) +
        `<p class="hint" style="margin-top:8px">All subnets associate <code>${esc(sample.rtName)}</code> (the RT-Spoke-Workloads route set).${k === "std22" ? ` Effective usable across the five subnets ≈ 487. <a class="ref" href="${MS}azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing" target="_blank" rel="noopener noreferrer" title="CAF: plan for IP addressing, Azure reserves 5 IPs per subnet">ⓘ</a>` : ""}</p>` +
        `</div></details>`;
    });
    wrap.innerHTML = html;
  }

  function renderRoutes() {
    const wrap = $("#route-tables");
    wrap.innerHTML = plan.routeTables.map(rt => {
      const bgpPill = rt.bgp === "Enabled" ? pill("BGP ✓ Enabled", "ok") : rt.bgp === "Disabled" ? pill("BGP ✕ Disabled", "neutral") : "";
      const body = rt.routes.length
        ? tbl(["Route", "Address Prefix", "Next Hop Type", "Next Hop"],
            rt.routes.map(r => `<tr><td>${esc(r.name)}</td><td class="mono">${esc(r.prefix)}</td><td>${esc(r.type)}</td><td class="mono">${esc(r.nextHop)}</td></tr>`).join(""))
        : "";
      return `<details class="block" open><summary><svg class="chev" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>${esc(rt.name)}<span class="sum-sub">${esc(rt.appliesTo)}</span>${bgpPill}</summary><div class="block-body">${body}${rt.note ? `<p class="hint">${noteHtml(rt.note)}</p>` : ""}</div></details>`;
    }).join("");

    $("#bgp-table").innerHTML = plan.bgpRows.length
      ? tbl(["Route table / subnet", "BGP propagation", "Reason"],
          plan.bgpRows.map(r => `<tr><td class="mono">${esc(r.name)}</td><td>${r.bgp === "Enabled" ? pill("Enabled", "ok") : r.bgp === "Disabled" ? pill("Disabled", "neutral") : pill(esc(r.bgp), "info")}</td><td class="muted">${esc(r.reason)}</td></tr>`).join(""))
      : `<p class="hint">No route tables in this design.</p>`;
  }

  function renderNsgs() {
    const wrap = $("#nsg-list");
    if (!plan.nsgs.length) {
      wrap.innerHTML = `<div class="panel"><p class="hint">No NSGs generated, enable hub services or spokes.</p></div>`;
    } else {
      wrap.innerHTML = plan.nsgs.map(n => {
        const inbound = n.rules.filter(r => r.dir === "Inbound");
        const outbound = n.rules.filter(r => r.dir === "Outbound");
        const sec = (label, rules) => rules.length
          ? `<p class="hint" style="margin:8px 0 4px"><b>${label}</b></p>` + tbl(["Pri", "Name", "Source", "Destination", "Ports", "Proto", "Action"],
              rules.map(r => `<tr><td class="mono">${r.prio}</td><td>${esc(r.name)}</td><td class="mono">${esc(r.src)}</td><td class="mono">${esc(r.dst)}</td><td class="mono">${esc(r.port)}</td><td>${esc(r.proto)}</td><td>${r.action === "Deny" ? pill("Deny", "err") : pill("Allow", "ok")}</td></tr>`).join(""))
          : "";
        return `<details class="block"${n.required ? " open" : ""}><summary><svg class="chev" viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>${esc(n.name)}<span class="sum-sub">${esc(n.appliesTo)}</span>${n.required ? pill("required", "info") : ""}</summary><div class="block-body">${sec("Inbound", inbound)}${sec("Outbound", outbound)}${n.note ? `<p class="hint">${noteHtml(n.note)}</p>` : ""}</div></details>`;
      }).join("");
    }
    $("#asg-table").innerHTML = tbl(["ASG", "Purpose", "Example members"],
      plan.asgs.map(a => `<tr><td class="mono">${esc(a.name)}</td><td>${esc(a.purpose)}</td><td class="muted">${esc(a.members)}</td></tr>`).join("")) +
      `<p class="hint" style="margin-top:6px">ASGs give dynamic membership and self-documenting rules; same region as the NIC, no cross-VNet mixing in a single rule (Section 10).</p>`;
  }

  function renderOps() {
    const p = plan.peering;
    $("#peering").innerHTML =
      `<p class="hint"><b>Hub → Spoke</b> (configured on the hub VNet)</p>` +
      tbl(["Flag", "Value", "Reason"], p.hubToSpoke.map(f => `<tr><td class="mono">${esc(f.flag)}</td><td class="mono">${f.value === "true" ? pill("true", "ok") : pill("false", "neutral")}</td><td class="muted">${noteHtml(f.why)}</td></tr>`).join("")) +
      `<p class="hint" style="margin-top:10px"><b>Spoke → Hub</b> (configured on each spoke VNet)</p>` +
      tbl(["Flag", "Value", "Reason"], p.spokeToHub.map(f => `<tr><td class="mono">${esc(f.flag)}</td><td class="mono">${f.value === "true" ? pill("true", "ok") : pill("false", "neutral")}</td><td class="muted">${noteHtml(f.why)}</td></tr>`).join("")) +
      p.notes.map(n => `<p class="hint" style="margin-top:8px">• ${noteHtml(n)}</p>`).join("");

    const d = plan.dns;
    $("#dns-pe").innerHTML = d
      ? tbl(["Endpoint", "Static IP", "Role"], [
          `<tr><td>DNS Resolver, Inbound</td><td class="mono">${d.inbound || "-"}</td><td class="muted">Spoke VNet DNS server + on-prem conditional-forwarder target</td></tr>`,
          `<tr><td>DNS Resolver, Outbound</td><td class="mono">${d.outbound || "-"}</td><td class="muted">Forwards on-prem domains out via the firewall</td></tr>`,
        ].join("")) +
        `<p class="hint" style="margin-top:8px"><b>Common privatelink zones:</b> ${d.zones.map(z => `<code>${esc(z)}</code>`).join(" ")}</p>` +
        d.notes.map(n => `<p class="hint" style="margin-top:6px">• ${noteHtml(n)}</p>`).join("")
      : `<p class="hint">DNS Private Resolver disabled, point spokes at your DNS servers and link privatelink zones to wherever resolution happens. Private Endpoint subnets still require <code>privateEndpointNetworkPolicies = Enabled</code> for NSG enforcement. <a class="ref" href="${MS}azure/private-link/private-endpoint-overview" target="_blank" rel="noopener noreferrer" title="Private endpoints overview, Microsoft Learn">ⓘ</a></p>`;
  }

  /* ───────────────────── SVG topology diagram ─────────────────
     Layout: on-prem/internet column (x24,w156) · hub (x256,w312)
     · spokes (x624,w188). Every text is truncated to its box and
     long chip subtitles wrap to a second line. "+N more spokes"
     toggles full expansion.                                      */
  function renderDiagram() {
    const s = plan.summary;
    const arch = state.security.arch;
    const hubSubs = plan.hub.subnets.filter(x => !x.reserved);
    const allSpokes = plan.pools.flatMap(p => p.allocs);
    const COLLAPSED = 5;
    const spokes = diagramExpanded ? allSpokes : allSpokes.slice(0, COLLAPSED);
    const more = allSpokes.length - spokes.length;

    const W = 824;
    const hubX = 256, hubW = 312, hubY = 70;
    const spX = 624, spW = 188;
    const CH_LABEL = 6.6, CH_SUB = 6.0, CH_TINY = 5.4;   // px per char approximations

    /* chips, each may carry 1 or 2 subtitle lines */
    const chips = [];
    const chipW = hubW - 28;
    const subBudget = chipW - 24;
    const wrapSub = (txt) => {
      txt = String(txt ?? "");
      const maxChars = Math.floor(subBudget / CH_SUB);
      if (txt.length <= maxChars) return [txt];
      // wrap at the last separator before the budget
      let cut = txt.lastIndexOf(" · ", maxChars);
      if (cut < maxChars * 0.4) cut = txt.lastIndexOf(" ", maxChars);
      if (cut < maxChars * 0.4) cut = maxChars;
      const l1 = txt.slice(0, cut).trim();
      const l2 = txt.slice(cut).replace(/^[\s·]+/, "").trim();
      return [l1, fitPx(l2, subBudget, CH_SUB)];
    };
    /* cls: "" | "dg-ns" | "dg-ew", colors the chip border per traffic plane */
    const addChip = (label, sub, cls, opts) => chips.push({
      label: fitPx(label, chipW - 28, CH_LABEL),
      subs: sub ? wrapSub(sub) : [],
      cls: cls || "",
      tip: sub ? `${label}, ${sub}` : label,
      egress: !!(opts && opts.egress),
      egName: (opts && opts.egName) || "",
    });

    if (state.connectivity.expressRoute || state.connectivity.vpn) {
      const g = hubSubs.find(x => x.key === "gw");
      addChip("Gateway subnet, " + [state.connectivity.expressRoute && "ER", state.connectivity.vpn && "VPN"].filter(Boolean).join(" + "), g ? g.cidr : "");
    }
    if (plan.nva.tiers.length) {
      const grpTxt = (g) => g.vmss ? `VMSS ${g.scale.min}–${g.scale.max}` : `${g.count}× ${g.ha ? "HA" : "single"}`;
      plan.nva.tiers.forEach(t => {
        const cls = arch === "dual" ? (t.key === "ns" ? "dg-ns" : "dg-ew") : "";
        // chained firewall renders INLINE at its slot; standalone groups follow after the chain
        const fwHere = plan.azfw && plan.azfw.chain &&
          (plan.azfw.chain === "ew" ? t.key === "ew" : (t.key === "ns" || t.key === "fw"));
        const chainedG = t.groups.filter(g => !g.standalone);
        const solosG = t.groups.filter(g => g.standalone);
        const seq = chainedG.map(g => ({ azfw: false, g }));
        if (fwHere) seq.splice((plan.azfw.chainPos || 1) - 1, 0, { azfw: true });
        seq.forEach((item, si) => {
          const last = si === seq.length - 1;
          const suffix = !last ? " → next hop"
            : arch === "single" ? ", all inspection"
            : (t.key === "ns" || t.key === "fw" ? " → Internet" : " → spokes/on-prem");
          const isEgress = last && (t.key === "ns" || t.key === "fw");
          const opts = isEgress ? { egress: true, egName: item.azfw ? "Azure Firewall" : item.g.display } : null;
          if (item.azfw) {
            addChip(`${si > 0 ? "↳ " : ""}Azure Firewall (hop ${si + 1})${suffix}`, `private IP ${plan.azfw.ip}`, cls, opts);
          } else {
            const g = item.g;
            addChip(`${si > 0 ? "↳ " : ""}${g.display} (${grpTxt(g)})${suffix}`, `${g.hop.label} ${g.hop.ip}`, cls, opts);
          }
        });
        solosG.forEach(g => addChip(`${g.display} (${grpTxt(g)}) · standalone`, `${g.hop.label} ${g.hop.ip}, direct access`, cls));
      });
    }
    if (plan.azfw && !plan.azfw.chain) {
      addChip(`Azure Firewall, ${plan.azfw.role}`, `private IP ${plan.azfw.ip}`, "", arch === "azfw" ? { egress: true, egName: "Azure Firewall" } : null);
    }
    const svcBits = [state.services.dns && "DNS Resolver", state.services.dc && "AD DS", state.services.bastion && "Bastion", state.services.jump && "Jump", state.services.mon && "Monitor"].filter(Boolean);
    if (svcBits.length) addChip("Shared services", svcBits.join(" · "));
    if (state.services.pe) {
      const pe = hubSubs.find(x => x.key === "pe");
      addChip("Private Endpoints", pe ? pe.cidr : "");
    }

    const chipH = (c) => 22 + c.subs.length * 12;
    const hubH = Math.max(80, 30 + chips.reduce((a, c) => a + chipH(c) + 8, 0) + 8);
    // spokes are centered against the hub's height
    const spokesBlockH = Math.max(spokes.length, 1) * 52 + (allSpokes.length > COLLAPSED ? 30 : 0);
    const spStart = Math.max(36, hubY + hubH / 2 - spokesBlockH / 2);
    const H = Math.max(300, hubY + hubH + 40, spStart + spokesBlockH + 40);

    let inner = "", iy = hubY + 26;
    let egressY = null, egressName = null;
    chips.forEach(c => {
      const h = chipH(c);
      if (c.egress) { egressY = iy + h / 2; egressName = c.egName; }
      inner += `<g><title>${esc(c.tip)}</title>
        <rect x="${hubX + 14}" y="${iy}" width="${chipW}" height="${h}" rx="6" class="dg-box ${c.cls}"></rect>
        ${c.cls ? `<circle cx="${hubX + 21}" cy="${iy + h / 2}" r="2.6" class="dgc-${c.cls === "dg-ns" ? "ns" : "ew"}"></circle>` : ""}
        <text x="${hubX + 28}" y="${iy + 15}" class="dg-label">${esc(c.label)}</text>` +
        c.subs.map((l, i) => `<text x="${hubX + 28}" y="${iy + 27 + i * 12}" class="dg-sub">${esc(l)}</text>`).join("") +
        `</g>`;
      iy += h + 8;
    });

    /* left column: internet + on-prem */
    const leftW = 156;
    const netH = 42;
    // the Internet box aligns with the chain's actual egress element
    const netY = egressY != null ? Math.min(Math.max(20, egressY - netH / 2), H - netH - 20) : 24;
    let opY = Math.max(netY + netH + 28, Math.min(H - 130, hubY + hubH / 2 - 20));
    const netSub = arch === "none" ? "NAT GW / public IPs" : egressName ? `egress: ${egressName}` : "no egress path";
    let left = `<g><title>${esc(arch === "none" ? "Internet egress via per-subnet NAT Gateways / public IPs (no central inspection)" : egressName ? `Internet egress leaves the chain at ${egressName}` : "No element currently provides internet egress")}</title>
      <rect x="24" y="${netY}" width="${leftW}" height="${netH}" rx="8" class="dg-box"></rect>
      <text x="${24 + leftW / 2}" y="${netY + 19}" text-anchor="middle" class="dg-label">Internet</text>
      <text x="${24 + leftW / 2}" y="${netY + 33}" text-anchor="middle" class="dg-tiny">${esc(fitPx(netSub, leftW - 12, CH_TINY))}</text></g>`;
    let leftLines = egressY != null
      ? `<g><title>Internet egress path, exits at ${esc(egressName || "")}</title><path class="dg-line dashed" d="M${24 + leftW} ${netY + netH / 2} H ${hubX}"></path></g>`
      : "";
    if (s.onpremCount) {
      const opH = 34 + Math.min(plan.onprem.length, 3) * 14 + (plan.onprem.length > 3 ? 14 : 0);
      left += `<rect x="24" y="${opY}" width="${leftW}" height="${opH}" rx="8" class="dg-box"></rect>
        <text x="${24 + leftW / 2}" y="${opY + 18}" text-anchor="middle" class="dg-label">On-Premises</text>` +
        plan.onprem.slice(0, 3).map((o, i) => `<text x="${24 + leftW / 2}" y="${opY + 32 + i * 14}" text-anchor="middle" class="dg-sub">${esc(fitPx(o.cidr, leftW - 14, CH_SUB))}</text>`).join("") +
        (plan.onprem.length > 3 ? `<text x="${24 + leftW / 2}" y="${opY + 32 + 3 * 14}" text-anchor="middle" class="dg-tiny">+${plan.onprem.length - 3} more</text>` : "");
      // hybrid links: ER solid; VPN dashed when it is the backup of ER, solid when alone
      const gapL = 24 + leftW, gapR = hubX;
      const midX = (gapL + gapR) / 2;
      const er = state.connectivity.expressRoute, vpn = state.connectivity.vpn;
      if (er && vpn) {
        leftLines += `<g><title>ExpressRoute, primary path</title>
            <path class="dg-line accent" d="M${gapL} ${opY + 20} H ${gapR}"></path>
            <text x="${midX}" y="${opY + 14}" text-anchor="middle" class="dg-tiny">${esc(fitPx("ER", gapR - gapL - 10, CH_TINY))}</text></g>
          <g><title>VPN, backup path</title>
            <path class="dg-line accent dashed" d="M${gapL} ${opY + 40} H ${gapR}"></path>
            <text x="${midX}" y="${opY + 54}" text-anchor="middle" class="dg-tiny">${esc(fitPx("VPN · backup", gapR - gapL - 10, CH_TINY))}</text></g>`;
      } else if (er || vpn) {
        leftLines += `<g><title>${er ? "ExpressRoute" : "VPN"}, primary path</title>
            <path class="dg-line accent" d="M${gapL} ${opY + 26} H ${gapR}"></path>
            <text x="${midX}" y="${opY + 19}" text-anchor="middle" class="dg-tiny">${esc(fitPx(er ? "ER" : "VPN", gapR - gapL - 10, CH_TINY))}</text></g>`;
      }
    }

    /* right: spokes (expandable) */
    let right = "", rightLines = "";
    spokes.forEach((sp, i) => {
      const y = spStart + i * 52;
      right += `<g><title>${esc(sp.name)} · ${esc(sp.cidr)} · ${esc(sp.size)} · env ${esc(sp.env)}</title>
        <rect x="${spX}" y="${y}" width="${spW}" height="40" rx="7" class="dg-box"></rect>
        <text x="${spX + 10}" y="${y + 17}" class="dg-label">${esc(fitPx(sp.name, spW - 20, CH_LABEL))}</text>
        <text x="${spX + 10}" y="${y + 30}" class="dg-sub">${esc(sp.cidr)} · ${esc(fitPx(sp.size, 70, CH_SUB))}</text></g>`;
      rightLines += `<path class="dg-line" d="M${hubX + hubW} ${hubY + hubH / 2} C ${hubX + hubW + 28} ${hubY + hubH / 2}, ${spX - 28} ${y + 20}, ${spX} ${y + 20}"></path>`;
    });
    if (allSpokes.length > COLLAPSED) {
      const y = spStart + spokes.length * 52 + 16;
      const txt = diagramExpanded ? "− show fewer spokes" : `+${fmt(more)} more spoke${more === 1 ? "" : "s"}, show all`;
      right += `<text id="dg-more" x="${spX + spW / 2}" y="${y}" text-anchor="middle" class="dg-link" role="button" tabindex="0">${esc(txt)}</text>`;
    }
    if (!allSpokes.length) right += `<text x="${spX + spW / 2}" y="${spStart + 24}" text-anchor="middle" class="dg-tiny">no spokes yet</text>`;

    const svg = `<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Network topology diagram">
      ${leftLines}${rightLines}
      <rect x="${hubX}" y="${hubY}" width="${hubW}" height="${hubH}" rx="10" class="dg-box dg-hub"><title>${esc(plan.hub.name)}, ${esc(plan.hub.prefixes.join(" + "))}</title></rect>
      <text x="${hubX + 14}" y="${hubY + 18}" class="dg-label">${esc(fitPx("Hub VNet · " + plan.hub.name, hubW - (arch === "dual" ? 130 : 100), CH_LABEL))}<title>${esc(plan.hub.name)}</title></text>
      <text x="${hubX + hubW - 14}" y="${hubY + 18}" text-anchor="end" class="dg-sub">${arch === "dual" ? `<tspan class="dgc-ns">●</tspan> N-S <tspan class="dgc-ew">●</tspan> E-W` : esc(plan.hub.prefixes[0] || "") + (plan.hub.prefixes.length > 1 ? " +2" : "")}</text>
      ${inner}${left}${right}
      <text x="${spX + spW / 2}" y="${Math.max(16, spStart - 12)}" text-anchor="middle" class="dg-tiny">${esc(fitPx(`spokes, peered, ${arch !== "none" ? "transit via hub inspection" : "no transit"}`, spW + 40, CH_TINY))}</text>
    </svg>`;
    $("#diagram").innerHTML = svg;
    const moreEl = $("#dg-more");
    if (moreEl) {
      const toggle = () => { diagramExpanded = !diagramExpanded; renderDiagram(); };
      moreEl.addEventListener("click", toggle);
      moreEl.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    }
  }

  /* ═══════════════════════ EXPORTS ═══════════════════════════ */

  /* Markdown / CSV / JSON serializers live in js/export.js (LZ_EXPORT)
     so the browser, the Node regeneration tool and the unit tests all
     produce identical artifacts.                                      */
  const buildMarkdown = () => X.buildMarkdown(plan, state);
  const csvAll = () => X.csvAll(plan);
  const csvSubnets = () => X.csvSubnets(plan);
  const csvRoutes = () => X.csvRoutes(plan);
  const csvNsg = () => X.csvNsg(plan);
  const designJson = () => X.designJson(state);

  $("#exp-md").addEventListener("click", () => { download("azip-ranger-design.md", buildMarkdown(), "text/markdown"); toast("Markdown report downloaded"); });
  $("#exp-csv-all").addEventListener("click", () => { download("azip-ranger-all.csv", csvAll(), "text/csv"); toast("Combined CSV downloaded"); });
  $("#exp-csv-subnets").addEventListener("click", () => { download("azip-ranger-subnets.csv", csvSubnets(), "text/csv"); toast("Subnets CSV downloaded"); });
  $("#exp-csv-routes").addEventListener("click", () => { download("azip-ranger-route-tables.csv", csvRoutes(), "text/csv"); toast("Route tables CSV downloaded"); });
  $("#exp-csv-nsg").addEventListener("click", () => { download("azip-ranger-nsg-rules.csv", csvNsg(), "text/csv"); toast("NSG rules CSV downloaded"); });
  $("#exp-json").addEventListener("click", () => { download("azip-ranger-design.json", designJson(), "application/json"); toast("Design file downloaded"); });

  $("#btn-save").addEventListener("click", () => { download("azip-ranger-design.json", designJson(), "application/json"); toast("Design saved as azip-ranger-design.json"); });
  $("#btn-load").addEventListener("click", () => $("#file-load").click());
  $("#file-load").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      try {
        const data = JSON.parse(rd.result);
        if (!data || !data.state || !data.state.azure) throw new Error("not a designer file");
        state = normalizeLegacy(Object.assign(E.defaultState(), data.state));
        state.onprem = Array.isArray(data.state.onprem) ? data.state.onprem : [];
        writeInputs();
        recompute();
        toast(`Loaded ${f.name}`);
      } catch (err) {
        toast("Could not load: " + err.message);
      }
      e.target.value = "";
    };
    rd.readAsText(f);
  });
  $("#btn-reset").addEventListener("click", () => {
    state = E.defaultState();
    diagramExpanded = false;
    writeInputs();
    recompute();
    toast(`Reset to v${V.ipPlan} reference defaults`);
  });

  /* ───────────────────────── tabs ───────────────────────────── */
  $$(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".tab").forEach(b => { b.classList.toggle("active", b === btn); b.setAttribute("aria-selected", b === btn ? "true" : "false"); });
      $$("[role=tabpanel]").forEach(p => p.hidden = p.id !== btn.getAttribute("aria-controls"));
    });
  });

  /* ─────────────────────── recompute ────────────────────────── */
  function recompute() {
    readStaticInputs();
    plan = E.buildPlan(state);
    syncConfigVisibility();
    renderWarnings();
    if (plan.ok) {
      renderSummary(); renderDiagram(); renderCapacity();
      renderMaster(); renderHub(); renderSpokes();
      renderRoutes(); renderNsgs(); renderOps();
      renderPoolMeters();
    } else {
      const placeholder = `<p class="hint err">Fix the configuration errors to generate the design.</p>`;
      $("#summary-cards").innerHTML = ""; $("#diagram").innerHTML = placeholder;
      $("#capacity").innerHTML = ""; $("#master-plan").innerHTML = placeholder;
      $("#hub-plan").innerHTML = ""; $("#spoke-plan").innerHTML = "";
      $("#route-tables").innerHTML = placeholder; $("#bgp-table").innerHTML = "";
      $("#nsg-list").innerHTML = placeholder; $("#asg-table").innerHTML = "";
      $("#peering").innerHTML = placeholder; $("#dns-pe").innerHTML = "";
      $("#pool-meters").innerHTML = "";
    }
    try { localStorage.setItem(LS_STATE, JSON.stringify(state)); } catch (e) {}
  }

  // bind every static input (dynamic rows bind their own listeners)
  $$(".config input, .config select").forEach(el => {
    el.addEventListener(el.tagName === "SELECT" ? "change" : (el.type === "text" || el.type === "number" ? "input" : "change"), recompute);
  });

  /* ─────────────────────── boot ─────────────────────────────── */
  function populateConfigLists() {
    const fill = (sel, items) => { const el = $(sel); if (el) el.innerHTML = (items || []).map(i => `<option value="${esc(i.value)}">${esc(i.name)}</option>`).join(""); };
    fill("#region-list", CFG.regions);
    fill("#env-list", CFG.environments);
    ["ns", "ew"].forEach(k => {
      const b = $(`#${k}-add-group`);
      if (b) b.addEventListener("click", () => {
        state.security[k].groups.push({ kind: "vm", count: 2, min: 2, max: 4, name: "", names: [] });
        renderTierGroups(k);
        recompute();
      });
    });
  }
  populateConfigLists();
  initTheme();
  applyVersion();
  try {
    const saved = localStorage.getItem(LS_STATE);
    if (saved) {
      const s = JSON.parse(saved);
      if (s && s.azure) { state = normalizeLegacy(Object.assign(E.defaultState(), s)); state.onprem = Array.isArray(s.onprem) ? s.onprem : []; }
    }
  } catch (e) { /* ignore corrupt saves */ }
  writeInputs();
  recompute();
}());
