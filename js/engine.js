/* ═══════════════════════════════════════════════════════════════
   AzIP-Ranger · engine.js — turns a configuration state into a
   complete landing zone design: master allocation, hub VNet &
   subnets, spoke pools, NVA tiers (VM or VMSS), ILB VIPs / next
   hops, route tables, NSGs, peering, DNS, capacity — with CAF
   naming built from <spoke>-<env>-<region>.

   Encodes the rules of:
   • "Azure Landing Zone – IP Addressing Scheme & Network Security
     Design v5.0" (hub /19 sections, dual-tier NS/EW NVAs, ILB VIPs
     .100, T-shirt spoke catalog with two-pointer allocation, UDR &
     NSG catalogs, BGP guardrails, capacity ceilings)
   • "Azure Landing Zone Network Design Guide v1.0"

   Inspection architectures:
     dual   — NS NVA tier + EW NVA tier (v5.0 reference)
              + optional Azure Firewall CHAINED into one tier
     single — one NVA tier inspects N-S and E-W
     mixed  — NVA takes one tier, Azure Firewall takes the other
     azfw   — Azure Firewall only · none — no central inspection

   Tier deployment: { kind:"vm", count:1..8 } or { kind:"vmss",
   min, max } — VMSS is always behind the ILB (dynamic NIC IPs).

   Spokes: free-form list [{ name, env, size }] — size S=/24,
   M=/22, L=/20. Reference mode allocates by SIZE into the doc's
   pools (M/L → 10.4.0.0/15 two-pointer, S → 10.6/16 then 10.7/16);
   auto mode creates one right-sized pool per environment.
   ═══════════════════════════════════════════════════════════════ */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./cidr.js"));
  } else {
    root.LZ_ENGINE = factory(root.LZ_CIDR);
  }
}(typeof self !== "undefined" ? self : this, function (C) {
  "use strict";

  const route = (name, prefix, type, nextHop) => ({ name, prefix, type, nextHop: nextHop || "—" });
  const rule = (prio, name, dir, src, dst, port, proto, action) =>
    ({ prio, name, dir, src, dst, port, proto, action });
  const DENY_IN = rule(4096, "DenyAllInbound", "Inbound", "Any", "Any", "Any", "Any", "Deny");
  const ALLOW_LB = rule(150, "AllowAzureLoadBalancer", "Inbound", "AzureLoadBalancer", "Any", "Any", "Any", "Allow");

  function nextPow2(n) { let p = 1; while (p < n) p *= 2; return p; }
  const clampI = (v, lo, hi, dflt) => {
    const n = parseInt(v, 10);
    return isNaN(n) ? dflt : Math.min(hi, Math.max(lo, n));
  };

  /** CAF-style slug: lowercase alphanumerics only */
  function slug(s, dflt) {
    const v = String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "").slice(0, 24);
    return v || dflt;
  }

  /* spoke sizes — overridable via config.js (AZIP_CONFIG.spokeSizes) */
  const CFG = (typeof self !== "undefined" && self.AZIP_CONFIG) ||
              (typeof globalThis !== "undefined" && globalThis.AZIP_CONFIG) || null;
  const SIZE = {};
  ((CFG && Array.isArray(CFG.spokeSizes) && CFG.spokeSizes.length ? CFG.spokeSizes : [
    { value: "S", prefix: 24 }, { value: "M", prefix: 22 }, { value: "L", prefix: 20 },
  ])).forEach(s => {
    const pfx = clampI(s.prefix, 16, 28, 24);
    const friendly = s.value === "S" ? "Small" : s.value === "M" ? "Medium" : s.value === "L" ? "Large" : String(s.value);
    SIZE[s.value] = {
      prefix: pfx, bytes: Math.pow(2, 32 - pfx),
      label: `${friendly} /${pfx}`,
      template: pfx === 22 ? "std22" : pfx === 24 ? "std24" : "large20",
    };
  });
  const VM_MAX = CFG && Array.isArray(CFG.nvaVmCounts) && CFG.nvaVmCounts.length
    ? Math.max(...CFG.nvaVmCounts.map(n => clampI(n, 1, 8, 3))) : 3;

  function normGroup(cfg) {
    const o = Object.assign({ kind: "vm", count: 2, min: 2, max: 4, name: "" }, cfg || {});
    o.kind = o.kind === "vmss" ? "vmss" : "vm";
    o.count = clampI(o.count, 1, VM_MAX, 2);            // beyond VM_MAX → use VMSS
    o.min = clampI(o.min, 1, 50, 2);
    o.max = Math.max(o.min, clampI(o.max, 1, 50, 4));
    o.name = typeof o.name === "string" ? o.name.trim() : "";
    o.names = Array.isArray(o.names) ? o.names.slice(0, VM_MAX).map(n => String(n || "").trim()) : [];
    o.standalone = !!o.standalone;        // outside the chain (e.g., explicit proxy)
    return o;
  }

  /** a tier is an ORDERED list of NVA groups, chained by sort order.
      Accepts: { groups: [...] } · legacy single-group { kind, count… } ·
      pre-v2 { nsCount / nsMode } shapes.                              */
  function normTier(cfg, legacyCount, legacyMode) {
    if (cfg && Array.isArray(cfg.groups) && cfg.groups.length) {
      return { groups: cfg.groups.slice(0, 160).map(normGroup) };  // above the 155-VIP ladder, so buildTier's precise guards always report
    }
    if (cfg) return { groups: [normGroup(cfg)] };
    const g = normGroup({});
    if (legacyMode === "single") g.count = 1;
    else if (legacyCount != null) g.count = clampI(legacyCount, 1, VM_MAX, 2);
    return { groups: [g] };
  }

  /** accepts the legacy {prodM, prodL, dev, test} shape and the new array shape */
  function normSpokes(input) {
    let arr = input;
    if (!Array.isArray(arr)) {
      const o = arr || {};
      arr = [];
      for (let i = 0; i < (o.prodM | 0); i++) arr.push({ name: `app${i + 1}`, env: "prod", size: "M" });
      for (let i = 0; i < (o.prodL | 0); i++) arr.push({ name: `big${i + 1}`, env: "prod", size: "L" });
      for (let i = 0; i < (o.dev | 0); i++) arr.push({ name: `app${i + 1}`, env: "dev", size: "S" });
      for (let i = 0; i < (o.test | 0); i++) arr.push({ name: `app${i + 1}`, env: "test", size: "S" });
    }
    return arr
      .filter(s => s && String(s.name || "").trim() !== "")   // blank rows are drafts
      .map((s, i) => ({
        id: s.id != null ? s.id : i,
        label: String(s.name).trim(),
        env: String(s.env || "prod").trim() || "prod",
        size: SIZE[s.size] ? s.size : "M",
      }));
  }

  function defaultState() {
    return {
      azure: { cidr: "10.0.0.0/12", region: "westeurope", mode: "reference", reserveRegion2: true, headroom: true },
      onprem: [
        { id: 1, name: "HQ / Datacenter", cidr: "192.168.0.0/16" },
      ],
      connectivity: { expressRoute: true, vpn: true, routeServer: false },
      security: {
        arch: "dual",
        mixedNvaRole: "ns",
        azfwAdd: false,
        azfwTier: "ns",
        azfwPos: 1,
        ns: { groups: [{ kind: "vm", count: 2, min: 2, max: 4, name: "", names: [] }] },
        ew: { groups: [{ kind: "vm", count: 2, min: 2, max: 4, name: "", names: [] }] },
        azfwReserve: true,
        azfwMgmt: true,
      },
      services: {
        bastion: true, dns: true, dc: true, mon: true, kv: true,
        jump: true, pe: true, mgmt: true, ddos: true,
      },
      spokes: [
        { id: 1, name: "crm", env: "prod", size: "M" },
        { id: 2, name: "erp", env: "prod", size: "M" },
        { id: 3, name: "analytics", env: "prod", size: "L" },
        { id: 4, name: "crm", env: "dev", size: "S" },
        { id: 5, name: "crm", env: "test", size: "S" },
      ],
    };
  }

  /* ═══════════════════════ buildPlan ═════════════════════════ */

  function buildPlan(state) {
    const msgs = [];
    const err  = (title, text) => msgs.push({ level: "err",  title, text });
    const warn = (title, text) => msgs.push({ level: "warn", title, text });
    const info = (title, text) => msgs.push({ level: "info", title, text });

    const plan = { ok: true, msgs, state };

    /* ── 1 · master supernet + region ────────────────────────── */
    const region = slug(state.azure.region, "westeurope");
    plan.region = region;

    const master = C.parseCidr(state.azure.cidr);
    if (!master.ok) {
      err("Azure supernet invalid", master.error);
      plan.ok = false;
      return plan;
    }
    if (!master.exact) {
      info("Supernet normalized",
        `${state.azure.cidr.trim()} is not aligned for /${master.prefix} — using ${master.normalized}.`);
    }
    const fb = C.forbiddenHit(master.base, master.prefix);
    if (fb) { err("Forbidden range", `Azure supernet overlaps ${fb} — never usable in a private design (§2.2).`); plan.ok = false; return plan; }
    if (!C.isRfc1918(master.base, master.prefix)) {
      warn("Non-RFC 1918 supernet",
        "CAF requires RFC 1918 space (10/8, 172.16/12, 192.168/16) unless your organization owns this public range (§2.2).");
    }
    if (master.prefix > 22) {
      err("Supernet too small", `/${master.prefix} leaves no room for a hub plus spokes. Use /22 or larger (the v5.0 reference uses /12).`);
      plan.ok = false; return plan;
    }

    /* ── 2 · on-prem networks ────────────────────────────────── */
    const onprem = [];
    (state.onprem || []).forEach((o, i) => {
      const name = (o.name || "").trim() || `Site ${i + 1}`;
      if (!(o.cidr || "").trim()) return;
      const p = C.parseCidr(o.cidr);
      if (!p.ok) { err(`On-prem "${name}" invalid`, p.error); return; }
      const f = C.forbiddenHit(p.base, p.prefix);
      if (f) { err(`On-prem "${name}" forbidden`, `Overlaps ${f} (§2.2).`); return; }
      if (C.overlaps(master.base, master.prefix, p.base, p.prefix)) {
        err(`On-prem "${name}" overlaps Azure`,
          `${p.normalized} intersects the Azure supernet ${master.normalized}. CAF overlap gate fails — renumber, or NAT that site on the VPN gateway (§2.2).`);
        return;
      }
      if (!C.isRfc1918(p.base, p.prefix)) {
        info(`On-prem "${name}" is public space`, "Acceptable only if your organization owns this range.");
      }
      onprem.push({ name, base: p.base, prefix: p.prefix, cidr: p.normalized });
    });
    for (let i = 0; i < onprem.length; i++) {
      for (let j = i + 1; j < onprem.length; j++) {
        if (C.overlaps(onprem[i].base, onprem[i].prefix, onprem[j].base, onprem[j].prefix)) {
          warn("On-prem sites overlap",
            `"${onprem[i].name}" (${onprem[i].cidr}) and "${onprem[j].name}" (${onprem[j].cidr}) intersect — routes will be ambiguous unless they are supernet/subnet by design.`);
        }
      }
    }
    plan.onprem = onprem;

    const conn = state.connectivity;
    const hybrid = conn.expressRoute || conn.vpn;
    if (onprem.length && !hybrid) {
      warn("On-prem defined but no gateway",
        "ExpressRoute and VPN are both disabled — on-prem prefixes are included in routes/NSGs but unreachable until a gateway exists.");
    }
    if (!onprem.length && hybrid) {
      info("Gateways without on-prem prefixes",
        "Add at least one on-prem network so To-OnPremises routes and AD/PE NSG sources can be generated.");
    }

    /* ── 3 · layout mode ─────────────────────────────────────── */
    let mode = state.azure.mode;
    if (mode === "reference" && master.prefix > 13) {
      warn("Reference layout needs ≥ /13",
        `The v5.0 template allocates a /13 per region; your supernet is /${master.prefix}. Switched to Auto right-size.`);
      mode = "auto";
    }
    plan.mode = mode;

    const sec = state.security;
    const svc = state.services;
    const arch = ["dual", "single", "mixed", "azfw", "none"].includes(sec.arch) ? sec.arch : "dual";

    /* ── 3.1 · inspection engines per traffic class ──────────── */
    const mixedRole = sec.mixedNvaRole === "ew" ? "ew" : "ns";
    let nsEngine, ewEngine;
    if (arch === "dual" || arch === "single") { nsEngine = "nva"; ewEngine = "nva"; }
    else if (arch === "mixed") { nsEngine = mixedRole === "ns" ? "nva" : "azfw"; ewEngine = mixedRole === "ew" ? "nva" : "azfw"; }
    else if (arch === "azfw") { nsEngine = "azfw"; ewEngine = "azfw"; }
    else { nsEngine = "none"; ewEngine = "none"; }

    // chain: AzFW added INTO an NVA tier's chain (dual: pick the tier; single: the only tier).
    // azfwPos = 1-based slot: 1 = entry (default) … groups+1 = last (egress side)
    const chain = sec.azfwAdd && arch === "dual" ? (sec.azfwTier === "ew" ? "ew" : "ns")
                : sec.azfwAdd && arch === "single" ? "fw" : null;

    const azfwDeployed = nsEngine === "azfw" || ewEngine === "azfw" || !!chain;
    const wantNSNVA = (arch === "dual" || arch === "single") || (arch === "mixed" && mixedRole === "ns");
    const wantEWNVA = arch === "dual" || (arch === "mixed" && mixedRole === "ew");
    const isNVA = wantNSNVA || wantEWNVA;

    const nsCfg = normTier(sec.ns, sec.nsCount, sec.nsMode);
    const ewCfg = normTier(sec.ew, sec.ewCount, sec.ewMode);
    const chainCfg = chain === "ew" ? ewCfg : nsCfg;
    const chainLast = chain ? chainCfg.groups.filter(g => !g.standalone).length + 1 : 0; // slots = chained groups + 1
    const chainPos = chain ? clampI(sec.azfwPos, 1, Math.max(chainLast, 1), 1) : 1;

    let tierLabel = {
      dual: "Dual-tier NVA (NS + EW)",
      single: "Single-tier NVA",
      mixed: mixedRole === "ns" ? "NVA (N-S) + Azure Firewall (E-W)" : "Azure Firewall (N-S) + NVA (E-W)",
      azfw: "Azure Firewall Premium",
      none: "No central inspection",
    }[arch];
    if (chain === "ns" || chain === "ew") tierLabel = `Dual-tier NVA + Azure Firewall (${chain === "ns" ? "N-S egress" : "E-W"} chain)`;
    if (chain === "fw") tierLabel = "Single-tier NVA + Azure Firewall (chained)";

    /* ════════ 4 · HUB SUBNET CATALOG ════════ */
    const FW_EXT = arch === "single" ? "Subnet-FW-External" : "Subnet-NS-External";
    const FW_INT = arch === "single" ? "Subnet-FW-Internal" : "Subnet-NS-Internal";

    const wantGw   = hybrid;
    const wantRS   = conn.routeServer;
    const azfwSubnetActive = azfwDeployed || (isNVA && sec.azfwReserve);
    const azfwMgmtActive = azfwDeployed ? sec.azfwMgmt : (isNVA && sec.azfwReserve);
    const azfwPurpose = azfwDeployed
      ? (chain === "fw" ? "Azure Firewall (chained in front of the NVA tier)"
        : chain ? `Azure Firewall (chained into ${chain === "ns" ? "North-South egress" : "East-West"})`
        : arch === "mixed" ? `Azure Firewall (${mixedRole === "ns" ? "East-West" : "North-South"} engine)` : "Azure Firewall")
      : "Azure Firewall (reserved exit ramp)";

    const cat = [];
    const add = (key, section, name, prefix, purpose, rt, nsg, opts) =>
      cat.push(Object.assign({ key, section, name, prefix, purpose, rt: rt || "—", nsg: nsg || "—" }, opts));

    add("gw",      "conn", "GatewaySubnet",                  26, "VPN / ExpressRoute gateways", "RT-GatewaySubnet", "None (not supported)", { active: wantGw });
    add("rs",      "conn", "RouteServerSubnet",              26, "Azure Route Server",          "None (not supported)", "None (not supported)", { active: wantRS });
    add("azfw",    "conn", "AzureFirewallSubnet",            26, azfwPurpose, chain && chainPos < chainLast ? "RT-AzureFirewallSubnet" : "None", "None (not supported)", { active: azfwSubnetActive, deployed: azfwDeployed });
    add("azfwm",   "conn", "AzureFirewallManagementSubnet",  26, "Azure Firewall mgmt (forced tunneling)", "None (Azure-managed)", "None (not supported)", { active: azfwMgmtActive, deployed: azfwDeployed && sec.azfwMgmt });
    add("bastion", "conn", "AzureBastionSubnet",             26, "Azure Bastion",               "None (not supported)", "NSG-Bastion (required)", { active: svc.bastion });
    add("nsext",   "conn", FW_EXT,                           24, arch === "single" ? "NVA external NICs (Internet)" : "North-South NVA external NICs", arch === "single" ? "RT-FW-External" : "RT-NS-External", arch === "single" ? "NSG-FW-External" : "NSG-NS-External", { active: wantNSNVA });
    add("nsint",   "conn", FW_INT,                           24, arch === "single" ? "NVA internal NICs (+ ILB VIP)" : "North-South NVA internal NICs", arch === "single" ? "RT-FW-Internal" : "RT-NS-Internal", arch === "single" ? "NSG-FW-Internal" : "NSG-NS-Internal", { active: wantNSNVA });
    add("ewext",   "conn", "Subnet-EW-External",             24, "East-West NVA external NICs", "RT-EW-External", "NSG-EW-External", { active: wantEWNVA });
    add("ewint",   "conn", "Subnet-EW-Internal",             24, "East-West NVA internal NICs (+ ILB VIP)", "RT-EW-Internal", "NSG-EW-Internal", { active: wantEWNVA });
    add("rsv",     "conn", "Subnet-Reserved-Hub",            24, "Reserved (future use)",       "—", "—", { active: false, refOnly: true });
    add("nvam",    "conn", "Subnet-NVA-Management",          24, "NVA management interfaces",   "RT-NVA-Mgmt", "NSG-NVA-Mgmt", { active: isNVA });
    add("pe",      "conn", "Subnet-PrivateEndpoints-Hub",    24, "Private Endpoints (hub)",     "— (PE return traffic bypasses UDRs)", "NSG-PrivateEndpoints", { active: svc.pe });

    add("dnsin",  "shared", "Subnet-DNS-Inbound",  28, "DNS Resolver inbound endpoint",  "RT-Platform-Workloads", "None (delegated)", { active: svc.dns, delegation: "Microsoft.Network/dnsResolvers" });
    add("dnsout", "shared", "Subnet-DNS-Outbound", 28, "DNS Resolver outbound endpoint", "RT-Platform-Workloads", "None (delegated)", { active: svc.dns, delegation: "Microsoft.Network/dnsResolvers" });
    add("dc",     "shared", "Subnet-DomainControllers", 24, "AD Domain Controllers",     "RT-Platform-Workloads", "NSG-SharedServices", { active: svc.dc });
    add("mon",    "shared", "Subnet-Monitoring",        24, "Log Analytics / monitoring", "RT-Platform-Workloads", "NSG-SharedServices", { active: svc.mon });
    add("kv",     "shared", "Subnet-KeyVault",          24, "Key Vault private endpoints", "RT-Platform-Workloads", "NSG-SharedServices", { active: svc.kv });
    add("jump",   "shared", "Subnet-JumpServers",       24, "Jump / admin servers",        "RT-Platform-Workloads", "NSG-JumpServers", { active: svc.jump });

    add("auto",   "mgmt", "Subnet-AzureAutomation",  24, "Automation accounts", "RT-Management", "NSG-Management", { active: svc.mgmt });
    add("backup", "mgmt", "Subnet-BackupVault",      24, "Recovery Services",   "RT-Management", "NSG-Management", { active: svc.mgmt });
    add("update", "mgmt", "Subnet-UpdateManagement", 24, "Update Management",   "RT-Management", "NSG-Management", { active: svc.mgmt });

    /* ════════ 5 · PLACE THE HUB ════════ */
    const regionBase = master.base;
    const hub = { name: `vnet-hub-${region}`, prefixes: [], sections: [], subnets: [], declared: 0, subnetted: 0 };
    const sectionDefs = [
      { key: "conn",   name: "Connectivity" },
      { key: "shared", name: "Shared Services" },
      { key: "mgmt",   name: "Management" },
    ];
    const S = {};

    if (mode === "reference") {
      sectionDefs.forEach((sd, i) => {
        const sBase = regionBase + i * 8192;
        sd.base = sBase; sd.cidr = C.cidr(sBase, 19);
        const items = cat.filter(c => c.section === sd.key);
        const res = C.allocate(sBase, items.map(c => ({ key: c.key, prefix: c.prefix })));
        res.items.forEach(p => { S[p.key] = p; });
        hub.sections.push({ name: sd.name, cidr: sd.cidr });
        hub.prefixes.push(sd.cidr);
        hub.declared += 8192;
      });
    } else {
      const items = cat.filter(c => c.active).map(c => ({ key: c.key, prefix: c.prefix }));
      if (!items.length) {
        info("Empty hub", "No hub components selected — only spoke pools will be planned.");
      }
      const res = C.allocate(regionBase, items);
      res.items.forEach(p => { S[p.key] = p; });
      if (items.length) {
        const cover = C.coveringPrefix(regionBase, res.end);
        hub.prefixes.push(C.cidr(cover.base, cover.prefix));
        hub.declared = C.sizeOf(cover.prefix);
        hub.autoEnd = cover.base + C.sizeOf(cover.prefix);
      } else {
        hub.autoEnd = regionBase;
      }
    }

    cat.forEach(c => {
      const placed = S[c.key];
      if (!placed) return;
      const isActive = c.active && !c.refOnly;
      if (mode === "auto" && !isActive) return;
      hub.subnets.push({
        key: c.key, section: c.section, name: c.name,
        cidr: placed.cidr, base: placed.base, prefix: c.prefix,
        usable: C.usable(c.prefix),
        purpose: c.purpose, rt: c.rt, nsg: c.nsg,
        delegation: c.delegation || null,
        reserved: !isActive || (("deployed" in c) && !c.deployed),
      });
      if (isActive) hub.subnetted += C.sizeOf(c.prefix);
    });
    plan.hub = hub;

    const hubEnd = mode === "reference" ? regionBase + 65536 : hub.autoEnd;
    const hubRouteCidr = mode === "reference"
      ? C.cidr(regionBase, 16)
      : (hub.prefixes[0] || C.cidr(regionBase, 24));

    /* ════════ 6 · NVA TIERS, AZURE FIREWALL, NEXT HOPS, ILBs ════════ */
    const ilbs = [];
    const tiers = [];
    let nsHop = null, ewHop = null;
    const ipAt = (key, off) => S[key] ? C.intToIp(S[key].base + off) : null;
    const azfwHop = azfwDeployed ? { ip: ipAt("azfw", 4), label: "Azure Firewall private IP", kind: "azfw" } : null;

    /* a tier = ordered chain of NVA groups in the SAME subnet pair.
       group 1 owns the doc VIP (.100) and is the routing ENTRY point;
       group i+1 gets the next VIP (.101, .102 …). Azure UDRs only ever
       reference the entry hop — each group's NVA OS must forward to
       the NEXT group's hop, and every group SNATs to its internal NICs
       so each chain hop stays flow-symmetric (§6.7).                  */
    function buildTier(key, label, ilbDocName, extKey, intKey, intName, tierCfg, purpose) {
      const ext = S[extKey], internal = S[intKey];
      if (!ext || !internal) return null;
      /* address law per /24 tier subnet (v5.1 §A1.2):
         statics .4–.99 (max 96) · VIP ladder .100+gi (max 155 groups) ·
         VMSS NICs dynamic from the remainder                            */
      let nicOff = 4;                                   // sequential NIC IPs across groups
      const groups = [];
      const gseen = {};
      tierCfg.groups.forEach((cfg, gi) => {
        const vmss = cfg.kind === "vmss";
        const ha = vmss || cfg.count >= 2;
        let group = slug(cfg.name, gi === 0 ? key : `${key}${gi + 1}`);
        gseen[group] = (gseen[group] || 0) + 1;
        if (gseen[group] > 1) group = `${group}${gseen[group]}`;
        const display = cfg.name || (gi === 0 ? label : group);
        if (100 + gi > 254) {
          err(`${label} tier VIP ladder exhausted`,
            `Group ${gi + 1} ("${display}") would need VIP .${100 + gi}; a /24 internal subnet supports at most 155 chained groups (.100–.254). Remove groups (§20.2).`);
          return;
        }
        if (!vmss && nicOff + cfg.count - 1 >= 100) {
          err(`${label} tier static NIC range exhausted`,
            `"${display}" needs static NICs .${nicOff}–.${nicOff + cfg.count - 1}, but statics must stay below .100 (the VIP ladder) — max 96 static NICs per tier. Convert later groups to VMSS (dynamic NICs) (§20.2).`);
          return;
        }
        const vip = C.intToIp(internal.base + 100 + gi);
        const ilbName = gi === 0 ? ilbDocName : `lbi-${key}-${group}`;
        const hop = ha
          ? { ip: vip, label: ilbName, kind: "ilb" }
          : { ip: C.intToIp(internal.base + nicOff), label: `${display} NVA NIC`, kind: "nic" };
        const instances = [];
        if (!vmss) {
          for (let i = 0; i < cfg.count; i++) {
            const override = (cfg.names && cfg.names[i]) ? slug(cfg.names[i], "") : "";
            instances.push({
              name: override ? `nva-${override}` : `nva-${group}-${String(i + 1).padStart(2, "0")}`,
              ext: C.intToIp(ext.base + nicOff + i),
              int: C.intToIp(internal.base + nicOff + i),
              mgmt: null,
              loopbacks: ha ? [vip] : [],
            });
          }
          nicOff += cfg.count;
        }
        const chainIdx = cfg.standalone ? null : (groups.filter(x => !x.standalone).length + 1);
        groups.push({ name: group, display, cfg, vmss, ha, count: vmss ? null : cfg.count,
                      scale: vmss ? { min: cfg.min, max: cfg.max } : null,
                      standalone: !!cfg.standalone, chainIdx,
                      vip, hop, ilbName: ha ? ilbName : null, vmssName: `vmss-${group}`, instances });
        if (ha) ilbs.push({
          name: ilbName, vip, subnet: intName,
          pool: vmss ? `vmss-${group} (Flex) — autoscale ${cfg.min}–${cfg.max} instances, dynamic NIC IPs` : instances.map(x => x.int).join(", "),
          purpose: cfg.standalone ? `${label} standalone — direct access (e.g., explicit proxy), not in the chain`
            : chainIdx === 1 ? purpose : `${label} chain hop ${chainIdx} — receives from the previous hop`,
        });
      });
      const chainedG = groups.filter(g => !g.standalone);
      if (!chainedG.length && groups.length) {
        err(`${label} tier has no chained group`,
          `All ${groups.length} groups are standalone — at least one group must be in the chain to receive routed traffic (0.0.0.0/0 / east-west). Standalone groups (e.g., explicit proxies) are reached directly by clients, never via UDR.`);
      }
      const g0 = chainedG[0] || groups[0];
      const t = {
        key, label, groups, chainLen: groups.length,
        hop: g0.hop, purpose,
        extSubnet: ext.cidr, intSubnet: internal.cidr, intName,
        // tier-level mirrors of group 1 (renderers + back-compat)
        display: g0.display, group: g0.name, vmssName: g0.vmssName,
        vmss: g0.vmss, ha: g0.ha, count: g0.count, scale: g0.scale, ilbName: g0.ilbName,
        instances: groups.flatMap(g => g.instances),
      };
      tiers.push(t);
      if (chainedG.length > 1) {
        const hops = chainedG.map((g, i) => `${i + 1}. ${g.display} (${g.hop.ip})`).join(" → ");
        info(`${label} tier — chained NVA groups`,
          `Traffic order: ${hops} → ${key === "ew" ? "destination (VNet)" : key === "fw" ? "destination / Internet" : "Internet"}. Azure route tables target only the entry hop (${g0.hop.ip}); configure each group's NVAs to forward to the NEXT group's hop, and SNAT to their internal NICs at every hop so each segment stays flow-symmetric (§6.7).`);
      }
      const solos = groups.filter(g => g.standalone);
      if (solos.length) {
        info(`${label} tier — standalone groups`,
          `${solos.map(g => `${g.display} (${g.hop.ip})`).join(", ")}: not part of the chain — reached directly (e.g., an explicit proxy via client/PAC configuration). No UDR points at them; they keep their VIP and subnet capacity.`);
      }
      return t;
    }

    if (arch === "dual") {
      const tNS = buildTier("ns", "North-South", "ILB-NS-Outbound", "nsext", "nsint", FW_INT, nsCfg, "Outbound to Internet");
      const tEW = buildTier("ew", "East-West", "ILB-EW-Outbound", "ewext", "ewint", "Subnet-EW-Internal", ewCfg, "Single entry point for all East-West inspection");
      nsHop = tNS && tNS.hop; ewHop = tEW && tEW.hop;
    } else if (arch === "single") {
      const t = buildTier("fw", "Inspection", "ILB-FW-Outbound", "nsext", "nsint", FW_INT, nsCfg, "All inspected traffic (N-S + E-W)");
      nsHop = ewHop = t && t.hop;
    } else if (arch === "mixed") {
      if (mixedRole === "ns") {
        const t = buildTier("ns", "North-South", "ILB-NS-Outbound", "nsext", "nsint", "Subnet-NS-Internal", nsCfg, "Outbound to Internet (NVA)");
        nsHop = t && t.hop; ewHop = azfwHop;
      } else {
        const t = buildTier("ew", "East-West", "ILB-EW-Outbound", "ewext", "ewint", "Subnet-EW-Internal", ewCfg, "East-West inspection (NVA)");
        ewHop = t && t.hop; nsHop = azfwHop;
      }
    } else if (arch === "azfw") {
      nsHop = ewHop = azfwHop;
    }

    if (S.nvam) {
      let mi = 4;
      tiers.forEach(t => t.instances.forEach(inst => { inst.mgmt = mi <= 254 ? C.intToIp(S.nvam.base + mi) : null; mi++; }));
      if (mi - 4 > 251) {
        err("Subnet-NVA-Management exhausted",
          `${mi - 4} static management NICs exceed the 251 usable addresses of the /24 (§20.2). Convert groups to VMSS (dynamic mgmt NICs).`);
      }
    }

    // workloads enter the chain at slot 1 — the firewall only becomes the
    // workload-facing hop when it occupies the entry slot
    let egressHop = nsHop, lateralHop = ewHop;
    if (chainPos === 1 && azfwHop) {
      if (chain === "ns") egressHop = azfwHop;
      if (chain === "ew") lateralHop = azfwHop;
      if (chain === "fw") { egressHop = azfwHop; lateralHop = azfwHop; }
    }

    plan.ilbs = ilbs;
    plan.nva = { tiers };
    plan.azfw = azfwDeployed && azfwHop ? {
      ip: azfwHop.ip,
      chain, chainPos: chain ? chainPos : null,
      role: chain ? `Chained — ${chain === "ns" ? "North-South" : chain === "ew" ? "East-West" : "single tier"}, hop ${chainPos} of ${chainLast}`
        : arch === "azfw" ? "N-S + E-W" : (mixedRole === "ns" ? "East-West" : "North-South"),
    } : null;
    plan.nsHop = egressHop; plan.ewHop = lateralHop;

    const spofGroups = tiers.flatMap(t => t.groups.filter(g => !g.ha).map(g => `${g.display} (${t.label})`));
    if (spofGroups.length) {
      warn(`Single-instance NVA group (${spofGroups.join(", ")})`,
        "One NVA is a single point of failure for every flow it inspects — routes point at its NIC IP, so failover requires UDR rewrites. Use 2-3 VMs (active-active behind a Standard ILB with HA ports) or a VMSS for autoscale.");
    }
    const vmssGroups = tiers.flatMap(t => t.groups.filter(g => g.vmss).map(g => ({ t, g })));
    if (vmssGroups.length) {
      info("VMSS NVA groups",
        `${vmssGroups.map(x => `${x.g.display} in ${x.t.label} (${x.g.scale.min}–${x.g.scale.max})`).join(", ")}: instance NICs are allocated dynamically from the tier subnets — routing anchors on the static ILB VIP. The vendor image must join the ILB backend pool on scale-out and SNAT via its internal NIC; validate flow symmetry after every scale event (§6.3/§6.7).`);
      vmssGroups.forEach(x => {
        if (x.g.scale.min < 2) warn(`VMSS floor of ${x.g.scale.min} (${x.g.display})`,
          "An autoscale minimum below 2 means a single instance during quiet periods or zone failure — effectively a periodic SPOF. Set min ≥ 2 for inspection tiers.");
      });
    }
    if (chain && azfwHop) {
      const chainTierObj = tiers.find(t => t.key === (chain === "ew" ? "ew" : chain === "fw" ? "fw" : "ns"));
      const seq = chainTierObj ? chainTierObj.groups.filter(g => !g.standalone).map(g => ({ label: g.display, ip: g.hop.ip })) : [];
      seq.splice(chainPos - 1, 0, { label: "Azure Firewall", ip: azfwHop.ip });
      const order = seq.map((s2, i) => `${i + 1}. ${s2.label} (${s2.ip})`).join(" → ");
      const exit = chain === "ew" ? "destination (VNet)" : chain === "fw" ? "destination / Internet" : "Internet";
      info(`Chained inspection — Azure Firewall at hop ${chainPos} of ${chainLast}`,
        `Order: ${order} → ${exit}. Azure route tables target only hop 1; every element forwards to the NEXT hop (appliance/firewall config) and SNATs at its segment so returns retrace the chain. ` +
        (chain === "ew" ? "Keep the firewall's default no-SNAT for RFC 1918 so downstream NVAs see true sources; the tier's NVA SNAT preserves return symmetry via To-NVA-Internal-Direct." :
          chainPos === chainLast ? "As the last hop the firewall egresses natively and SNATs to its public IP." :
          "The firewall SNATs to its private range so its segment's returns retrace it."));
    }
    if (azfwDeployed && ewEngine === "azfw") {
      info("Azure Firewall east-west SNAT",
        "By default Azure Firewall does not SNAT RFC 1918 traffic. For the ILB-symmetry-free spoke↔spoke pattern set Private IP ranges = 255.255.255.255/32 (always SNAT) on the Firewall Policy (§6.5).");
    }
    if (arch === "mixed") {
      info("Mixed inspection plane",
        `Only one AzureFirewallSubnet exists per VNet, so the firewall exclusively serves the ${mixedRole === "ns" ? "East-West" : "North-South"} role; the NVA tier keeps the ${mixedRole === "ns" ? "North-South" : "East-West"} role. Both engines see complete sessions because each traffic class keeps a single inspection point.`);
    }
    if (arch === "none") {
      warn("No central egress path",
        "Default outbound access is retired for new VNets (API ≥ 31 Mar 2026): without a firewall/NVA, every spoke needs explicit egress — NAT Gateway per subnet or instance public IPs (§12.6). Spoke↔spoke also requires direct peering per pair (no transit).");
    }
    if (wantRS && !isNVA) {
      info("Route Server without NVAs", "Route Server exists to exchange BGP routes with NVAs — with no NVA tier it usually has no peer.");
    }
    if (svc.dns && conn.expressRoute) {
      warn("ExpressRoute FastPath must stay OFF",
        "DNS Private Resolver inbound resolution from on-prem is incompatible with FastPath (§3.2.1). ErGw2AZ conveniently does not support FastPath; keep it off if you upgrade SKUs.");
      info("No wildcard DNS forwarding rules",
        "Resolver + ER gateway in the same VNet: the forwarding ruleset must contain only explicit domain rules, never a catch-all \".\" rule (§3.2.1).");
    }

    /* ════════ 7 · SPOKES — free-form catalog with CAF naming ════════ */
    const spokesIn = normSpokes(state.spokes);

    // CAF naming with duplicate handling: vnet-<name>-<env>-<region>[-NNN]
    const seen = {};
    spokesIn.forEach(s => {
      const base = `${slug(s.label, "app")}-${slug(s.env, "prod")}-${region}`;
      seen[base] = (seen[base] || 0) + 1;
      s.nameBase = seen[base] === 1 ? base : `${base}-${String(seen[base]).padStart(3, "0")}`;
      s.vnetName = `vnet-${s.nameBase}`;
      s.rtName = `rt-${s.nameBase}`;
    });
    if (Object.values(seen).some(n => n > 1)) {
      info("Duplicate spoke names", "Spokes sharing the same name + environment received -002/-003 instance suffixes (CAF style). Rename them if you want distinct identities.");
    }

    const pools = [];
    let spokeAreaEnd = hubEnd;

    function poolObj(key, name, base, prefix, note) {
      return { key, name, base, prefix, cidr: C.cidr(base, prefix), size: C.sizeOf(prefix), note: note || "", allocs: [], used: 0 };
    }
    function pushAlloc(pool, s, base, prefix) {
      pool.allocs.push({
        id: s.id, label: s.label, env: s.env, sizeKey: s.size,
        name: s.vnetName, nameBase: s.nameBase, rtName: s.rtName,
        cidr: C.cidr(base, prefix), base, prefix,
        size: SIZE[s.size].label, template: SIZE[s.size].template,
      });
      pool.used += C.sizeOf(prefix);
    }

    let growth = null;

    if (mode === "reference") {
      /* size-based doc pools (env is naming metadata):
         M+L → 10.4.0.0/15 two-pointer · S → 10.6.0.0/16, overflow 10.7.0.0/16 */
      const poolML = poolObj("ml", "Medium / Large", regionBase + 4 * 65536, 15, "Medium /22 bottom-up · Large /20 top-down (§4.1.1)");
      const poolS1 = poolObj("s1", "Small", regionBase + 6 * 65536, 16, "Small /24 sequential");
      const poolS2 = poolObj("s2", "Small (overflow)", regionBase + 7 * 65536, 16, "Used when the first Small pool fills");
      growth = { name: "Reserved — platform growth", cidr: `${C.cidr(regionBase + 65536, 16)} + ${C.cidr(regionBase + 2 * 65536, 15)}`, size: 196608 };
      spokeAreaEnd = regionBase + 8 * 65536;

      const custom = spokesIn.filter(s => ![20, 22, 24].includes(SIZE[s.size].prefix));
      if (custom.length) {
        err("Custom spoke sizes need Auto mode",
          `${custom.map(s => s.vnetName).join(", ")}: the v5.0 reference pools only hold /24, /22 and /20 slots. Switch the layout mode to Auto right-size for custom prefixes.`);
      }
      const mediums = spokesIn.filter(s => SIZE[s.size].prefix === 22);
      const larges = spokesIn.filter(s => SIZE[s.size].prefix === 20);
      const smalls = spokesIn.filter(s => SIZE[s.size].prefix === 24);

      poolML.maxM = poolML.size / 1024; poolML.maxL = poolML.size / 4096;
      const needML = mediums.length * 1024 + larges.length * 4096;
      if (needML > poolML.size) {
        err("Medium/Large pool exhausted",
          `${mediums.length}× /22 + ${larges.length}× /20 needs ${C.fmt(needML)} addresses but ${poolML.cidr} holds ${C.fmt(poolML.size)}. Reduce sizes/counts or switch to Auto mode.`);
      }
      let mBase = poolML.base;
      mediums.forEach(s => { if (mBase + 1024 <= poolML.base + poolML.size) { pushAlloc(poolML, s, mBase, 22); mBase += 1024; } });
      let lTop = poolML.base + poolML.size;
      larges.forEach(s => { const b = lTop - 4096; if (b >= mBase) { pushAlloc(poolML, s, b, 20); lTop = b; } });

      poolS1.maxS = 256; poolS2.maxS = 256;
      if (smalls.length > 512) err("Small pools exhausted", `${smalls.length}× /24 exceeds the 512 slots of ${poolS1.cidr} + ${poolS2.cidr}.`);
      smalls.forEach((s, i) => {
        if (i < 256) pushAlloc(poolS1, s, poolS1.base + i * 256, 24);
        else if (i < 512) pushAlloc(poolS2, s, poolS2.base + (i - 256) * 256, 24);
      });

      pools.push(poolML, poolS1, poolS2);
    } else {
      /* auto: one right-sized pool per environment (insertion order) */
      const f = state.azure.headroom ? 2 : 1;
      let cursor = hubEnd;
      const envOrder = [];
      const byEnv = {};
      spokesIn.forEach(s => {
        const e = slug(s.env, "prod");
        if (!byEnv[e]) { byEnv[e] = []; envOrder.push(e); }
        byEnv[e].push(s);
      });
      envOrder.forEach(e => {
        const list = byEnv[e];
        const need = list.reduce((a, s) => a + SIZE[s.size].bytes, 0);
        const slotMax = Math.max(...list.map(s => SIZE[s.size].bytes));
        const sizeP = Math.max(nextPow2(need * f), slotMax);
        const pfx = C.prefixForSize(sizeP);
        const base = C.alignUp(cursor, pfx);
        const pool = poolObj(e, `Environment: ${e}`, base, pfx, `right-sized for ${list.length} spoke${list.length === 1 ? "" : "s"}${state.azure.headroom ? " · ≈2× headroom" : ""}`);
        cursor = base + sizeP;
        // big prefixes (≤ /20) top-down, the rest bottom-up by ascending prefix
        let bBase = pool.base;
        let bTop = pool.base + pool.size;
        list.filter(s => SIZE[s.size].prefix > 20)
            .sort((a, b) => SIZE[a.size].prefix - SIZE[b.size].prefix)
            .forEach(s => { const pfx = SIZE[s.size].prefix; bBase = C.alignUp(bBase, pfx); pushAlloc(pool, s, bBase, pfx); bBase += SIZE[s.size].bytes; });
        list.filter(s => SIZE[s.size].prefix <= 20).forEach(s => {
          const pfx = SIZE[s.size].prefix;
          const b = C.alignUp(bTop - SIZE[s.size].bytes, pfx) === bTop - SIZE[s.size].bytes ? bTop - SIZE[s.size].bytes : Math.floor((bTop - SIZE[s.size].bytes) / SIZE[s.size].bytes) * SIZE[s.size].bytes;
          if (b >= bBase) { pushAlloc(pool, s, b, pfx); bTop = b; }
          else { err(`Pool "${e}" exhausted`, `${SIZE[s.size].label} spoke ${s.vnetName} does not fit — enable headroom or enlarge the supernet.`); }
        });
        pools.push(pool);
      });
      spokeAreaEnd = cursor;
    }
    plan.pools = pools;
    plan.growth = growth;
    const allAllocs = pools.flatMap(p => p.allocs);
    const totalSpokes = allAllocs.length;

    const masterEnd = master.base + master.size;
    if (spokeAreaEnd > masterEnd) {
      const cover = C.coveringPrefix(master.base, spokeAreaEnd);
      err("Supernet too small for this design",
        `The plan needs ${C.fmt(spokeAreaEnd - master.base)} addresses but ${master.normalized} holds ${C.fmt(master.size)}. Use at least a /${cover.prefix}.`);
    }

    plan.region2 = null;
    if (state.azure.reserveRegion2) {
      if (mode === "reference") {
        const r2Base = regionBase + C.sizeOf(13);
        if (r2Base + C.sizeOf(13) <= masterEnd) plan.region2 = { cidr: C.cidr(r2Base, 13), size: C.sizeOf(13) };
        else info("No room for Region 2", `A second /13 does not fit inside ${master.normalized} — the v5.0 pattern consumes a full /12 for two regions.`);
      } else {
        const span = spokeAreaEnd - master.base;
        const cover = C.coveringPrefix(master.base, spokeAreaEnd);
        const r2Base = C.alignUp(spokeAreaEnd, cover.prefix);
        if (span > 0 && r2Base + C.sizeOf(cover.prefix) <= masterEnd) {
          plan.region2 = { cidr: C.cidr(r2Base, cover.prefix), size: C.sizeOf(cover.prefix) };
        } else if (span > 0) {
          info("No room for Region 2", "An identical second-region block does not fit in the remaining supernet space.");
        }
      }
    }

    /* spoke template tiers — instantiated per spoke as snet-/nsg-<tier>-<spoke>-<env>-<region> */
    plan.templates = {
      std22: [
        { tier: "web", off: 0, prefix: 25, purpose: "Web tier" },
        { tier: "app", off: 128, prefix: 25, purpose: "Application tier" },
        { tier: "data", off: 256, prefix: 25, purpose: "Database tier" },
        { tier: "pe", off: 384, prefix: 26, purpose: "Private Endpoints" },
        { tier: "reserved", off: 448, prefix: 26, purpose: "Future use", reserved: true },
        { tier: "(upper /23)", off: 512, prefix: 23, purpose: "Expansion: extra tiers / AKS pools / PE growth", reserved: true },
      ],
      std24: [
        { tier: "workload", off: 0, prefix: 26, purpose: "Combined web/app tier" },
        { tier: "data", off: 64, prefix: 26, purpose: "Database tier" },
        { tier: "pe", off: 128, prefix: 27, purpose: "Private Endpoints" },
        { tier: "reserved", off: 160, prefix: 27, purpose: "Future use", reserved: true },
        { tier: "reserved2", off: 192, prefix: 26, purpose: "Future use", reserved: true },
      ],
      large20: [
        { tier: "(workload-defined)", off: 0, prefix: 20, purpose: "AKS (Azure CNI), AVS, big data — size subnets from the service's documented IP consumption (§4.1.1)" },
      ],
    };

    /* ════════ 8 · MASTER ALLOCATION TABLE ════════ */
    const masterRows = [];
    masterRows.push({ name: "Master supernet", cidr: master.normalized, addresses: master.size, kind: "master", note: "All Azure Landing Zone networks" });
    if (mode === "reference") {
      masterRows.push({ name: "Region 1", cidr: C.cidr(regionBase, 13), addresses: C.sizeOf(13), kind: "region", note: `Primary region — ${region}` });
      masterRows.push({ name: "├─ Platform Landing Zone", cidr: C.cidr(regionBase, 16), addresses: 65536, kind: "block", note: `${hub.name} declares ${hub.prefixes.length} × /19 = ${C.fmt(hub.declared)} addresses; remainder plan-reserved (§3.0)` });
      masterRows.push({ name: "├─ Reserved — platform growth", cidr: growth.cidr, addresses: growth.size, kind: "reserved", note: "Second hub / Identity VNet; never assign to spokes (§2)" });
      masterRows.push({ name: "└─ Application Landing Zones", cidr: C.cidr(regionBase + 4 * 65536, 14), addresses: C.sizeOf(14), kind: "block", note: "Size-based pools below — environment lives in the name, not the pool" });
      pools.forEach(p => masterRows.push({ name: `&nbsp;&nbsp;&nbsp;&nbsp;${p.name} pool`, cidr: p.cidr, addresses: p.size, kind: "pool", note: p.note }));
    } else {
      if (hub.prefixes.length) masterRows.push({ name: hub.name, cidr: hub.prefixes[0], addresses: hub.declared, kind: "block", note: "Right-sized; extend online later (peering resync per change, §2.2)" });
      pools.forEach(p => masterRows.push({ name: `${p.name} pool`, cidr: p.cidr, addresses: p.size, kind: "block", note: `${p.allocs.length} spokes · ${p.note}` }));
    }
    if (plan.region2) masterRows.push({ name: "Region 2 (reserved)", cidr: plan.region2.cidr, addresses: plan.region2.size, kind: "reserved", note: "Deploy with the identical internal template (§2.1)" });
    const masterEnd2 = master.base + master.size;
    const freeStart = mode === "reference" ? (plan.region2 ? regionBase + 2 * C.sizeOf(13) : regionBase + C.sizeOf(13)) : (plan.region2 ? null : spokeAreaEnd);
    if (freeStart !== null && freeStart < masterEnd2) {
      masterRows.push({ name: "Unallocated", cidr: `${C.intToIp(freeStart)} – ${C.intToIp(masterEnd2 - 1)}`, addresses: masterEnd2 - freeStart, kind: "free", note: "Future regions — reserve in IPAM before use (§2)" });
    }
    plan.masterRows = masterRows;

    /* ════════ 9 · ROUTE TABLES ════════ */
    const rts = [];
    const spokesPrefixes = mode === "reference"
      ? [C.cidr(regionBase + 4 * 65536, 14)]
      : pools.map(p => p.cidr);
    const sharedCidr = mode === "reference" ? C.cidr(regionBase + 8192, 19) : null;
    const mgmtCidr   = mode === "reference" ? C.cidr(regionBase + 16384, 19) : null;
    const sharedKeys = ["dnsin", "dnsout", "dc", "mon", "kv", "jump"];
    const hasShared = sharedKeys.some(k => S[k] && cat.find(c => c.key === k).active);
    const hasMgmt = svc.mgmt;
    const va = "Virtual Appliance";

    const onpremRoutes = (hop) => onprem.map((o, i) =>
      route(onprem.length > 1 ? `To-OnPremises-${i + 1}` : "To-OnPremises", o.cidr, va, `${hop.ip} (${hop.label})`));

    const ewIntKey = ewEngine === "nva" ? (arch === "dual" || arch === "mixed" ? "ewint" : "nsint") : null;
    const ewSnatRange = ewEngine === "nva" ? (S[ewIntKey] && S[ewIntKey].cidr) : (ewEngine === "azfw" ? (S.azfw && S.azfw.cidr) : null);

    if (arch !== "none" && nsHop && ewHop) {
      const nsTo = `${egressHop.ip} (${egressHop.label})`;
      const ewTo = `${lateralHop.ip} (${lateralHop.label})`;
      const tierNsTo = `${nsHop.ip} (${nsHop.label})`;
      const tierEwTo = `${ewHop.ip} (${ewHop.label})`;

      if (wantGw) {
        const r = [];
        spokesPrefixes.forEach((p, i) => r.push(route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)));
        if (hasShared) r.push(route("To-SharedServices", sharedCidr || hubRouteCidr, va, ewTo));
        if (hasMgmt && mgmtCidr) r.push(route("To-Management", mgmtCidr, va, ewTo));
        rts.push({ name: "RT-GatewaySubnet", appliesTo: "GatewaySubnet", bgp: "Enabled", required: true, routes: r,
          note: "On-prem traffic arriving via VPN/ER is steered through the East-West inspector before reaching spokes or platform services. 0.0.0.0/0 is NOT permitted here; BGP propagation must stay enabled (§7.0)." });
      }

      {
        const r = [route("To-Internet", "0.0.0.0/0", va, nsTo), route("To-Hub", hubRouteCidr, va, ewTo)];
        spokesPrefixes.forEach((p, i) => r.push(route(spokesPrefixes.length > 1 ? `To-OtherSpokes-${i + 1}` : "To-OtherSpokes", p, va, ewTo)));
        r.push(...onpremRoutes(lateralHop));
        if (ewEngine === "nva" && S[ewIntKey]) {
          r.push(route("To-NVA-Internal-Direct", S[ewIntKey].cidr, "Virtual Network", "—"));
        }
        rts.push({ name: "RT-Spoke-Workloads", appliesTo: `every spoke subnet — instantiated per spoke as rt-<spoke>-<env>-${region}`, bgp: "Disabled", routes: r,
          note: (mode === "reference" ? "To-Hub deliberately uses the /16 plan supernet — packets to unassigned hub space are steered to the firewall and dropped there (inspected black-hole, §3.0). " : "") +
                (ewEngine === "nva" ? "To-NVA-Internal-Direct lets SNAT return traffic reach the specific NVA instance directly, preventing asymmetry in active-active scenarios (§7.1)." : "Azure Firewall return traffic needs no direct route — the platform handles symmetry.") });
      }

      if (chain && chainPos < chainLast) {
        // the firewall forwards to the CHAINED group occupying the next slot
        const chainTierObj = tiers.find(t => t.key === (chain === "ew" ? "ew" : chain === "fw" ? "fw" : "ns"));
        const nxt = chainTierObj && chainTierObj.groups.filter(g => !g.standalone)[chainPos - 1];
        const to = nxt ? `${nxt.hop.ip} (${nxt.hop.label})` : tierNsTo;
        rts.push({
          name: "RT-AzureFirewallSubnet", appliesTo: "AzureFirewallSubnet", bgp: "Disabled",
          routes: chain === "ns"
            ? [route("To-Internet-via-NVA", "0.0.0.0/0", va, to)]
            : chain === "fw"
            ? [
                route("To-Internet-via-NVA", "0.0.0.0/0", va, to),
                ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, to)),
                ...(hasShared ? [route("To-SharedServices", sharedCidr || hubRouteCidr, va, to)] : []),
                ...(hasMgmt && mgmtCidr ? [route("To-Management", mgmtCidr, va, to)] : []),
              ]
            : [
                ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, to)),
                ...(hasShared ? [route("To-SharedServices", sharedCidr || hubRouteCidr, va, to)] : []),
                ...(hasMgmt && mgmtCidr ? [route("To-Management", mgmtCidr, va, to)] : []),
              ],
          note: `Chain hop ${chainPos}: the firewall forwards to ${nxt ? nxt.display : "the next group"} (hop ${chainPos + 1}). BGP propagation disabled — explicit routes only. AzureFirewallManagementSubnet must keep Azure-managed routing (no UDR).`,
        });
      } else if (chain) {
        info("Azure Firewall is the last chain hop",
          chain === "ew"
            ? "No RT-AzureFirewallSubnet needed — the firewall delivers to destinations via VNet system routes. The preceding NVA group must forward its inspected lateral traffic to the firewall's private IP."
            : "No RT-AzureFirewallSubnet needed — the firewall egresses to Internet natively (SNAT to its public IP). The preceding NVA group must forward internet-bound traffic to the firewall's private IP.");
      }

      if (nsEngine === "nva" && arch !== "single") {
        rts.push({ name: "RT-NS-External", appliesTo: "Subnet-NS-External", bgp: "Disabled", routes: [
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, tierNsTo)),
          ...(hasShared ? [route("To-SharedServices", sharedCidr || hubRouteCidr, va, tierNsTo)] : []),
        ], note: "Defensive cascade, not a loop: a stray internal-destined packet egressing the external NIC is intercepted and cascaded external → internal → East-West inspection (§7.2)." });

        rts.push({ name: "RT-NS-Internal", appliesTo: "Subnet-NS-Internal", bgp: "Disabled", routes:
          spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)),
          note: "Internet-bound replies leave via the external NIC using system routing — no 0.0.0.0/0 here (§7.3)." });
      }

      if (ewEngine === "nva" && arch !== "single") {
        rts.push({ name: "RT-EW-External", appliesTo: "Subnet-EW-External", bgp: "Disabled", routes: [
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, "Virtual Network", "—")),
          ...(hasShared ? [route("To-SharedServices", sharedCidr || hubRouteCidr, "Virtual Network", "—")] : []),
          route("To-Internet", "0.0.0.0/0", va, nsTo),
        ], note: "Virtual Network next-hops prevent the EW sandwich loop (§7.4). No data-plane traffic on this NIC in the current design." });

        rts.push({ name: "RT-EW-Internal", appliesTo: "Subnet-EW-Internal", bgp: "Enabled", routes: [
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, "Virtual Network", "—")),
          route("To-Hub", hubRouteCidr, "Virtual Network", "—"),
        ], note: "BGP enabled so the EW NVA learns the return path to on-prem; explicit Virtual-Network UDRs override BGP via longest-prefix match (§7.5)." });
      }

      if (arch === "single") {
        rts.push({ name: "RT-FW-External", appliesTo: FW_EXT, bgp: "Disabled", routes:
          spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)),
          note: "Defensive: internal-destined packets leaking out the external NIC are steered back through the ILB for inspection." });
        rts.push({ name: "RT-FW-Internal", appliesTo: FW_INT, bgp: "Enabled", routes: [
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, "Virtual Network", "—")),
          route("To-Hub", hubRouteCidr, "Virtual Network", "—"),
        ], note: "The NVA egresses directly via VNet peering, never back through its own ILB. BGP enabled for the on-prem return path." });
      }

      if (hasShared || svc.dns) {
        rts.push({ name: "RT-Platform-Workloads", appliesTo: "DomainControllers, Monitoring, KeyVault, JumpServers + DNS Resolver subnets", bgp: "Disabled", routes: [
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)),
          route("To-Internet", "0.0.0.0/0", va, nsTo),
          ...onpremRoutes(lateralHop),
        ], note: svc.dns ? "DNS Resolver egress transits the firewall — it must explicitly allow outbound endpoint → Internet:53 and → on-prem DNS:53, or resolution fails silently (§3.2.2)." : "" });
      }

      if (isNVA) {
        rts.push({ name: "RT-NVA-Mgmt", appliesTo: "Subnet-NVA-Management", bgp: "Disabled", routes: [
          route("To-Internet", "0.0.0.0/0", va, nsTo),
          ...onpremRoutes(lateralHop),
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)),
        ], note: "Management plane is inspected like any platform flow. If the vendor requires out-of-band management independent of the data-plane NVAs, remove 0.0.0.0/0 and document the exception (§7.7)." });
      }

      if (hasMgmt) {
        rts.push({ name: "RT-Management", appliesTo: "AzureAutomation, BackupVault, UpdateManagement", bgp: "Disabled", routes: [
          route("To-Internet", "0.0.0.0/0", va, nsTo),
          ...onpremRoutes(lateralHop),
          ...spokesPrefixes.map((p, i) => route(spokesPrefixes.length > 1 ? `To-Spokes-${i + 1}` : "To-Spokes", p, va, ewTo)),
        ], note: "Identical to RT-Platform-Workloads; kept separate for blast-radius isolation (§7.8)." });
      }
    } else if (arch === "none") {
      if (wantGw) {
        rts.push({ name: "(no route tables required)", appliesTo: "—", bgp: "—", routes: [],
          note: "System routes + VNet peering with gateway transit handle all reachability. Spokes learn on-prem prefixes via BGP automatically; spoke↔spoke needs direct peering per pair." });
      } else {
        rts.push({ name: "(no route tables required)", appliesTo: "—", bgp: "—", routes: [],
          note: "System routes handle everything. Add NAT Gateways for internet egress (default outbound access is retired)." });
      }
    }
    plan.routeTables = rts;

    plan.bgpRows = rts.filter(r => r.routes.length || r.bgp === "Enabled").map(r => ({
      name: r.name, bgp: r.bgp,
      reason: r.name === "RT-GatewaySubnet" ? "Required — disabling breaks the gateway (§8)"
        : r.bgp === "Enabled" ? "Learns on-prem prefixes for the NVA return path; explicit UDRs win via LPM"
        : "Force all traffic through inspection via explicit UDRs",
    }));
    if (wantRS) plan.bgpRows.push({ name: "RouteServerSubnet", bgp: "N/A (Azure-managed)", reason: "No UDR or NSG supported" });

    /* ════════ 10 · NSGs ════════ */
    const nsgs = [];
    const onpremSrc = onprem.map(o => o.cidr).join(", ") || null;
    const spokesSrc = spokesPrefixes.join(", ");
    const platformSrc = mode === "reference" ? C.cidr(regionBase, 16) : hubRouteCidr;
    const bastionCidr = S.bastion && svc.bastion ? S.bastion.cidr : null;
    const bastionRule = bastionCidr ? rule(140, "AllowBastionInbound", "Inbound", bastionCidr, "Any", "22,3389", "TCP", "Allow") : null;
    const pairCidr = (a, b) => (a && b && b.base === a.base + 256 && a.base % 512 === 0) ? C.cidr(a.base, 23) : (a && b ? `${a.cidr}, ${b.cidr}` : null);

    if (svc.bastion) {
      nsgs.push({
        name: "NSG-Bastion", appliesTo: "AzureBastionSubnet", required: true,
        note: "Azure Bastion requires these exact rules — missing rules fail deployment. Four rules use protocol Any per the normative Microsoft summary table; do not tighten to TCP without lab validation (§9.1).",
        rules: [
          rule(120, "AllowHttpsInbound", "Inbound", "Internet", "*", "443", "TCP", "Allow"),
          rule(130, "AllowGatewayManagerInbound", "Inbound", "GatewayManager", "*", "443", "TCP", "Allow"),
          rule(140, "AllowAzureLoadBalancerInbound", "Inbound", "AzureLoadBalancer", "*", "443", "TCP", "Allow"),
          rule(150, "AllowBastionHostCommunication", "Inbound", "VirtualNetwork", "VirtualNetwork", "8080,5701", "Any", "Allow"),
          DENY_IN,
          rule(100, "AllowSshRdpOutbound", "Outbound", "*", "VirtualNetwork", "22,3389", "Any", "Allow"),
          rule(110, "AllowAzureCloudOutbound", "Outbound", "*", "AzureCloud", "443", "TCP", "Allow"),
          rule(120, "AllowBastionCommunication", "Outbound", "VirtualNetwork", "VirtualNetwork", "8080,5701", "Any", "Allow"),
          rule(130, "AllowHttpOutbound", "Outbound", "*", "Internet", "80", "Any", "Allow"),
          rule(4096, "DenyAllOutbound", "Outbound", "Any", "Any", "Any", "Any", "Deny"),
        ],
      });
    }

    if (wantNSNVA && S.nsext && S.nsint) {
      const extName = arch === "single" ? "NSG-FW-External" : "NSG-NS-External";
      nsgs.push({
        name: extName, appliesTo: FW_EXT,
        note: "Inbound publishing rules — only what the NVAs actually terminate. On-prem traffic never enters here; it arrives via the GatewaySubnet (§9.2).",
        rules: [
          rule(100, "AllowHTTPS-Inbound", "Inbound", "Internet", S.nsext.cidr, "443", "TCP", "Allow"),
          rule(110, "AllowHTTP-Inbound", "Inbound", "Internet", S.nsext.cidr, "80", "TCP", "Allow"),
          ALLOW_LB, DENY_IN,
        ],
      });
      const intName = arch === "single" ? "NSG-FW-Internal" : "NSG-NS-Internal";
      const intRules = [rule(100, "AllowFromSpokes", "Inbound", spokesSrc, S.nsint.cidr, "Any", "Any", "Allow")];
      let prio = 110;
      if (hasShared) { intRules.push(rule(prio, "AllowFromSharedServices", "Inbound", sharedCidr || platformSrc, S.nsint.cidr, "Any", "Any", "Allow")); prio += 10; }
      if (ewEngine === "nva" && arch === "dual" && S.ewext && S.ewint) {
        intRules.push(rule(prio, "AllowFromEW", "Inbound", pairCidr(S.ewext, S.ewint), S.nsint.cidr, "Any", "Any", "Allow")); prio += 10;
      }
      if ((ewEngine === "azfw" || chain === "ns" || chain === "fw") && S.azfw) {
        intRules.push(rule(prio, "AllowFromAzureFirewall", "Inbound", S.azfw.cidr, S.nsint.cidr, "Any", "Any", "Allow")); prio += 10;
      }
      if (arch === "single") { intRules.push(rule(prio, "AllowFromPlatform", "Inbound", platformSrc, S.nsint.cidr, "Any", "Any", "Allow")); prio += 10; }
      intRules.push(ALLOW_LB, DENY_IN);
      nsgs.push({ name: intName, appliesTo: FW_INT, note: arch === "single" ? "Entry point for all inspected traffic (ILB VIP lives here)." : "", rules: intRules });
    }

    if (wantEWNVA && S.ewext && S.ewint) {
      const ewExtRules = [
        rule(100, "AllowFromSpokes", "Inbound", spokesSrc, S.ewext.cidr, "Any", "Any", "Allow"),
        ...(hasShared ? [rule(110, "AllowFromSharedServices", "Inbound", sharedCidr || platformSrc, S.ewext.cidr, "Any", "Any", "Allow")] : []),
        ...(nsEngine === "nva" && S.nsext && S.nsint ? [rule(120, "AllowFromNS", "Inbound", pairCidr(S.nsext, S.nsint), S.ewext.cidr, "Any", "Any", "Allow")] : []),
        rule(130, "AllowFromPlatform", "Inbound", platformSrc, S.ewext.cidr, "Any", "Any", "Allow"),
        ALLOW_LB, DENY_IN,
      ];
      nsgs.push({ name: "NSG-EW-External", appliesTo: "Subnet-EW-External", rules: ewExtRules,
        note: "Management plane / future expansion only — no data-plane traffic in this design (§9.4)." });
      nsgs.push({
        name: "NSG-EW-Internal", appliesTo: "Subnet-EW-Internal",
        rules: [
          rule(100, "AllowFromEWExternal", "Inbound", S.ewext.cidr, S.ewint.cidr, "Any", "Any", "Allow"),
          rule(110, "AllowFromSpokes", "Inbound", spokesSrc, S.ewint.cidr, "Any", "Any", "Allow"),
          ...(hasShared ? [rule(120, "AllowFromSharedServices", "Inbound", sharedCidr || platformSrc, S.ewint.cidr, "Any", "Any", "Allow")] : []),
          ...(chain === "ew" && S.azfw ? [rule(125, "AllowFromAzureFirewall", "Inbound", S.azfw.cidr, S.ewint.cidr, "Any", "Any", "Allow")] : []),
          rule(130, "AllowFromPlatform", "Inbound", platformSrc, S.ewint.cidr, "Any", "Any", "Allow"),
          ALLOW_LB, DENY_IN,
        ],
        note: ewHop && ewHop.kind === "ilb" ? `${ewHop.label} (${ewHop.ip}) is the single entry point for all East-West inspection — spokes and platform must be allowed in (§9.5).` : "",
      });
    }

    if (svc.dc || svc.mon) {
      const adSrc = onpremSrc ? `${master.normalized}, ${onpremSrc}` : master.normalized;
      const r = [];
      if (svc.dc && S.dc) {
        r.push(rule(100, "AllowAD-TCP", "Inbound", adSrc, S.dc.cidr, "53,88,135,389,445,464,636,3268,3269,49152-65535", "TCP", "Allow"));
        r.push(rule(105, "AllowAD-UDP", "Inbound", adSrc, S.dc.cidr, "53,88,123,389,464", "UDP", "Allow"));
      }
      if (svc.mon && S.mon) r.push(rule(110, "AllowMonitoring", "Inbound", master.normalized, S.mon.cidr, "443", "TCP", "Allow"));
      if (bastionRule) r.push(bastionRule);
      r.push(ALLOW_LB, DENY_IN);
      r.push(rule(200, "AllowOutboundToSpokes", "Outbound", "Any", spokesSrc, "Any", "Any", "Allow"));
      r.push(rule(210, "AllowOutboundToInternet", "Outbound", "Any", "Internet", "443", "TCP", "Allow"));
      nsgs.push({
        name: "NSG-SharedServices", appliesTo: [svc.dc && "DomainControllers", svc.mon && "Monitoring", svc.kv && "KeyVault"].filter(Boolean).map(s => "Subnet-" + s).join(", "),
        note: svc.dc ? "Full AD port set incl. UDP Kerberos/DNS, RPC mapper + dynamic range, Global Catalog and W32Time — and on-prem sources, or DC replication/logons break (§9.6). Restrict the dynamic RPC range only if DCs pin a static port." : "",
        rules: r,
      });
    }

    if (svc.jump && S.jump) {
      const r = [];
      if (bastionRule) r.push(bastionRule);
      if (onpremSrc) r.push(rule(100, "AllowAdminFromOnPrem", "Inbound", onpremSrc, S.jump.cidr, "22,3389", "TCP", "Allow"));
      r.push(ALLOW_LB, DENY_IN);
      nsgs.push({ name: "NSG-JumpServers", appliesTo: "Subnet-JumpServers", note: "Tighten the admin source to your PAW/management ranges — owner + expiry on any exception (guide §15.2).", rules: r });
    }

    if (svc.mgmt) {
      const r = [];
      if (bastionRule) r.push(bastionRule);
      r.push(rule(100, "AllowFromPlatform", "Inbound", platformSrc, "Any", "443", "TCP", "Allow"));
      r.push(ALLOW_LB, DENY_IN);
      nsgs.push({ name: "NSG-Management", appliesTo: "Management section subnets", rules: r, note: "" });
    }

    if (isNVA) {
      const r = [];
      if (bastionRule) r.push(bastionRule);
      const mgmtSrcs = [S.jump && svc.jump ? S.jump.cidr : null, onpremSrc].filter(Boolean).join(", ");
      if (mgmtSrcs) r.push(rule(100, "AllowNVAMgmt", "Inbound", mgmtSrcs, S.nvam ? S.nvam.cidr : "Subnet-NVA-Management", "22,443", "TCP", "Allow"));
      r.push(ALLOW_LB, DENY_IN);
      nsgs.push({ name: "NSG-NVA-Mgmt", appliesTo: "Subnet-NVA-Management", rules: r, note: "Vendor consoles only from jump servers / on-prem admin ranges. VMSS tiers attach this NSG via the scale-set NIC profile." });
    }

    const spokeWeb = [
      rule(100, "AllowHTTPS", "Inbound", "Any", "ASG-WebServers", "443", "TCP", "Allow"),
      rule(110, "AllowHTTP", "Inbound", "Any", "ASG-WebServers", "80", "TCP", "Allow"),
      rule(120, "AllowFromAppTier", "Inbound", "ASG-AppServers", "ASG-WebServers", "8080", "TCP", "Allow"),
    ];
    const spokeApp = [
      rule(100, "AllowFromWebTier", "Inbound", "ASG-WebServers", "ASG-AppServers", "8080,8443", "TCP", "Allow"),
      rule(110, "AllowFromDataTier", "Inbound", "ASG-DataServers", "ASG-AppServers", "1433", "TCP", "Allow"),
    ];
    const spokeData = [
      rule(100, "AllowSQL", "Inbound", "ASG-AppServers", "ASG-DataServers", "1433", "TCP", "Allow"),
      ...(svc.mgmt && S.backup ? [rule(110, "AllowBackup", "Inbound", S.backup.cidr, "ASG-DataServers", "443", "TCP", "Allow")] : []),
    ];
    [spokeWeb, spokeApp, spokeData].forEach(r => { if (bastionRule) r.push(bastionRule); r.push(ALLOW_LB, DENY_IN); });
    if (totalSpokes > 0) {
      const inst = (t) => `instantiated per spoke as nsg-${t}-<spoke>-<env>-${region}`;
      nsgs.push({ name: "NSG-Spoke-Web", appliesTo: `web tiers — ${inst("web")}`, rules: spokeWeb, note: bastionRule ? "Rule 140 is mandatory: the custom DenyAllInbound at 4096 means the default AllowVnetInBound never fires — without it Bastion sessions are silently blocked (§9.7–9.9)." : "" });
      nsgs.push({ name: "NSG-Spoke-App", appliesTo: `app tiers — ${inst("app")}`, rules: spokeApp, note: "" });
      nsgs.push({ name: "NSG-Spoke-Data", appliesTo: `data tiers — ${inst("data")}`, rules: spokeData, note: "" });
    }

    if (svc.pe || totalSpokes > 0) {
      const r = [];
      if (ewSnatRange) r.push(rule(100, "AllowFromInspection-SNAT", "Inbound", ewSnatRange, "Subnet-PE", "443", "TCP", "Allow"));
      if (hasShared) r.push(rule(110, "AllowFromSharedServices", "Inbound", sharedCidr || platformSrc, "Subnet-PE", "443", "TCP", "Allow"));
      onprem.forEach((o, i) => r.push(rule(120 + i, `AllowFromOnPrem${onprem.length > 1 ? "-" + (i + 1) : ""}`, "Inbound", o.cidr, "Subnet-PE", "443", "TCP", "Allow")));
      r.push(DENY_IN);
      nsgs.push({
        name: "NSG-PrivateEndpoints", appliesTo: "Hub + spoke PE subnets",
        note: "NSGs evaluate the post-SNAT source — rule 100 matches the East-West inspector's internal range, not the workload range (§11.3). Requires privateEndpointNetworkPolicies = Enabled. On-prem → PE is intentionally direct (uninspected); do not force it through the inspector without extending SNAT scope.",
        rules: r,
      });
    }
    plan.nsgs = nsgs;

    plan.asgs = [
      { name: "ASG-WebServers", purpose: "Web tier VMs", members: "IIS, Nginx, Apache" },
      { name: "ASG-AppServers", purpose: "Application tier VMs", members: "API servers, middleware" },
      { name: "ASG-DataServers", purpose: "Database tier VMs", members: "SQL Server, PostgreSQL" },
      { name: "ASG-JumpServers", purpose: "Administrative access", members: "Jump boxes" },
      { name: "ASG-DomainControllers", purpose: "AD infrastructure", members: "Domain controllers" },
    ];

    /* ════════ 11 · PEERING ════════ */
    plan.peering = {
      hubToSpoke: [
        { flag: "AllowVirtualNetworkAccess", value: "true", why: "Hub ↔ spoke VM connectivity (default)" },
        { flag: "AllowForwardedTraffic", value: "true", why: "Hub accepts forwarded traffic from spokes — kept true for symmetry/future-proofing" },
        { flag: "AllowGatewayTransit", value: hybrid ? "true" : "false", why: hybrid ? "Required — hub gateway serves the spokes" : "No gateway deployed" },
        { flag: "UseRemoteGateways", value: "false", why: "The hub owns the gateway" },
      ],
      spokeToHub: [
        { flag: "AllowVirtualNetworkAccess", value: "true", why: "Spoke ↔ hub VM connectivity (default)" },
        { flag: "AllowForwardedTraffic", value: "true", why: "REQUIRED — legalises un-SNAT'd NVA-forwarded traffic entering the spoke; without it Azure silently drops it (§4.3.2)" },
        { flag: "AllowGatewayTransit", value: "false", why: "Spokes host no gateway" },
        { flag: "UseRemoteGateways", value: hybrid ? "true" : "false", why: hybrid ? "Required — spoke reaches on-prem via the hub gateway" : "No gateway — must be false" },
      ],
      notes: [
        arch !== "none" ? "Direct spoke↔spoke peering is NOT permitted — all east-west traffic transits the hub inspection point (§4.3.3)." :
          "Without central inspection, spoke↔spoke connectivity requires explicit direct peering per pair (peering is non-transitive).",
        totalSpokes > 100 ? "At this scale manage peering + flag drift with Azure Virtual Network Manager connectivity configurations instead of per-spoke IaC (§4.3)." : null,
        "Hub address-space changes require a peering resync on every spoke — online, but budget it into the change window (§2.2).",
      ].filter(Boolean),
    };

    /* ════════ 12 · DNS & PE panel ════════ */
    plan.dns = svc.dns ? {
      inbound: S.dnsin ? C.intToIp(S.dnsin.base + 4) : null,
      outbound: S.dnsout ? C.intToIp(S.dnsout.base + 4) : null,
      notes: [
        "Link every privatelink.* zone to the Hub VNet only; spokes resolve via the inbound endpoint (set as their VNet DNS server) — no per-spoke zone-link sprawl (§11.5.2).",
        onprem.length ? "On-prem DNS: add a conditional forwarder per privatelink.* zone → the inbound endpoint (§11.5.3)." : null,
        "Forwarding ruleset: explicit on-prem domains only — wildcard \".\" rules are prohibited with an ER gateway in the same VNet (§3.2.1).",
        arch !== "none" ? "Firewall must explicitly allow outbound-endpoint DNS egress (UDP/TCP 53) or resolution fails silently (§3.2.2)." : null,
      ].filter(Boolean),
      zones: ["privatelink.vaultcore.azure.net", "privatelink.blob.core.windows.net", "privatelink.database.windows.net", "privatelink.azurewebsites.net + scm", "privatelink.azurecr.io", "privatelink.monitor.azure.com (full AMPLS set)"],
    } : null;

    /* ════════ 13 · CAPACITY & GUARDRAILS ════════ */
    const peerings = totalSpokes + (plan.region2 ? 1 : 0);
    const erPrefixes = hub.prefixes.length + totalSpokes;
    if (totalSpokes > 499) err("Hub peering limit exceeded", `${totalSpokes} spokes > the 500-peerings-per-VNet platform limit (practical ceiling ≈ 499). Plan a second hub VNet or Virtual WAN (§15.4).`);
    else if (totalSpokes >= 400) warn("Approaching hub peering ceiling", `${totalSpokes} spokes — at ~400 begin planning a second hub VNet (platform-growth space) or the Virtual WAN re-evaluation (§15.4).`);
    if (conn.expressRoute && erPrefixes > 1000) err("ER advertisement limit", `${erPrefixes} prefixes advertised to on-prem exceeds the 1,000 ER private-peering limit (§15.4). Keep spokes single-prefix and reduce count.`);

    plan.capacity = {
      cards: [
        { label: "Supernet", value: master.normalized, sub: `${C.fmt(master.size)} addresses` },
        { label: "Hub declared", value: hub.prefixes.length ? `${C.fmt(hub.declared)}` : "—", sub: hub.prefixes.length > 1 ? `${hub.prefixes.length} × /19 prefixes` : (hub.prefixes[0] || "no hub"), accent: false },
        { label: "Hub subnetted", value: C.fmt(hub.subnetted), sub: hub.declared ? `${Math.round(hub.subnetted / hub.declared * 100)}% of declared space` : "—" },
        { label: "Spokes", value: String(totalSpokes), sub: `${C.fmt(pools.reduce((a, p) => a + p.used, 0))} addresses allocated`, accent: true },
      ],
      guardrails: [
        { name: "VNet peerings on the hub", value: `${peerings} / 500`, status: totalSpokes > 499 ? "err" : totalSpokes >= 400 ? "warn" : "ok", note: "Binding platform constraint — practical ceiling ≈ 499 spokes per regional hub (§15.4)" },
        conn.expressRoute ? { name: "ER prefixes advertised to on-prem", value: `${erPrefixes} / 1,000`, status: erPrefixes > 1000 ? "err" : erPrefixes > 800 ? "warn" : "ok", note: `${hub.prefixes.length} hub prefix${hub.prefixes.length > 1 ? "es" : ""} + 1 per spoke — keep spokes single-prefix (§15.4)` } : null,
        ...tiers.map(t => {
          const statics = t.groups.reduce((a, g) => a + (g.vmss ? 0 : g.count), 0);
          const vips = t.groups.filter(g => g.ha).length;
          const dyn = t.groups.reduce((a, g) => a + (g.vmss ? g.scale.max : 0), 0);
          const need = statics + vips + dyn;
          const cap = C.usable(24);
          return { name: `${t.label} tier subnet capacity`, value: `${need} / ${cap} IPs`,
                   status: need > cap || statics > 96 ? "err" : need > cap * 0.8 || statics > 76 ? "warn" : "ok",
                   note: `${t.groups.length} group${t.groups.length === 1 ? "" : "s (chained)"}: ${statics} static NICs (max 96, .4–.99) + ${vips} ILB VIPs (.100 ladder) + ${dyn} VMSS dynamic NICs (§20.2)` };
        }),
        ...pools.filter(p => p.allocs.length || mode === "reference").map(p => {
          const pct = Math.round(p.used / p.size * 100);
          return { name: `${p.name} pool utilisation`, value: `${pct}% of ${p.cidr}`, status: pct > 100 ? "err" : pct > 80 ? "warn" : "ok",
                   note: p.key === "ml" ? `max ${p.maxM} Medium or ${p.maxL} Large (each Large displaces 4 Mediums)` : p.maxS ? `max ${p.maxS} Small spokes` : p.note };
        }),
        svc.ddos ? { name: "DDoS Network Protection", value: "1 plan, all VNets", status: "ok", note: "Single plan in the Connectivity subscription, associated to hub + every spoke (§1.1)" } : null,
      ].filter(Boolean),
    };

    plan.summary = {
      arch: tierLabel,
      hybrid: [conn.expressRoute && "ExpressRoute", conn.vpn && "VPN"].filter(Boolean).join(" + ") || "None",
      totalSpokes,
      onpremCount: onprem.length,
      region,
      nsHop: plan.nsHop, ewHop: plan.ewHop, mode,
    };

    return plan;
  }

  return { buildPlan, defaultState };
}));
