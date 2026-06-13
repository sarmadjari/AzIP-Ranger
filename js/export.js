/* ═══════════════════════════════════════════════════════════════
   AzIP-Ranger · export.js, pure plan/state → Markdown · CSV ·
   JSON serializers. No DOM. Used by app.js (browser downloads),
   the Node regeneration tool (tools/generate.js) and the unit
   tests, so exported artifacts are byte-identical everywhere.
   ═══════════════════════════════════════════════════════════════ */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./cidr.js"));
  } else {
    root.LZ_EXPORT = factory(root.LZ_CIDR);
  }
}(typeof self !== "undefined" ? self : this, function (C) {
  "use strict";

  const fmt = C.fmt;
  const DOC_BASIS = "based on IP Plan v5.2 + Network Design Guide v1.1";

  function mdTable(headers, rows) {
    return `| ${headers.join(" | ")} |\n|${headers.map(() => "---").join("|")}|\n` +
      rows.map(r => `| ${r.map(c => String(c ?? "").replace(/\|/g, "\\|")).join(" | ")} |`).join("\n") + "\n";
  }

  function buildMarkdown(plan, state, dateStr) {
    const s = plan.summary;
    const lines = [];
    lines.push(`# AzIP-Ranger, Generated Azure Landing Zone Network Design`);
    lines.push(`> Generated ${dateStr || new Date().toISOString().slice(0, 10)} · ${DOC_BASIS} · region: ${s.region}\n`);
    lines.push(`## 1. Configuration Summary\n`);
    lines.push(mdTable(["Setting", "Value"], [
      ["Azure supernet", state.azure.cidr],
      ["Region (naming)", s.region],
      ["Layout mode", s.mode === "reference" ? "v5.0 reference (/13 regional template)" : "Auto right-size"],
      ["Architecture", s.arch],
      ["Hybrid connectivity", s.hybrid],
      ["On-prem prefixes", plan.onprem.map(o => `${o.name}: ${o.cidr}`).join("; ") || "-"],
      ["Spokes", String(s.totalSpokes)],
    ]));
    const issues = plan.msgs;
    if (issues.length) {
      lines.push(`## 2. Findings\n`);
      lines.push(mdTable(["Level", "Finding", "Detail"], issues.map(m => [m.level.toUpperCase(), m.title, m.text])));
    }
    lines.push(`## 3. Master IP Allocation\n`);
    lines.push(mdTable(["Block", "CIDR", "Addresses", "Note"], plan.masterRows.map(r => [r.name.replace(/&nbsp;/g, " "), r.cidr, fmt(r.addresses), r.note])));
    lines.push(`## 4. Hub VNet, \`${plan.hub.name}\`\n`);
    lines.push(`Address prefixes: ${plan.hub.prefixes.map(p => `\`${p}\``).join(" + ")}\n`);
    lines.push(mdTable(["Subnet", "CIDR", "Usable", "Purpose", "Route Table", "NSG", "Status"],
      plan.hub.subnets.map(x => [x.name, x.cidr, x.reserved ? "-" : fmt(x.usable), x.purpose, x.rt, x.nsg, x.reserved ? "Reserved" : "Active"])));
    if (plan.ilbs.length) {
      lines.push(`### Internal Load Balancers (Standard SKU, HA Ports, Floating IP)\n`);
      lines.push(mdTable(["ILB", "VIP", "Subnet", "Backend pool", "Purpose"], plan.ilbs.map(l => [l.name, l.vip, l.subnet, l.pool, l.purpose])));
    }
    if (plan.nva && plan.nva.tiers.length) {
      lines.push(`### NVA Inventory\n`);
      plan.nva.tiers.forEach(t => {
        if (t.groups.length > 1) {
          lines.push(`**${t.label} tier chain**: ${t.groups.map((g, i) => `${i + 1}. ${g.display} (${g.hop.ip})`).join(" → ")}, workload route tables target only the entry hop; each segment's OWN subnet route table steers inspected traffic to the next hop (fabric-routed UDR cascade, Section 20), and every group SNATs to its forwarding NIC.\n`);
        }
        t.groups.forEach((g, gi) => {
          const pos = t.groups.length > 1 ? ` (chain ${gi === 0 ? "entry" : "hop " + (gi + 1)})` : "";
          const extS = g.extSubnet || t.extSubnet, intS = g.intSubnet || t.intSubnet;
          if (g.vmss) {
            lines.push(`**${g.display}, ${t.label}${pos}**: VMSS Flex (${g.vmssName}), autoscale ${g.scale.min}–${g.scale.max} behind ${g.ilbName} (VIP ${g.hop.ip}). Instance NICs are dynamic in ${extS} / ${intS}.\n`);
          } else {
            lines.push(`**${g.display}, ${t.label}${pos}**: ${g.count}× ${g.ha ? `active-active behind ${g.ilbName} (VIP ${g.hop.ip})` : "single instance (next hop = NIC IP)"}\n`);
            lines.push(mdTable(["NVA", "External NIC", "Internal NIC", "Mgmt NIC", "Loopback VIP"],
              g.instances.map(x => [x.name, `${x.ext} (${g.extName || extS})`, `${x.int} (${g.intName || intS})`, x.mgmt || "-", x.loopbacks.join(", ") || "-"])));
          }
        });
      });
    }
    if (plan.azfw) lines.push(`**Azure Firewall**: role: ${plan.azfw.role}, private IP ${plan.azfw.ip}.\n`);
    lines.push(`## 5. Spoke VNets\n`);
    plan.pools.filter(p => p.allocs.length).forEach(p => {
      lines.push(`### ${p.name} pool, \`${p.cidr}\` (${Math.round(p.used / p.size * 100)}% used)\n`);
      lines.push(mdTable(["VNet", "Workload", "Env", "Size", "CIDR", "Route table"], p.allocs.map(a => [a.name, a.label, a.env, a.size, a.cidr, a.rtName])));
    });
    const allAllocs = plan.pools.flatMap(p => p.allocs);
    Object.entries(plan.templates).forEach(([k, t]) => {
      const sample = allAllocs.find(a => a.template === k);
      if (!sample) return;
      lines.push(`### Template ${k} (example: ${sample.name} = ${sample.cidr})\n`);
      lines.push(mdTable(["Subnet", "CIDR", "Purpose", "NSG"], t.map(x => {
        const named = x.reserved || x.tier.startsWith("(");
        return [named ? x.tier : `snet-${x.tier}-${sample.nameBase}`, C.cidr(sample.base + x.off, x.prefix), x.purpose, named ? "-" : `nsg-${x.tier}-${sample.nameBase}`];
      })));
    });
    lines.push(`## 6. Route Tables\n`);
    plan.routeTables.forEach(rt => {
      lines.push(`### ${rt.name}, applies to: ${rt.appliesTo} (BGP propagation: ${rt.bgp})\n`);
      if (rt.routes.length) lines.push(mdTable(["Route", "Prefix", "Next hop type", "Next hop"], rt.routes.map(r => [r.name, r.prefix, r.type, r.nextHop])));
      if (rt.note) lines.push(`> ${rt.note}\n`);
    });
    lines.push(`## 7. NSGs\n`);
    plan.nsgs.forEach(n => {
      lines.push(`### ${n.name}, ${n.appliesTo}\n`);
      lines.push(mdTable(["Pri", "Name", "Dir", "Source", "Destination", "Ports", "Proto", "Action"],
        n.rules.map(r => [r.prio, r.name, r.dir, r.src, r.dst, r.port, r.proto, r.action])));
      if (n.note) lines.push(`> ${n.note}\n`);
    });
    lines.push(`## 8. Peering Flags\n### Hub → Spoke\n`);
    lines.push(mdTable(["Flag", "Value", "Reason"], plan.peering.hubToSpoke.map(f => [f.flag, f.value, f.why])));
    lines.push(`### Spoke → Hub\n`);
    lines.push(mdTable(["Flag", "Value", "Reason"], plan.peering.spokeToHub.map(f => [f.flag, f.value, f.why])));
    plan.peering.notes.forEach(n => lines.push(`> ${n}\n`));
    if (plan.dns) {
      lines.push(`## 9. DNS\n`);
      lines.push(mdTable(["Endpoint", "IP"], [["Inbound", plan.dns.inbound], ["Outbound", plan.dns.outbound]]));
      plan.dns.notes.forEach(n => lines.push(`- ${n}`));
      lines.push("");
    }
    lines.push(`## 10. Capacity & Guardrails\n`);
    lines.push(mdTable(["Guardrail", "Value", "Status", "Note"], plan.capacity.guardrails.map(g => [g.name, g.value, g.status.toUpperCase(), g.note])));
    return lines.join("\n");
  }

  function csvEsc(v) {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }
  function toCsv(headers, rows) {
    return [headers.join(","), ...rows.map(r => r.map(csvEsc).join(","))].join("\r\n");
  }

  function csvVnets(plan) {
    const rows = [[plan.hub.name, "Hub", "platform", plan.hub.prefixes.join(" + "), plan.summary.region]];
    plan.pools.forEach(p => p.allocs.forEach(a => rows.push([a.name, "Spoke", a.env, a.cidr, plan.summary.region])));
    return toCsv(["VNet", "Role", "Environment", "AddressSpace", "Region"], rows);
  }
  function csvSubnets(plan) {
    const rows = [];
    plan.hub.subnets.forEach(x => rows.push(["Hub", plan.hub.name, x.section, x.name, x.cidr, x.reserved ? "" : C.usable(x.prefix), x.purpose, x.rt, x.nsg, x.delegation || "", x.reserved ? "Reserved" : "Active"]));
    plan.pools.forEach(p => p.allocs.forEach(a => {
      rows.push(["Spoke", a.name, a.env, "(VNet)", a.cidr, "", a.size + " spoke VNet", a.rtName, "", "", "Active"]);
      (plan.templates[a.template] || []).forEach(t => {
        const named = t.reserved || t.tier.startsWith("(");
        rows.push(["Spoke", a.name, a.env, named ? t.tier : `snet-${t.tier}-${a.nameBase}`, C.cidr(a.base + t.off, t.prefix), t.reserved ? "" : C.usable(t.prefix), t.purpose, t.reserved ? "-" : a.rtName, t.reserved ? "-" : (named ? "per workload" : `nsg-${t.tier}-${a.nameBase}`), "", t.reserved ? "Reserved" : "Active"]);
      });
    }));
    return toCsv(["Scope", "VNet", "Section/Env", "Subnet", "CIDR", "UsableIPs", "Purpose", "RouteTable", "NSG", "Delegation", "Status"], rows);
  }
  function csvRoutes(plan) {
    const rows = [];
    plan.routeTables.forEach(rt => rt.routes.forEach(r => rows.push([rt.name, rt.appliesTo, rt.bgp, r.name, r.prefix, r.type, r.nextHop])));
    return toCsv(["RouteTable", "AppliesTo", "BGPPropagation", "Route", "AddressPrefix", "NextHopType", "NextHop"], rows);
  }
  function csvNsg(plan) {
    const rows = [];
    plan.nsgs.forEach(n => n.rules.forEach(r => rows.push([n.name, n.appliesTo, r.prio, r.name, r.dir, r.src, r.dst, r.port, r.proto, r.action])));
    return toCsv(["NSG", "AppliesTo", "Priority", "Rule", "Direction", "Source", "Destination", "Ports", "Protocol", "Action"], rows);
  }
  function csvAll(plan) {
    return [
      "### VNETS", csvVnets(plan), "",
      "### SUBNETS", csvSubnets(plan), "",
      "### ROUTE TABLES", csvRoutes(plan), "",
      "### NSG RULES", csvNsg(plan),
    ].join("\r\n");
  }

  function designJson(state, savedAt) {
    return JSON.stringify({ tool: "azip-ranger", version: 2, savedAt: savedAt || new Date().toISOString(), state }, null, 2);
  }

  return { buildMarkdown, csvAll, csvVnets, csvSubnets, csvRoutes, csvNsg, designJson, mdTable, toCsv };
}));
