# Why AzIP-Ranger: What It's Good At and What It Helps With

> A plain-language companion to the two reference docs
> ([IP Plan](azure-landing-zone-ip-plan.md) · [Network Design Guide](azure-landing-zone-network-design-guide.md)).
> This file explains **the value** of the project; those two explain **the rules**.

---

## 1. The problem it solves

Planning the network for an Azure Landing Zone (ALZ) is deceptively hard. The IP
math is the *easy* part, the traps are the rules that fail **silently** at deploy
time:

- **IP overlap & exhaustion**: a spoke that overlaps on-prem, or a `/16` VNet that
  wastes a region's address budget, isn't caught until much later.
- **Route longest-prefix-match (LPM) traps**: a tidy `To-Spokes 10.4.0.0/14`
  summary route **silently loses** to the more-specific peering routes, so traffic
  bypasses your firewall and you never get an error.
- **Post-SNAT NSG sources**: an NSG rule sourced from the workload range
  (`10.4.0.0/14`) never fires for traffic the NVA SNATs to `10.0.5.x`; the default
  rule quietly covers it and your "tight" rule does nothing.
- **Peering-flag silent failures**: one missing `AllowForwardedTraffic` and the
  peering object exists but the packets are dropped.
- **Capacity ceilings**: the 500-peerings, 1,000-ER-prefix and 400/1,000-UDR
  limits bind *before* the address plan does, and only at scale.

AzIP-Ranger turns a handful of structured inputs into a **complete, validated**
hub-and-spoke design that has these traps designed out, and tells you, in plain
language, *why* each choice was made.

## 2. What it produces

From a few inputs (supernet, region, on-prem ranges, inspection architecture,
services, and a free-form spoke list) it generates:

| Output | What you get |
|---|---|
| **Master IP allocation** | Regional `/13` template, platform + spoke pools, reserved growth, Region-2 reservation. |
| **Hub VNet & subnets** | Connectivity / Shared-Services / Management sections, every subnet sized and placed, CAF-named. |
| **NVA tiers & ILBs** | VM or VMSS groups, VIP ladder (`.100`/`.101`…), static NIC ranges (`.4`–`.99`), chained groups + Azure Firewall slots. |
| **Route tables (RTs)** | Every RT with exact-prefix routes, BGP-propagation flag, and an inline note explaining the intent. |
| **NSGs** | Per-subnet rule sets (Bastion, AD, Key Vault PE, spoke tiers, chain segments) with priorities and rationale. |
| **Peering, DNS, capacity** | Hub↔spoke flag tables, Private DNS/Resolver guidance, and live capacity guardrails. |
| **Exports** | Markdown report, CSV (subnets / routes / NSGs), and a reload-able JSON design. |

## 3. How it helps specifically with **NSG and RT summarization & planning**

This is where the tool earns its keep, and it works on two levels:

**The app makes it easy to *plan*.**
- Every **route table** is rendered as a clean table, *Route · Prefix · Next-hop
  type · Next-hop*: followed by a one-paragraph **note** that states the intent
  ("exact `/19` hub prefixes so the UDR ties-and-wins over the peering route", "no
  `To-Spokes` here or you create one-sided flows the firewall drops", etc.).
- Every **NSG** is rendered the same way, *Priority · Name · Direction · Source ·
  Destination · Ports · Protocol · Action*: with a note explaining the non-obvious
  rules (post-SNAT sources, the mandatory Bastion 22/3389 allow, the own-spoke PE
  rule).
- Inline **section-reference tooltips** link each note straight to the relevant Microsoft
  Learn page, so "why" is always one click away.
- A live **findings panel** (errors / warnings / info) and **capacity guardrails**
  flag problems *as you design*, not after.
- **CSV/Markdown export** gives you the whole RT and NSG catalog as a portable
  summary for review, change tickets, or hand-off to IaC.

**The docs make it easy to *explain*.**
- [IP Plan Section 7](azure-landing-zone-ip-plan.md) is the complete RT catalog;
  [Section 8](azure-landing-zone-ip-plan.md) is the BGP-propagation guardrail table;
  [Section 9](azure-landing-zone-ip-plan.md) is the complete NSG catalog, each with
  rationale and a full fix history so reviewers can see *why*, not just *what*.
- The [Network Design Guide](azure-landing-zone-network-design-guide.md) distils it
  into a route-intent model (Section 8) and NSG layering strategy (Section 9) plus "golden rules".

> **Honest caveat**: the catalogs are *exhaustive and rule-driven* rather than a
> one-paragraph executive summary. If you want the 30-second version, the app's
> per-RT/per-NSG **notes** and this file are that summary; the design docs are the
> deep reference behind them.

## 4. The NVA arm model (External · Internal · Management)

A recurring question when reading any hub design is *"why do the NVAs have these
three subnets?"* The concept is now documented end-to-end in
[IP Plan Section 6.1.1](azure-landing-zone-ip-plan.md):

- **External** = the *dirty/edge* side (Internet ingress + egress NAT).
- **Internal** = the *clean/VNet* side the whole landing zone **routes to** (hosts
  the ILB VIP `.100` and the SNAT/return anchor).
- **Management** = the *out-of-band* door (admin consoles, vendor licensing) on its
  own subnet, NSG, and RT, so you can still reach the appliance when the data
  plane is broken, and a data-plane change can't lock you out.

The app surfaces all three structurally too: the **NVA inventory** lists each
instance's External NIC, Internal NIC, **Mgmt NIC**, and Loopback VIP.

## 5. Why you can trust the output

- **Verified against live Microsoft Learn**, not memory, route-selection/LPM, the
  400/1,000-UDR limit, 500 peerings, post-SNAT NSG behaviour, default-outbound
  retirement, and flow-log changes were all re-checked against current docs.
- **Doc ↔ engine lockstep**: every rule in the design docs is encoded in the
  engine, and the exports are byte-identical across the browser, the CLI tool, and
  the tests.
- **166-assertion test suite** including an **effective-route LPM simulator** that
  replays real flows (spoke→spoke, on-prem→spoke, spoke→PE) and proves traffic is
  actually inspected and symmetric.
- **100% client-side**: no server, no telemetry; your design never leaves the
  browser.

## 6. Who it's for

Cloud platform architects, network engineers, and security architects who are
**standardizing or reviewing** an ALZ hub-and-spoke design and want a fast,
opinionated, CAF-aligned starting point, plus a validation harness that catches
the silent-failure traps before deployment.

## 7. What it is **not**

- **Not an official Microsoft product**: a personal tool, provided as-is. Always
  validate against your org's requirements and live Microsoft docs before deploying.
- **Not (yet) an IaC generator**: it plans and validates; it doesn't deploy.
  Bicep/Terraform/AVNM export is on the [roadmap](../ROADMAP.md).
- **Not a substitute for the design docs**: it operationalizes them; the
  [IP Plan](azure-landing-zone-ip-plan.md) and
  [Design Guide](azure-landing-zone-network-design-guide.md) remain the source of
  truth for *why*.
