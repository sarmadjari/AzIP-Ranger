# AzIP-Ranger — Roadmap (Exploratory)

> **Status: nothing here is confirmed or scheduled.** This is a parking lot of possible nice-to-have features, kept so good ideas don't get lost. Items may change, merge, or never happen. The current app is considered feature-complete for its core job: planning and validating an Azure Landing Zone network design.

## Deployment & automation

- **IaC export** — generate Bicep and/or Terraform (AVM modules) directly from a plan: hub VNet + subnets, route tables, NSGs, peerings, ILBs. Would remove the manual transcription step entirely.
- **AVNM artifacts** — export Azure Virtual Network Manager configurations: hub-and-spoke connectivity config (peering flags enforced centrally) and UDR routing configuration (needed anyway beyond ~400 spokes' routes per table).
- **Azure Policy pack** — emit the §12.7 guardrail catalog (G-1…G-12) as ready-to-assign policy definition JSON.
- **Spoke vending bundle** — per-spoke export (subnets, instantiated rt-/nsg- objects, the hub-side route additions) as the payload a subscription-vending pipeline consumes.

## Architecture modeling

- **Gateway Load Balancer insertion** — model GWLB as a first-class North-South option (the docs already recommend it over deep NS chains); plan provider VNet, chained frontends, and health-probe layout.
- **Active Region-2 generation** — turn the reserved second /13 into a fully generated mirror region with hub-to-hub global peering and cross-region inspection routes (§2.1).
- **IPv6 dual-stack planning** — optional /64 overlays per subnet, mirrored NSG rules, Front Door / dual-stack edge patterns (§2.3).
- **On-prem overlap helper** — when an on-prem site overlaps the Azure supernet, propose the VPN-gateway NAT plan for that site instead of just erroring (§2.2).
- **Explicit DR/HA annotations** — zone counts per ILB/VMSS, planned-maintenance notes in exports.

## App & UX

- **Diagram: chain-segment subnets** — render each chain group's own subnet and the per-segment route hops in the SVG topology (today chains show as ordered chips only).
- **Shareable designs** — encode the design state into a URL fragment (still 100% client-side) for review links.
- **Print/PDF-friendly report view** — one-click rendered report matching the Markdown export.
- **Diff view** — compare two saved design JSONs (routes/NSGs/subnets added-removed-changed) for change-window reviews.
- **What-if capacity slider** — drag spoke counts and watch peering/UDR/ER-prefix guardrails approach their ceilings.

## Validation & docs

- **Effective-route explorer in the UI** — interactive version of the test suite's LPM simulator: pick source + destination, see the winning route and inspection path.
- **Import from Azure** — read an existing environment (exported `az network` JSON) and diff it against the generated plan.
- **Config-driven hub catalog** — allow adding custom hub subnets (e.g., dedicated AKS-mgmt or ADO agents) via `config.js` without code changes.
